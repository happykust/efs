# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path
from types import SimpleNamespace

import questionary
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn

console = Console()

_SUPPORTED_TOOLS = [
    questionary.Choice("cdxgen (CycloneDX Generator)", value="cdxgen"),
    questionary.Choice("trivy (Aqua Security)", value="trivy"),
]

_CONFIG_FILENAME = '.sbom-config.json'


def _step_scanner_choice() -> tuple[str, str] | None:
    """Шаг 1: Выбор инструмента и настройка — возвращает (tool, sbom_filename) или None."""
    console.rule("[bold]Шаг 1/5: Выбор инструмента для генерации SBOM[/bold]")

    tool = questionary.select(
        "Какой инструмент использовать?",
        choices=_SUPPORTED_TOOLS,
    ).ask()
    if tool is None:
        return None

    sbom_filename = questionary.text(
        "Имя выходного SBOM-файла:",
        default="bom.json",
    ).ask()
    if sbom_filename is None:
        return None

    return tool, sbom_filename


def _step_scan(tool: str, sbom_filename: str) -> bool:
    """Шаг 2: Генерация SBOM выбранным инструментом."""
    console.rule(f"[bold]Шаг 2/5: Генерация SBOM ({tool})[/bold]")

    run_it = questionary.confirm(
        f"Запустить {tool} для генерации SBOM?",
        default=True,
    ).ask()
    if not run_it:
        console.print("  Пропущено.")
        return False

    src_dir = questionary.text(
        "Директория с исходным кодом (или имя образа для trivy image):",
        default=".",
    ).ask()
    if src_dir is None:
        return False

    from efc.scanner import run_scan

    with console.status(f"Генерация SBOM через {tool}..."):
        return run_scan(tool, src_dir, sbom_filename)


def _step_config(sbom_filename: str, tool: str):
    """Шаг 3: Создание конфига (.sbom-config.json)."""
    console.rule("[bold]Шаг 3/5: Создание конфига[/bold]")

    create_config = questionary.confirm(
        "Создать .sbom-config.json (единый конфиг для компонентов)?",
        default=True,
    ).ask()
    if not create_config:
        console.print("  Пропущено.")
        return

    sbom_path = Path.cwd() / sbom_filename
    if not sbom_path.is_file():
        console.print(f"  [red]✗[/red] Файл {sbom_filename} не найден. Сначала сгенерируйте SBOM.")
        return

    from efc.config import init_config

    with open(sbom_path, encoding="utf-8") as f:
        bom = json.load(f)

    config = init_config(bom)

    # Сохранить настройки сканера в конфиг
    config_path = Path.cwd() / _CONFIG_FILENAME
    config["scanner"] = {
        "tool": tool,
        "output": sbom_filename,
        "target": ".",
        "options": {},
    }
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    console.print("  [green]✓[/green] Конфиг создан (включая настройки сканера)")


def _iter_components_flat(components):
    """Рекурсивный обход всех компонентов (включая вложенные)."""
    for comp in components:
        yield comp
        yield from _iter_components_flat(comp.get('components', []))


def _step_vcs_refs(sbom_filename: str):
    """Шаг 4: Поиск VCS-ссылок и запись в конфиг."""
    console.rule("[bold]Шаг 4/5: Поиск VCS-ссылок[/bold]")

    find_refs = questionary.confirm(
        "Найти VCS-ссылки для компонентов через API?",
        default=True,
    ).ask()
    if not find_refs:
        console.print("  Пропущено.")
        return

    sbom_path = Path.cwd() / sbom_filename
    if not sbom_path.is_file():
        console.print(f"  [red]✗[/red] Файл {sbom_filename} не найден.")
        return

    config_path = Path.cwd() / _CONFIG_FILENAME
    if not config_path.is_file():
        console.print(f"  [red]✗[/red] Конфиг {_CONFIG_FILENAME} не найден. Сначала создайте его (шаг 3).")
        return

    from efc.config import _purl_without_version
    from efc.updater import RefFinder

    with open(sbom_path, encoding="utf-8") as f:
        bom = json.load(f)

    with open(config_path, encoding="utf-8") as f:
        config = json.load(f)

    # Собрать уникальные purl из SBOM
    components = list(_iter_components_flat(bom.get('components', [])))
    purls = []
    seen = set()
    for comp in components:
        purl = comp.get('purl', '')
        if purl and purl not in seen:
            purls.append(purl)
            seen.add(purl)

    if not purls:
        console.print("  Компоненты без purl — нечего искать.")
        return

    ref_finder = RefFinder()
    found = 0
    skipped = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("{task.fields[component]}"),
        console=console,
    ) as progress:
        task = progress.add_task("Поиск VCS-ссылок", total=len(purls), component="")

        for idx, purl in enumerate(purls, 1):
            base_purl = _purl_without_version(purl)
            progress.update(task, completed=idx, component=base_purl.split('/')[-1])

            # Пропустить если в конфиге уже есть VCS для этого purl
            entry = config.get('components', {}).get(base_purl, {})
            if entry.get('vcs'):
                skipped += 1
                continue

            url = ref_finder.process_purl(purl)
            if url and not url.startswith('sbom-updater_generated_placeholder:'):
                if base_purl not in config.get('components', {}):
                    config.setdefault('components', {})[base_purl] = {}
                config['components'][base_purl]['vcs'] = url
                found += 1

    ref_finder.dump_repos()

    # Сохранить обновлённый конфиг
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    console.print(f"  [green]✓[/green] Найдено VCS-ссылок: {found}, пропущено (уже есть): {skipped}")
    console.print(f"  Конфиг обновлён: {config_path}")


def _step_postprocess(sbom_filename: str):
    """Шаг 5: Постобработка SBOM."""
    console.rule("[bold]Шаг 5/5: Постобработка SBOM[/bold]")

    run_postprocess = questionary.confirm(
        "Выполнить постобработку SBOM (очистка, ГОСТ-свойства, метаданные)?",
        default=True,
    ).ask()
    if not run_postprocess:
        console.print("  Пропущено.")
        return

    sbom_path = Path.cwd() / sbom_filename
    if not sbom_path.is_file():
        console.print(f"  [red]✗[/red] Файл {sbom_filename} не найден.")
        return

    app_name = questionary.text(
        "Название продукта:",
        default="",
    ).ask()
    if app_name is None:
        return

    app_version = questionary.text(
        "Версия продукта:",
        default="",
    ).ask()
    if app_version is None:
        return

    manufacturer = questionary.text(
        "Организация-изготовитель:",
        default="",
    ).ask()
    if manufacturer is None:
        return

    output_name = questionary.text(
        "Имя выходного файла:",
        default=sbom_filename,
    ).ask()
    if output_name is None:
        return

    from efc.postprocess import run as postprocess_run

    args = SimpleNamespace(
        input=str(sbom_path),
        output=str(Path.cwd() / output_name),
        app_name=app_name or None,
        app_version=app_version or None,
        manufacturer=manufacturer or None,
        gost_default="no",
        strip_only=False,
        keep_all_fields=False,
        provided_by=None,
        purl_to_vcs=None,
        purl_to_gost=None,
        purl_exclude=None,
        init_exclude=False,
        config=None,
        pretty=True,
    )

    with console.status("Постобработка SBOM..."):
        postprocess_run(args)

    console.print(f"  [green]✓[/green] Результат сохранён в {output_name}")


def run_wizard(verbose: bool = False):
    """Запускает пошаговый мастер инициализации SBOM-проекта."""
    console.print()
    console.rule("[bold cyan]Мастер инициализации SBOM-проекта[/bold cyan]")
    console.print()

    # Шаг 1
    result = _step_scanner_choice()
    if result is None:
        console.print("\nОтменено.")
        return
    tool, sbom_filename = result

    # Шаг 2
    _step_scan(tool, sbom_filename)

    # Шаг 3
    _step_config(sbom_filename, tool)

    # Шаг 4
    _step_vcs_refs(sbom_filename)

    # Шаг 5
    _step_postprocess(sbom_filename)

    console.print()
    console.rule("[bold green]Готово![/bold green]")
    console.print()
