# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import questionary
from rich.console import Console

console = Console()

_CDXGENRC_TEMPLATE = {
    "type": "universal",
    "deep": True,
    "output": "bom.json",
    "spec-version": "1.6",
}


def _step_cdxgenrc() -> str | None:
    """Шаг 1: Настройка .cdxgenrc — возвращает имя выходного SBOM-файла."""
    console.rule("[bold]Шаг 1/4: Настройка .cdxgenrc[/bold]")

    sbom_filename = questionary.text(
        "Имя выходного SBOM-файла:",
        default="bom.json",
    ).ask()
    if sbom_filename is None:
        return None

    cdxgenrc_path = Path.cwd() / ".cdxgenrc"

    if cdxgenrc_path.exists():
        overwrite = questionary.confirm(
            f"Файл {cdxgenrc_path} уже существует. Перезаписать?",
            default=False,
        ).ask()
        if not overwrite:
            console.print("  Пропущено — .cdxgenrc не изменён.")
            return sbom_filename

    config = _CDXGENRC_TEMPLATE.copy()
    config["output"] = sbom_filename

    cdxgenrc_path.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    console.print(f"  [green]✓[/green] Записан {cdxgenrc_path}")
    return sbom_filename


def _step_cdxgen(sbom_filename: str) -> bool:
    """Шаг 2: Генерация SBOM через cdxgen."""
    console.rule("[bold]Шаг 2/4: Генерация SBOM (cdxgen)[/bold]")

    run_cdxgen = questionary.confirm(
        "Запустить cdxgen для генерации SBOM?",
        default=True,
    ).ask()
    if not run_cdxgen:
        console.print("  Пропущено.")
        return False

    if not shutil.which("cdxgen"):
        console.print("  [red]✗[/red] cdxgen не найден в PATH. Установите: npm install -g @cyclonedx/cdxgen")
        return False

    src_dir = questionary.path(
        "Директория с исходным кодом:",
        default=".",
        only_directories=True,
    ).ask()
    if src_dir is None:
        return False

    with console.status("Генерация SBOM через cdxgen..."):
        result = subprocess.run(
            ["cdxgen", "-o", sbom_filename, src_dir],
            capture_output=True,
            text=True,
        )

    if result.returncode == 0:
        console.print(f"  [green]✓[/green] SBOM сохранён в {sbom_filename}")
        return True
    else:
        console.print(f"  [red]✗[/red] cdxgen завершился с ошибкой (код {result.returncode})")
        if result.stderr:
            console.print(result.stderr.strip())
        return False


def _step_mappings(sbom_filename: str):
    """Шаг 3: Создание конфига (.sbom-config.json)."""
    console.rule("[bold]Шаг 3/4: Создание конфига[/bold]")

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

    import json
    from sbom_utils.config import init_config

    with open(sbom_path, encoding="utf-8") as f:
        bom = json.load(f)

    init_config(bom)
    console.print("  [green]✓[/green] Конфиг создан")


def _step_vcs_refs(sbom_filename: str):
    """Шаг 4: Поиск VCS-ссылок."""
    console.rule("[bold]Шаг 4/4: Поиск VCS-ссылок[/bold]")

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

    output_name = questionary.text(
        "Имя выходного файла:",
        default=sbom_filename,
    ).ask()
    if output_name is None:
        return

    from sbom_utils.updater import run

    args = SimpleNamespace(
        input=str(sbom_path),
        output=str(Path.cwd() / output_name),
        props=False,
        app_name=None,
        app_version=None,
        manufacturer=None,
        ref=True,
        purl_to_vcs=None,
        gost=False,
        purl_to_gost=None,
        init_gost_map=False,
        init_purl_map=False,
        fix_all=False,
        update=None,
        verbose=False,
    )

    with console.status("Поиск VCS-ссылок..."):
        run(args)

    console.print(f"  [green]✓[/green] Результат сохранён в {output_name}")


def run_wizard(verbose: bool = False):
    """Запускает пошаговый мастер инициализации SBOM-проекта."""
    console.print()
    console.rule("[bold cyan]Мастер инициализации SBOM-проекта[/bold cyan]")
    console.print()

    # Шаг 1
    sbom_filename = _step_cdxgenrc()
    if sbom_filename is None:
        console.print("\nОтменено.")
        return

    # Шаг 2
    _step_cdxgen(sbom_filename)

    # Шаг 3
    _step_mappings(sbom_filename)

    # Шаг 4
    _step_vcs_refs(sbom_filename)

    console.print()
    console.rule("[bold green]Готово![/bold green]")
    console.print()
