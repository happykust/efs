# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

from enum import StrEnum
from pathlib import Path
from types import SimpleNamespace

import typer


def _enum_value(option):
    """Значение опции-перечисления: typer отдаёт то член Enum, то строку по умолчанию."""
    return getattr(option, "value", option)


class SbomFormat(StrEnum):
    """Форма перечня: заимствованные компоненты или образы контейнеров."""

    oss = "oss"
    container = "container"


class ScanTool(StrEnum):
    """Поддерживаемые генераторы SBOM."""

    cdxgen = "cdxgen"
    trivy = "trivy"


class GostValue(StrEnum):
    """Допустимые значения ГОСТ-свойств."""

    yes = "yes"
    no = "no"
    indirect = "indirect"


app = typer.Typer(
    name="efs",
    help="efs — Easy FSTEC SBOMs: генерация, проверка и обогащение SBOM под ФСТЭК (CycloneDX + ГОСТ)",
    rich_markup_mode="rich",
    invoke_without_command=True,
)
export_app = typer.Typer(name="export", help="Экспорт SBOM в различные форматы", invoke_without_command=True)
app.add_typer(export_app)
config_app = typer.Typer(name="config", help="Управление единым конфигом .efs-config.json", invoke_without_command=True)
app.add_typer(config_app)

state = {"verbose": False}


def _print_version(value: bool):
    if value:
        from efs import __version__

        typer.echo(f"efs {__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "-v", "--verbose", help="подробный вывод"),
    version: bool = typer.Option(
        False, "-V", "--version", callback=_print_version, is_eager=True, help="показать версию и выйти"
    ),
):
    state["verbose"] = verbose
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


@export_app.callback()
def export_callback(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


@config_app.callback()
def config_callback(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


# ── check ──────────────────────────────────────────────────────────────────────


@app.command("check", help="Валидация SBOM")
def cmd_check(
    filename: Path = typer.Argument(
        ..., exists=True, dir_okay=False, readable=True, help="входной файл в формате CycloneDX JSON для проверки"
    ),
    errors: int = typer.Option(10, "-e", "--errors", help="максимальное число ошибок для вывода; 0 = все"),
    check_vcs: bool = typer.Option(False, "--check-vcs", help="проверка url типа vcs на git/svn/hg/fossil-репозиторий"),
    check_vcs_leaf_only: bool = typer.Option(
        False, "--check-vcs-leaf-only", help="то же, что и --check-vcs, но только для листовых компонентов"
    ),
    check_source_distribution: bool = typer.Option(
        False, "--check-source-distribution", help="проверка существования URL для типа source-distribution"
    ),
    format_: SbomFormat = typer.Option(SbomFormat.oss, "--format", help="форма перечня"),
):
    from efs.checker import run

    args = SimpleNamespace(
        filename=str(filename),
        errors=errors,
        check_vcs=check_vcs,
        check_vcs_leaf_only=check_vcs_leaf_only,
        check_source_distribution=check_source_distribution,
        format=_enum_value(format_),
        verbose=state["verbose"],
    )
    raise typer.Exit(code=run(args) or 0)


# ── update ─────────────────────────────────────────────────────────────────────


@app.command("update", help="Обогащение SBOM")
def cmd_update(
    input_: Path = typer.Argument(
        ..., metavar="INPUT", exists=True, dir_okay=False, readable=True, help="входной файл CycloneDX JSON"
    ),
    output: str | None = typer.Argument(None, help="выходной файл с дооформленным перечнем"),
    props: bool = typer.Option(False, "--props", help="добавить GOST:attack_surface и GOST:security_function"),
    app_name: str | None = typer.Option(None, "--app-name", help="название продукта"),
    app_version: str | None = typer.Option(None, "--app-version", help="версия продукта"),
    manufacturer: str | None = typer.Option(None, "--manufacturer", help="организация-изготовитель"),
    ref: bool = typer.Option(False, "--ref", help="установить externalReferences на основе purl"),
    purl_to_vcs: str | None = typer.Option(None, "--purl-to-vcs", help="путь к файлу маппинга purl→vcs"),
    gost: bool = typer.Option(False, "--gost", help="установить GOST-свойства из файла маппинга"),
    purl_to_gost: str | None = typer.Option(None, "--purl-to-gost", help="путь к файлу маппинга purl→GOST"),
    extra_input: list[str] | None = typer.Option(None, "-i", "--extra-input", help="дополнительные SBOM-файлы"),
    fix_all: bool = typer.Option(False, "--fix-all", help="применить все опции"),
    update: Path | None = typer.Option(
        None, "--update", metavar="OLD_SBOM", exists=True, dir_okay=False, help="предыдущая версия перечня"
    ),
):
    from efs.updater import run

    args = SimpleNamespace(
        input=str(input_),
        output=output,
        props=props,
        app_name=app_name,
        app_version=app_version,
        manufacturer=manufacturer,
        ref=ref,
        purl_to_vcs=purl_to_vcs,
        gost=gost,
        purl_to_gost=purl_to_gost,
        extra_input=extra_input or [],
        fix_all=fix_all,
        update=str(update) if update else None,
        verbose=state["verbose"],
    )
    run(args)


# ── merge ──────────────────────────────────────────────────────────────────────


@app.command("merge", help="Слияние нескольких SBOM")
def cmd_merge(
    files: list[str] = typer.Argument(..., help="входные файлы и последний — выходной файл"),
    app_name: str = typer.Option(..., "--app-name", help="название продукта"),
    app_version: str = typer.Option(..., "--app-version", help="версия продукта"),
    manufacturer: str = typer.Option(..., "--manufacturer", help="организация-изготовитель"),
):
    from efs.unifier import run

    if len(files) < 2:
        typer.echo("ошибка: необходимо указать хотя бы один входной файл и один выходной файл", err=True)
        raise typer.Exit(code=1)

    args = SimpleNamespace(
        input=files[:-1],
        output=files[-1],
        app_name=app_name,
        app_version=app_version,
        manufacturer=manufacturer,
        verbose=state["verbose"],
    )
    run(args)


# ── export csv ─────────────────────────────────────────────────────────────────


@export_app.command("csv", help="Экспорт SBOM в CSV")
def cmd_export_csv(
    input_: Path = typer.Argument(
        ..., metavar="INPUT", exists=True, dir_okay=False, readable=True, help="входной файл CycloneDX JSON"
    ),
    output: str = typer.Argument(..., help="выходной CSV файл"),
):
    from efs.to_csv import run

    args = SimpleNamespace(
        input=str(input_),
        output=output,
        verbose=state["verbose"],
    )
    run(args)


# ── export odt ─────────────────────────────────────────────────────────────────


@export_app.command("odt", help="Экспорт SBOM в ODT")
def cmd_export_odt(
    input_: Path = typer.Argument(
        ..., metavar="INPUT", exists=True, dir_okay=False, readable=True, help="входной файл CycloneDX JSON"
    ),
    output: str = typer.Argument(..., help="выходной ODT файл"),
    pa_fb_ontop: bool = typer.Option(False, "-t", "--pa-fb-ontop", help="помещение записей «ПА» и «ФБ» в топ таблицы"),
    format_: SbomFormat = typer.Option(SbomFormat.oss, "--format", help="форма перечня"),
):
    from efs.to_odt import run

    args = SimpleNamespace(
        input=str(input_),
        output=output,
        pa_fb_ontop=pa_fb_ontop,
        format=_enum_value(format_),
        verbose=state["verbose"],
    )
    run(args)


# ── postprocess ────────────────────────────────────────────────────────────────


@app.command("postprocess", help="Постобработка вывода cdxgen")
def cmd_postprocess(
    input_: Path = typer.Argument(
        ..., metavar="INPUT", exists=True, dir_okay=False, readable=True, help="входной BOM файл (JSON)"
    ),
    output: str = typer.Argument(..., help="выходной BOM файл (JSON)"),
    app_name: str | None = typer.Option(None, "--app-name", help="название продукта"),
    app_version: str | None = typer.Option(None, "--app-version", help="версия продукта"),
    manufacturer: str | None = typer.Option(None, "--manufacturer", help="организация-изготовитель"),
    gost_default: GostValue = typer.Option(GostValue.no, "--gost-default", help="значение ГОСТ-свойств по умолчанию"),
    strip_only: bool = typer.Option(False, "--strip-only", help="только очистить лишние поля"),
    keep_all_fields: bool = typer.Option(False, "--keep-all-fields", help="не удалять необязательные поля компонентов"),
    provided_by: str | None = typer.Option(
        None, "--provided-by", help="установить GOST:provided_by для leaf-компонентов"
    ),
    purl_to_vcs: str | None = typer.Option(None, "--purl-to-vcs", help="путь к файлу маппинга purl→vcs"),
    purl_to_gost: str | None = typer.Option(None, "--purl-to-gost", help="путь к файлу маппинга purl→GOST"),
    purl_exclude: str | None = typer.Option(
        None, "--purl-exclude", help="путь к файлу списка purl для исключения (.purl_exclude.json)"
    ),
    pretty: bool = typer.Option(True, "--pretty/--no-pretty", help="форматировать JSON"),
    config: str | None = typer.Option(
        None, "--config", help="путь к .efs-config.json (по умолчанию ищется в текущей директории)"
    ),
):
    from efs.postprocess import run

    args = SimpleNamespace(
        input=str(input_),
        output=output,
        app_name=app_name,
        app_version=app_version,
        manufacturer=manufacturer,
        gost_default=_enum_value(gost_default),
        strip_only=strip_only,
        keep_all_fields=keep_all_fields,
        provided_by=provided_by,
        purl_to_vcs=purl_to_vcs,
        purl_to_gost=purl_to_gost,
        purl_exclude=purl_exclude,
        pretty=pretty,
        config=config,
        verbose=state["verbose"],
    )
    run(args)


# ── scan ──────────────────────────────────────────────────────────────────────


@app.command("scan", help="Генерация SBOM с помощью cdxgen или trivy")
def cmd_scan(
    tool: ScanTool | None = typer.Option(None, "--tool", help="инструмент генерации SBOM"),
    target: str | None = typer.Option(None, "--target", help="путь или образ для сканирования"),
    output: str | None = typer.Option(None, "--output", "-o", help="выходной файл SBOM"),
    config: str | None = typer.Option(None, "--config", help="путь к .efs-config.json"),
):
    from efs.config import get_scanner_config, load_config
    from efs.scanner import SUPPORTED_TOOLS, run_scan

    cfg = load_config(config)

    # Если конфига нет — запускаем init wizard
    if cfg is None:
        typer.echo("Конфиг .efs-config.json не найден. Запускаем мастер инициализации...")
        from efs.init_wizard import run_wizard

        run_wizard(verbose=state["verbose"])
        return

    scanner_cfg = get_scanner_config(cfg)

    # CLI-флаги переопределяют конфиг
    scan_tool = _enum_value(tool) if tool else scanner_cfg.get("tool", "cdxgen")
    scan_target = target or scanner_cfg.get("target", ".")
    scan_output = output or scanner_cfg.get("output", "bom.json")
    scan_options = scanner_cfg.get("options", {})

    if scan_tool not in SUPPORTED_TOOLS:
        typer.echo(
            f"ошибка: неизвестный инструмент '{scan_tool}'. Поддерживаются: {', '.join(SUPPORTED_TOOLS)}", err=True
        )
        raise typer.Exit(code=1)

    success = run_scan(scan_tool, scan_target, scan_output, scan_options)
    if not success:
        raise typer.Exit(code=1)


# ── config ─────────────────────────────────────────────────────────────────────


@config_app.command(
    "find-vcs", help="Найти VCS-ссылки для компонентов конфига без VCS (исключая exclude и provided_by)"
)
def cmd_config_find_vcs(
    config_path: str | None = typer.Option(None, "--config", "-c", help="путь к .efs-config.json"),
    workers: int = typer.Option(8, "--workers", "-w", help="число параллельных потоков"),
):
    import json

    from rich.console import Console
    from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn

    from efs.config import load_config

    console = Console()

    config = load_config(config_path)
    if not config:
        console.print("[red]✗[/red] Конфиг .efs-config.json не найден")
        raise typer.Exit(code=1)

    # Определить путь к файлу конфига для сохранения
    from pathlib import Path

    if config_path:
        save_path = Path(config_path)
    else:
        save_path = Path.cwd() / ".efs-config.json"

    components = config.get("components", {})

    # Отобрать purl без VCS, не exclude, не provided_by
    purls_to_find = []
    for purl, entry in components.items():
        if not isinstance(entry, dict):
            continue
        if entry.get("vcs"):
            continue
        if entry.get("exclude"):
            continue
        if entry.get("provided_by"):
            continue
        purls_to_find.append(purl)

    if not purls_to_find:
        console.print("[green]✓[/green] Все компоненты уже имеют VCS, exclude или provided_by")
        return

    console.print(f"Компонентов для поиска VCS: {len(purls_to_find)}")

    from efs.updater import RefFinder

    ref_finder = RefFinder()
    found = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("{task.fields[component]}"),
        console=console,
    ) as progress:
        task = progress.add_task("Поиск VCS-ссылок", total=len(purls_to_find), component="")

        import concurrent.futures
        import threading

        _progress_counter = threading.Lock()
        _completed = [0]

        def _find_vcs(purl):
            url = ref_finder.process_purl(purl)
            with _progress_counter:
                _completed[0] += 1
                progress.update(task, completed=_completed[0], component=purl.split("/")[-1])
            if url and not url.startswith("sbom-updater_generated_placeholder:"):
                return purl, url
            return purl, None

        max_w = min(workers, len(purls_to_find))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_w) as executor:
            for purl, url in executor.map(_find_vcs, purls_to_find):
                if url:
                    components[purl]["vcs"] = url
                    found += 1

    ref_finder.dump_repos()

    # Сохранить обновлённый конфиг
    with open(save_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    console.print(f"[green]✓[/green] Найдено VCS: {found} из {len(purls_to_find)}")
    console.print(f"  Конфиг обновлён: {save_path}")


@config_app.command(
    "status", help="Показать компоненты конфига, для которых не хватает VCS, provided_by или GOST-свойств"
)
def cmd_config_status(
    config_path: str | None = typer.Option(None, "--config", "-c", help="путь к .efs-config.json"),
    show_all: bool = typer.Option(False, "--all", "-a", help="показать все компоненты, не только проблемные"),
):
    from rich.console import Console
    from rich.table import Table

    from efs.config import guess_source_langs, load_config

    console = Console()

    config = load_config(config_path)
    if not config:
        console.print("[red]✗[/red] Конфиг .efs-config.json не найден")
        raise typer.Exit(code=1)

    components = config.get("components", {})
    if not components:
        console.print("Конфиг пуст — нет компонентов.")
        return

    missing_vcs = []
    missing_langs = []
    excluded = []
    has_vcs = []
    has_provided_by = []

    for purl, entry in sorted(components.items()):
        if not isinstance(entry, dict):
            continue
        if entry.get("exclude"):
            excluded.append(purl)
            continue
        if not entry.get("source_langs") and not guess_source_langs(purl):
            missing_langs.append(purl)
        if entry.get("provided_by"):
            has_provided_by.append(purl)
        elif entry.get("vcs"):
            has_vcs.append(purl)
        else:
            # Нет ни vcs, ни provided_by, ни exclude
            missing_vcs.append(purl)

    total = len(components)
    console.print(f"Всего компонентов: {total}")
    console.print(f"  [green]С VCS:[/green] {len(has_vcs)}")
    console.print(f"  [green]С provided_by:[/green] {len(has_provided_by)}")
    console.print(f"  [dim]Исключены (exclude):[/dim] {len(excluded)}")
    console.print(f"  [red]Не заполнены:[/red] {len(missing_vcs)}")

    console.print(f"  [red]Без языка:[/red] {len(missing_langs)}")

    if missing_vcs:
        console.print()
        table = Table(title="Компоненты без VCS / provided_by", show_lines=False)
        table.add_column("purl", style="yellow")
        for purl in missing_vcs:
            table.add_row(purl)
        console.print(table)

    if missing_langs:
        console.print()
        table = Table(title="Компоненты без языка (source_langs)", show_lines=False)
        table.add_column("purl", style="yellow")
        for purl in missing_langs:
            table.add_row(purl)
        console.print(table)

    if show_all and (has_vcs or has_provided_by):
        console.print()
        table = Table(title="Заполненные компоненты", show_lines=False)
        table.add_column("purl")
        table.add_column("тип", style="green")
        table.add_column("значение", style="dim")
        for purl in has_vcs:
            table.add_row(purl, "vcs", components[purl].get("vcs", ""))
        for purl in has_provided_by:
            table.add_row(purl, "provided_by", components[purl].get("provided_by", ""))
        console.print(table)


@config_app.command("init", help="Сгенерировать .efs-config.json из одного или нескольких SBOM")
def cmd_config_init(
    inputs: list[Path] = typer.Argument(
        ..., metavar="INPUT", exists=True, dir_okay=False, readable=True, help="входные файлы CycloneDX JSON"
    ),
    output: str | None = typer.Option(
        None, "-o", "--output", help="путь к выходному конфигу (по умолчанию .efs-config.json)"
    ),
):
    import json

    from efs.config import init_config

    boms = []
    for path in inputs:
        with open(path, encoding="utf-8") as f:
            boms.append(json.load(f))

    init_config(boms[0], output_path=output, extra_boms=boms[1:])


@config_app.command("migrate", help="Мигрировать старые файлы маппингов в .efs-config.json")
def cmd_config_migrate(
    vcs: str | None = typer.Option(None, "--vcs", help="путь к .purl_to_vcs.json"),
    gost: str | None = typer.Option(None, "--gost", help="путь к .purl_to_gost.json"),
    exclude: str | None = typer.Option(None, "--exclude", help="путь к .purl_exclude.json"),
    output: str | None = typer.Option(
        None, "-o", "--output", help="путь к выходному конфигу (по умолчанию .efs-config.json)"
    ),
):
    from efs.config import migrate_config

    migrate_config(vcs_path=vcs, gost_path=gost, exclude_path=exclude, output_path=output)


# ── init ───────────────────────────────────────────────────────────────────────


@app.command("init", help="Пошаговый мастер инициализации SBOM-проекта")
def cmd_init():
    from efs.init_wizard import run_wizard

    run_wizard(verbose=state["verbose"])


# ── точка входа ────────────────────────────────────────────────────────────────


def main():
    app()


if __name__ == "__main__":
    main()
