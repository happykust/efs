# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace
from typing import Optional

import typer

app = typer.Typer(
    name="sbom",
    help="Утилита для проверки и обработки SBOM-файлов (CycloneDX JSON)",
    rich_markup_mode="rich",
    invoke_without_command=True,
)
export_app = typer.Typer(name="export", help="Экспорт SBOM в различные форматы", invoke_without_command=True)
app.add_typer(export_app)
config_app = typer.Typer(name="config", help="Управление единым конфигом .sbom-config.json", invoke_without_command=True)
app.add_typer(config_app)

state = {"verbose": False}


@app.callback()
def main_callback(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "-v", "--verbose", help="подробный вывод"),
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
    filename: str = typer.Argument(..., help="входной файл в формате CycloneDX JSON для проверки"),
    errors: int = typer.Option(10, "-e", "--errors", help="максимальное число ошибок для вывода; 0 = все"),
    check_vcs: bool = typer.Option(False, "--check-vcs", help="проверка url типа vcs на git/svn/hg/fossil-репозиторий"),
    check_vcs_leaf_only: bool = typer.Option(False, "--check-vcs-leaf-only", help="то же, что и --check-vcs, но только для листовых компонентов"),
    check_source_distribution: bool = typer.Option(False, "--check-source-distribution", help="проверка существования URL для типа source-distribution"),
    format_: str = typer.Option("oss", "--format", help="oss | container; по умолчанию oss"),
):
    from sbom_utils.checker import run

    args = SimpleNamespace(
        filename=filename,
        errors=errors,
        check_vcs=check_vcs,
        check_vcs_leaf_only=check_vcs_leaf_only,
        check_source_distribution=check_source_distribution,
        format=format_,
        verbose=state["verbose"],
    )
    run(args)


# ── update ─────────────────────────────────────────────────────────────────────


@app.command("update", help="Обогащение SBOM")
def cmd_update(
    input_: str = typer.Argument(..., metavar="INPUT", help="входной файл CycloneDX JSON"),
    output: Optional[str] = typer.Argument(None, help="выходной файл с дооформленным перечнем"),
    props: bool = typer.Option(False, "--props", help="добавить GOST:attack_surface и GOST:security_function"),
    app_name: Optional[str] = typer.Option(None, "--app-name", help="название продукта"),
    app_version: Optional[str] = typer.Option(None, "--app-version", help="версия продукта"),
    manufacturer: Optional[str] = typer.Option(None, "--manufacturer", help="организация-изготовитель"),
    ref: bool = typer.Option(False, "--ref", help="установить externalReferences на основе purl"),
    purl_to_vcs: Optional[str] = typer.Option(None, "--purl-to-vcs", help="путь к файлу маппинга purl→vcs"),
    gost: bool = typer.Option(False, "--gost", help="установить GOST-свойства из файла маппинга"),
    purl_to_gost: Optional[str] = typer.Option(None, "--purl-to-gost", help="путь к файлу маппинга purl→GOST"),
    init_gost_map: bool = typer.Option(False, "--init-gost-map", help="сгенерировать шаблон .purl_to_gost.json"),
    init_purl_map: bool = typer.Option(False, "--init-purl-map", help="сгенерировать шаблон .purl_to_vcs.json"),
    extra_input: Optional[list[str]] = typer.Option(None, "-i", "--extra-input", help="дополнительные SBOM-файлы для --init-purl-map / --init-gost-map"),
    fix_all: bool = typer.Option(False, "--fix-all", help="применить все опции"),
    update: Optional[str] = typer.Option(None, "--update", metavar="OLD_SBOM", help="предыдущая версия перечня"),
):
    from sbom_utils.updater import run

    args = SimpleNamespace(
        input=input_,
        output=output,
        props=props,
        app_name=app_name,
        app_version=app_version,
        manufacturer=manufacturer,
        ref=ref,
        purl_to_vcs=purl_to_vcs,
        gost=gost,
        purl_to_gost=purl_to_gost,
        init_gost_map=init_gost_map,
        init_purl_map=init_purl_map,
        extra_input=extra_input or [],
        fix_all=fix_all,
        update=update,
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
    from sbom_utils.unifier import run

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
    input_: str = typer.Argument(..., metavar="INPUT", help="входной файл CycloneDX JSON"),
    output: str = typer.Argument(..., help="выходной CSV файл"),
):
    from sbom_utils.to_csv import run

    args = SimpleNamespace(
        input=input_,
        output=output,
        verbose=state["verbose"],
    )
    run(args)


# ── export odt ─────────────────────────────────────────────────────────────────


@export_app.command("odt", help="Экспорт SBOM в ODT")
def cmd_export_odt(
    input_: str = typer.Argument(..., metavar="INPUT", help="входной файл CycloneDX JSON"),
    output: str = typer.Argument(..., help="выходной ODT файл"),
    pa_fb_ontop: bool = typer.Option(False, "-t", "--pa-fb-ontop", help="помещение записей «ПА» и «ФБ» в топ таблицы"),
    format_: str = typer.Option("oss", "--format", help="oss | container; по умолчанию oss"),
):
    from sbom_utils.to_odt import run

    args = SimpleNamespace(
        input=input_,
        output=output,
        pa_fb_ontop=pa_fb_ontop,
        format=format_,
        verbose=state["verbose"],
    )
    run(args)


# ── postprocess ────────────────────────────────────────────────────────────────


@app.command("postprocess", help="Постобработка вывода cdxgen")
def cmd_postprocess(
    input_: str = typer.Argument(..., metavar="INPUT", help="входной BOM файл (JSON)"),
    output: str = typer.Argument(..., help="выходной BOM файл (JSON)"),
    app_name: Optional[str] = typer.Option(None, "--app-name", help="название продукта"),
    app_version: Optional[str] = typer.Option(None, "--app-version", help="версия продукта"),
    manufacturer: Optional[str] = typer.Option(None, "--manufacturer", help="организация-изготовитель"),
    gost_default: str = typer.Option("no", "--gost-default", help="значение ГОСТ-свойств по умолчанию (yes/no/indirect)"),
    strip_only: bool = typer.Option(False, "--strip-only", help="только очистить лишние поля"),
    keep_all_fields: bool = typer.Option(False, "--keep-all-fields", help="не удалять необязательные поля компонентов"),
    provided_by: Optional[str] = typer.Option(None, "--provided-by", help="установить GOST:provided_by для leaf-компонентов"),
    purl_to_vcs: Optional[str] = typer.Option(None, "--purl-to-vcs", help="путь к файлу маппинга purl→vcs"),
    purl_to_gost: Optional[str] = typer.Option(None, "--purl-to-gost", help="путь к файлу маппинга purl→GOST"),
    purl_exclude: Optional[str] = typer.Option(None, "--purl-exclude", help="путь к файлу списка purl для исключения (.purl_exclude.json)"),
    init_exclude: bool = typer.Option(False, "--init-exclude", help="сгенерировать шаблон .purl_exclude.json из входного BOM и выйти"),
    pretty: bool = typer.Option(True, "--pretty/--no-pretty", help="форматировать JSON"),
    config: Optional[str] = typer.Option(None, "--config", help="путь к .sbom-config.json (по умолчанию ищется в текущей директории)"),
):
    from sbom_utils.cdxgen_postprocess import run

    if gost_default not in ("yes", "no", "indirect"):
        typer.echo("ошибка: --gost-default должен быть yes, no или indirect", err=True)
        raise typer.Exit(code=1)

    args = SimpleNamespace(
        input=input_,
        output=output,
        app_name=app_name,
        app_version=app_version,
        manufacturer=manufacturer,
        gost_default=gost_default,
        strip_only=strip_only,
        keep_all_fields=keep_all_fields,
        provided_by=provided_by,
        purl_to_vcs=purl_to_vcs,
        purl_to_gost=purl_to_gost,
        purl_exclude=purl_exclude,
        init_exclude=init_exclude,
        pretty=pretty,
        config=config,
        verbose=state["verbose"],
    )
    run(args)


# ── config ─────────────────────────────────────────────────────────────────────


@config_app.command("init", help="Сгенерировать .sbom-config.json из одного или нескольких SBOM")
def cmd_config_init(
    inputs: list[str] = typer.Argument(..., metavar="INPUT", help="входные файлы CycloneDX JSON (один или несколько)"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="путь к выходному конфигу (по умолчанию .sbom-config.json)"),
):
    import json
    from sbom_utils.config import init_config

    boms = []
    for path in inputs:
        with open(path, encoding="utf-8") as f:
            boms.append(json.load(f))

    init_config(boms[0], output_path=output, extra_boms=boms[1:])


@config_app.command("migrate", help="Мигрировать из старых файлов в .sbom-config.json")
def cmd_config_migrate(
    vcs: Optional[str] = typer.Option(None, "--vcs", help="путь к .purl_to_vcs.json"),
    gost: Optional[str] = typer.Option(None, "--gost", help="путь к .purl_to_gost.json"),
    exclude: Optional[str] = typer.Option(None, "--exclude", help="путь к .purl_exclude.json"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="путь к выходному конфигу"),
):
    from sbom_utils.config import migrate_config

    migrate_config(vcs_path=vcs, gost_path=gost, exclude_path=exclude, output_path=output)


# ── init ───────────────────────────────────────────────────────────────────────


@app.command("init", help="Пошаговый мастер инициализации SBOM-проекта")
def cmd_init():
    from sbom_utils.init_wizard import run_wizard

    run_wizard(verbose=state["verbose"])


# ── точка входа ────────────────────────────────────────────────────────────────


def main():
    app()


if __name__ == "__main__":
    main()
