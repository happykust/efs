#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Постобработка SBOM, сгенерированного cdxgen, для прохождения валидации sbom-checker.

Скрипт приводит выход cdxgen к минимальному виду, удовлетворяющему схемам
sbom-checker (CycloneDX 1.6 + ГОСТ-расширения), убирая лишние поля.

Использование:
    # Полный конвейер: cdxgen → постобработка
    cdxgen -o raw_bom.json .
    cdxgen-postprocess raw_bom.json bom.json \
        --app-name "МойПродукт" --app-version "1.0.0" --manufacturer "МояОрганизация"

    # Только очистка (ГОСТ-свойства уже есть)
    cdxgen-postprocess raw_bom.json bom.json --strip-only
"""

import argparse
import datetime
import json
from collections import deque
from pathlib import Path

from sbom_utils.config import (
    load_config,
    config_to_purl_to_vcs,
    config_to_purl_to_gost,
    config_to_purl_exclude,
    apply_config_to_component,
    get_pedigree,
    get_manufacturer,
    is_excluded,
)

_PURL_TO_VCS_FILENAME = '.purl_to_vcs.json'
_PURL_TO_GOST_FILENAME = '.purl_to_gost.json'
_PURL_EXCLUDE_FILENAME = '.purl_exclude.json'

# ── Разрешённые поля по уровням (согласно schema.json с additionalProperties: false) ──

ROOT_ALLOWED = {
    "$schema", "bomFormat", "specVersion", "serialNumber", "version",
    "metadata", "components", "services", "externalReferences",
    "dependencies", "compositions", "vulnerabilities", "annotations",
    "formulation", "declarations", "definitions", "properties",
}

METADATA_ALLOWED = {
    "timestamp", "lifecycles", "tools", "manufacturer", "authors",
    "component", "manufacture", "supplier", "licenses", "properties",
}

# Поля, которые cdxgen генерирует, но валидатор не требует и которые можно
# безопасно убрать для минимизации SBOM.  Если поле допускается схемой,
# но не используется валидатором — оставляем по умолчанию (не ломаем схему).
COMPONENT_STRIP_FIELDS = {
    "description", "scope", "evidence", "pedigree",
    "releaseNotes", "modelCard", "data", "cryptoProperties",
    "tags", "omniborId", "swhid",
}

# Поля корневого уровня, которые можно убрать для минимизации
ROOT_STRIP_FIELDS = {
    "services", "compositions", "vulnerabilities", "annotations",
    "formulation", "declarations", "definitions",
}

# Префикс свойств, которые сохраняются в properties (остальные удаляются)
ALLOWED_PROPERTY_PREFIX = "GOST:"

DEFAULT_GOST_VALUE = "no"


def normalize_gost_prop(props, name, default_value):
    """Добавить или нормализовать ГОСТ-свойство в массиве properties."""
    allowed = {"yes", "no", "indirect"}
    idxs = []
    for i, elem in enumerate(props):
        if elem.get("name", "") == name:
            idxs.append(i)
            if elem.get("value") not in allowed:
                elem["value"] = default_value
    if not idxs:
        props.append({"name": name, "value": default_value})
        return
    # Удалить дубликаты (оставить первый)
    for i in reversed(idxs[1:]):
        props.pop(i)


def has_gost_provided_by(props):
    """Проверить наличие свойства GOST:provided_by."""
    for p in props:
        if p.get("name") == "GOST:provided_by" and p.get("value"):
            return True
    return False


def has_required_ext_ref(refs):
    """Проверить наличие vcs или source-distribution в externalReferences."""
    if not isinstance(refs, list):
        return False
    for ref in refs:
        if isinstance(ref, dict) and ref.get("type") in {"vcs", "source-distribution"}:
            return True
    return False


def strip_component(comp, strip_fields, gost_default, purl_to_vcs=None, provided_by=None, purl_to_gost=None, config=None):
    """Обработать один компонент: убрать лишнее, добавить обязательное."""
    # Если есть конфиг — применить pedigree/manufacturer ДО strip (чтобы pedigree не удалился)
    purl = comp.get("purl", "")
    has_config_pedigree = config and purl and get_pedigree(config, purl)

    # Удалить необязательные поля (кроме pedigree, если он задан в конфиге)
    for field in strip_fields:
        if field == "pedigree" and has_config_pedigree:
            continue
        comp.pop(field, None)

    # Гарантировать version
    if "version" not in comp:
        comp["version"] = "unknown"

    # Гарантировать properties
    if "properties" not in comp:
        comp["properties"] = []

    # Оставить только GOST-свойства
    comp["properties"] = [p for p in comp["properties"] if p.get("name", "").startswith(ALLOWED_PROPERTY_PREFIX)]

    # Если есть конфиг — применить настройки компонента (GOST, pedigree, manufacturer, vcs)
    if config and purl:
        apply_config_to_component(comp, config, gost_default, provided_by)

    # ГОСТ-свойства: если есть маппинг purl→GOST, использовать его
    # Формат маппинга: {"GOST:attack_surface": {"purl": "yes/indirect"}, ...}

    gost_as = purl_to_gost.get("GOST:attack_surface", {}).get(purl, gost_default) if purl and purl_to_gost else gost_default
    gost_sf = purl_to_gost.get("GOST:security_function", {}).get(purl, gost_default) if purl and purl_to_gost else gost_default
    normalize_gost_prop(comp["properties"], "GOST:attack_surface", gost_as)
    normalize_gost_prop(comp["properties"], "GOST:security_function", gost_sf)

    # GOST:provided_by из маппинга
    gost_pb = purl_to_gost.get("GOST:provided_by", {}).get(purl, "") if purl and purl_to_gost else ""
    if gost_pb:
        comp["properties"] = [p for p in comp["properties"] if p.get("name") != "GOST:provided_by"]
        comp["properties"].append({"name": "GOST:provided_by", "value": gost_pb})

    # Leaf-компоненты: добавить GOST:provided_by или externalReferences
    is_leaf = not comp.get("components")
    if is_leaf:
        if provided_by and not has_gost_provided_by(comp["properties"]):
            comp["properties"].append({"name": "GOST:provided_by", "value": provided_by})

        if not has_gost_provided_by(comp["properties"]):
            refs = comp.get("externalReferences")
            if not has_required_ext_ref(refs):
                if not isinstance(refs, list):
                    comp["externalReferences"] = []
                    refs = comp["externalReferences"]
                vcs_url = purl_to_vcs.get(purl, "") if purl and purl_to_vcs else ""
                refs.append({"type": "vcs", "url": vcs_url or "TODO"})

    # Рекурсия для вложенных компонентов
    for child in comp.get("components", []):
        strip_component(child, strip_fields, gost_default, purl_to_vcs, provided_by, purl_to_gost, config)


def strip_root(bom, strip_root_fields):
    """Убрать необязательные секции корневого уровня, если они пустые или не нужны."""
    for field in strip_root_fields:
        val = bom.get(field)
        if val is None or val == [] or val == {}:
            bom.pop(field, None)


def ensure_metadata(bom, app_name, app_version, manufacturer):
    """Гарантировать наличие обязательных полей metadata."""
    if "metadata" not in bom:
        bom["metadata"] = {}
    meta = bom["metadata"]

    # timestamp
    meta["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # metadata.component
    if "component" not in meta:
        meta["component"] = {}
    mc = meta["component"]

    if "type" not in mc:
        mc["type"] = "application"
    if app_name:
        mc["name"] = app_name
    elif "name" not in mc:
        mc["name"] = "TODO"
    if app_version:
        mc["version"] = app_version
    elif "version" not in mc:
        mc["version"] = "TODO"

    # manufacturer
    if "manufacturer" not in mc:
        mc["manufacturer"] = {}
    if manufacturer:
        mc["manufacturer"]["name"] = manufacturer
    elif "name" not in mc["manufacturer"]:
        mc["manufacturer"]["name"] = "TODO"

    # Очистить properties в metadata.component
    if "properties" in mc:
        mc["properties"] = [p for p in mc["properties"] if p.get("name", "").startswith(ALLOWED_PROPERTY_PREFIX)]
        if not mc["properties"]:
            del mc["properties"]

    # Очистить properties в metadata
    if "properties" in meta:
        meta["properties"] = [p for p in meta["properties"] if p.get("name", "").startswith(ALLOWED_PROPERTY_PREFIX)]
        if not meta["properties"]:
            del meta["properties"]

    # Убрать лишние поля из metadata.component (bom-ref, purl, description)
    for field in ("bom-ref", "purl", "description"):
        mc.pop(field, None)

    # Убрать лишние поля из metadata
    keys_to_remove = [k for k in meta if k not in METADATA_ALLOWED]
    for k in keys_to_remove:
        del meta[k]


def ensure_root(bom):
    """Гарантировать обязательные поля корневого уровня."""
    bom["bomFormat"] = "CycloneDX"
    bom["specVersion"] = "1.6"
    if "version" not in bom or not isinstance(bom.get("version"), int):
        bom["version"] = 1

    # Очистить корневые properties
    if "properties" in bom:
        bom["properties"] = [p for p in bom["properties"] if p.get("name", "").startswith(ALLOWED_PROPERTY_PREFIX)]
        if not bom["properties"]:
            del bom["properties"]

    # Убрать поля, не допускаемые схемой
    keys_to_remove = [k for k in bom if k not in ROOT_ALLOWED]
    for k in keys_to_remove:
        del bom[k]


def _load_purl_to_vcs(cli_path=None):
    """Загрузить маппинг purl→vcs.

    Порядок поиска:
    1. Явно указанный через CLI (--purl-to-vcs)
    2. .purl_to_vcs.json в текущей рабочей директории
    3. None (маппинг не используется)
    """
    if cli_path:
        p = Path(cli_path)
        if p.is_file():
            with open(p) as f:
                return json.load(f)
        raise FileNotFoundError(f"Указанный файл не найден: {cli_path}")

    cwd_file = Path.cwd() / _PURL_TO_VCS_FILENAME
    if cwd_file.is_file():
        with open(cwd_file) as f:
            return json.load(f)

    return None


def _load_purl_to_gost(cli_path=None):
    """Загрузить маппинг purl→GOST-свойства.

    Порядок поиска:
    1. Явно указанный через CLI (--purl-to-gost)
    2. .purl_to_gost.json в текущей рабочей директории
    3. None (маппинг не используется)
    """
    if cli_path:
        p = Path(cli_path)
        if p.is_file():
            with open(p) as f:
                return json.load(f)
        raise FileNotFoundError(f"Указанный файл не найден: {cli_path}")

    cwd_file = Path.cwd() / _PURL_TO_GOST_FILENAME
    if cwd_file.is_file():
        with open(cwd_file) as f:
            return json.load(f)

    return None


def _load_purl_exclude(cli_path=None):
    """Загрузить список purl для исключения из SBOM.

    Формат файла — JSON-массив purl-префиксов (без версии):
        ["pkg:pypi/pytest", "pkg:pypi/mypy", "pkg:npm/eslint"]

    Порядок поиска:
    1. Явно указанный через CLI (--purl-exclude)
    2. .purl_exclude.json в текущей рабочей директории
    3. None (исключение не используется)
    """
    if cli_path:
        p = Path(cli_path)
        if p.is_file():
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        raise FileNotFoundError(f"Указанный файл не найден: {cli_path}")

    cwd_file = Path.cwd() / _PURL_EXCLUDE_FILENAME
    if cwd_file.is_file():
        with open(cwd_file, encoding="utf-8") as f:
            return json.load(f)

    return None


def _purl_without_version(purl):
    """Убрать версию из purl: pkg:pypi/pytest@8.0.0 → pkg:pypi/pytest."""
    at = purl.find("@")
    return purl[:at] if at != -1 else purl


def _purl_matches_exclude(purl, exclude_set):
    """Проверить, попадает ли purl под исключение (сравнение без версии)."""
    return _purl_without_version(purl) in exclude_set


def _iter_components_flat(components):
    """Рекурсивный обход всех компонентов (включая вложенные)."""
    for comp in components:
        yield comp
        yield from _iter_components_flat(comp.get("components", []))


def _filter_components_recursive(components, refs_to_remove):
    """Рекурсивно удалить компоненты по bom-ref, вернуть отфильтрованный список."""
    result = []
    for comp in components:
        ref = comp.get("bom-ref", comp.get("purl", ""))
        if ref in refs_to_remove:
            continue
        children = comp.get("components", [])
        if children:
            comp["components"] = _filter_components_recursive(children, refs_to_remove)
        result.append(comp)
    return result


def exclude_components(bom, exclude_purls):
    """Исключить компоненты из BOM по списку purl-префиксов и их транзитивные зависимости.

    Алгоритм:
    1. Найти bom-ref всех компонентов, чей purl совпадает с exclude-списком.
    2. Если есть секция dependencies — построить граф и найти транзитивные
       зависимости, которые достижимы ТОЛЬКО из исключаемых компонентов.
    3. Удалить найденные компоненты и записи из dependencies.
    """
    components = bom.get("components", [])
    if not components:
        return 0

    exclude_set = {_purl_without_version(p) for p in exclude_purls}

    # Собрать все bom-ref компонентов, попадающих под исключение
    direct_excluded = set()
    all_refs = set()
    for comp in _iter_components_flat(components):
        ref = comp.get("bom-ref", comp.get("purl", ""))
        purl = comp.get("purl", "")
        all_refs.add(ref)
        if purl and _purl_matches_exclude(purl, exclude_set):
            direct_excluded.add(ref)

    if not direct_excluded:
        return 0

    dependencies = bom.get("dependencies", [])
    refs_to_remove = set(direct_excluded)

    if dependencies:
        # Построить граф зависимостей: ref → [dependsOn]
        graph = {}
        for entry in dependencies:
            ref = entry.get("ref", "")
            graph[ref] = list(entry.get("dependsOn", []))

        # Найти корень BOM (metadata.component.bom-ref)
        root_ref = bom.get("metadata", {}).get("component", {}).get("bom-ref", "")

        # Построить «prod-граф» — копию графа без рёбер к direct_excluded
        # Это эмулирует удаление dev-зависимостей из манифеста
        prod_graph = {}
        for ref, deps_list in graph.items():
            if ref in direct_excluded:
                continue
            prod_graph[ref] = [d for d in deps_list if d not in direct_excluded]

        # BFS от корня (или всех не-excluded узлов) по prod-графу
        # → всё достижимое — prod-зависимости, которые нужно сохранить
        prod_reachable = set()
        prod_starts = {root_ref} if root_ref else set(prod_graph.keys())
        queue = deque(prod_starts)
        while queue:
            node = queue.popleft()
            if node in prod_reachable:
                continue
            prod_reachable.add(node)
            for child in prod_graph.get(node, []):
                if child not in prod_reachable:
                    queue.append(child)

        # BFS от excluded вниз по оригинальному графу — все потомки excluded
        dev_reachable = set()
        queue = deque(direct_excluded)
        while queue:
            node = queue.popleft()
            if node in dev_reachable:
                continue
            dev_reachable.add(node)
            for child in graph.get(node, []):
                if child not in dev_reachable:
                    queue.append(child)

        # Удаляем: всё что достижимо из excluded, но НЕ достижимо из prod
        refs_to_remove = dev_reachable - prod_reachable

        # Очистить секцию dependencies
        bom["dependencies"] = [
            d for d in dependencies
            if d.get("ref", "") not in refs_to_remove
        ]
        for entry in bom["dependencies"]:
            entry["dependsOn"] = [
                d for d in entry.get("dependsOn", [])
                if d not in refs_to_remove
            ]

    # Удалить компоненты (рекурсивно, включая вложенные)
    bom["components"] = _filter_components_recursive(components, refs_to_remove)

    return len(refs_to_remove)


def init_purl_exclude(bom, output_path):
    """Сгенерировать шаблон .purl_exclude.json из текущего BOM.

    Создаёт файл со всеми purl (без версий) из BOM для удобного выбора
    компонентов на исключение.
    """
    purls = sorted({
        _purl_without_version(comp.get("purl", ""))
        for comp in _iter_components_flat(bom.get("components", []))
        if comp.get("purl")
    })
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(purls, f, indent=2, ensure_ascii=False)
    print(f"Шаблон записан: {output_path} ({len(purls)} purl)")
    print("  Удалите из файла те purl, которые НЕ нужно исключать, и передайте через --purl-exclude")


def process_bom(bom, args, purl_to_vcs=None, purl_to_gost=None, purl_exclude=None, config=None):
    """Основная обработка BOM."""
    ensure_root(bom)

    # Исключение компонентов по purl_exclude (до остальной обработки)
    n_excluded = 0
    if purl_exclude:
        n_excluded = exclude_components(bom, purl_exclude)
        if n_excluded:
            print(f"  Исключено компонентов (с транзитивными): {n_excluded}")

    if not args.strip_only:
        ensure_metadata(bom, args.app_name, args.app_version, args.manufacturer)

    # Обработка компонентов
    gost_default = args.gost_default
    provided_by = getattr(args, 'provided_by', None)
    strip_fields = COMPONENT_STRIP_FIELDS if not args.keep_all_fields else set()

    for comp in bom.get("components", []):
        strip_component(comp, strip_fields, gost_default, purl_to_vcs, provided_by, purl_to_gost, config)

    # Убрать пустые корневые секции
    if not args.keep_all_fields:
        strip_root(bom, ROOT_STRIP_FIELDS)

    return bom


def configure_parser(parser):
    parser.add_argument("input", help="Входной файл BOM (JSON)")
    parser.add_argument("output", help="Выходной файл BOM (JSON)")
    parser.add_argument("--app-name", help="Название продукта (metadata.component.name)")
    parser.add_argument("--app-version", help="Версия продукта (metadata.component.version)")
    parser.add_argument("--manufacturer", help="Организация-изготовитель (metadata.component.manufacturer.name)")
    parser.add_argument(
        "--gost-default",
        default=DEFAULT_GOST_VALUE,
        choices=["yes", "no", "indirect"],
        help=f"Значение ГОСТ-свойств по умолчанию (default: {DEFAULT_GOST_VALUE})",
    )
    parser.add_argument(
        "--strip-only",
        action="store_true",
        help="Только очистить лишние поля, не трогать metadata",
    )
    parser.add_argument(
        "--keep-all-fields",
        action="store_true",
        help="Не удалять необязательные поля компонентов",
    )
    parser.add_argument(
        "--provided-by",
        metavar="VALUE",
        help="Установить GOST:provided_by для leaf-компонентов без этого свойства (например, название поставщика)",
    )
    parser.add_argument(
        "--purl-to-vcs",
        metavar="PATH",
        help=f"Путь к файлу маппинга purl→vcs (по умолчанию ищется {_PURL_TO_VCS_FILENAME} в текущей директории)",
    )
    parser.add_argument(
        "--purl-to-gost",
        metavar="PATH",
        help=f"Путь к файлу маппинга purl→GOST-свойства (по умолчанию ищется {_PURL_TO_GOST_FILENAME} в текущей директории)",
    )
    parser.add_argument(
        "--purl-exclude",
        metavar="PATH",
        help=f"Путь к файлу списка purl для исключения (по умолчанию ищется {_PURL_EXCLUDE_FILENAME} в текущей директории)",
    )
    parser.add_argument(
        "--init-exclude",
        action="store_true",
        help=f"Сгенерировать шаблон {_PURL_EXCLUDE_FILENAME} из входного BOM и выйти",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Форматировать JSON (по умолчанию: да)",
    )


def run(args):
    # Чтение
    try:
        with open(args.input, encoding="utf-8") as f:
            bom = json.load(f)
    except UnicodeDecodeError:
        with open(args.input, encoding="utf-8-sig") as f:
            bom = json.load(f)

    # --init-exclude: сгенерировать шаблон и выйти
    if getattr(args, 'init_exclude', False):
        out = getattr(args, 'purl_exclude', None) or _PURL_EXCLUDE_FILENAME
        init_purl_exclude(bom, out)
        return

    # Попытка загрузить единый конфиг (.sbom-config.json)
    config = load_config(getattr(args, 'config', None))

    purl_to_vcs = None
    purl_to_gost = None
    purl_exclude = None

    if config:
        # Конвертировать конфиг в старые форматы для обратной совместимости
        purl_to_vcs = config_to_purl_to_vcs(config)
        purl_to_gost = config_to_purl_to_gost(config)
        exclude_list = config_to_purl_exclude(config)
        purl_exclude = exclude_list if exclude_list else None
    else:
        # Старый режим: отдельные файлы
        purl_to_vcs = _load_purl_to_vcs(args.purl_to_vcs)
        purl_to_gost = _load_purl_to_gost(args.purl_to_gost)
        purl_exclude = _load_purl_exclude(getattr(args, 'purl_exclude', None))

    # Обработка
    bom = process_bom(bom, args, purl_to_vcs, purl_to_gost, purl_exclude, config)

    # Запись
    indent = 2 if args.pretty else None
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(bom, f, indent=indent, ensure_ascii=False)

    # Статистика
    n_components = len(bom.get("components", []))
    n_todo_vcs = 0
    for comp in bom.get("components", []):
        for ref in comp.get("externalReferences", []):
            if ref.get("url") == "TODO":
                n_todo_vcs += 1
                break

    print(f"Готово: {args.output}")
    print(f"  Компонентов: {n_components}")
    if n_todo_vcs:
        print(f"  Компонентов без VCS (нужно заполнить): {n_todo_vcs}")
    meta_comp = bom.get("metadata", {}).get("component", {})
    for field in ("name", "version"):
        if meta_comp.get(field) == "TODO":
            print(f"  ВНИМАНИЕ: metadata.component.{field} = TODO — нужно заполнить")
    mfr = meta_comp.get("manufacturer", {})
    if mfr.get("name") == "TODO":
        print(f"  ВНИМАНИЕ: metadata.component.manufacturer.name = TODO — нужно заполнить")


def main():
    parser = argparse.ArgumentParser(
        description="Постобработка SBOM из cdxgen для sbom-checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    configure_parser(parser)
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
