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
import copy
import datetime
import json
from pathlib import Path
import sys

_PURL_TO_VCS_FILENAME = '.purl_to_vcs.json'
_PURL_TO_GOST_FILENAME = '.purl_to_gost.json'

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


def strip_component(comp, strip_fields, gost_default, purl_to_vcs=None, provided_by=None, purl_to_gost=None):
    """Обработать один компонент: убрать лишнее, добавить обязательное."""
    # Удалить необязательные поля
    for field in strip_fields:
        comp.pop(field, None)

    # Гарантировать version
    if "version" not in comp:
        comp["version"] = "unknown"

    # Гарантировать properties
    if "properties" not in comp:
        comp["properties"] = []

    # Оставить только GOST-свойства
    comp["properties"] = [p for p in comp["properties"] if p.get("name", "").startswith(ALLOWED_PROPERTY_PREFIX)]

    # ГОСТ-свойства: если есть маппинг purl→GOST, использовать его
    # Формат маппинга: {"GOST:attack_surface": {"purl": "yes/indirect"}, ...}
    purl = comp.get("purl", "")

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
        strip_component(child, strip_fields, gost_default, purl_to_vcs, provided_by, purl_to_gost)


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


def process_bom(bom, args, purl_to_vcs=None, purl_to_gost=None):
    """Основная обработка BOM."""
    ensure_root(bom)

    if not args.strip_only:
        ensure_metadata(bom, args.app_name, args.app_version, args.manufacturer)

    # Обработка компонентов
    gost_default = args.gost_default
    provided_by = getattr(args, 'provided_by', None)
    strip_fields = COMPONENT_STRIP_FIELDS if not args.keep_all_fields else set()

    for comp in bom.get("components", []):
        strip_component(comp, strip_fields, gost_default, purl_to_vcs, provided_by, purl_to_gost)

    # Убрать пустые корневые секции
    if not args.keep_all_fields:
        strip_root(bom, ROOT_STRIP_FIELDS)

    return bom


def main():
    parser = argparse.ArgumentParser(
        description="Постобработка SBOM из cdxgen для sbom-checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
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
        "--pretty",
        action="store_true",
        default=True,
        help="Форматировать JSON (по умолчанию: да)",
    )

    args = parser.parse_args()

    # Чтение
    try:
        with open(args.input, encoding="utf-8") as f:
            bom = json.load(f)
    except UnicodeDecodeError:
        with open(args.input, encoding="utf-8-sig") as f:
            bom = json.load(f)

    # Маппинг purl→vcs
    purl_to_vcs = _load_purl_to_vcs(args.purl_to_vcs)

    # Маппинг purl→GOST
    purl_to_gost = _load_purl_to_gost(args.purl_to_gost)

    # Обработка
    bom = process_bom(bom, args, purl_to_vcs, purl_to_gost)

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


if __name__ == "__main__":
    main()
