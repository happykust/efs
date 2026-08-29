# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

"""
Единый конфиг .efs-config.json для управления обработкой компонентов SBOM.

Объединяет функциональность .purl_to_vcs.json, .purl_to_gost.json и .purl_exclude.json
в один файл с поддержкой pedigree (CycloneDX) и manufacturer per-component.
"""

import json
import logging
from pathlib import Path

from .utils import get_prop, purl_without_version

_CONFIG_FILENAME = ".efs-config.json"
_LEGACY_CONFIG_FILENAME = ".sbom-config.json"

_GOST_PROPS = ("GOST:attack_surface", "GOST:security_function")

# Язык программирования, однозначно следующий из экосистемы пакета.
# Дистрибутивные пакеты (deb, rpm) сюда не входят: там язык произвольный,
# а перечень идёт регулятору — угадывать нельзя.
_LANG_BY_PURL_TYPE = {
    "pypi": "Python",
    "npm": "JavaScript",
    "maven": "Java",
    "gradle": "Java",
    "cargo": "Rust",
    "golang": "Go",
    "gem": "Ruby",
    "nuget": "C#",
    "composer": "PHP",
    "cocoapods": "Objective-C",
    "hex": "Elixir",
    "cran": "R",
    "pub": "Dart",
    "conan": "C++",
    "swift": "Swift",
}
_GOST_ALLOWED_VALUES = {"yes", "no", "indirect"}
_GOST_DEFAULT_VALUE = "no"


def _purl_without_version(purl):
    """Убрать версию из purl: pkg:pypi/pytest@8.0.0 → pkg:pypi/pytest.

    Общая с постобработкой реализация: она не путает версию со скоупом npm
    (`@babel/runtime`), понимает закодированный `%40` и отбрасывает квалификаторы.
    """
    return purl_without_version(purl)


def normalize_source_langs(value):
    """Привести значение source_langs к списку языков.

    Принимает список или строку; строка с запятыми раскладывается на отдельные
    языки, потому что ФСТЭК требует по одному свойству GOST:source_langs на язык.
    """
    if isinstance(value, (list, tuple)):
        items = value
    elif isinstance(value, str):
        items = value.split(",")
    else:
        return []
    return [str(item).strip() for item in items if str(item).strip()]


def guess_source_langs(purl):
    """Определить язык программирования по типу purl.

    Возвращает пустую строку, если по экосистеме язык не определяется однозначно.
    """
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return ""
    purl_type = purl[4:].split("/", 1)[0].lower()
    return _LANG_BY_PURL_TYPE.get(purl_type, "")


def load_config(cli_path=None):
    """Загрузить .sbom-config.json.

    Порядок поиска:
    1. Явно указанный через CLI (--config)
    2. .efs-config.json в текущей рабочей директории
    3. .sbom-config.json — прежнее имя, поддерживается для совместимости
    4. None (конфиг не используется)
    """
    if cli_path:
        p = Path(cli_path)
        if p.is_file():
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            logging.info(f"используется конфиг: {p}")
            return data
        raise FileNotFoundError(f"Указанный файл конфига не найден: {cli_path}")

    for filename in (_CONFIG_FILENAME, _LEGACY_CONFIG_FILENAME):
        cwd_file = Path.cwd() / filename
        if cwd_file.is_file():
            with open(cwd_file, encoding="utf-8") as f:
                data = json.load(f)
            logging.info(f"используется конфиг: {cwd_file}")
            return data

    return None


def _lookup_component(config, purl):
    """Найти настройки компонента в конфиге по purl.

    Порядок поиска:
    1. Точное совпадение (purl с версией)
    2. Совпадение без версии
    """
    components = config.get("components", {})

    # Точное совпадение
    if purl in components:
        return components[purl]

    # Без версии
    base = _purl_without_version(purl)
    if base in components:
        return components[base]

    return None


def get_vcs(config, purl):
    """Получить VCS URL для purl из конфига."""
    entry = _lookup_component(config, purl)
    if entry:
        return entry.get("vcs", "")
    return ""


def get_gost_prop(config, purl, prop_name):
    """Получить значение GOST-свойства для purl из конфига.

    Возвращает значение из конфига компонента, затем defaults, затем 'no'.
    """
    defaults = config.get("defaults", {})

    # Маппинг имён свойств на ключи конфига
    key_map = {
        "GOST:attack_surface": "attack_surface",
        "GOST:security_function": "security_function",
        "GOST:provided_by": "provided_by",
        "GOST:source_langs": "source_langs",
    }
    config_key = key_map.get(prop_name, prop_name)

    entry = _lookup_component(config, purl)
    if entry and config_key in entry:
        return entry[config_key]

    default_val = defaults.get(config_key, "")
    if not default_val and prop_name in _GOST_PROPS:
        return _GOST_DEFAULT_VALUE
    return default_val


def is_excluded(config, purl):
    """Проверить, исключён ли компонент по конфигу.

    Возвращает:
    - False — не исключён
    - True — исключён с каскадом (транзитивные зависимости тоже удаляются)
    - "direct" — исключён только сам компонент (зависимости остаются)
    """
    entry = _lookup_component(config, purl)
    if entry:
        val = entry.get("exclude", False)
        if val == "direct":
            return "direct"
        return bool(val)
    return False


def get_pedigree(config, purl):
    """Получить pedigree для компонента из конфига."""
    entry = _lookup_component(config, purl)
    if entry:
        return entry.get("pedigree")
    return None


def get_manufacturer(config, purl):
    """Получить manufacturer для компонента из конфига.

    Возвращает dict (например {"name": "ООО Компания"}) или None.
    """
    entry = _lookup_component(config, purl)
    if entry and "manufacturer" in entry:
        return entry["manufacturer"]

    defaults = config.get("defaults", {})
    return defaults.get("manufacturer")


def get_metadata_config(config):
    """Получить настройки metadata из конфига.

    Возвращает dict с полями для metadata.component (pedigree, manufacturer, name, version и т.д.)
    или пустой dict.
    """
    return config.get("metadata", {})


def get_scanner_config(config):
    """Получить настройки сканера из конфига.

    Возвращает dict с полями tool, output, target, options
    или пустой dict.
    """
    return config.get("scanner", {})


# ── Конвертация в старые форматы ──────────────────────────────────────────────


def config_to_purl_to_vcs(config):
    """Конвертировать конфиг в формат purl_to_vcs (для обратной совместимости)."""
    result = {}
    for purl, entry in config.get("components", {}).items():
        if isinstance(entry, dict) and "vcs" in entry:
            result[purl] = entry["vcs"]
    return result


def config_to_purl_to_gost(config):
    """Конвертировать конфиг в формат purl_to_gost (для обратной совместимости)."""
    result = {
        "GOST:attack_surface": {},
        "GOST:security_function": {},
        "GOST:provided_by": {},
    }
    for purl, entry in config.get("components", {}).items():
        if not isinstance(entry, dict):
            continue
        if "attack_surface" in entry:
            result["GOST:attack_surface"][purl] = entry["attack_surface"]
        if "security_function" in entry:
            result["GOST:security_function"][purl] = entry["security_function"]
        if "provided_by" in entry:
            result["GOST:provided_by"][purl] = entry["provided_by"]
    return result


def config_to_purl_exclude(config):
    """Конвертировать конфиг в формат purl_exclude (для обратной совместимости).

    Возвращает tuple (cascade_list, direct_list):
    - cascade_list: purl для исключения с каскадом транзитивных зависимостей
    - direct_list: purl для исключения только самого компонента (без каскада)
    """
    cascade = []
    direct = []
    for purl, entry in config.get("components", {}).items():
        if isinstance(entry, dict):
            val = entry.get("exclude", False)
            if val == "direct":
                direct.append(purl)
            elif val:
                cascade.append(purl)
    return cascade, direct


def config_to_purl_keep(config):
    """Собрать purl, помеченные явным `exclude: false` — их нельзя убирать каскадом.

    Отсутствие ключа `exclude` означает «решения по компоненту не принимали»:
    каскад вправе унести его вместе с исключённым родителем. Записанный руками
    `exclude: false` — обратное указание: компонент поставляется, оставить его
    в перечне, даже если все его родители исключены.
    """
    return [
        purl
        for purl, entry in config.get("components", {}).items()
        if isinstance(entry, dict) and entry.get("exclude") is False
    ]


# ── Генерация конфига ─────────────────────────────────────────────────────────


def _iter_components_flat(components):
    """Рекурсивный обход всех компонентов (включая вложенные)."""
    for comp in components:
        yield comp
        yield from _iter_components_flat(comp.get("components", []))


def init_config(bom, output_path=None, extra_boms=None):
    """Сгенерировать .efs-config.json из SBOM.

    Создаёт конфиг со всеми purl (без версий) из BOM,
    с дефолтными значениями GOST-свойств.
    Если конфиг уже существует, обновляет его (добавляет новые, удаляет отсутствующие).
    """
    if output_path is None:
        output_path = Path.cwd() / _CONFIG_FILENAME
    else:
        output_path = Path(output_path)

    # Собрать все purl из BOM (и дополнительных)
    all_boms = [bom] + (extra_boms or [])
    purls = set()
    for b in all_boms:
        for comp in _iter_components_flat(b.get("components", [])):
            purl = comp.get("purl", "")
            if purl:
                purls.add(_purl_without_version(purl))

    # Загрузить существующий конфиг: сначала по целевому пути, затем по прежнему имени
    existing = {}
    source = output_path
    if not source.is_file() and output_path.name == _CONFIG_FILENAME:
        legacy = output_path.with_name(_LEGACY_CONFIG_FILENAME)
        if legacy.is_file():
            source = legacy
            print(f"  Настройки перенесены из {legacy.name} в {_CONFIG_FILENAME}")
    if source.is_file() and source.stat().st_size > 0:
        with open(source, encoding="utf-8") as f:
            existing = json.load(f)

    # Сохранить metadata
    if "metadata" not in existing:
        existing["metadata"] = {
            "name": "TODO",
            "version": "TODO",
            "manufacturer": {"name": "TODO"},
        }

    # Сохранить defaults
    if "defaults" not in existing:
        existing["defaults"] = {
            "attack_surface": "no",
            "security_function": "no",
        }

    if "components" not in existing:
        existing["components"] = {}

    components = existing["components"]

    # Удалить purl, которых нет во входных файлах
    removed = [k for k in components if _purl_without_version(k) not in purls]
    for k in removed:
        del components[k]

    # Добавить новые purl, сразу подставив язык, следующий из экосистемы
    added = 0
    for purl in sorted(purls):
        if purl not in components:
            langs = guess_source_langs(purl)
            components[purl] = {"source_langs": [langs]} if langs else {}
            added += 1

    # Записать
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)

    total = len(components)
    non_empty = sum(1 for v in components.values() if v)
    print(f"Конфиг записан: {output_path} ({total} компонентов)")
    if non_empty:
        print(f"  С настройками: {non_empty}")
    if removed:
        print(f"  Удалено устаревших: {len(removed)}")
    if added:
        print(f"  Добавлено новых: {added}")

    return existing


def migrate_config(vcs_path=None, gost_path=None, exclude_path=None, output_path=None):
    """Мигрировать из старых файлов (.purl_to_vcs.json, .purl_to_gost.json, .purl_exclude.json)
    в единый .efs-config.json.
    """
    if output_path is None:
        output_path = Path.cwd() / _CONFIG_FILENAME
    else:
        output_path = Path(output_path)

    config = {"defaults": {}, "components": {}}

    # Загрузить существующий конфиг (если есть)
    if output_path.is_file() and output_path.stat().st_size > 0:
        with open(output_path, encoding="utf-8") as f:
            config = json.load(f)
        if "defaults" not in config:
            config["defaults"] = {}
        if "components" not in config:
            config["components"] = {}

    components = config["components"]

    # Миграция purl_to_vcs
    vcs_file = Path(vcs_path) if vcs_path else Path.cwd() / ".purl_to_vcs.json"
    if vcs_file.is_file():
        with open(vcs_file, encoding="utf-8") as f:
            vcs_data = json.load(f)
        migrated_vcs = 0
        for purl, url in vcs_data.items():
            if not url:
                continue
            base = _purl_without_version(purl)
            if base not in components:
                components[base] = {}
            if "vcs" not in components[base]:
                components[base]["vcs"] = url
                migrated_vcs += 1
        print(f"  purl_to_vcs: мигрировано {migrated_vcs} записей из {vcs_file}")
    else:
        print(f"  purl_to_vcs: файл не найден ({vcs_file})")

    # Миграция purl_to_gost
    gost_file = Path(gost_path) if gost_path else Path.cwd() / ".purl_to_gost.json"
    if gost_file.is_file():
        with open(gost_file, encoding="utf-8") as f:
            gost_data = json.load(f)
        migrated_gost = 0
        # attack_surface
        for purl, val in gost_data.get("GOST:attack_surface", {}).items():
            base = _purl_without_version(purl)
            if base not in components:
                components[base] = {}
            if val != _GOST_DEFAULT_VALUE:
                components[base]["attack_surface"] = val
                migrated_gost += 1
        # security_function
        for purl, val in gost_data.get("GOST:security_function", {}).items():
            base = _purl_without_version(purl)
            if base not in components:
                components[base] = {}
            if val != _GOST_DEFAULT_VALUE:
                components[base]["security_function"] = val
                migrated_gost += 1
        # provided_by
        for purl, val in gost_data.get("GOST:provided_by", {}).items():
            if not val:
                continue
            base = _purl_without_version(purl)
            if base not in components:
                components[base] = {}
            components[base]["provided_by"] = val
            migrated_gost += 1
        print(f"  purl_to_gost: мигрировано {migrated_gost} записей из {gost_file}")
    else:
        print(f"  purl_to_gost: файл не найден ({gost_file})")

    # Миграция purl_exclude
    exclude_file = Path(exclude_path) if exclude_path else Path.cwd() / ".purl_exclude.json"
    if exclude_file.is_file():
        with open(exclude_file, encoding="utf-8") as f:
            exclude_data = json.load(f)
        migrated_exclude = 0
        for purl in exclude_data:
            base = _purl_without_version(purl)
            if base not in components:
                components[base] = {}
            components[base]["exclude"] = True
            migrated_exclude += 1
        print(f"  purl_exclude: мигрировано {migrated_exclude} записей из {exclude_file}")
    else:
        print(f"  purl_exclude: файл не найден ({exclude_file})")

    # Удалить пустые записи
    components = {k: v for k, v in components.items() if v}
    config["components"] = components

    # Записать
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    print(f"Конфиг записан: {output_path} ({len(components)} компонентов)")
    return config


# ── Применение конфига к компонентам ──────────────────────────────────────────


def apply_config_to_component(comp, config, gost_default="no", provided_by_default=None):
    """Применить настройки конфига к одному компоненту.

    Устанавливает:
    - GOST-свойства (attack_surface, security_function, provided_by)
    - pedigree (если указан в конфиге)
    - manufacturer (если указан в конфиге)
    - externalReferences[type=vcs] (если указан vcs в конфиге)
    """
    purl = comp.get("purl", "")
    if not purl:
        return

    entry = _lookup_component(config, purl)

    # source_langs: конфиг важнее эвристики, эвристика важнее defaults — иначе общий
    # defaults подменил бы язык, выведенный из экосистемы. Работает и для компонентов,
    # которых нет в конфиге: язык следует из purl.
    entry_langs = normalize_source_langs(entry.get("source_langs")) if entry else []
    langs = (
        entry_langs
        or normalize_source_langs(guess_source_langs(purl))
        or normalize_source_langs(config.get("defaults", {}).get("source_langs"))
    )
    if langs:
        existing_props = comp.setdefault("properties", [])
        if entry_langs or not get_prop(existing_props, "GOST:source_langs"):
            _set_langs(existing_props, langs)

    if entry is None and not config.get("defaults"):
        return

    # GOST-свойства
    if "properties" not in comp:
        comp["properties"] = []

    props = comp["properties"]

    # attack_surface
    as_val = get_gost_prop(config, purl, "GOST:attack_surface") or gost_default
    if as_val not in _GOST_ALLOWED_VALUES:
        as_val = gost_default
    _set_prop(props, "GOST:attack_surface", as_val)

    # security_function
    sf_val = get_gost_prop(config, purl, "GOST:security_function") or gost_default
    if sf_val not in _GOST_ALLOWED_VALUES:
        sf_val = gost_default
    _set_prop(props, "GOST:security_function", sf_val)

    # provided_by
    pb_val = get_gost_prop(config, purl, "GOST:provided_by")
    if not pb_val and provided_by_default:
        pb_val = provided_by_default
    if pb_val:
        _set_prop(props, "GOST:provided_by", pb_val)

    # pedigree
    pedigree = get_pedigree(config, purl)
    if pedigree:
        comp["pedigree"] = pedigree

    # manufacturer (per-component)
    manufacturer = get_manufacturer(config, purl)
    if manufacturer and entry and "manufacturer" in entry:
        comp["manufacturer"] = manufacturer

    # VCS из конфига
    vcs_url = get_vcs(config, purl)
    if vcs_url:
        if "externalReferences" not in comp or not isinstance(comp.get("externalReferences"), list):
            comp["externalReferences"] = []
        refs = comp["externalReferences"]
        vcs_idx = None
        for i, r in enumerate(refs):
            if r.get("type") == "vcs":
                vcs_idx = i
                break
        if vcs_idx is not None:
            refs[vcs_idx]["url"] = vcs_url
        else:
            refs.append({"type": "vcs", "url": vcs_url})


def _set_langs(props, langs):
    """Записать языки: по одному свойству GOST:source_langs на язык."""
    props[:] = [p for p in props if p.get("name") != "GOST:source_langs"]
    props.extend({"name": "GOST:source_langs", "value": lang} for lang in langs)


def _set_prop(props, name, value):
    """Установить значение свойства (заменить существующее или добавить)."""
    for elem in props:
        if elem.get("name", "") == name:
            elem["value"] = value
            return
    props.append({"name": name, "value": value})
