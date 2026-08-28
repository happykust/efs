# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

import datetime
import json
from pathlib import Path

from .utils import opener

_PKG_DIR = Path(__file__).parent.resolve()


def get_prop(arr, name):
    for elem in arr:
        if elem.get("name", "") == name:
            return elem.get("value", "")
    return ""


def eval_prop(components, name):
    vals = set()
    for comp in components:
        vals.add(get_prop(comp.get("properties", []), name))
    if "yes" in vals:
        return "yes"
    if "indirect" in vals:
        return "indirect"
    if vals == {"no"}:
        return "no"
    return ""


def is_trivy_sbom(data):
    """Определить, что SBOM сформирован trivy, по записи об инструменте в metadata."""
    tools = data.get("metadata", {}).get("tools", {})
    if not isinstance(tools, dict):
        return False
    for tool in tools.get("components", []):
        if tool.get("group") == "aquasecurity" and tool.get("name") == "trivy":
            return True
    return False


def _build_output(args, components, extra_sections=None):
    """Собрать результирующий SBOM с метаданными продукта из аргументов CLI."""
    output_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "component": {
                "type": "application",
                "name": args.app_name,
                "version": args.app_version,
                "manufacturer": {"name": args.manufacturer},
            },
        },
        "components": components,
    }
    for name, section in (extra_sections or {}).items():
        if section:
            output_data[name] = section
    return output_data


def _merge_properties(target, source):
    """Добавить в target свойства из source, которых там ещё нет (сравнение по имени)."""
    existing = {p.get("name") for p in target.get("properties", [])}
    extra = [p for p in source.get("properties", []) if p.get("name") not in existing]
    if extra:
        target.setdefault("properties", []).extend(extra)


def _is_manifest(comp):
    """Файл-манифест: trivy добавляет их как application без purl."""
    return comp.get("type") == "application" and not comp.get("purl")


def _merge_trivy_components(files):
    """Собрать компоненты из всех файлов, отбросив манифесты и схлопнув дубликаты по purl.

    Возвращает список компонентов и маппинг bom-ref удалённых дубликатов на оставшийся.
    """
    components = []
    by_purl = {}
    ref_map = {}

    for data, _ in files:
        for comp in data.get("components", []):
            if _is_manifest(comp):
                continue
            purl = comp.get("purl")
            if not purl:
                components.append(comp)
                continue
            canonical = by_purl.get(purl)
            if canonical is None:
                by_purl[purl] = comp
                components.append(comp)
                continue
            _merge_properties(canonical, comp)
            ref = comp.get("bom-ref")
            canonical_ref = canonical.get("bom-ref")
            if ref and canonical_ref and ref != canonical_ref:
                ref_map[ref] = canonical_ref

    return components, ref_map


def _remap(ref, ref_map):
    """Заменить bom-ref удалённого дубликата на оставшийся."""
    return ref_map.get(ref, ref)


def _merge_trivy_vulnerabilities(files, ref_map):
    """Объединить уязвимости с дедупликацией по id и слиянием списков affects."""
    merged = {}
    for data, _ in files:
        for vuln in data.get("vulnerabilities", []):
            affects = [dict(a, ref=_remap(a.get("ref"), ref_map)) for a in vuln.get("affects", [])]
            known = merged.get(vuln.get("id"))
            if known is None:
                merged[vuln.get("id")] = dict(vuln, affects=affects) if affects else dict(vuln)
                continue
            seen = {a.get("ref") for a in known.get("affects", [])}
            known.setdefault("affects", []).extend(a for a in affects if a.get("ref") not in seen)
    return list(merged.values())


def _merge_trivy_dependencies(files, ref_map, known_refs):
    """Объединить зависимости: пересопоставить ссылки, схлопнуть записи с одинаковым ref.

    Ссылки на компоненты, которых нет в результате — удалённые манифесты и корни
    входных файлов, — отбрасываются, иначе в SBOM остаются висячие bom-ref.
    """
    merged = {}
    for data, _ in files:
        for entry in data.get("dependencies", []):
            ref = _remap(entry.get("ref"), ref_map)
            if ref not in known_refs:
                continue
            depends_on = [_remap(d, ref_map) for d in entry.get("dependsOn", [])]
            depends_on = [d for d in depends_on if d in known_refs]
            known = merged.get(ref)
            if known is None:
                merged[ref] = {"ref": ref, "dependsOn": depends_on}
                continue
            known["dependsOn"].extend(d for d in depends_on if d not in known["dependsOn"])
    return list(merged.values())


def _merge_trivy(args, files):
    """Объединить сырые отчёты trivy."""
    all_components, ref_map = _merge_trivy_components(files)
    known_refs = {comp.get("bom-ref") for comp in all_components}
    vulnerabilities = _merge_trivy_vulnerabilities(files, ref_map)
    dependencies = _merge_trivy_dependencies(files, ref_map, known_refs)

    output_data = _build_output(
        args,
        all_components,
        {"dependencies": dependencies, "vulnerabilities": vulnerabilities},
    )
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)


def run(args):
    files = [opener(fn) for fn in args.input]
    trivy_flags = [is_trivy_sbom(data) for data, _ in files]

    if all(trivy_flags):
        return _merge_trivy(args, files)
    if any(trivy_flags):
        raise SystemExit(
            "ошибка: смешивание сырых отчётов trivy и обычных SBOM не поддерживается — объединяйте файлы одного типа"
        )
    return _merge_standard(args, files)


def _merge_standard(args, files):
    with open(_PKG_DIR / "schemas" / "schema.json") as f:
        schema = json.load(f)
        keys = set(schema["properties"]).intersection(schema["$defs"]["component"]["properties"])
        if "version" in keys:
            keys.remove("version")
        if "name" in keys:
            keys.remove("name")
        if "type" in keys:
            keys.remove("type")

    encoding = files[-1][1]
    all_components = []
    for data, _ in files:
        new_data = data["metadata"]["component"].copy()
        for key in keys:
            if key in data:
                new_data[key] = data[key]
        if "properties" not in new_data:
            new_data["properties"] = []
        if not get_prop(new_data.get("properties", []), "GOST:attack_surface"):
            new_data["properties"].append(
                {"name": "GOST:attack_surface", "value": eval_prop(data.get("components", []), "GOST:attack_surface")}
            )
        if not get_prop(new_data.get("properties", []), "GOST:security_function"):
            new_data["properties"].append(
                {
                    "name": "GOST:security_function",
                    "value": eval_prop(data.get("components", []), "GOST:security_function"),
                }
            )
        all_components.append(new_data)

    output_data = _build_output(args, all_components)

    with open(args.output, "w", encoding=encoding) as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
