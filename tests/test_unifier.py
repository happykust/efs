# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

"""Тесты слияния нескольких SBOM в один перечень."""

import json
from types import SimpleNamespace

import pytest

from efs.unifier import eval_prop, is_trivy_sbom, run

from .conftest import make_bom, make_component, make_trivy_bom, trivy_component, trivy_manifest


def merge_boms(tmp_path, boms):
    """Записать SBOM во временные файлы, слить их и вернуть результат."""
    inputs = []
    for i, bom in enumerate(boms):
        path = tmp_path / f"in{i}.json"
        path.write_text(json.dumps(bom, ensure_ascii=False), encoding="utf-8")
        inputs.append(str(path))
    out = tmp_path / "merged.json"
    run(
        SimpleNamespace(
            input=inputs,
            output=str(out),
            app_name="Продукт",
            app_version="1.0",
            manufacturer="ООО Тест",
        )
    )
    return json.loads(out.read_text(encoding="utf-8"))


def _gost(name, value):
    return {"name": name, "value": value}


class TestEvalProp:
    def test_yes_wins(self):
        comps = [
            {"properties": [_gost("GOST:attack_surface", "no")]},
            {"properties": [_gost("GOST:attack_surface", "yes")]},
        ]
        assert eval_prop(comps, "GOST:attack_surface") == "yes"

    def test_indirect_when_no_yes(self):
        comps = [
            {"properties": [_gost("GOST:attack_surface", "no")]},
            {"properties": [_gost("GOST:attack_surface", "indirect")]},
        ]
        assert eval_prop(comps, "GOST:attack_surface") == "indirect"

    def test_all_no(self):
        comps = [{"properties": [_gost("GOST:attack_surface", "no")]}]
        assert eval_prop(comps, "GOST:attack_surface") == "no"

    def test_empty_when_property_absent(self):
        assert eval_prop([{"properties": []}], "GOST:attack_surface") == ""


class TestRun:
    def _write_bom(self, tmp_path, name, app_name, components):
        bom = make_bom(components)
        bom["metadata"]["component"]["name"] = app_name
        path = tmp_path / name
        path.write_text(json.dumps(bom, ensure_ascii=False), encoding="utf-8")
        return str(path)

    def test_each_input_becomes_component(self, tmp_path):
        first = self._write_bom(tmp_path, "a.json", "Сервис А", [make_component("requests", "2.32.5")])
        second = self._write_bom(tmp_path, "b.json", "Сервис Б", [make_component("flask", "3.0.0")])
        out = tmp_path / "merged.json"

        run(
            SimpleNamespace(
                input=[first, second],
                output=str(out),
                app_name="Продукт",
                app_version="1.0",
                manufacturer="ООО Тест",
            )
        )

        result = json.loads(out.read_text(encoding="utf-8"))
        assert [c["name"] for c in result["components"]] == ["Сервис А", "Сервис Б"]
        assert result["metadata"]["component"]["name"] == "Продукт"
        assert result["metadata"]["component"]["manufacturer"]["name"] == "ООО Тест"
        assert result["bomFormat"] == "CycloneDX"
        assert result["specVersion"] == "1.6"

    def test_gost_props_aggregated_from_components(self, tmp_path):
        components = [
            make_component("safe", "1.0", properties=[_gost("GOST:attack_surface", "no")]),
            make_component("exposed", "1.0", properties=[_gost("GOST:attack_surface", "yes")]),
        ]
        path = self._write_bom(tmp_path, "a.json", "Сервис А", components)
        out = tmp_path / "merged.json"

        run(
            SimpleNamespace(
                input=[path],
                output=str(out),
                app_name="Продукт",
                app_version="1.0",
                manufacturer="ООО Тест",
            )
        )

        result = json.loads(out.read_text(encoding="utf-8"))
        props = {p["name"]: p["value"] for p in result["components"][0]["properties"]}
        assert props["GOST:attack_surface"] == "yes"

    def test_existing_gost_prop_preserved(self, tmp_path):
        bom = make_bom([make_component("safe", "1.0", properties=[_gost("GOST:attack_surface", "no")])])
        bom["metadata"]["component"]["properties"] = [_gost("GOST:attack_surface", "indirect")]
        path = tmp_path / "a.json"
        path.write_text(json.dumps(bom, ensure_ascii=False), encoding="utf-8")
        out = tmp_path / "merged.json"

        run(
            SimpleNamespace(
                input=[str(path)],
                output=str(out),
                app_name="Продукт",
                app_version="1.0",
                manufacturer="ООО Тест",
            )
        )

        result = json.loads(out.read_text(encoding="utf-8"))
        props = {p["name"]: p["value"] for p in result["components"][0]["properties"]}
        assert props["GOST:attack_surface"] == "indirect"


class TestIsTrivySbom:
    def test_detects_trivy_report(self):
        assert is_trivy_sbom(make_trivy_bom()) is True

    def test_regular_sbom_is_not_trivy(self):
        assert is_trivy_sbom(make_bom([make_component("requests", "2.32.5")])) is False

    def test_missing_metadata_keys_are_safe(self):
        assert is_trivy_sbom({}) is False
        assert is_trivy_sbom({"metadata": {}}) is False
        assert is_trivy_sbom({"metadata": {"tools": {}}}) is False

    def test_other_tool_is_not_trivy(self):
        bom = make_trivy_bom()
        bom["metadata"]["tools"]["components"] = [{"group": "cyclonedx", "name": "cdxgen"}]
        assert is_trivy_sbom(bom) is False


class TestTrivyRouting:
    def _write(self, tmp_path, name, data):
        path = tmp_path / name
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return str(path)

    def _args(self, inputs, out):
        return SimpleNamespace(
            input=inputs,
            output=str(out),
            app_name="Продукт",
            app_version="1.0",
            manufacturer="ООО Тест",
        )

    def test_mixed_inputs_rejected(self, tmp_path):
        trivy = self._write(tmp_path, "trivy.json", make_trivy_bom())
        regular = self._write(tmp_path, "regular.json", make_bom([make_component("requests", "2.32.5")]))

        with pytest.raises(SystemExit):
            run(self._args([trivy, regular], tmp_path / "merged.json"))

    def test_trivy_components_kept_as_components(self, tmp_path):
        """В trivy-режиме компоненты переносятся сами, а не сворачиваются в один на файл."""
        first = self._write(
            tmp_path,
            "a.json",
            make_trivy_bom([trivy_component("lodash", "4.17.21", "ref-1", "pkg:npm/lodash@4.17.21")]),
        )
        second = self._write(
            tmp_path,
            "b.json",
            make_trivy_bom([trivy_component("axios", "1.6.0", "ref-2", "pkg:npm/axios@1.6.0")]),
        )
        out = tmp_path / "merged.json"

        run(self._args([first, second], out))

        result = json.loads(out.read_text(encoding="utf-8"))
        assert sorted(c["name"] for c in result["components"]) == ["axios", "lodash"]

    def test_metadata_built_from_cli_arguments(self, tmp_path):
        path = self._write(tmp_path, "a.json", make_trivy_bom())
        out = tmp_path / "merged.json"

        run(self._args([path], out))

        result = json.loads(out.read_text(encoding="utf-8"))
        assert result["metadata"]["component"] == {
            "type": "application",
            "name": "Продукт",
            "version": "1.0",
            "manufacturer": {"name": "ООО Тест"},
        }
        assert "tools" not in result["metadata"]


class TestTrivyComponents:
    def test_manifest_components_removed(self, tmp_path):
        bom = make_trivy_bom(
            [
                trivy_manifest("package-lock.json", "manifest-1"),
                trivy_component("lodash", "4.17.21", "ref-1", "pkg:npm/lodash@4.17.21"),
            ]
        )
        result = merge_boms(tmp_path, [bom])
        assert [c["name"] for c in result["components"]] == ["lodash"]

    def test_duplicate_purl_collapsed(self, tmp_path):
        first = make_trivy_bom([trivy_component("lodash", "4.17.21", "ref-a", "pkg:npm/lodash@4.17.21")])
        second = make_trivy_bom([trivy_component("lodash", "4.17.21", "ref-b", "pkg:npm/lodash@4.17.21")])
        result = merge_boms(tmp_path, [first, second])
        assert len(result["components"]) == 1

    def test_different_versions_kept_apart(self, tmp_path):
        first = make_trivy_bom([trivy_component("lodash", "4.17.21", "ref-a", "pkg:npm/lodash@4.17.21")])
        second = make_trivy_bom([trivy_component("lodash", "3.10.1", "ref-b", "pkg:npm/lodash@3.10.1")])
        result = merge_boms(tmp_path, [first, second])
        assert sorted(c["version"] for c in result["components"]) == ["3.10.1", "4.17.21"]

    def test_properties_of_duplicates_merged(self, tmp_path):
        first = make_trivy_bom(
            [
                trivy_component(
                    "lodash",
                    "4.17.21",
                    "ref-a",
                    "pkg:npm/lodash@4.17.21",
                    properties=[{"name": "aquasecurity:trivy:PkgType", "value": "npm"}],
                )
            ]
        )
        second = make_trivy_bom(
            [
                trivy_component(
                    "lodash",
                    "4.17.21",
                    "ref-b",
                    "pkg:npm/lodash@4.17.21",
                    properties=[{"name": "aquasecurity:trivy:LayerDigest", "value": "sha256:abc"}],
                )
            ]
        )
        result = merge_boms(tmp_path, [first, second])
        names = {p["name"] for p in result["components"][0]["properties"]}
        assert names == {"aquasecurity:trivy:PkgType", "aquasecurity:trivy:LayerDigest"}

    def test_trivy_properties_preserved(self, tmp_path):
        bom = make_trivy_bom([trivy_component("lodash", "4.17.21", "ref-a", "pkg:npm/lodash@4.17.21")])
        result = merge_boms(tmp_path, [bom])
        assert result["components"][0]["properties"] == [{"name": "aquasecurity:trivy:PkgType", "value": "npm"}]

    def test_component_without_purl_kept_when_not_application(self, tmp_path):
        bom = make_trivy_bom([trivy_component("безымянный", "1.0", "ref-a")])
        result = merge_boms(tmp_path, [bom])
        assert [c["name"] for c in result["components"]] == ["безымянный"]


class TestTrivyVulnerabilities:
    def test_section_absent_when_no_vulnerabilities(self, tmp_path):
        result = merge_boms(tmp_path, [make_trivy_bom()])
        assert "vulnerabilities" not in result

    def test_vulnerabilities_collected(self, tmp_path):
        first = make_trivy_bom(
            [trivy_component("lodash", "4.17.21", "ref-a", "pkg:npm/lodash@4.17.21")],
            vulnerabilities=[{"id": "CVE-2021-23337", "affects": [{"ref": "ref-a"}]}],
        )
        second = make_trivy_bom(
            [trivy_component("axios", "1.6.0", "ref-b", "pkg:npm/axios@1.6.0")],
            vulnerabilities=[{"id": "CVE-2023-45857", "affects": [{"ref": "ref-b"}]}],
        )
        result = merge_boms(tmp_path, [first, second])
        assert sorted(v["id"] for v in result["vulnerabilities"]) == ["CVE-2021-23337", "CVE-2023-45857"]

    def test_same_cve_deduplicated_and_affects_merged(self, tmp_path):
        first = make_trivy_bom(
            [trivy_component("lodash", "4.17.21", "ref-a", "pkg:npm/lodash@4.17.21")],
            vulnerabilities=[{"id": "CVE-2021-23337", "affects": [{"ref": "ref-a"}]}],
        )
        second = make_trivy_bom(
            [trivy_component("axios", "1.6.0", "ref-b", "pkg:npm/axios@1.6.0")],
            vulnerabilities=[{"id": "CVE-2021-23337", "affects": [{"ref": "ref-b"}]}],
        )
        result = merge_boms(tmp_path, [first, second])
        assert len(result["vulnerabilities"]) == 1
        assert sorted(a["ref"] for a in result["vulnerabilities"][0]["affects"]) == ["ref-a", "ref-b"]

    def test_affects_ref_remapped_to_surviving_component(self, tmp_path):
        """Дубликат компонента исчез — ссылка на его bom-ref должна вести на оставшийся."""
        first = make_trivy_bom([trivy_component("lodash", "4.17.21", "ref-a", "pkg:npm/lodash@4.17.21")])
        second = make_trivy_bom(
            [trivy_component("lodash", "4.17.21", "ref-b", "pkg:npm/lodash@4.17.21")],
            vulnerabilities=[{"id": "CVE-2021-23337", "affects": [{"ref": "ref-b"}]}],
        )
        result = merge_boms(tmp_path, [first, second])
        assert result["vulnerabilities"][0]["affects"] == [{"ref": "ref-a"}]


class TestTrivyDependencies:
    def test_section_absent_when_no_dependencies(self, tmp_path):
        result = merge_boms(tmp_path, [make_trivy_bom()])
        assert "dependencies" not in result

    def test_dependencies_collected(self, tmp_path):
        first = make_trivy_bom(
            [trivy_component("lodash", "4.17.21", "ref-a", "pkg:npm/lodash@4.17.21")],
            dependencies=[{"ref": "ref-a", "dependsOn": []}],
        )
        second = make_trivy_bom(
            [trivy_component("axios", "1.6.0", "ref-b", "pkg:npm/axios@1.6.0")],
            dependencies=[{"ref": "ref-b", "dependsOn": []}],
        )
        result = merge_boms(tmp_path, [first, second])
        assert sorted(d["ref"] for d in result["dependencies"]) == ["ref-a", "ref-b"]

    def test_refs_remapped_and_deduplicated(self, tmp_path):
        first = make_trivy_bom(
            [
                trivy_component("lodash", "4.17.21", "ref-a", "pkg:npm/lodash@4.17.21"),
                trivy_component("axios", "1.6.0", "ref-x", "pkg:npm/axios@1.6.0"),
            ],
            dependencies=[{"ref": "ref-a", "dependsOn": ["ref-x"]}],
        )
        second = make_trivy_bom(
            [
                trivy_component("lodash", "4.17.21", "ref-b", "pkg:npm/lodash@4.17.21"),
                trivy_component("chalk", "5.3.0", "ref-y", "pkg:npm/chalk@5.3.0"),
            ],
            dependencies=[{"ref": "ref-b", "dependsOn": ["ref-y"]}],
        )
        result = merge_boms(tmp_path, [first, second])
        lodash_entries = [d for d in result["dependencies"] if d["ref"] == "ref-a"]
        assert len(lodash_entries) == 1
        assert sorted(lodash_entries[0]["dependsOn"]) == ["ref-x", "ref-y"]

    def test_depends_on_entries_remapped(self, tmp_path):
        first = make_trivy_bom([trivy_component("lodash", "4.17.21", "ref-a", "pkg:npm/lodash@4.17.21")])
        second = make_trivy_bom(
            [
                trivy_component("lodash", "4.17.21", "ref-b", "pkg:npm/lodash@4.17.21"),
                trivy_component("axios", "1.6.0", "ref-c", "pkg:npm/axios@1.6.0"),
            ],
            dependencies=[{"ref": "ref-c", "dependsOn": ["ref-b"]}],
        )
        result = merge_boms(tmp_path, [first, second])
        assert result["dependencies"] == [{"ref": "ref-c", "dependsOn": ["ref-a"]}]

    def test_manifest_dependencies_dropped(self, tmp_path):
        """Манифест удалён из компонентов — записи о нём не должны остаться в dependencies."""
        bom = make_trivy_bom(
            [
                trivy_manifest("uv.lock", "manifest-1"),
                trivy_component("lodash", "4.17.21", "ref-a", "pkg:npm/lodash@4.17.21"),
            ],
            dependencies=[
                {"ref": "manifest-1", "dependsOn": ["ref-a"]},
                {"ref": "ref-a", "dependsOn": ["manifest-1"]},
            ],
        )
        result = merge_boms(tmp_path, [bom])
        assert result["dependencies"] == [{"ref": "ref-a", "dependsOn": []}]

    def test_source_root_reference_dropped(self, tmp_path):
        """Корень входного файла в результат не переносится — ссылки на него тоже."""
        bom = make_trivy_bom(
            [trivy_component("lodash", "4.17.21", "ref-a", "pkg:npm/lodash@4.17.21")],
            dependencies=[
                {"ref": "root-ref", "dependsOn": ["ref-a"]},
                {"ref": "ref-a", "dependsOn": []},
            ],
        )
        result = merge_boms(tmp_path, [bom])
        assert result["dependencies"] == [{"ref": "ref-a", "dependsOn": []}]

    def test_no_dangling_references_after_merge(self, tmp_path):
        first = make_trivy_bom(
            [
                trivy_manifest("package-lock.json", "manifest-1"),
                trivy_component("lodash", "4.17.21", "ref-a", "pkg:npm/lodash@4.17.21"),
            ],
            dependencies=[{"ref": "manifest-1", "dependsOn": ["ref-a"]}, {"ref": "ref-a", "dependsOn": []}],
        )
        second = make_trivy_bom(
            [
                trivy_manifest("uv.lock", "manifest-2"),
                trivy_component("lodash", "4.17.21", "ref-b", "pkg:npm/lodash@4.17.21"),
                trivy_component("axios", "1.6.0", "ref-c", "pkg:npm/axios@1.6.0"),
            ],
            dependencies=[
                {"ref": "manifest-2", "dependsOn": ["ref-b", "ref-c"]},
                {"ref": "ref-c", "dependsOn": ["ref-b"]},
            ],
        )
        result = merge_boms(tmp_path, [first, second])

        known = {c["bom-ref"] for c in result["components"]}
        for entry in result["dependencies"]:
            assert entry["ref"] in known
            for ref in entry["dependsOn"]:
                assert ref in known


class TestMergeSourceLangs:
    def _component(self, name, purl, langs):
        return make_component(
            name,
            "1.0",
            purl=purl,
            properties=[{"name": "GOST:source_langs", "value": lang} for lang in langs],
        )

    def test_languages_aggregated_from_components(self, tmp_path):
        """Компонент-сервис в сводном перечне наследует языки своих компонентов."""
        bom = make_bom(
            [
                self._component("requests", "pkg:pypi/requests@1.0", ["Python"]),
                self._component("cryptography", "pkg:pypi/cryptography@1.0", ["Python", "C"]),
            ]
        )
        result = merge_boms(tmp_path, [bom])
        langs = [p["value"] for p in result["components"][0]["properties"] if p["name"] == "GOST:source_langs"]
        assert sorted(langs) == ["C", "Python"]

    def test_each_language_is_separate_property(self, tmp_path):
        bom = make_bom([self._component("cryptography", "pkg:pypi/cryptography@1.0", ["Python", "C"])])
        result = merge_boms(tmp_path, [bom])
        names = [p["name"] for p in result["components"][0]["properties"]]
        assert names.count("GOST:source_langs") == 2

    def test_explicit_language_of_service_preserved(self, tmp_path):
        bom = make_bom([self._component("requests", "pkg:pypi/requests@1.0", ["Python"])])
        bom["metadata"]["component"]["properties"] = [{"name": "GOST:source_langs", "value": "Go"}]
        result = merge_boms(tmp_path, [bom])
        langs = [p["value"] for p in result["components"][0]["properties"] if p["name"] == "GOST:source_langs"]
        assert langs == ["Go"]

    def test_no_language_property_when_components_have_none(self, tmp_path):
        bom = make_bom([make_component("requests", "1.0")])
        result = merge_boms(tmp_path, [bom])
        assert all(p["name"] != "GOST:source_langs" for p in result["components"][0]["properties"])

    def test_languages_collected_from_nested_components(self, tmp_path):
        """В контейнерных SBOM компоненты вложены в образ — их языки тоже нужны."""
        inner = self._component("libssl", "pkg:deb/debian/libssl@1.0", ["C"])
        outer = make_component("app-image", "1.0", purl="pkg:oci/app@1.0", components=[inner])
        result = merge_boms(tmp_path, [make_bom([outer])])
        langs = [p["value"] for p in result["components"][0]["properties"] if p["name"] == "GOST:source_langs"]
        assert langs == ["C"]


class TestMergedServiceKeepsItsListing:
    """Компонент-сервис несёт внутри себя перечень своих заимствованных компонентов."""

    def _service_bom(self, service_name, components):
        bom = make_bom(components)
        bom["metadata"]["component"]["name"] = service_name
        return bom

    def test_nested_listing_transferred(self, tmp_path):
        bom = self._service_bom("Сервис А", [make_component("requests", "2.32.5")])
        result = merge_boms(tmp_path, [bom])
        nested = result["components"][0].get("components", [])
        assert [c["name"] for c in nested] == ["requests"]

    def test_service_version_comes_from_metadata(self, tmp_path):
        bom = self._service_bom("Сервис А", [make_component("requests", "2.32.5")])
        bom["metadata"]["component"]["version"] = "3.1.8"
        result = merge_boms(tmp_path, [bom])
        assert result["components"][0]["version"] == "3.1.8"

    def test_document_version_is_one(self, tmp_path):
        result = merge_boms(tmp_path, [self._service_bom("Сервис", [])])
        assert result["version"] == 1

    def test_timestamp_present(self, tmp_path):
        result = merge_boms(tmp_path, [self._service_bom("Сервис", [])])
        assert result["metadata"]["timestamp"]


class TestGostAggregationPriority:
    def _bom_with(self, values):
        components = [
            make_component(f"lib{i}", "1.0", properties=[{"name": "GOST:attack_surface", "value": v}])
            for i, v in enumerate(values)
        ]
        return make_bom(components)

    def test_yes_beats_indirect(self, tmp_path):
        """yes > indirect > no: сервис с компонентом на поверхности атаки помечается yes."""
        result = merge_boms(tmp_path, [self._bom_with(["indirect", "yes"])])
        props = {p["name"]: p["value"] for p in result["components"][0]["properties"]}
        assert props["GOST:attack_surface"] == "yes"

    def test_indirect_beats_no(self, tmp_path):
        result = merge_boms(tmp_path, [self._bom_with(["no", "indirect"])])
        props = {p["name"]: p["value"] for p in result["components"][0]["properties"]}
        assert props["GOST:attack_surface"] == "indirect"

    def test_missing_value_does_not_become_no(self, tmp_path):
        """Если у части компонентов свойства нет, заявлять «влияния нет» нельзя."""
        bom = make_bom(
            [
                make_component("lib0", "1.0", properties=[{"name": "GOST:attack_surface", "value": "no"}]),
                make_component("lib1", "1.0"),
            ]
        )
        result = merge_boms(tmp_path, [bom])
        props = {p["name"]: p["value"] for p in result["components"][0]["properties"]}
        assert props["GOST:attack_surface"] == ""

    def test_explicit_security_function_preserved(self, tmp_path):
        bom = make_bom([make_component("lib", "1.0", properties=[{"name": "GOST:security_function", "value": "no"}])])
        bom["metadata"]["component"]["properties"] = [{"name": "GOST:security_function", "value": "indirect"}]
        result = merge_boms(tmp_path, [bom])
        values = [p["value"] for p in result["components"][0]["properties"] if p["name"] == "GOST:security_function"]
        assert values == ["indirect"]


class TestTrivyDetectionPrecision:
    def test_requires_both_group_and_name(self):
        for tool in ({"group": "aquasecurity", "name": "trivy-db"}, {"group": "acme", "name": "trivy"}):
            bom = make_trivy_bom()
            bom["metadata"]["tools"]["components"] = [tool]
            assert is_trivy_sbom(bom) is False, tool

    def test_tools_as_list_is_not_trivy(self):
        bom = make_bom([])
        bom["metadata"]["tools"] = [{"vendor": "cyclonedx", "name": "cdxgen"}]
        assert is_trivy_sbom(bom) is False

    def test_mixed_inputs_rejected_in_any_order(self, tmp_path):
        trivy = make_trivy_bom()
        regular = make_bom([make_component("requests", "2.32.5")])
        for order in ([trivy, regular], [regular, trivy]):
            with pytest.raises(SystemExit):
                merge_boms(tmp_path, order)


class TestTrivyMergeDetails:
    def test_first_occurrence_wins_for_fields(self, tmp_path):
        first = make_trivy_bom([trivy_component("lodash", "4.17.21", "ref-a", "pkg:npm/lodash@4.17.21")])
        first["components"][0]["licenses"] = [{"license": {"id": "MIT"}}]
        second = make_trivy_bom([trivy_component("lodash", "4.17.21", "ref-b", "pkg:npm/lodash@4.17.21")])
        second["components"][0]["licenses"] = [{"license": {"id": "GPL-3.0"}}]
        result = merge_boms(tmp_path, [first, second])
        assert result["components"][0]["licenses"] == [{"license": {"id": "MIT"}}]

    def test_properties_merged_when_first_has_none(self, tmp_path):
        first = make_trivy_bom([trivy_component("lodash", "4.17.21", "ref-a", "pkg:npm/lodash@4.17.21", properties=[])])
        second = make_trivy_bom(
            [
                trivy_component(
                    "lodash",
                    "4.17.21",
                    "ref-b",
                    "pkg:npm/lodash@4.17.21",
                    properties=[{"name": "aquasecurity:trivy:PkgType", "value": "npm"}],
                )
            ]
        )
        result = merge_boms(tmp_path, [first, second])
        names = {p["name"] for p in result["components"][0].get("properties", [])}
        assert "aquasecurity:trivy:PkgType" in names

    def test_same_cve_on_same_component_not_duplicated(self, tmp_path):
        vuln = {"id": "CVE-2021-23337", "affects": [{"ref": "ref-a"}]}
        first = make_trivy_bom(
            [trivy_component("lodash", "4.17.21", "ref-a", "pkg:npm/lodash@4.17.21")], vulnerabilities=[vuln]
        )
        second = make_trivy_bom(
            [trivy_component("lodash", "4.17.21", "ref-a", "pkg:npm/lodash@4.17.21")],
            vulnerabilities=[json.loads(json.dumps(vuln))],
        )
        result = merge_boms(tmp_path, [first, second])
        assert result["vulnerabilities"][0]["affects"] == [{"ref": "ref-a"}]

    def test_shared_dependency_not_duplicated(self, tmp_path):
        def bom_with(ref):
            return make_trivy_bom(
                [
                    trivy_component("lodash", "4.17.21", ref, "pkg:npm/lodash@4.17.21"),
                    trivy_component("axios", "1.6.0", "ref-x", "pkg:npm/axios@1.6.0"),
                ],
                dependencies=[{"ref": ref, "dependsOn": ["ref-x"]}],
            )

        result = merge_boms(tmp_path, [bom_with("ref-a"), bom_with("ref-b")])
        entry = next(d for d in result["dependencies"] if d["ref"] == "ref-a")
        assert entry["dependsOn"] == ["ref-x"]

    def test_manufacturer_comes_from_cli(self, tmp_path):
        bom = make_trivy_bom([trivy_component("lodash", "4.17.21", "ref-a", "pkg:npm/lodash@4.17.21")])
        bom["metadata"]["component"]["manufacturer"] = {"name": "Aqua Security"}
        result = merge_boms(tmp_path, [bom])
        assert result["metadata"]["component"]["manufacturer"] == {"name": "ООО Тест"}
