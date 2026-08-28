# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

"""Тесты слияния нескольких SBOM в один перечень."""

import json
from types import SimpleNamespace

from efc.unifier import eval_prop, run

from .conftest import make_bom, make_component


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
