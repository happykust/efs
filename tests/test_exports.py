# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

"""Структурные тесты отчётных форм: проверяются колонки и их содержимое, а не наличие подстроки."""

import csv
import re
import zipfile
from types import SimpleNamespace

from efs.to_csv import run as csv_run
from efs.to_odt import run as odt_run

from .conftest import make_bom, make_component

# Порядок граф формы перечня заимствованных компонентов
NUMBER, NAME, VERSION, LANGS, GOST, SOURCE = range(6)


def component(name, version="1.0", langs=("Python",), attack="no", security="no", **extra):
    comp = make_component(name, version, purl=f"pkg:pypi/{name}@{version}")
    comp["properties"] = [
        {"name": "GOST:attack_surface", "value": attack},
        {"name": "GOST:security_function", "value": security},
    ] + [{"name": "GOST:source_langs", "value": lang} for lang in langs]
    comp.setdefault("externalReferences", [{"type": "vcs", "url": f"https://github.com/example/{name}"}])
    comp.update(extra)
    return comp


def export_csv(tmp_path, bom):
    source = tmp_path / "bom.json"
    source.write_text(__import__("json").dumps(bom, ensure_ascii=False), encoding="utf-8")
    out = tmp_path / "perechen.csv"
    csv_run(SimpleNamespace(input=str(source), output=str(out), verbose=False))
    with open(out, encoding="utf-8") as handle:
        return list(csv.reader(handle))


def export_odt_rows(tmp_path, bom, **args):
    source = tmp_path / "bom.json"
    source.write_text(__import__("json").dumps(bom, ensure_ascii=False), encoding="utf-8")
    out = tmp_path / "perechen.odt"
    odt_run(
        SimpleNamespace(
            input=str(source),
            output=str(out),
            pa_fb_ontop=args.get("pa_fb_ontop", False),
            format=args.get("format", "oss"),
            verbose=False,
        )
    )
    with zipfile.ZipFile(out) as archive:
        xml = archive.read("content.xml").decode("utf-8")
    rows = []
    for row_xml in re.findall(r"<table:table-row.*?</table:table-row>", xml, re.S):
        cells = [
            re.sub(r"<[^>]+>", "", cell)
            for cell in re.findall(r"<table:table-cell.*?</table:table-cell>", row_xml, re.S)
        ]
        if cells:
            rows.append(cells)
    return rows


class TestCsvStructure:
    def test_header_names_the_required_columns(self, tmp_path):
        header = export_csv(tmp_path, make_bom([component("requests")]))[0]
        assert header[NUMBER].strip().lower().startswith("№")
        assert "аименование" in header[NAME]
        assert "ерсия" in header[VERSION]
        assert "зык" in header[LANGS]
        assert "поверхности атаки" in header[GOST]
        assert "исходный код" in header[SOURCE]

    def test_values_land_in_their_columns(self, tmp_path):
        rows = export_csv(tmp_path, make_bom([component("requests", "2.32.5")]))
        assert rows[1][NAME] == "requests"
        assert rows[1][VERSION] == "2.32.5"
        assert rows[1][LANGS] == "Python"
        assert "github.com/example/requests" in rows[1][SOURCE]

    def test_rows_are_numbered_sequentially(self, tmp_path):
        bom = make_bom([component("a"), component("b"), component("c")])
        rows = export_csv(tmp_path, bom)
        assert [row[NUMBER] for row in rows[1:]] == ["1", "2", "3"]

    def test_gost_values_are_real_not_placeholder(self, tmp_path):
        rows = export_csv(tmp_path, make_bom([component("requests", attack="no", security="no")]))
        assert "yes/indirect/no" not in rows[1][GOST]
        assert "'GOST:attack_surface': 'no'" in rows[1][GOST]

    def test_all_languages_listed(self, tmp_path):
        rows = export_csv(tmp_path, make_bom([component("cryptography", langs=("Python", "C"))]))
        assert rows[1][LANGS] == "Python, C"

    def test_nested_components_included(self, tmp_path):
        outer = component("внешний")
        outer["components"] = [component("вложенный")]
        rows = export_csv(tmp_path, make_bom([outer]))
        assert {row[NAME] for row in rows[1:]} == {"внешний", "вложенный"}

    def test_identical_components_deduplicated(self, tmp_path):
        rows = export_csv(tmp_path, make_bom([component("requests"), component("requests")]))
        assert len(rows) == 2

    def test_different_versions_kept_apart(self, tmp_path):
        rows = export_csv(tmp_path, make_bom([component("openssl", "1.1.1"), component("openssl", "3.0")]))
        assert sorted(row[VERSION] for row in rows[1:]) == ["1.1.1", "3.0"]

    def test_repository_link_labelled_correctly(self, tmp_path):
        rows = export_csv(tmp_path, make_bom([component("requests")]))
        assert rows[1][SOURCE].startswith("Репозиторий:")

    def test_certified_product_fills_source_column(self, tmp_path):
        comp = component("crypto-module", externalReferences=[])
        comp["properties"].append({"name": "GOST:provided_by", "value": "КриптоПро CSP"})
        rows = export_csv(tmp_path, make_bom([comp]))
        assert "КриптоПро CSP" in rows[1][SOURCE]

    def test_existing_links_not_replaced_by_fallback(self, tmp_path):
        comp = component("requests", externalReferences=[{"type": "website", "url": "https://example.org"}])
        rows = export_csv(tmp_path, make_bom([comp]))
        assert "example.org" in rows[1][SOURCE]


class TestOdtStructure:
    def _data_rows(self, rows):
        return [row for row in rows if row and row[NUMBER].strip().isdigit()]

    def test_values_land_in_their_columns(self, tmp_path):
        rows = self._data_rows(export_odt_rows(tmp_path, make_bom([component("requests", "2.32.5")])))
        assert rows[0][NAME] == "requests"
        assert rows[0][VERSION] == "2.32.5"
        assert rows[0][LANGS] == "Python"
        assert "github.com/example/requests" in rows[0][SOURCE]

    def test_rows_are_numbered_sequentially(self, tmp_path):
        bom = make_bom([component("a"), component("b"), component("c")])
        rows = self._data_rows(export_odt_rows(tmp_path, bom))
        assert [row[NUMBER] for row in rows] == ["1", "2", "3"]

    def test_attack_surface_wording(self, tmp_path):
        rows = self._data_rows(export_odt_rows(tmp_path, make_bom([component("requests", attack="yes")])))
        assert rows[0][GOST] == "поверхность атаки"

    def test_indirect_attack_surface_wording(self, tmp_path):
        rows = self._data_rows(export_odt_rows(tmp_path, make_bom([component("requests", attack="indirect")])))
        assert "косвенная поверхность атаки" in rows[0][GOST]

    def test_security_function_wording(self, tmp_path):
        rows = self._data_rows(export_odt_rows(tmp_path, make_bom([component("openssl", security="yes")])))
        assert "функция безопасности" in rows[0][GOST]

    def test_attack_and_security_are_independent(self, tmp_path):
        """Отметки берутся каждая из своего свойства, а не обе из одного."""
        rows = self._data_rows(export_odt_rows(tmp_path, make_bom([component("x", attack="yes", security="no")])))
        assert "поверхность атаки" in rows[0][GOST]
        assert "функция безопасности" not in rows[0][GOST]

    def test_nested_components_included(self, tmp_path):
        outer = component("внешний")
        outer["components"] = [component("вложенный")]
        rows = self._data_rows(export_odt_rows(tmp_path, make_bom([outer])))
        assert {row[NAME] for row in rows} == {"внешний", "вложенный"}

    def test_identical_components_deduplicated(self, tmp_path):
        rows = self._data_rows(export_odt_rows(tmp_path, make_bom([component("requests"), component("requests")])))
        assert len(rows) == 1

    def test_pa_fb_ontop_moves_marked_components_up(self, tmp_path):
        bom = make_bom([component("обычный"), component("опасный", attack="yes")])
        rows = self._data_rows(export_odt_rows(tmp_path, bom, pa_fb_ontop=True))
        assert rows[0][NAME] == "опасный"

    def test_indirect_also_moved_up(self, tmp_path):
        bom = make_bom([component("обычный"), component("косвенный", attack="indirect")])
        rows = self._data_rows(export_odt_rows(tmp_path, bom, pa_fb_ontop=True))
        assert rows[0][NAME] == "косвенный"

    def test_order_preserved_without_flag(self, tmp_path):
        bom = make_bom([component("обычный"), component("опасный", attack="yes")])
        rows = self._data_rows(export_odt_rows(tmp_path, bom, pa_fb_ontop=False))
        assert rows[0][NAME] == "обычный"

    def test_certified_product_fills_source_column(self, tmp_path):
        comp = component("crypto-module", externalReferences=[])
        comp["properties"].append({"name": "GOST:provided_by", "value": "КриптоПро CSP"})
        rows = self._data_rows(export_odt_rows(tmp_path, make_bom([comp])))
        assert "КриптоПро CSP" in rows[0][SOURCE]


class TestContainerForm:
    """Форма перечня образов контейнеров: № / Наименование / Назначение / Состав / ПА и ФБ."""

    C_NUMBER, C_NAME, C_PURPOSE, C_CONTENT, C_GOST = range(5)

    def _container_bom(self, description="Образ прикладного сервиса", nested=None):
        inner = nested if nested is not None else [component("libssl", "3.0")]
        return make_bom(
            [
                {
                    "type": "container",
                    "name": "app-image",
                    "version": "1.0",
                    "description": description,
                    "properties": [
                        {"name": "GOST:attack_surface", "value": "yes"},
                        {"name": "GOST:security_function", "value": "no"},
                    ],
                    "components": inner,
                }
            ]
        )

    def _rows(self, tmp_path, bom):
        rows = export_odt_rows(tmp_path, bom, format="container")
        return [row for row in rows if row and row[0].strip().isdigit()]

    def test_purpose_taken_from_description(self, tmp_path):
        rows = self._rows(tmp_path, self._container_bom())
        assert rows[0][self.C_PURPOSE] == "Образ прикладного сервиса"

    def test_content_lists_included_software(self, tmp_path):
        rows = self._rows(tmp_path, self._container_bom())
        assert "libssl 3.0" in rows[0][self.C_CONTENT]

    def test_content_includes_deeper_levels(self, tmp_path):
        deep = component("zlib", "1.3")
        middle = component("libssl", "3.0")
        middle["components"] = [deep]
        rows = self._rows(tmp_path, self._container_bom(nested=[middle]))
        assert "zlib 1.3" in rows[0][self.C_CONTENT]

    def test_content_has_no_duplicates(self, tmp_path):
        rows = self._rows(
            tmp_path, self._container_bom(nested=[component("libssl", "3.0"), component("libssl", "3.0")])
        )
        assert rows[0][self.C_CONTENT].count("libssl 3.0") == 1

    def test_attack_surface_wording_present(self, tmp_path):
        rows = self._rows(tmp_path, self._container_bom())
        assert "поверхность атаки" in rows[0][self.C_GOST]


class TestSourceColumnPrecision:
    """Графа источника должна содержать адрес исходного кода, а не любую попавшуюся ссылку."""

    def _component_with_both_links(self):
        return component(
            "requests",
            externalReferences=[
                {"type": "website", "url": "https://requests.example/docs"},
                {"type": "vcs", "url": "https://github.com/psf/requests"},
            ],
        )

    def test_odt_prefers_repository_over_website(self, tmp_path):
        rows = export_odt_rows(tmp_path, make_bom([self._component_with_both_links()]), format="oss")
        data = [row for row in rows if row and row[NUMBER].strip().isdigit()]
        assert "github.com/psf/requests" in data[0][SOURCE]
        assert "requests.example/docs" not in data[0][SOURCE]

    def test_odt_prefers_repository_over_distribution(self, tmp_path):
        comp = component(
            "requests",
            externalReferences=[
                {"type": "source-distribution", "url": "https://example.org/requests.tar.gz"},
                {"type": "vcs", "url": "https://github.com/psf/requests"},
            ],
        )
        rows = export_odt_rows(tmp_path, make_bom([comp]), format="oss")
        data = [row for row in rows if row and row[NUMBER].strip().isdigit()]
        assert "github.com/psf/requests" in data[0][SOURCE]

    def test_distribution_used_when_no_repository(self, tmp_path):
        comp = component(
            "requests",
            externalReferences=[{"type": "source-distribution", "url": "https://example.org/requests.tar.gz"}],
        )
        rows = export_odt_rows(tmp_path, make_bom([comp]), format="oss")
        data = [row for row in rows if row and row[NUMBER].strip().isdigit()]
        assert "requests.tar.gz" in data[0][SOURCE]

    def test_placeholder_link_never_shown_as_source(self, tmp_path):
        comp = component("internal", externalReferences=[{"type": "vcs", "url": "TODO"}])
        comp["properties"].append({"name": "GOST:provided_by", "value": "КриптоПро CSP"})
        rows = export_csv(tmp_path, make_bom([comp]))
        assert "TODO" not in rows[1][SOURCE]
        assert "КриптоПро CSP" in rows[1][SOURCE]
