# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

"""Тесты единого конфига .sbom-config.json."""

import json

import pytest

from efc.config import (
    apply_config_to_component,
    config_to_purl_exclude,
    config_to_purl_to_gost,
    config_to_purl_to_vcs,
    get_gost_prop,
    get_manufacturer,
    get_metadata_config,
    get_pedigree,
    get_scanner_config,
    get_vcs,
    guess_source_langs,
    init_config,
    is_excluded,
    load_config,
    migrate_config,
)

from .conftest import make_bom, make_component


def _langs_of(comp):
    """Все языки компонента в порядке следования свойств."""
    return [p["value"] for p in comp.get("properties", []) if p["name"] == "GOST:source_langs"]


class TestLookup:
    def test_vcs_by_purl_without_version(self, config):
        assert get_vcs(config, "pkg:pypi/requests@2.32.5") == "https://github.com/psf/requests"

    def test_vcs_exact_version_match(self, config):
        assert get_vcs(config, "pkg:pypi/cryptography@42.0.0").endswith("cryptography-fork")

    def test_vcs_other_version_not_matched(self, config):
        """Ключ с версией не должен матчить другую версию того же пакета."""
        assert get_vcs(config, "pkg:pypi/cryptography@41.0.0") == ""

    def test_vcs_unknown_purl(self, config):
        assert get_vcs(config, "pkg:pypi/unknown@1.0.0") == ""


class TestGostProps:
    def test_component_value_wins_over_defaults(self, config):
        assert get_gost_prop(config, "pkg:pypi/requests@2.32.5", "GOST:attack_surface") == "yes"

    def test_falls_back_to_defaults(self, config):
        assert get_gost_prop(config, "pkg:pypi/requests@2.32.5", "GOST:security_function") == "no"

    def test_provided_by_from_defaults(self, config):
        assert get_gost_prop(config, "pkg:pypi/anything@1.0", "GOST:provided_by") == "ООО Умолчание"

    def test_default_no_when_nothing_configured(self):
        assert get_gost_prop({}, "pkg:pypi/x@1.0", "GOST:attack_surface") == "no"


class TestExclude:
    def test_cascade_exclude(self, config):
        assert is_excluded(config, "pkg:npm/left-pad@1.3.0") is True

    def test_direct_exclude(self, config):
        assert is_excluded(config, "pkg:npm/ajv@6.12.6") == "direct"

    def test_not_excluded(self, config):
        assert is_excluded(config, "pkg:pypi/requests@2.32.5") is False

    def test_config_to_purl_exclude_splits_modes(self, config):
        cascade, direct = config_to_purl_exclude(config)
        assert cascade == ["pkg:npm/left-pad"]
        assert direct == ["pkg:npm/ajv@6.12.6"]


class TestPedigreeAndManufacturer:
    def test_pedigree_returned(self, config):
        assert get_pedigree(config, "pkg:pypi/cryptography@42.0.0") == {"notes": "Форк с ГОСТ-патчами"}

    def test_no_pedigree(self, config):
        assert get_pedigree(config, "pkg:pypi/requests@2.32.5") is None

    def test_component_manufacturer(self, config):
        assert get_manufacturer(config, "pkg:pypi/cryptography@42.0.0") == {"name": "ООО Форк"}

    def test_manufacturer_falls_back_to_defaults(self, config):
        assert get_manufacturer(config, "pkg:pypi/requests@2.32.5") == {"name": "ООО Умолчание"}


class TestApplyConfigToComponent:
    def test_sets_gost_properties(self, config):
        comp = make_component("requests", "2.32.5")
        apply_config_to_component(comp, config)
        props = {p["name"]: p["value"] for p in comp["properties"]}
        assert props["GOST:attack_surface"] == "yes"
        assert props["GOST:security_function"] == "no"
        assert props["GOST:provided_by"] == "ООО Умолчание"

    def test_sets_vcs_reference(self, config):
        comp = make_component("requests", "2.32.5")
        apply_config_to_component(comp, config)
        assert comp["externalReferences"] == [{"type": "vcs", "url": "https://github.com/psf/requests"}]

    def test_replaces_placeholder_vcs(self, config):
        comp = make_component("requests", "2.32.5", externalReferences=[{"type": "vcs", "url": "TODO"}])
        apply_config_to_component(comp, config)
        assert comp["externalReferences"][0]["url"] == "https://github.com/psf/requests"

    def test_keeps_other_reference_types(self, config):
        comp = make_component(
            "requests", "2.32.5", externalReferences=[{"type": "website", "url": "https://example.org"}]
        )
        apply_config_to_component(comp, config)
        types = [r["type"] for r in comp["externalReferences"]]
        assert types == ["website", "vcs"]

    def test_sets_pedigree_and_manufacturer(self, config):
        comp = make_component("cryptography", "42.0.0")
        apply_config_to_component(comp, config)
        assert comp["pedigree"] == {"notes": "Форк с ГОСТ-патчами"}
        assert comp["manufacturer"] == {"name": "ООО Форк"}

    def test_defaults_manufacturer_not_written_to_component(self, config):
        """defaults.manufacturer относится к продукту, а не к каждому компоненту."""
        comp = make_component("requests", "2.32.5")
        apply_config_to_component(comp, config)
        assert "manufacturer" not in comp

    def test_component_without_purl_untouched(self, config):
        comp = {"type": "library", "name": "no-purl"}
        apply_config_to_component(comp, config)
        assert comp == {"type": "library", "name": "no-purl"}

    def test_invalid_gost_value_replaced_by_default(self):
        cfg = {"components": {"pkg:pypi/x": {"attack_surface": "maybe"}}}
        comp = make_component("x", "1.0")
        apply_config_to_component(comp, cfg, gost_default="indirect")
        props = {p["name"]: p["value"] for p in comp["properties"]}
        assert props["GOST:attack_surface"] == "indirect"


class TestLegacyConversion:
    def test_purl_to_vcs(self, config):
        mapping = config_to_purl_to_vcs(config)
        assert mapping["pkg:pypi/requests"] == "https://github.com/psf/requests"
        assert "pkg:npm/left-pad" not in mapping

    def test_purl_to_gost(self, config):
        """Легаси-формат — «свойство → purl → значение»."""
        mapping = config_to_purl_to_gost(config)
        assert mapping["GOST:attack_surface"]["pkg:pypi/requests"] == "yes"
        assert mapping["GOST:security_function"] == {"pkg:pypi/cryptography@42.0.0": "yes"}


class TestSections:
    def test_scanner_absent_returns_empty(self):
        """Дефолт cdxgen подставляет CLI, а не конфиг."""
        assert get_scanner_config({}) == {}

    def test_scanner_from_config(self):
        cfg = {"scanner": {"tool": "trivy", "target": "img:latest"}}
        scanner = get_scanner_config(cfg)
        assert scanner["tool"] == "trivy"
        assert scanner["target"] == "img:latest"

    def test_metadata_section(self):
        cfg = {"metadata": {"name": "Продукт", "version": "2.0"}}
        assert get_metadata_config(cfg)["name"] == "Продукт"

    def test_metadata_missing(self):
        assert get_metadata_config({}) == {}


class TestLoadConfig:
    def test_explicit_path(self, write_json):
        path = write_json(".sbom-config.json", {"components": {}})
        assert load_config(str(path)) == {"components": {}}

    def test_missing_explicit_path_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_config(str(tmp_path / "нет.json"))

    def test_found_in_cwd(self, tmp_path, monkeypatch, write_json):
        write_json(".sbom-config.json", {"components": {"pkg:pypi/x": {}}})
        monkeypatch.chdir(tmp_path)
        assert load_config() == {"components": {"pkg:pypi/x": {}}}

    def test_absent_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert load_config() is None


class TestInitConfig:
    def test_collects_purls_without_versions(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        bom = make_bom([make_component("requests", "2.32.5"), make_component("urllib3", "2.2.1")])
        init_config(bom)
        result = json.loads((tmp_path / ".sbom-config.json").read_text(encoding="utf-8"))
        assert set(result["components"]) == {"pkg:pypi/requests", "pkg:pypi/urllib3"}

    def test_merges_extra_boms(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        first = make_bom([make_component("requests", "2.32.5")])
        second = make_bom([make_component("flask", "3.0.0")])
        init_config(first, extra_boms=[second])
        result = json.loads((tmp_path / ".sbom-config.json").read_text(encoding="utf-8"))
        assert set(result["components"]) == {"pkg:pypi/requests", "pkg:pypi/flask"}

    def test_preserves_existing_settings(self, tmp_path, monkeypatch, write_json):
        write_json(".sbom-config.json", {"components": {"pkg:pypi/requests": {"vcs": "https://example.org/repo"}}})
        monkeypatch.chdir(tmp_path)
        init_config(make_bom([make_component("requests", "2.32.5"), make_component("flask", "3.0.0")]))
        result = json.loads((tmp_path / ".sbom-config.json").read_text(encoding="utf-8"))
        assert result["components"]["pkg:pypi/requests"]["vcs"] == "https://example.org/repo"
        assert "pkg:pypi/flask" in result["components"]


class TestMigrateConfig:
    def test_merges_three_legacy_files(self, tmp_path, monkeypatch, write_json):
        write_json(".purl_to_vcs.json", {"pkg:pypi/requests": "https://github.com/psf/requests"})
        write_json(".purl_to_gost.json", {"GOST:attack_surface": {"pkg:pypi/requests": "yes"}})
        write_json(".purl_exclude.json", ["pkg:npm/left-pad"])
        monkeypatch.chdir(tmp_path)

        migrate_config()

        result = json.loads((tmp_path / ".sbom-config.json").read_text(encoding="utf-8"))
        assert result["components"]["pkg:pypi/requests"]["vcs"] == "https://github.com/psf/requests"
        assert result["components"]["pkg:pypi/requests"]["attack_surface"] == "yes"
        assert result["components"]["pkg:npm/left-pad"]["exclude"] is True


class TestSourceLangs:
    @pytest.mark.parametrize(
        ("purl", "expected"),
        [
            ("pkg:pypi/requests@2.32.5", "Python"),
            ("pkg:npm/lodash@4.17.21", "JavaScript"),
            ("pkg:npm/%40babel/runtime@7.9.0", "JavaScript"),
            ("pkg:maven/org.slf4j/slf4j-api@2.0.9", "Java"),
            ("pkg:cargo/serde@1.0.0", "Rust"),
            ("pkg:golang/github.com/gin-gonic/gin@1.9.1", "Go"),
            ("pkg:gem/rails@7.1.0", "Ruby"),
            ("pkg:nuget/Newtonsoft.Json@13.0.3", "C#"),
            ("pkg:composer/symfony/console@6.4.0", "PHP"),
        ],
    )
    def test_language_guessed_from_ecosystem(self, purl, expected):
        assert guess_source_langs(purl) == expected

    @pytest.mark.parametrize(
        "purl",
        [
            "pkg:deb/debian/curl@7.88.1",
            "pkg:rpm/fedora/curl@8.0.1",
            "pkg:generic/internal-lib@1.0",
            "не-purl",
            "",
        ],
    )
    def test_language_not_guessed_when_ambiguous(self, purl):
        """Для дистрибутивных пакетов язык не выводится — врать в документе для регулятора нельзя."""
        assert guess_source_langs(purl) == ""

    def test_value_from_config_used(self):
        cfg = {"components": {"pkg:pypi/cryptography": {"source_langs": "Python"}}}
        comp = make_component("cryptography", "42.0.0")
        apply_config_to_component(comp, cfg)
        assert _langs_of(comp) == ["Python"]

    def test_each_language_becomes_separate_property(self):
        """ФСТЭК требует отдельное свойство на каждый язык, а не список через запятую."""
        cfg = {"components": {"pkg:pypi/cryptography": {"source_langs": ["Python", "C", "Rust"]}}}
        comp = make_component("cryptography", "42.0.0")
        apply_config_to_component(comp, cfg)
        assert _langs_of(comp) == ["Python", "C", "Rust"]
        assert [p["name"] for p in comp["properties"]].count("GOST:source_langs") == 3

    def test_comma_separated_string_split_into_properties(self):
        """Строка с запятыми — привычная запись; раскладывается на отдельные свойства."""
        cfg = {"components": {"pkg:pypi/pillow": {"source_langs": "Python, C"}}}
        comp = make_component("pillow", "10.0.0")
        apply_config_to_component(comp, cfg)
        assert _langs_of(comp) == ["Python", "C"]

    def test_config_replaces_all_previous_languages(self):
        comp = make_component(
            "pillow",
            "10.0.0",
            properties=[
                {"name": "GOST:source_langs", "value": "устарело"},
                {"name": "GOST:source_langs", "value": "тоже устарело"},
            ],
        )
        apply_config_to_component(comp, {"components": {"pkg:pypi/pillow": {"source_langs": ["Python", "C"]}}})
        assert _langs_of(comp) == ["Python", "C"]

    def test_guessed_when_config_silent(self):
        comp = make_component("requests", "2.32.5")
        apply_config_to_component(comp, {"defaults": {}})
        assert _langs_of(comp) == ["Python"]

    def test_config_wins_over_guess(self):
        cfg = {"components": {"pkg:pypi/pillow": {"source_langs": "C"}}}
        comp = make_component("pillow", "10.0.0")
        apply_config_to_component(comp, cfg)
        assert _langs_of(comp) == ["C"]

    def test_defaults_used_only_where_guess_fails(self):
        """defaults закрывает deb/rpm, но не подменяет язык, выведенный из экосистемы."""
        cfg = {"defaults": {"source_langs": "C"}}
        deb = make_component("curl", "7.88.1", purl="pkg:deb/debian/curl@7.88.1")
        npm = make_component("lodash", "4.17.21", purl="pkg:npm/lodash@4.17.21")
        apply_config_to_component(deb, cfg)
        apply_config_to_component(npm, cfg)
        assert _langs_of(deb) == ["C"]
        assert _langs_of(npm) == ["JavaScript"]

    def test_existing_value_not_overwritten_by_guess(self):
        comp = make_component("requests", "2.32.5", properties=[{"name": "GOST:source_langs", "value": "Python, Rust"}])
        apply_config_to_component(comp, {})
        props = {p["name"]: p["value"] for p in comp["properties"]}
        assert props["GOST:source_langs"] == "Python, Rust"

    def test_explicit_config_overwrites_existing_value(self):
        cfg = {"components": {"pkg:pypi/requests": {"source_langs": "Python"}}}
        comp = make_component("requests", "2.32.5", properties=[{"name": "GOST:source_langs", "value": "устарело"}])
        apply_config_to_component(comp, cfg)
        props = {p["name"]: p["value"] for p in comp["properties"]}
        assert props["GOST:source_langs"] == "Python"

    def test_nothing_written_when_unknown(self):
        comp = make_component("curl", "7.88.1", purl="pkg:deb/debian/curl@7.88.1")
        apply_config_to_component(comp, {})
        assert all(p["name"] != "GOST:source_langs" for p in comp.get("properties", []))

    def test_init_config_fills_guessed_language(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        bom = make_bom(
            [
                make_component("requests", "2.32.5"),
                make_component("lodash", "4.17.21", purl="pkg:npm/lodash@4.17.21"),
                make_component("curl", "7.88.1", purl="pkg:deb/debian/curl@7.88.1"),
            ]
        )
        init_config(bom)
        components = json.loads((tmp_path / ".sbom-config.json").read_text(encoding="utf-8"))["components"]
        assert components["pkg:pypi/requests"]["source_langs"] == ["Python"]
        assert components["pkg:npm/lodash"]["source_langs"] == ["JavaScript"]
        assert "source_langs" not in components["pkg:deb/debian/curl"]

    def test_init_config_keeps_manual_language(self, tmp_path, monkeypatch, write_json):
        write_json(".sbom-config.json", {"components": {"pkg:pypi/requests": {"source_langs": ["Python", "C"]}}})
        monkeypatch.chdir(tmp_path)
        init_config(make_bom([make_component("requests", "2.32.5")]))
        components = json.loads((tmp_path / ".sbom-config.json").read_text(encoding="utf-8"))["components"]
        assert components["pkg:pypi/requests"]["source_langs"] == ["Python", "C"]
