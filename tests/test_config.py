# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

"""Тесты единого конфига .sbom-config.json."""

import json

import pytest

from efs.config import _purl_without_version as config_purl_without_version
from efs.config import (
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
        result = json.loads((tmp_path / ".efs-config.json").read_text(encoding="utf-8"))
        assert set(result["components"]) == {"pkg:pypi/requests", "pkg:pypi/urllib3"}

    def test_merges_extra_boms(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        first = make_bom([make_component("requests", "2.32.5")])
        second = make_bom([make_component("flask", "3.0.0")])
        init_config(first, extra_boms=[second])
        result = json.loads((tmp_path / ".efs-config.json").read_text(encoding="utf-8"))
        assert set(result["components"]) == {"pkg:pypi/requests", "pkg:pypi/flask"}

    def test_preserves_existing_settings(self, tmp_path, monkeypatch, write_json):
        write_json(".efs-config.json", {"components": {"pkg:pypi/requests": {"vcs": "https://example.org/repo"}}})
        monkeypatch.chdir(tmp_path)
        init_config(make_bom([make_component("requests", "2.32.5"), make_component("flask", "3.0.0")]))
        result = json.loads((tmp_path / ".efs-config.json").read_text(encoding="utf-8"))
        assert result["components"]["pkg:pypi/requests"]["vcs"] == "https://example.org/repo"
        assert "pkg:pypi/flask" in result["components"]


class TestMigrateConfig:
    def test_merges_three_legacy_files(self, tmp_path, monkeypatch, write_json):
        write_json(".purl_to_vcs.json", {"pkg:pypi/requests": "https://github.com/psf/requests"})
        write_json(".purl_to_gost.json", {"GOST:attack_surface": {"pkg:pypi/requests": "yes"}})
        write_json(".purl_exclude.json", ["pkg:npm/left-pad"])
        monkeypatch.chdir(tmp_path)

        migrate_config()

        result = json.loads((tmp_path / ".efs-config.json").read_text(encoding="utf-8"))
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
        components = json.loads((tmp_path / ".efs-config.json").read_text(encoding="utf-8"))["components"]
        assert components["pkg:pypi/requests"]["source_langs"] == ["Python"]
        assert components["pkg:npm/lodash"]["source_langs"] == ["JavaScript"]
        assert "source_langs" not in components["pkg:deb/debian/curl"]

    def test_init_config_keeps_manual_language(self, tmp_path, monkeypatch, write_json):
        write_json(".efs-config.json", {"components": {"pkg:pypi/requests": {"source_langs": ["Python", "C"]}}})
        monkeypatch.chdir(tmp_path)
        init_config(make_bom([make_component("requests", "2.32.5")]))
        components = json.loads((tmp_path / ".efs-config.json").read_text(encoding="utf-8"))["components"]
        assert components["pkg:pypi/requests"]["source_langs"] == ["Python", "C"]


class TestConfigFilename:
    def test_new_name_found_in_cwd(self, tmp_path, monkeypatch, write_json):
        write_json(".efs-config.json", {"components": {"pkg:pypi/x": {}}})
        monkeypatch.chdir(tmp_path)
        assert load_config() == {"components": {"pkg:pypi/x": {}}}

    def test_legacy_name_still_works(self, tmp_path, monkeypatch, write_json):
        """Проекты со старым .sbom-config.json продолжают работать."""
        write_json(".sbom-config.json", {"components": {"pkg:pypi/legacy": {}}})
        monkeypatch.chdir(tmp_path)
        assert load_config() == {"components": {"pkg:pypi/legacy": {}}}

    def test_new_name_wins_over_legacy(self, tmp_path, monkeypatch, write_json):
        write_json(".efs-config.json", {"components": {"pkg:pypi/new": {}}})
        write_json(".sbom-config.json", {"components": {"pkg:pypi/legacy": {}}})
        monkeypatch.chdir(tmp_path)
        assert load_config() == {"components": {"pkg:pypi/new": {}}}

    def test_init_writes_new_name(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        init_config(make_bom([make_component("requests", "2.32.5")]))
        assert (tmp_path / ".efs-config.json").is_file()

    def test_init_carries_legacy_settings_over(self, tmp_path, monkeypatch, write_json):
        write_json(".sbom-config.json", {"components": {"pkg:pypi/requests": {"attack_surface": "yes"}}})
        monkeypatch.chdir(tmp_path)
        init_config(make_bom([make_component("requests", "2.32.5")]))
        result = json.loads((tmp_path / ".efs-config.json").read_text(encoding="utf-8"))
        assert result["components"]["pkg:pypi/requests"]["attack_surface"] == "yes"


class TestPurlNormalization:
    """Нормализация purl в конфиге должна совпадать с той, что применяет постобработка."""

    @pytest.mark.parametrize(
        ("purl", "expected"),
        [
            ("pkg:pypi/requests@2.32.5", "pkg:pypi/requests"),
            ("pkg:npm/@babel/runtime@7.9.0", "pkg:npm/@babel/runtime"),
            ("pkg:npm/@superset-ui/core@0.20.4", "pkg:npm/@superset-ui/core"),
            ("pkg:npm/%40babel/runtime@7.9.0", "pkg:npm/%40babel/runtime"),
            ("pkg:golang/github.com/gin-gonic/gin@v1.9.1", "pkg:golang/github.com/gin-gonic/gin"),
            ("pkg:npm/ajv@8.20.0?arch=x64", "pkg:npm/ajv"),
            ("pkg:npm/@2toad/profanity@2.0.0", "pkg:npm/@2toad/profanity"),
        ],
    )
    def test_version_stripped_without_losing_scope(self, purl, expected):
        assert config_purl_without_version(purl) == expected

    def test_scoped_packages_do_not_share_one_key(self):
        """Схлопывание скоупа в pkg:npm/ применило бы настройки одного пакета ко всем npm."""
        first = config_purl_without_version("pkg:npm/@superset-ui/core@0.20.4")
        second = config_purl_without_version("pkg:npm/@rtdv/plugin-chart-kepler@1.0.0")
        assert first != second
        assert first != "pkg:npm/"

    def test_lookup_finds_scoped_component(self):
        cfg = {"components": {"pkg:npm/@superset-ui/core": {"vcs": "https://github.com/apache/superset"}}}
        assert get_vcs(cfg, "pkg:npm/@superset-ui/core@0.20.4") == "https://github.com/apache/superset"

    def test_exclude_of_scoped_package_does_not_leak(self):
        cfg = {"components": {"pkg:npm/@superset-ui/core": {"exclude": True}}}
        assert is_excluded(cfg, "pkg:npm/@superset-ui/core@0.20.4") is True
        assert is_excluded(cfg, "pkg:npm/lodash@4.17.21") is False


class TestVersionSpecificEntries:
    """Форк конкретной версии: точечная запись должна побеждать общую."""

    def _config(self):
        return {
            "components": {
                "pkg:pypi/cryptography": {"vcs": "https://github.com/pyca/cryptography", "attack_surface": "no"},
                "pkg:pypi/cryptography@42.0.0": {
                    "vcs": "https://github.com/our-org/cryptography-fork",
                    "attack_surface": "yes",
                },
            }
        }

    def test_exact_version_wins_over_generic(self):
        assert get_vcs(self._config(), "pkg:pypi/cryptography@42.0.0").endswith("cryptography-fork")

    def test_other_version_uses_generic(self):
        assert get_vcs(self._config(), "pkg:pypi/cryptography@41.0.0").endswith("pyca/cryptography")

    def test_gost_prop_follows_same_priority(self):
        cfg = self._config()
        assert get_gost_prop(cfg, "pkg:pypi/cryptography@42.0.0", "GOST:attack_surface") == "yes"
        assert get_gost_prop(cfg, "pkg:pypi/cryptography@41.0.0", "GOST:attack_surface") == "no"

    def test_init_keeps_version_specific_entry(self, tmp_path, monkeypatch, write_json):
        """config init не должен стирать ручную настройку для конкретной версии."""
        write_json(".efs-config.json", self._config())
        monkeypatch.chdir(tmp_path)
        init_config(make_bom([make_component("cryptography", "42.0.0")]))
        components = json.loads((tmp_path / ".efs-config.json").read_text(encoding="utf-8"))["components"]
        assert "pkg:pypi/cryptography@42.0.0" in components
        assert components["pkg:pypi/cryptography@42.0.0"]["vcs"].endswith("cryptography-fork")

    def test_init_removes_components_absent_from_sbom(self, tmp_path, monkeypatch, write_json):
        write_json(".efs-config.json", {"components": {"pkg:npm/исчезнувший": {"vcs": "https://x"}}})
        monkeypatch.chdir(tmp_path)
        init_config(make_bom([make_component("requests", "2.32.5")]))
        components = json.loads((tmp_path / ".efs-config.json").read_text(encoding="utf-8"))["components"]
        assert "pkg:npm/исчезнувший" not in components


class TestDefaultsApplication:
    def test_defaults_reach_components_absent_from_config(self):
        """«Хвост» зависимостей без своих записей должен получать значения из defaults."""
        cfg = {"defaults": {"attack_surface": "yes", "provided_by": "ООО Умолчание"}}
        comp = make_component("requests", "2.32.5")
        apply_config_to_component(comp, cfg)
        props = {p["name"]: p["value"] for p in comp["properties"]}
        assert props["GOST:attack_surface"] == "yes"
        assert props["GOST:provided_by"] == "ООО Умолчание"

    def test_empty_config_adds_no_gost_properties(self):
        """Без конфига и defaults ГОСТ-значения не выдумываются — их проставит постобработка."""
        comp = make_component("curl", "7.88.1", purl="pkg:deb/debian/curl@7.88.1")
        apply_config_to_component(comp, {})
        names = {p["name"] for p in comp.get("properties", [])}
        assert "GOST:attack_surface" not in names

    def test_explicit_empty_value_is_not_overridden_by_defaults(self):
        cfg = {"defaults": {"provided_by": "ООО Умолчание"}, "components": {"pkg:pypi/requests": {"provided_by": ""}}}
        assert get_gost_prop(cfg, "pkg:pypi/requests@2.32.5", "GOST:provided_by") == ""

    def test_provided_by_default_argument_applied(self):
        """Аргумент --provided-by доходит до компонента."""
        comp = make_component("requests", "2.32.5")
        apply_config_to_component(comp, {"components": {"pkg:pypi/requests": {}}}, provided_by_default="ООО Поставщик")
        props = {p["name"]: p["value"] for p in comp["properties"]}
        assert props["GOST:provided_by"] == "ООО Поставщик"


class TestGostValueValidation:
    @pytest.mark.parametrize("prop", ["attack_surface", "security_function"])
    def test_invalid_value_replaced_for_both_props(self, prop):
        cfg = {"components": {"pkg:pypi/x": {prop: "ДА"}}}
        comp = make_component("x", "1.0")
        apply_config_to_component(comp, cfg)
        props = {p["name"]: p["value"] for p in comp["properties"]}
        assert props[f"GOST:{prop}"] == "no"

    @pytest.mark.parametrize("prop", ["attack_surface", "security_function"])
    def test_indirect_accepted_from_config(self, prop):
        cfg = {"components": {"pkg:pypi/x": {prop: "indirect"}}}
        comp = make_component("x", "1.0")
        apply_config_to_component(comp, cfg)
        props = {p["name"]: p["value"] for p in comp["properties"]}
        assert props[f"GOST:{prop}"] == "indirect"

    def test_default_no_for_both_props(self):
        for name in ("GOST:attack_surface", "GOST:security_function"):
            assert get_gost_prop({}, "pkg:pypi/x@1.0", name) == "no"


class TestMigrationSafety:
    def test_existing_vcs_not_overwritten(self, tmp_path, monkeypatch, write_json):
        """Миграция не должна затирать выверенные вручную ссылки старым файлом."""
        write_json(".efs-config.json", {"components": {"pkg:pypi/requests": {"vcs": "https://наш/репозиторий"}}})
        write_json(".purl_to_vcs.json", {"pkg:pypi/requests": "https://старый/мусор"})
        monkeypatch.chdir(tmp_path)
        migrate_config()
        components = json.loads((tmp_path / ".efs-config.json").read_text(encoding="utf-8"))["components"]
        assert components["pkg:pypi/requests"]["vcs"] == "https://наш/репозиторий"

    def test_default_gost_values_not_migrated(self, tmp_path, monkeypatch, write_json):
        """Значения по умолчанию не переносятся — конфиг остаётся компактным."""
        write_json(".purl_to_gost.json", {"GOST:attack_surface": {"pkg:pypi/a": "no", "pkg:pypi/b": "yes"}})
        monkeypatch.chdir(tmp_path)
        migrate_config()
        components = json.loads((tmp_path / ".efs-config.json").read_text(encoding="utf-8"))["components"]
        assert "pkg:pypi/b" in components
        assert "pkg:pypi/a" not in components


class TestLanguageTableCompleteness:
    @pytest.mark.parametrize(
        ("purl", "expected"),
        [
            ("pkg:gradle/org.example/lib@1.0", "Java"),
            ("pkg:conan/zlib@1.3", "C++"),
            ("pkg:swift/apple/swift-log@1.5", "Swift"),
            ("pkg:cran/ggplot2@3.4", "R"),
            ("pkg:hex/phoenix@1.7", "Elixir"),
            ("pkg:pub/http@1.2", "Dart"),
            ("pkg:cocoapods/AFNetworking@4.0", "Objective-C"),
        ],
    )
    def test_every_declared_ecosystem_resolves(self, purl, expected):
        assert guess_source_langs(purl) == expected

    @pytest.mark.parametrize("purl", ["pkg:PyPI/requests@2.32.5", "pkg:NuGet/Newtonsoft.Json@13.0.3"])
    def test_purl_type_is_case_insensitive(self, purl):
        """Спецификация purl допускает любой регистр типа, и сканеры этим пользуются."""
        assert guess_source_langs(purl) != ""

    @pytest.mark.parametrize("value", ["urn:pypi/x", "0123npm/x", "npm/x", "простая строка"])
    def test_language_not_invented_for_non_purl(self, value):
        """Строка, не являющаяся purl, не должна давать язык — в документе он был бы выдуманным."""
        assert guess_source_langs(value) == ""


class TestConfigKeyMatching:
    def test_key_case_preserved(self):
        """Ключи NuGet и Maven регистрозависимы — приводить их к нижнему регистру нельзя."""
        cfg = {"components": {"pkg:nuget/Newtonsoft.Json": {"vcs": "https://github.com/JamesNK/Newtonsoft.Json"}}}
        assert get_vcs(cfg, "pkg:nuget/Newtonsoft.Json@13.0.3").endswith("Newtonsoft.Json")

    @pytest.mark.parametrize("value", ["yes", 1, "true"])
    def test_unknown_exclude_value_means_cascade(self, value):
        """Любое непустое значение, кроме "direct", означает обычное исключение."""
        cfg = {"components": {"pkg:npm/x": {"exclude": value}}}
        assert is_excluded(cfg, "pkg:npm/x@1.0") is True

    @pytest.mark.parametrize("value", [False, 0, "", None])
    def test_falsy_exclude_means_kept(self, value):
        cfg = {"components": {"pkg:npm/x": {"exclude": value}}}
        assert is_excluded(cfg, "pkg:npm/x@1.0") is False


class TestConfigGeneration:
    def test_defaults_start_from_no(self, tmp_path, monkeypatch):
        """Свежий конфиг не должен объявлять всё поверхностью атаки."""
        monkeypatch.chdir(tmp_path)
        init_config(make_bom([make_component("requests", "2.32.5")]))
        defaults = json.loads((tmp_path / ".efs-config.json").read_text(encoding="utf-8"))["defaults"]
        assert defaults["attack_surface"] == "no"
        assert defaults["security_function"] == "no"

    def test_nested_components_included(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        inner = make_component("nested", "2.0", purl="pkg:pypi/nested@2.0")
        outer = make_component("parent", "1.0", purl="pkg:pypi/parent@1.0")
        outer["components"] = [inner]
        init_config(make_bom([outer]))
        components = json.loads((tmp_path / ".efs-config.json").read_text(encoding="utf-8"))["components"]
        assert {"pkg:pypi/parent", "pkg:pypi/nested"} <= set(components)


class TestLegacyExportKeys:
    def test_version_specific_key_preserved(self):
        """Ключ с версией не должен схлопываться: vcs форка применился бы ко всем версиям."""
        cfg = {"components": {"pkg:pypi/cryptography@42.0.0": {"vcs": "https://github.com/our-org/fork"}}}
        mapping = config_to_purl_to_vcs(cfg)
        assert "pkg:pypi/cryptography@42.0.0" in mapping
        assert "pkg:pypi/cryptography" not in mapping


class TestMigrationCleanup:
    def test_empty_entries_not_created(self, tmp_path, monkeypatch, write_json):
        write_json(".purl_to_gost.json", {"GOST:attack_surface": {"pkg:pypi/a": "no"}})
        monkeypatch.chdir(tmp_path)
        migrate_config()
        components = json.loads((tmp_path / ".efs-config.json").read_text(encoding="utf-8"))["components"]
        assert components == {}
