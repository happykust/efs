# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

"""Тесты постобработки SBOM: purl-матчинг, исключения, очистка полей, metadata."""

import pytest

from efs.postprocess import (
    COMPONENT_STRIP_FIELDS,
    _exclude_direct,
    _purl_matches_exclude,
    _purl_without_version,
    _remove_manifest_components,
    _split_exclude,
    ensure_metadata,
    exclude_components,
    strip_component,
)

from .conftest import make_bom, make_component


class TestPurlWithoutVersion:
    @pytest.mark.parametrize(
        ("purl", "expected"),
        [
            ("pkg:pypi/pytest@8.0.0", "pkg:pypi/pytest"),
            ("pkg:pypi/pytest", "pkg:pypi/pytest"),
            ("pkg:npm/@babel/runtime@7.9.0", "pkg:npm/@babel/runtime"),
            ("pkg:npm/color-name%401.1.3", "pkg:npm/color-name"),
            ("pkg:npm/%40babel/runtime@7.9.0", "pkg:npm/%40babel/runtime"),
            ("pkg:npm/ajv@8.20.0?arch=x64", "pkg:npm/ajv"),
            ("pkg:deb/debian/curl@7.88.1?distro=bookworm#subpath", "pkg:deb/debian/curl"),
        ],
    )
    def test_strips_only_version(self, purl, expected):
        assert _purl_without_version(purl) == expected

    def test_nested_dependency_path_kept(self):
        """Для вложенных зависимостей trivy пишет в purl весь путь."""
        assert _purl_without_version("pkg:npm/@babel/highlight/chalk@chalk@2.4.2") == (
            "pkg:npm/@babel/highlight/chalk@chalk"
        )


class TestExcludeMatching:
    def test_bare_key_matches_any_version(self):
        exclude = _split_exclude(["pkg:npm/left-pad"])
        assert _purl_matches_exclude("pkg:npm/left-pad@1.3.0", exclude) is True
        assert _purl_matches_exclude("pkg:npm/left-pad@2.0.0", exclude) is True

    def test_versioned_key_matches_only_that_version(self):
        exclude = _split_exclude(["pkg:npm/ajv@6.12.6"])
        assert _purl_matches_exclude("pkg:npm/ajv@6.12.6", exclude) is True
        assert _purl_matches_exclude("pkg:npm/ajv@8.20.0", exclude) is False

    def test_encoded_scope_matches_plain_scope(self):
        exclude = _split_exclude(["pkg:npm/@babel/runtime"])
        assert _purl_matches_exclude("pkg:npm/%40babel/runtime@7.9.0", exclude) is True

    def test_unrelated_purl_not_matched(self):
        exclude = _split_exclude(["pkg:npm/left-pad"])
        assert _purl_matches_exclude("pkg:npm/right-pad@1.0.0", exclude) is False


class TestExcludeComponents:
    def test_removes_matching_component(self):
        bom = make_bom([make_component("left-pad", "1.3.0", purl="pkg:npm/left-pad@1.3.0")])
        removed = exclude_components(bom, ["pkg:npm/left-pad"])
        assert removed == 1
        assert bom["components"] == []

    def test_keeps_other_versions_for_versioned_key(self):
        bom = make_bom(
            [
                make_component("ajv", "6.12.6", purl="pkg:npm/ajv@6.12.6"),
                make_component("ajv", "8.20.0", purl="pkg:npm/ajv@8.20.0"),
            ]
        )
        exclude_components(bom, ["pkg:npm/ajv@6.12.6"])
        assert [c["version"] for c in bom["components"]] == ["8.20.0"]

    def test_cascade_removes_exclusive_transitive_dependency(self):
        """Зависимость, которую держал только исключённый компонент, удаляется вместе с ним."""
        bom = make_bom(
            [
                make_component("eslint", "8.0.0", purl="pkg:npm/eslint@8.0.0"),
                make_component("espree", "9.0.0", purl="pkg:npm/espree@9.0.0"),
                make_component("lodash", "4.17.21", purl="pkg:npm/lodash@4.17.21"),
            ],
            dependencies=[
                {"ref": "pkg:npm/eslint@8.0.0", "dependsOn": ["pkg:npm/espree@9.0.0"]},
                {"ref": "pkg:npm/espree@9.0.0", "dependsOn": []},
                {"ref": "pkg:npm/lodash@4.17.21", "dependsOn": []},
            ],
        )
        removed = exclude_components(bom, ["pkg:npm/eslint"])
        assert removed == 2
        names = sorted(c["name"] for c in bom["components"])
        assert names == ["lodash"]

    def test_cascade_keeps_shared_dependency(self):
        """Зависимость, нужная и не исключённому компоненту, остаётся."""
        bom = make_bom(
            [
                make_component("eslint", "8.0.0", purl="pkg:npm/eslint@8.0.0"),
                make_component("app-lib", "1.0.0", purl="pkg:npm/app-lib@1.0.0"),
                make_component("lodash", "4.17.21", purl="pkg:npm/lodash@4.17.21"),
            ],
            dependencies=[
                {"ref": "pkg:npm/eslint@8.0.0", "dependsOn": ["pkg:npm/lodash@4.17.21"]},
                {"ref": "pkg:npm/app-lib@1.0.0", "dependsOn": ["pkg:npm/lodash@4.17.21"]},
                {"ref": "pkg:npm/lodash@4.17.21", "dependsOn": []},
            ],
        )
        exclude_components(bom, ["pkg:npm/eslint"])
        names = sorted(c["name"] for c in bom["components"])
        assert names == ["app-lib", "lodash"]

    def test_orphaned_component_survives_cascade(self):
        """Компонент без входящих рёбер — верхнеуровневая зависимость, а не потомок исключённого.

        После удаления узлов-манифестов реальные prod-зависимости остаются
        «осиротевшими»; каскад не должен выносить их из SBOM.
        """
        bom = make_bom(
            [
                make_component("eslint", "8.0.0", purl="pkg:npm/eslint@8.0.0"),
                make_component("runtime-lib", "1.0.0", purl="pkg:npm/runtime-lib@1.0.0"),
            ],
            dependencies=[
                {"ref": "pkg:npm/eslint@8.0.0", "dependsOn": []},
                {"ref": "pkg:npm/runtime-lib@1.0.0", "dependsOn": []},
            ],
        )
        exclude_components(bom, ["pkg:npm/eslint"])
        assert [c["name"] for c in bom["components"]] == ["runtime-lib"]

    def test_cascade_stops_at_components_nobody_excluded(self):
        """Каскад снимает лишь то, что держал только исключённый компонент.

        Внук остаётся: его родитель под exclude не помечен, значит решения по нему
        никто не принимал, а сам компонент по-прежнему поставляется.
        """
        bom = make_bom(
            [
                make_component("eslint", "8.0.0", purl="pkg:npm/eslint@8.0.0"),
                make_component("espree", "9.0.0", purl="pkg:npm/espree@9.0.0"),
                make_component("acorn", "8.11.0", purl="pkg:npm/acorn@8.11.0"),
            ],
            dependencies=[
                {"ref": "pkg:npm/eslint@8.0.0", "dependsOn": ["pkg:npm/espree@9.0.0"]},
                {"ref": "pkg:npm/espree@9.0.0", "dependsOn": ["pkg:npm/acorn@8.11.0"]},
                {"ref": "pkg:npm/acorn@8.11.0", "dependsOn": []},
            ],
        )
        exclude_components(bom, ["pkg:npm/eslint"])
        assert [c["name"] for c in bom["components"]] == ["acorn"]

    def test_nothing_to_exclude(self):
        bom = make_bom([make_component("requests", "2.32.5")])
        assert exclude_components(bom, ["pkg:npm/absent"]) == 0
        assert len(bom["components"]) == 1


class TestExcludeDirect:
    def test_removes_component_but_keeps_its_dependency(self):
        bom = make_bom(
            [
                make_component("our-module", "1.0.0", purl="pkg:pypi/our-module@1.0.0"),
                make_component("requests", "2.32.5", purl="pkg:pypi/requests@2.32.5"),
            ],
            dependencies=[
                {"ref": "pkg:pypi/our-module@1.0.0", "dependsOn": ["pkg:pypi/requests@2.32.5"]},
                {"ref": "pkg:pypi/requests@2.32.5", "dependsOn": []},
            ],
        )
        removed = _exclude_direct(bom, ["pkg:pypi/our-module"])
        assert removed == 1
        assert [c["name"] for c in bom["components"]] == ["requests"]

    def test_drops_dangling_references(self):
        bom = make_bom(
            [
                make_component("our-module", "1.0.0", purl="pkg:pypi/our-module@1.0.0"),
                make_component("requests", "2.32.5", purl="pkg:pypi/requests@2.32.5"),
            ],
            dependencies=[
                {"ref": "pkg:pypi/requests@2.32.5", "dependsOn": ["pkg:pypi/our-module@1.0.0"]},
            ],
        )
        _exclude_direct(bom, ["pkg:pypi/our-module"])
        assert bom["dependencies"] == [{"ref": "pkg:pypi/requests@2.32.5", "dependsOn": []}]


class TestRemoveManifestComponents:
    def test_removes_application_without_purl(self):
        bom = make_bom(
            [
                {"type": "application", "name": "uv.lock", "bom-ref": "manifest-1"},
                make_component("requests", "2.32.5"),
            ],
            dependencies=[
                {"ref": "manifest-1", "dependsOn": ["pkg:pypi/requests@2.32.5"]},
                {"ref": "pkg:pypi/requests@2.32.5", "dependsOn": []},
            ],
        )
        removed = _remove_manifest_components(bom)
        assert removed == 1
        assert [c["name"] for c in bom["components"]] == ["requests"]
        assert [d["ref"] for d in bom["dependencies"]] == ["pkg:pypi/requests@2.32.5"]

    def test_keeps_application_with_purl(self):
        bom = make_bom([make_component("app", "1.0.0", purl="pkg:generic/app@1.0.0", type="application")])
        assert _remove_manifest_components(bom) == 0


class TestStripComponent:
    def test_drops_optional_fields(self):
        comp = make_component("requests", "2.32.5", description="HTTP for humans", scope="required", tags=["http"])
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no")
        for field in ("description", "scope", "tags"):
            assert field not in comp

    def test_keeps_only_gost_properties(self):
        comp = make_component(
            "requests",
            "2.32.5",
            properties=[
                {"name": "GOST:source_langs", "value": "Python"},
                {"name": "cdx:npm:package:path", "value": "node_modules/x"},
            ],
        )
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no")
        assert [p["name"] for p in comp["properties"] if p["name"] == "cdx:npm:package:path"] == []
        assert any(p["name"] == "GOST:source_langs" for p in comp["properties"])

    def test_adds_default_gost_properties(self):
        comp = make_component("requests", "2.32.5")
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no")
        props = {p["name"]: p["value"] for p in comp["properties"]}
        assert props["GOST:attack_surface"] == "no"
        assert props["GOST:security_function"] == "no"

    def test_adds_todo_vcs_when_unknown(self):
        comp = make_component("requests", "2.32.5")
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no")
        assert comp["externalReferences"] == [{"type": "vcs", "url": "TODO"}]

    def test_uses_purl_to_vcs_mapping(self):
        comp = make_component("requests", "2.32.5")
        strip_component(
            comp,
            COMPONENT_STRIP_FIELDS,
            "no",
            purl_to_vcs={"pkg:pypi/requests": "https://github.com/psf/requests"},
        )
        assert comp["externalReferences"][0]["url"] == "https://github.com/psf/requests"

    def test_provided_by_drops_placeholder_vcs(self):
        """Для компонента с известным поставщиком VCS-ссылка не требуется."""
        comp = make_component("internal-lib", "1.0.0", externalReferences=[{"type": "vcs", "url": "TODO"}])
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no", provided_by="ООО Поставщик")
        assert "externalReferences" not in comp

    def test_missing_version_filled(self):
        comp = {"type": "library", "name": "x", "purl": "pkg:pypi/x"}
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no")
        assert comp["version"] == "unknown"

    def test_recurses_into_nested_components(self):
        comp = make_component("outer", "1.0.0", components=[make_component("inner", "2.0.0", description="drop me")])
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no")
        assert "description" not in comp["components"][0]


class TestEnsureMetadata:
    def test_cli_arguments_win(self):
        bom = make_bom()
        ensure_metadata(bom, "Продукт", "2.0", "ООО Изготовитель")
        mc = bom["metadata"]["component"]
        assert mc["name"] == "Продукт"
        assert mc["version"] == "2.0"
        assert mc["manufacturer"]["name"] == "ООО Изготовитель"

    def test_falls_back_to_config_metadata(self):
        bom = make_bom()
        bom["metadata"]["component"].pop("name")
        bom["metadata"]["component"].pop("version")
        config = {"metadata": {"name": "Из конфига", "version": "3.0", "manufacturer": "ООО Конфиг"}}
        ensure_metadata(bom, None, None, None, config=config)
        mc = bom["metadata"]["component"]
        assert mc["name"] == "Из конфига"
        assert mc["version"] == "3.0"
        assert mc["manufacturer"] == {"name": "ООО Конфиг"}

    def test_todo_placeholders_when_nothing_given(self):
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}
        ensure_metadata(bom, None, None, None)
        mc = bom["metadata"]["component"]
        assert mc["name"] == "TODO"
        assert mc["version"] == "TODO"
        assert mc["manufacturer"]["name"] == "TODO"

    def test_removes_noise_fields(self):
        bom = make_bom()
        bom["metadata"]["component"].update(
            {"bom-ref": "root", "purl": "pkg:generic/app", "description": "x", "components": []}
        )
        ensure_metadata(bom, "Продукт", "1.0", "ООО")
        mc = bom["metadata"]["component"]
        for field in ("bom-ref", "purl", "description", "components"):
            assert field not in mc

    def test_pedigree_from_config(self):
        bom = make_bom()
        config = {"metadata": {"pedigree": {"notes": "Собственная сборка"}}}
        ensure_metadata(bom, "Продукт", "1.0", "ООО", config=config)
        assert bom["metadata"]["component"]["pedigree"] == {"notes": "Собственная сборка"}


class TestSourceLangsWhenStripping:
    def test_language_filled_without_config(self):
        """Язык следует из purl и не должен зависеть от наличия конфига."""
        comp = make_component("requests", "2.32.5")
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no")
        langs = [p["value"] for p in comp["properties"] if p["name"] == "GOST:source_langs"]
        assert langs == ["Python"]

    def test_language_not_invented_for_distro_packages(self):
        comp = make_component("curl", "7.88.1", purl="pkg:deb/debian/curl@7.88.1")
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no")
        assert all(p["name"] != "GOST:source_langs" for p in comp["properties"])

    def test_existing_language_preserved_without_config(self):
        comp = make_component("requests", "2.32.5", properties=[{"name": "GOST:source_langs", "value": "Python, Rust"}])
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no")
        langs = [p["value"] for p in comp["properties"] if p["name"] == "GOST:source_langs"]
        assert langs == ["Python, Rust"]


class TestContainerPurpose:
    def test_description_kept_for_containers(self):
        """Назначение образа берётся из description — постобработка не должна его стирать."""
        comp = make_component("app-image", "1.0", purl="pkg:oci/app@1.0", type="container")
        comp["description"] = "Образ прикладного сервиса"
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no")
        assert comp["description"] == "Образ прикладного сервиса"

    def test_description_still_dropped_for_libraries(self):
        comp = make_component("requests", "2.32.5", description="HTTP for humans")
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no")
        assert "description" not in comp


class TestCascadeKeepsLiveParents:
    def _bom(self):
        def comp(name):
            return make_component(name, "1.0", purl=f"pkg:npm/{name}@1.0")

        def ref(name):
            return f"pkg:npm/{name}@1.0"

        return make_bom(
            [comp(n) for n in ("our-plugin", "kepler", "deck-layers", "deck-core", "lodash")],
            dependencies=[
                {"ref": ref("our-plugin"), "dependsOn": [ref("kepler"), ref("deck-core")]},
                {"ref": ref("kepler"), "dependsOn": [ref("deck-layers")]},
                {"ref": ref("deck-layers"), "dependsOn": [ref("deck-core")]},
                {"ref": ref("deck-core"), "dependsOn": []},
                {"ref": ref("lodash"), "dependsOn": []},
            ],
        )

    def test_component_with_unexcluded_parent_survives(self):
        """У deck-core два родителя, исключён один — компонент поставляется и остаётся."""
        bom = self._bom()
        exclude_components(bom, ["pkg:npm/our-plugin"])
        assert "deck-core" in [c["name"] for c in bom["components"]]

    def test_only_child_of_excluded_removed(self):
        """kepler держал только исключённый плагин — его в поставке больше нет."""
        bom = self._bom()
        exclude_components(bom, ["pkg:npm/our-plugin"])
        names = [c["name"] for c in bom["components"]]
        assert "our-plugin" not in names
        assert "kepler" not in names

    def test_grandchild_of_excluded_survives(self):
        """deck-layers держал kepler, а он не помечен exclude — решение о нём не принималось."""
        bom = self._bom()
        exclude_components(bom, ["pkg:npm/our-plugin"])
        assert "deck-layers" in [c["name"] for c in bom["components"]]

    def test_unrelated_component_untouched(self):
        bom = self._bom()
        exclude_components(bom, ["pkg:npm/our-plugin"])
        assert "lodash" in [c["name"] for c in bom["components"]]
