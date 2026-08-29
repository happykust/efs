# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

import json

"""Тесты постобработки SBOM: purl-матчинг, исключения, очистка полей, metadata."""

from types import SimpleNamespace

import pytest

from efs import __version__
from efs.postprocess import (
    COMPONENT_STRIP_FIELDS,
    ROOT_STRIP_FIELDS,
    _exclude_direct,
    _purl_matches_exclude,
    _purl_without_version,
    _remove_manifest_components,
    _split_exclude,
    ensure_metadata,
    ensure_root,
    exclude_components,
    process_bom,
    run,
    strip_component,
    strip_root,
)

from .conftest import make_bom, make_component, postprocess_args


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


class TestDirectParentCountsAsKept:
    def _bom(self):
        def comp(name):
            return make_component(name, "1.0", purl=f"pkg:npm/{name}@1.0")

        def ref(name):
            return f"pkg:npm/{name}@1.0"

        return make_bom(
            [comp(n) for n in ("our-preset", "nomnom", "underscore", "lodash")],
            dependencies=[
                {"ref": ref("our-preset"), "dependsOn": [ref("underscore")]},
                {"ref": ref("nomnom"), "dependsOn": [ref("underscore")]},
                {"ref": ref("underscore"), "dependsOn": []},
                {"ref": ref("lodash"), "dependsOn": []},
            ],
        )

    def _run(self, bom):
        args = SimpleNamespace(
            input="",
            output="",
            app_name=None,
            app_version=None,
            manufacturer=None,
            gost_default="no",
            strip_only=False,
            keep_all_fields=False,
            provided_by=None,
            purl_to_vcs=None,
            purl_to_gost=None,
            purl_exclude=None,
            config=None,
            pretty=True,
        )
        return process_bom(
            bom,
            args,
            purl_exclude=["pkg:npm/nomnom"],
            purl_exclude_direct=["pkg:npm/our-preset"],
        )

    def test_dependency_of_direct_parent_survives_cascade(self):
        """underscore тянут наш пресет (direct) и nomnom (true) — direct-родитель оставлен, значит и он."""
        bom = self._run(self._bom())
        assert "underscore" in [c["name"] for c in bom["components"]]

    def test_both_excluded_components_removed(self):
        bom = self._run(self._bom())
        names = [c["name"] for c in bom["components"]]
        assert "our-preset" not in names
        assert "nomnom" not in names

    def test_unrelated_component_untouched(self):
        bom = self._run(self._bom())
        assert "lodash" in [c["name"] for c in bom["components"]]


class TestManifestEdgesMovedToRoot:
    def _bom(self):
        def comp(name):
            return make_component(name, "1.0", purl=f"pkg:npm/{name}@1.0")

        def ref(name):
            return f"pkg:npm/{name}@1.0"

        bom = make_bom(
            [
                {"bom-ref": "manifest-1", "type": "application", "name": "package-lock.json"},
                comp("storybook-builder"),
                comp("css-loader"),
            ],
            dependencies=[
                {"ref": "manifest-1", "dependsOn": [ref("css-loader"), ref("storybook-builder")]},
                {"ref": ref("storybook-builder"), "dependsOn": [ref("css-loader")]},
                {"ref": ref("css-loader"), "dependsOn": []},
            ],
        )
        bom["metadata"]["component"]["bom-ref"] = "root"
        bom["dependencies"].insert(0, {"ref": "root", "dependsOn": ["manifest-1"]})
        return bom

    def test_root_inherits_manifest_dependencies(self):
        """Манифест перечислял прямые зависимости продукта — после его удаления их держит корень."""
        bom = self._bom()
        _remove_manifest_components(bom)
        root_deps = next(d["dependsOn"] for d in bom["dependencies"] if d["ref"] == "root")
        assert sorted(root_deps) == ["pkg:npm/css-loader@1.0", "pkg:npm/storybook-builder@1.0"]

    def test_dependency_of_manifest_survives_cascade(self):
        """css-loader держали манифест и storybook: манифест удалён, но продукт пакет поставляет."""
        bom = self._bom()
        _remove_manifest_components(bom)
        exclude_components(bom, ["pkg:npm/storybook-builder"])
        assert "css-loader" in [c["name"] for c in bom["components"]]

    def test_manifest_itself_gone(self):
        bom = self._bom()
        _remove_manifest_components(bom)
        assert "package-lock.json" not in [c["name"] for c in bom["components"]]
        assert all(d["ref"] != "manifest-1" for d in bom["dependencies"])


class TestProcessBomAsWhole:
    """Проводка внутри process_bom: флаги и порядок шагов, а не отдельные функции."""

    def _component(self):
        return make_component(
            "requests",
            "2.32.5",
            description="HTTP for humans",
            scope="required",
            evidence={"identity": {"field": "purl"}},
        )

    def test_optional_fields_stripped_by_default(self):
        bom = process_bom(make_bom([self._component()]), postprocess_args())
        comp = bom["components"][0]
        for field in ("description", "scope", "evidence"):
            assert field not in comp, f"{field} должно вычищаться по умолчанию"

    def test_keep_all_fields_preserves_them(self):
        bom = process_bom(make_bom([self._component()]), postprocess_args(keep_all_fields=True))
        comp = bom["components"][0]
        assert comp["description"] == "HTTP for humans"
        assert comp["scope"] == "required"

    def test_gost_properties_added_for_every_component(self):
        bom = process_bom(make_bom([self._component(), make_component("flask", "3.0.0")]), postprocess_args())
        for comp in bom["components"]:
            names = {p["name"] for p in comp["properties"]}
            assert {"GOST:attack_surface", "GOST:security_function"} <= names

    def test_metadata_filled_from_arguments(self):
        bom = process_bom(
            make_bom([self._component()]),
            postprocess_args(app_name="Продукт", app_version="2.0", manufacturer="ООО Тест"),
        )
        meta = bom["metadata"]["component"]
        assert (meta["name"], meta["version"], meta["manufacturer"]["name"]) == ("Продукт", "2.0", "ООО Тест")

    def test_strip_only_leaves_metadata_alone(self):
        bom = make_bom([self._component()])
        bom["metadata"]["component"]["name"] = "Исходное"
        result = process_bom(bom, postprocess_args(strip_only=True, app_name="Новое"))
        assert result["metadata"]["component"]["name"] == "Исходное"


class TestProcessBomExcludeOrder:
    """Порядок шагов: манифесты → каскад → прямое исключение."""

    def _bom(self):
        def ref(name):
            return f"pkg:npm/{name}@1.0"

        bom = make_bom(
            [
                {"bom-ref": "manifest-1", "type": "application", "name": "package-lock.json"},
                make_component("storybook", "1.0", purl=ref("storybook")),
                make_component("css-loader", "1.0", purl=ref("css-loader")),
                make_component("our-module", "1.0", purl=ref("our-module")),
                make_component("underscore", "1.0", purl=ref("underscore")),
            ],
            dependencies=[
                {"ref": "root", "dependsOn": ["manifest-1"]},
                {"ref": "manifest-1", "dependsOn": [ref("css-loader"), ref("storybook")]},
                {"ref": ref("storybook"), "dependsOn": [ref("css-loader")]},
                {"ref": ref("our-module"), "dependsOn": [ref("underscore")]},
            ],
        )
        bom["metadata"]["component"]["bom-ref"] = "root"
        return bom

    def _run(self):
        return process_bom(
            self._bom(),
            postprocess_args(),
            purl_exclude=["pkg:npm/storybook"],
            purl_exclude_direct=["pkg:npm/our-module"],
        )

    def test_manifest_child_survives_cascade(self):
        """Зависимость манифеста держит продукт — каскад её не трогает."""
        assert "css-loader" in [c["name"] for c in self._run()["components"]]

    def test_direct_parent_does_not_trigger_cascade(self):
        """underscore тянет наш модуль с exclude=direct — он остаётся в перечне."""
        assert "underscore" in [c["name"] for c in self._run()["components"]]

    def test_excluded_components_gone(self):
        names = [c["name"] for c in self._run()["components"]]
        assert "storybook" not in names
        assert "our-module" not in names
        assert "package-lock.json" not in names

    def test_no_dangling_references(self):
        result = self._run()
        known = {c.get("bom-ref") for c in result["components"]} | {"root"}
        for entry in result.get("dependencies", []):
            assert entry["ref"] in known
            for dep in entry.get("dependsOn", []):
                assert dep in known


class TestGostPropertiesPrecision:
    """Значения ГОСТ-свойств попадают в документ регулятору — перепутать их нельзя."""

    def _component(self, properties=None):
        return make_component("requests", "2.32.5", properties=properties or [])

    def _props(self, comp):
        return {p["name"]: p["value"] for p in comp["properties"]}

    def test_mapping_values_not_swapped(self):
        """Поверхность атаки и функция безопасности берутся каждая из своей секции."""
        comp = self._component()
        mapping = {
            "GOST:attack_surface": {"pkg:pypi/requests@2.32.5": "yes"},
            "GOST:security_function": {"pkg:pypi/requests@2.32.5": "indirect"},
        }
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no", purl_to_gost=mapping)
        props = self._props(comp)
        assert props["GOST:attack_surface"] == "yes"
        assert props["GOST:security_function"] == "indirect"

    def test_indirect_value_preserved(self):
        """indirect — допустимый статус, его нельзя молча заменять на no."""
        comp = self._component(
            properties=[
                {"name": "GOST:attack_surface", "value": "indirect"},
                {"name": "GOST:security_function", "value": "indirect"},
            ]
        )
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no")
        props = self._props(comp)
        assert props["GOST:attack_surface"] == "indirect"
        assert props["GOST:security_function"] == "indirect"

    def test_duplicate_gost_properties_collapsed(self):
        comp = self._component(
            properties=[
                {"name": "GOST:attack_surface", "value": "yes"},
                {"name": "GOST:attack_surface", "value": "no"},
                {"name": "GOST:attack_surface", "value": "indirect"},
            ]
        )
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no")
        values = [p["value"] for p in comp["properties"] if p["name"] == "GOST:attack_surface"]
        assert values == ["yes"]

    def test_invalid_value_replaced_by_default(self):
        comp = self._component(properties=[{"name": "GOST:security_function", "value": "ДА"}])
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no")
        assert self._props(comp)["GOST:security_function"] == "no"

    def test_provided_by_not_duplicated(self):
        comp = self._component(properties=[{"name": "GOST:provided_by", "value": "ООО Старое"}])
        mapping = {"GOST:provided_by": {"pkg:pypi/requests@2.32.5": "ООО Новое"}}
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no", purl_to_gost=mapping)
        values = [p["value"] for p in comp["properties"] if p["name"] == "GOST:provided_by"]
        assert values == ["ООО Новое"]

    def test_blank_provided_by_does_not_replace_source(self):
        """Пустой поставщик — не сведения об источнике: компонент всё равно нуждается в ссылке."""
        comp = self._component(properties=[{"name": "GOST:provided_by", "value": ""}])
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no")
        assert any(r.get("type") == "vcs" for r in comp.get("externalReferences", []))

    def test_source_distribution_counts_as_source(self):
        """Архив исходного кода — законный источник, заглушку TODO дописывать не нужно."""
        comp = self._component()
        comp["externalReferences"] = [{"type": "source-distribution", "url": "https://example.org/x.tar.gz"}]
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no")
        urls = [r["url"] for r in comp["externalReferences"]]
        assert "TODO" not in urls

    def test_foreign_properties_dropped(self):
        comp = self._component(
            properties=[
                {"name": "GOSTX:поддельное", "value": "1"},
                {"name": "aquasecurity:trivy:PkgType", "value": "npm"},
            ]
        )
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no")
        names = {p["name"] for p in comp["properties"]}
        assert "GOSTX:поддельное" not in names
        assert "aquasecurity:trivy:PkgType" not in names


class TestMetadataPrecedence:
    def test_cli_wins_over_config(self):
        """--app-name должен перекрывать конфиг, иначе в титуле окажется чужое имя изделия."""
        bom = make_bom([])
        config = {"metadata": {"name": "Из конфига", "version": "9.9", "manufacturer": "ООО Конфиг"}}
        ensure_metadata(bom, "Из CLI", "1.0", "ООО CLI", config=config)
        meta = bom["metadata"]["component"]
        assert meta["name"] == "Из CLI"
        assert meta["version"] == "1.0"
        assert meta["manufacturer"]["name"] == "ООО CLI"

    def test_config_used_when_cli_silent(self):
        bom = make_bom([])
        bom["metadata"]["component"].pop("name")
        config = {"metadata": {"name": "Из конфига"}}
        ensure_metadata(bom, None, None, None, config=config)
        assert bom["metadata"]["component"]["name"] == "Из конфига"


class TestPurlVariants:
    @pytest.mark.parametrize(
        ("purl", "expected"),
        [
            ("pkg:golang/github.com/gin-gonic/gin@v1.9.1", "pkg:golang/github.com/gin-gonic/gin"),
            ("pkg:npm/@2toad/profanity@2.0.0", "pkg:npm/@2toad/profanity"),
            ("pkg:npm/@v8/tools@1.0.0", "pkg:npm/@v8/tools"),
            ("pkg:npm/ajv@8.20.0?arch=x64", "pkg:npm/ajv"),
            ("pkg:npm/ajv?arch=x64", "pkg:npm/ajv"),
            ("pkg:npm/chalk@2.4.2/ansi-styles@3.2.1", "pkg:npm/chalk@2.4.2/ansi-styles"),
            ("pkg:npm/@2toad/profanity", "pkg:npm/@2toad/profanity"),
            ("pkg:npm/@v8/tools", "pkg:npm/@v8/tools"),
        ],
    )
    def test_version_stripped_correctly(self, purl, expected):
        assert _purl_without_version(purl) == expected

    def test_encoded_scope_in_exclude_key_matches(self):
        """Ключ конфига может быть записан в закодированной форме."""
        bom = make_bom([make_component("runtime", "7.9.0", purl="pkg:npm/@babel/runtime@7.9.0")])
        assert exclude_components(bom, ["pkg:npm/%40babel/runtime"]) == 1

    def test_qualifier_does_not_break_exclude(self):
        bom = make_bom([make_component("ajv", "8.20.0", purl="pkg:npm/ajv@8.20.0?arch=x64")])
        assert exclude_components(bom, ["pkg:npm/ajv"]) == 1


class TestGostDeduplication:
    def _component(self, values):
        return make_component(
            "requests",
            "2.32.5",
            properties=[{"name": "GOST:attack_surface", "value": v} for v in values],
        )

    def test_three_duplicates_collapse_to_first_valid(self):
        comp = self._component(["yes", "indirect", "no"])
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no")
        values = [p["value"] for p in comp["properties"] if p["name"] == "GOST:attack_surface"]
        assert values == ["yes"]

    def test_second_property_of_other_kind_survives(self):
        comp = make_component(
            "requests",
            "2.32.5",
            properties=[
                {"name": "GOST:attack_surface", "value": "yes"},
                {"name": "GOST:attack_surface", "value": "no"},
                {"name": "GOST:security_function", "value": "indirect"},
            ],
        )
        strip_component(comp, COMPONENT_STRIP_FIELDS, "no")
        props = {p["name"]: p["value"] for p in comp["properties"]}
        assert props["GOST:attack_surface"] == "yes"
        assert props["GOST:security_function"] == "indirect"


class TestDocumentRoot:
    def test_version_normalised_to_integer(self):
        bom = {"version": "3"}
        ensure_root(bom)
        assert bom["version"] == 1

    def test_spec_version_is_16(self):
        bom = {}
        ensure_root(bom)
        assert bom["specVersion"] == "1.6"

    def test_non_empty_root_sections_kept(self):
        """Сведения об уязвимостях нельзя терять при очистке корня."""
        bom = make_bom([], vulnerabilities=[{"id": "CVE-2024-0001"}], services=[])
        strip_root(bom, ROOT_STRIP_FIELDS)
        assert bom["vulnerabilities"] == [{"id": "CVE-2024-0001"}]
        assert "services" not in bom


class TestNestedExclusion:
    def _bom(self):
        inner = make_component("вложенный", "1.0", purl="pkg:npm/inner@1.0")
        inner["bom-ref"] = "ref-inner"
        outer = make_component("внешний", "1.0", purl="pkg:npm/outer@1.0")
        outer["bom-ref"] = "ref-outer"
        outer["components"] = [inner]
        return make_bom([outer])

    def test_nested_component_excluded_by_purl(self):
        """bom-ref у cdxgen не совпадает с purl — исключение всё равно должно сработать."""
        bom = self._bom()
        assert exclude_components(bom, ["pkg:npm/inner"]) == 1
        assert bom["components"][0].get("components", []) == []

    def test_outer_component_survives(self):
        bom = self._bom()
        exclude_components(bom, ["pkg:npm/inner"])
        assert [c["name"] for c in bom["components"]] == ["внешний"]

    def test_nested_component_counted_in_config_autofill(self, tmp_path, monkeypatch, write_json):
        write_json(".efs-config.json", {"components": {}})
        monkeypatch.chdir(tmp_path)
        bom = self._bom()
        (tmp_path / "bom.json").write_text(json.dumps(bom, ensure_ascii=False), encoding="utf-8")
        run(
            SimpleNamespace(
                input=str(tmp_path / "bom.json"),
                output=str(tmp_path / "out.json"),
                app_name="П",
                app_version="1",
                manufacturer="ООО",
                gost_default="no",
                strip_only=False,
                keep_all_fields=False,
                provided_by=None,
                purl_to_vcs=None,
                purl_to_gost=None,
                purl_exclude=None,
                config=None,
                pretty=True,
            )
        )
        config = json.loads((tmp_path / ".efs-config.json").read_text(encoding="utf-8"))
        assert "pkg:npm/inner" in config["components"]


class TestManifestRootLoop:
    def test_root_does_not_depend_on_itself(self):
        bom = make_bom(
            [
                {"bom-ref": "manifest-1", "type": "application", "name": "package-lock.json"},
                make_component("lodash", "1.0", purl="pkg:npm/lodash@1.0"),
            ],
            dependencies=[
                {"ref": "root", "dependsOn": ["manifest-1"]},
                {"ref": "manifest-1", "dependsOn": ["root", "pkg:npm/lodash@1.0"]},
            ],
        )
        bom["metadata"]["component"]["bom-ref"] = "root"
        _remove_manifest_components(bom)
        root_deps = next(d["dependsOn"] for d in bom["dependencies"] if d["ref"] == "root")
        assert "root" not in root_deps


class TestExcludeKeep:
    """Явный `exclude: false` — приказ оставить компонент, даже если каскад забрал бы его."""

    def _graph(self):
        return make_bom(
            [
                make_component("own-module", "1.0.0", purl="pkg:npm/own-module@1.0.0"),
                make_component("assert", "2.1.0", purl="pkg:npm/assert@2.1.0"),
                make_component("url", "0.11.4", purl="pkg:npm/url@0.11.4"),
            ],
            dependencies=[
                {"ref": "pkg:npm/own-module@1.0.0", "dependsOn": ["pkg:npm/assert@2.1.0", "pkg:npm/url@0.11.4"]},
                {"ref": "pkg:npm/assert@2.1.0", "dependsOn": []},
                {"ref": "pkg:npm/url@0.11.4", "dependsOn": []},
            ],
        )

    def test_kept_component_survives_cascade(self):
        bom = self._graph()
        exclude_components(bom, ["pkg:npm/own-module"], ["pkg:npm/assert"])
        assert sorted(c["name"] for c in bom["components"]) == ["assert"]

    def test_kept_component_not_counted_as_removed(self):
        bom = self._graph()
        removed = exclude_components(bom, ["pkg:npm/own-module"], ["pkg:npm/assert"])
        assert removed == 2

    def test_several_kept_components(self):
        bom = self._graph()
        exclude_components(bom, ["pkg:npm/own-module"], ["pkg:npm/assert", "pkg:npm/url"])
        assert sorted(c["name"] for c in bom["components"]) == ["assert", "url"]

    def test_kept_component_stays_in_dependencies(self):
        bom = self._graph()
        exclude_components(bom, ["pkg:npm/own-module"], ["pkg:npm/assert"])
        assert [d["ref"] for d in bom["dependencies"]] == ["pkg:npm/assert@2.1.0"]

    def test_keep_wins_over_direct_match(self):
        """Если purl попал и в exclude, и в keep, компонент остаётся."""
        bom = make_bom([make_component("assert", "2.1.0", purl="pkg:npm/assert@2.1.0")])
        removed = exclude_components(bom, ["pkg:npm/assert"], ["pkg:npm/assert"])
        assert removed == 0
        assert [c["name"] for c in bom["components"]] == ["assert"]

    def test_keep_bare_purl_covers_any_version(self):
        bom = self._graph()
        exclude_components(bom, ["pkg:npm/own-module"], ["pkg:npm/assert"])
        assert [c["version"] for c in bom["components"]] == ["2.1.0"]

    def test_keep_versioned_purl_shields_only_that_version(self):
        bom = make_bom(
            [
                make_component("own-module", "1.0.0", purl="pkg:npm/own-module@1.0.0"),
                make_component("assert", "2.1.0", purl="pkg:npm/assert@2.1.0"),
                make_component("assert", "1.0.0", purl="pkg:npm/assert@1.0.0"),
            ],
            dependencies=[
                {"ref": "pkg:npm/own-module@1.0.0", "dependsOn": ["pkg:npm/assert@2.1.0", "pkg:npm/assert@1.0.0"]},
                {"ref": "pkg:npm/assert@2.1.0", "dependsOn": []},
                {"ref": "pkg:npm/assert@1.0.0", "dependsOn": []},
            ],
        )
        exclude_components(bom, ["pkg:npm/own-module"], ["pkg:npm/assert@2.1.0"])
        assert [c["version"] for c in bom["components"]] == ["2.1.0"]

    def test_no_keep_list_behaves_as_before(self):
        bom = self._graph()
        exclude_components(bom, ["pkg:npm/own-module"])
        assert bom["components"] == []

    def test_keep_without_exclude_changes_nothing(self):
        bom = self._graph()
        assert exclude_components(bom, [], ["pkg:npm/assert"]) == 0
        assert len(bom["components"]) == 3


class TestProcessBomKeep:
    """`exclude: false` в конфиге доходит до каскада через process_bom."""

    def _bom(self):
        return make_bom(
            [
                make_component("own-module", "1.0.0", purl="pkg:npm/own-module@1.0.0"),
                make_component("assert", "2.1.0", purl="pkg:npm/assert@2.1.0"),
            ],
            dependencies=[
                {"ref": "pkg:npm/own-module@1.0.0", "dependsOn": ["pkg:npm/assert@2.1.0"]},
                {"ref": "pkg:npm/assert@2.1.0", "dependsOn": []},
            ],
        )

    def test_config_keep_survives_cascade(self, tmp_path):
        config_path = tmp_path / ".efs-config.json"
        config_path.write_text(
            json.dumps(
                {
                    "components": {
                        "pkg:npm/own-module": {"exclude": True},
                        "pkg:npm/assert": {"exclude": False},
                    }
                }
            ),
            encoding="utf-8",
        )
        bom = run_with_config(self._bom(), config_path, tmp_path)
        assert [c["name"] for c in bom["components"]] == ["assert"]

    def test_without_explicit_keep_component_leaves(self, tmp_path):
        config_path = tmp_path / ".efs-config.json"
        config_path.write_text(
            json.dumps({"components": {"pkg:npm/own-module": {"exclude": True}, "pkg:npm/assert": {}}}),
            encoding="utf-8",
        )
        bom = run_with_config(self._bom(), config_path, tmp_path)
        assert bom.get("components", []) == []


def run_with_config(bom, config_path, tmp_path):
    """Прогнать postprocess.run с конфигом и вернуть результат."""
    src = tmp_path / "in.json"
    src.write_text(json.dumps(bom, ensure_ascii=False), encoding="utf-8")
    out = tmp_path / "out.json"
    run(postprocess_args(input=str(src), output=str(out), config=str(config_path)))
    return json.loads(out.read_text(encoding="utf-8"))


class TestToolRecord:
    """efs отмечается в metadata.tools, чтобы обработанный файл не путали с сырым отчётом."""

    def _tools(self, bom):
        return bom.get("metadata", {}).get("tools", {}).get("components", [])

    def test_efs_recorded(self):
        bom = process_bom(make_bom([make_component("requests", "2.32.5")]), postprocess_args())
        assert [t["name"] for t in self._tools(bom)] == ["efs"]

    def test_record_carries_group_and_version(self):
        bom = process_bom(make_bom([]), postprocess_args())
        record = self._tools(bom)[0]
        assert record["group"] == "efs"
        assert record["type"] == "application"
        assert record["version"] == __version__

    def test_scanner_record_kept(self):
        bom = make_bom([])
        bom["metadata"]["tools"] = {
            "components": [{"type": "application", "group": "aquasecurity", "name": "trivy", "version": "0.74.0"}]
        }
        process_bom(bom, postprocess_args())
        assert [t["name"] for t in self._tools(bom)] == ["trivy", "efs"]

    def test_record_not_duplicated(self):
        bom = process_bom(make_bom([]), postprocess_args())
        process_bom(bom, postprocess_args())
        assert [t["name"] for t in self._tools(bom)] == ["efs"]

    def test_legacy_list_form_normalized(self):
        bom = make_bom([])
        bom["metadata"]["tools"] = [{"vendor": "cyclonedx", "name": "cdxgen", "version": "11.0.0"}]
        process_bom(bom, postprocess_args())
        names = [t["name"] for t in self._tools(bom)]
        assert names == ["cdxgen", "efs"]
        assert self._tools(bom)[0]["group"] == "cyclonedx"

    def test_strip_only_leaves_tools_alone(self):
        bom = make_bom([])
        bom["metadata"]["tools"] = {"components": []}
        process_bom(bom, postprocess_args(strip_only=True))
        assert self._tools(bom) == []
