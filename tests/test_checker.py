# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

"""Тесты валидации SBOM по JSON Schema и проверок внешних ссылок."""

import json
from types import SimpleNamespace

import pytest

from efs import checker

from .conftest import make_bom, make_component


def args_for(path, **overrides):
    base = {
        "filename": str(path),
        "errors": 10,
        "check_vcs": False,
        "check_vcs_leaf_only": False,
        "check_source_distribution": False,
        "format": "oss",
        "verbose": False,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def complete_component(name="requests", version="2.32.5"):
    """Компонент, полностью готовый к сдаче: ГОСТ-свойства, языки и ссылка на репозиторий."""
    comp = gost_component(name, version)
    comp["properties"].append({"name": "GOST:source_langs", "value": "Python"})
    return comp


def gost_component(name, version="1.0.0", **extra):
    """Компонент, проходящий схему: с GOST-свойствами и VCS-ссылкой."""
    comp = make_component(name, version, **extra)
    comp.setdefault(
        "properties",
        [
            {"name": "GOST:attack_surface", "value": "no"},
            {"name": "GOST:security_function", "value": "no"},
        ],
    )
    comp.setdefault("externalReferences", [{"type": "vcs", "url": f"https://github.com/example/{name}"}])
    return comp


class TestSchemaValidation:
    def test_valid_bom_reported_as_correct(self, write_json, capsys):
        path = write_json("bom.json", make_bom([complete_component()]))
        checker.run(args_for(path))
        assert "файл корректный" in capsys.readouterr().out

    def test_missing_required_field_is_error(self, write_json, capsys):
        bom = make_bom([gost_component("requests", "2.32.5")])
        del bom["specVersion"]
        path = write_json("bom.json", bom)
        checker.run(args_for(path))
        out = capsys.readouterr().out
        assert "ERROR" in out
        assert "файл корректный" not in out

    def test_unknown_field_rejected(self, write_json, capsys):
        bom = make_bom([gost_component("requests", "2.32.5")])
        bom["неизвестное"] = 1
        path = write_json("bom.json", bom)
        checker.run(args_for(path))
        assert "Additional properties are not allowed" in capsys.readouterr().out

    def test_error_limit_respected(self, write_json, capsys):
        bom = make_bom([{"type": "library"} for _ in range(5)])
        path = write_json("bom.json", bom)
        checker.run(args_for(path, errors=2))
        assert capsys.readouterr().out.count("ERROR") == 2

    def test_duplicate_keys_rejected(self, write_json):
        path = write_json("bom.json", None, raw=b'{"version": 1, "version": 2}')
        with pytest.raises(ValueError, match="Duplicate key"):
            checker.run(args_for(path))


class TestVcsCheck:
    def test_reports_unreachable_repository(self, write_json, capsys, monkeypatch):
        monkeypatch.setattr(checker, "load_cache", lambda kind: {})
        monkeypatch.setattr(checker, "dump_cache", lambda kind, data: None)
        monkeypatch.setattr(checker, "check_repo", lambda url: (False, "не репозиторий"))

        path = write_json("bom.json", make_bom([gost_component("requests", "2.32.5")]))
        checker.run(args_for(path, check_vcs=True))
        assert "не является git/svn/hg/fossil-репозиторием" in capsys.readouterr().out

    def test_reachable_repository_passes(self, write_json, capsys, monkeypatch):
        monkeypatch.setattr(checker, "load_cache", lambda kind: {})
        monkeypatch.setattr(checker, "dump_cache", lambda kind, data: None)
        monkeypatch.setattr(checker, "check_repo", lambda url: (True, ""))

        path = write_json("bom.json", make_bom([complete_component()]))
        checker.run(args_for(path, check_vcs=True))
        assert "файл корректный" in capsys.readouterr().out


class TestSourceDistributionCheck:
    def _bom_with_source_dist(self):
        comp = complete_component()
        comp["externalReferences"].append(
            {"type": "source-distribution", "url": "https://example.org/requests-2.32.5.tar.gz"}
        )
        return make_bom([comp])

    def test_archive_url_checked_with_session(self, write_json, capsys, monkeypatch):
        """Регрессия: is_archive_url принимает (session, url) — вызов без сессии падал в исключение."""
        monkeypatch.setattr(checker, "load_cache", lambda kind: {})
        monkeypatch.setattr(checker, "dump_cache", lambda kind, data: None)
        monkeypatch.setattr(checker, "check_repo", lambda url: (True, ""))
        monkeypatch.setattr(checker, "is_archive_url", lambda session, url: (True, ""))

        path = write_json("bom.json", self._bom_with_source_dist())
        checker.run(args_for(path, check_source_distribution=True))
        out = capsys.readouterr().out
        assert "generated an exception" not in out
        assert "файл корректный" in out

    def test_non_archive_url_reported(self, write_json, capsys, monkeypatch):
        monkeypatch.setattr(checker, "load_cache", lambda kind: {})
        monkeypatch.setattr(checker, "dump_cache", lambda kind, data: None)
        monkeypatch.setattr(checker, "check_repo", lambda url: (True, ""))
        monkeypatch.setattr(checker, "is_archive_url", lambda session, url: (False, "не архив"))

        path = write_json("bom.json", self._bom_with_source_dist())
        checker.run(args_for(path, check_source_distribution=True))
        assert "не указывает на архив или не существует" in capsys.readouterr().out


class TestContainerFormat:
    def _container_bom(self, container_as, component_as):
        component = gost_component("libssl", "3.0.0")
        component["properties"] = [
            {"name": "GOST:attack_surface", "value": component_as},
            {"name": "GOST:security_function", "value": "no"},
        ]
        container = {
            "type": "container",
            "name": "app-image",
            "version": "1.0.0",
            "properties": [
                {"name": "GOST:attack_surface", "value": container_as},
                {"name": "GOST:security_function", "value": "no"},
            ],
            "components": [component],
        }
        return make_bom([container])

    def test_component_exceeding_container_attack_surface(self, write_json, capsys):
        path = write_json("bom.json", self._container_bom("no", "yes"))
        checker.run(args_for(path, format="container"))
        assert "с бóльшим значением поверхности атаки" in capsys.readouterr().out

    def test_matching_attack_surface_passes(self, write_json, capsys):
        path = write_json("bom.json", self._container_bom("yes", "yes"))
        checker.run(args_for(path, format="container"))
        assert "поверхности атаки" not in capsys.readouterr().out


class TestExitCodes:
    def test_valid_and_complete_returns_zero(self, write_json):
        assert checker.run(args_for(write_json("bom.json", make_bom([complete_component()])))) == 0

    def test_schema_error_returns_one(self, write_json):
        bom = make_bom([gost_component("requests", "2.32.5")])
        del bom["specVersion"]
        assert checker.run(args_for(write_json("bom.json", bom))) == 1

    def test_incomplete_listing_returns_three(self, write_json):
        """Код 2 занят click под ошибку использования, поэтому незаполненность — 3."""
        bom = make_bom([gost_component("requests", "2.32.5")])
        assert checker.run(args_for(write_json("bom.json", bom))) == 3

    def test_unreachable_repository_returns_one(self, write_json, monkeypatch):
        monkeypatch.setattr(checker, "load_cache", lambda kind: {})
        monkeypatch.setattr(checker, "dump_cache", lambda kind, data: None)
        monkeypatch.setattr(checker, "check_repo", lambda url: (False, "не репозиторий"))
        bom = make_bom([complete_component()])
        assert checker.run(args_for(write_json("bom.json", bom), check_vcs=True)) == 1


class TestReadiness:
    def _run(self, write_json, capsys, bom):
        checker.run(args_for(write_json("bom.json", bom)))
        return capsys.readouterr().out

    def test_todo_in_metadata_reported(self, write_json, capsys):
        bom = make_bom([complete_component()])
        bom["metadata"]["component"]["name"] = "TODO"
        out = self._run(write_json, capsys, bom)
        assert "TODO" in out
        assert "metadata.component.name" in out

    def test_todo_manufacturer_reported(self, write_json, capsys):
        bom = make_bom([complete_component()])
        bom["metadata"]["component"]["manufacturer"]["name"] = "TODO"
        out = self._run(write_json, capsys, bom)
        assert "manufacturer" in out

    def test_missing_gost_property_reported(self, write_json, capsys):
        comp = complete_component()
        comp["properties"] = [p for p in comp["properties"] if p["name"] != "GOST:attack_surface"]
        out = self._run(write_json, capsys, make_bom([comp]))
        assert "GOST:attack_surface" in out
        assert "requests" in out

    def test_missing_source_langs_reported(self, write_json, capsys):
        out = self._run(write_json, capsys, make_bom([gost_component("requests", "2.32.5")]))
        assert "GOST:source_langs" in out

    def test_component_without_vcs_and_provided_by_reported(self, write_json, capsys):
        comp = complete_component()
        del comp["externalReferences"]
        out = self._run(write_json, capsys, make_bom([comp]))
        assert "requests" in out
        assert "GOST:provided_by" in out

    def test_provided_by_replaces_vcs_requirement(self, write_json, capsys):
        comp = complete_component()
        del comp["externalReferences"]
        comp["properties"].append({"name": "GOST:provided_by", "value": "ООО Поставщик"})
        out = self._run(write_json, capsys, make_bom([comp]))
        assert "файл корректный" in out

    def test_placeholder_vcs_counts_as_missing(self, write_json, capsys):
        comp = complete_component()
        comp["externalReferences"] = [{"type": "vcs", "url": "TODO"}]
        out = self._run(write_json, capsys, make_bom([comp]))
        assert "requests" in out

    def test_complete_listing_reports_no_warnings(self, write_json, capsys):
        out = self._run(write_json, capsys, make_bom([complete_component()]))
        assert "файл корректный" in out
        assert "не заполнено" not in out


class TestReadinessSummary:
    def test_summary_groups_issues_by_kind(self, write_json, capsys):
        components = []
        for i in range(3):
            comp = gost_component(f"lib{i}", "1.0")
            components.append(comp)
        bom = make_bom(components)
        bom["metadata"]["component"]["version"] = "TODO"

        checker.run(args_for(write_json("bom.json", bom), errors=2))
        out = capsys.readouterr().out

        assert "отсутствует GOST:source_langs: 3" in out
        assert "metadata.component.version" in out

    def test_summary_absent_when_listing_is_ready(self, write_json, capsys):
        checker.run(args_for(write_json("bom.json", make_bom([complete_component()]))))
        out = capsys.readouterr().out
        assert "GOST:source_langs" not in out


class TestContainerReadiness:
    def _container_bom(self, description=None):
        component = gost_component("libssl", "3.0.0")
        container = {
            "type": "container",
            "name": "app-image",
            "version": "1.0.0",
            "properties": [
                {"name": "GOST:attack_surface", "value": "no"},
                {"name": "GOST:security_function", "value": "no"},
                {"name": "GOST:source_langs", "value": "C"},
            ],
            "components": [component],
        }
        if description is not None:
            container["description"] = description
        return make_bom([container])

    def test_missing_purpose_reported(self, write_json, capsys):
        """В форме перечня образов есть графа «Назначение» — она берётся из description."""
        path = write_json("bom.json", self._container_bom())
        checker.run(args_for(path, format="container"))
        assert "назначение" in capsys.readouterr().out.lower()

    def test_purpose_present_not_reported(self, write_json, capsys):
        path = write_json("bom.json", self._container_bom("Образ прикладного сервиса"))
        checker.run(args_for(path, format="container"))
        assert "назначение" not in capsys.readouterr().out.lower()


class TestCheckProgress:
    def test_progress_shown_while_checking_links(self, write_json, capsys, monkeypatch):
        """Проверка ссылок ходит в сеть и занимает минуты — молчать всё это время нельзя."""
        monkeypatch.setattr(checker, "load_cache", lambda kind: {})
        monkeypatch.setattr(checker, "dump_cache", lambda kind, data: None)
        monkeypatch.setattr(checker, "check_repo", lambda url: (True, ""))

        components = [complete_component(f"lib{i}") for i in range(3)]
        for number, comp in enumerate(components):
            comp["externalReferences"] = [{"type": "vcs", "url": f"https://github.com/example/lib{number}"}]
        path = write_json("bom.json", make_bom(components))

        checker.run(args_for(path, check_vcs=True))
        out = capsys.readouterr().out
        assert "проверка ссылок" in out.lower()

    def test_no_progress_without_link_checks(self, write_json, capsys):
        path = write_json("bom.json", make_bom([complete_component()]))
        checker.run(args_for(path))
        assert "проверка ссылок" not in capsys.readouterr().out.lower()


class TestUniqueness:
    def _bom_with_duplicates(self):
        comp = complete_component()
        return make_bom([comp, json.loads(json.dumps(comp))])

    def test_duplicate_components_reported(self, write_json, capsys):
        path = write_json("bom.json", self._bom_with_duplicates())
        code = checker.run(args_for(path))
        out = capsys.readouterr().out
        assert code == 1
        assert "non-unique" in out.lower() or "неуникальные" in out.lower()

    def test_duplicate_dependencies_reported(self, write_json, capsys):
        bom = make_bom([complete_component()])
        bom["dependencies"] = [{"ref": "pkg:pypi/requests@2.32.5"}, {"ref": "pkg:pypi/requests@2.32.5"}]
        path = write_json("bom.json", bom)
        assert checker.run(args_for(path)) == 1

    def test_unique_document_passes(self, write_json):
        bom = make_bom([complete_component("requests"), complete_component("flask")])
        bom["dependencies"] = [{"ref": "a"}, {"ref": "b"}]
        assert checker.run(args_for(write_json("bom.json", bom))) == 0

    def test_large_dependency_graph_checked_quickly(self, write_json):
        """Проверка не должна быть квадратичной: у trivy зависимостей столько же, сколько компонентов."""
        import time

        components = [complete_component(f"lib{i}", f"1.{i}.0") for i in range(300)]
        bom = make_bom(components)
        bom["dependencies"] = [
            {"ref": f"pkg:pypi/lib{i}@1.{i}.0", "dependsOn": [f"pkg:pypi/lib{j}@1.{j}.0" for j in range(i % 5)]}
            for i in range(6000)
        ]
        path = write_json("bom.json", bom)

        start = time.perf_counter()
        checker.run(args_for(path, errors=1))
        assert time.perf_counter() - start < 10


class TestReadinessUnit:
    """check_readiness проверяется отдельно от схемы: она даёт понятные замечания и работает для контейнеров."""

    def _component(self, **overrides):
        comp = {
            "type": "library",
            "name": "requests",
            "version": "2.32.5",
            "purl": "pkg:pypi/requests@2.32.5",
            "properties": [
                {"name": "GOST:attack_surface", "value": "no"},
                {"name": "GOST:security_function", "value": "no"},
                {"name": "GOST:source_langs", "value": "Python"},
            ],
            "externalReferences": [{"type": "vcs", "url": "https://github.com/psf/requests"}],
        }
        comp.update(overrides)
        return comp

    @pytest.mark.parametrize("prop_name", ["GOST:attack_surface", "GOST:security_function"])
    def test_each_required_gost_prop_checked(self, prop_name, capsys):
        comp = self._component()
        comp["properties"] = [p for p in comp["properties"] if p["name"] != prop_name]
        assert checker.check_readiness(make_bom([comp])) == 1
        assert prop_name in capsys.readouterr().out

    def test_ready_component_has_no_issues(self, capsys):
        assert checker.check_readiness(make_bom([self._component()])) == 0

    def test_nested_component_checked(self, capsys):
        nested = self._component(name="вложенный")
        nested["properties"] = [p for p in nested["properties"] if p["name"] != "GOST:source_langs"]
        outer = self._component(name="внешний", components=[nested])
        assert checker.check_readiness(make_bom([outer])) == 1
        assert "вложенный" in capsys.readouterr().out

    def test_third_level_checked(self, capsys):
        deep = self._component(name="глубокий")
        deep["properties"] = [p for p in deep["properties"] if p["name"] != "GOST:attack_surface"]
        middle = self._component(name="средний", components=[deep])
        outer = self._component(name="внешний", components=[middle])
        assert checker.check_readiness(make_bom([outer])) == 1
        assert "глубокий" in capsys.readouterr().out

    def test_website_is_not_source_evidence(self, capsys):
        """Домашняя страница — не адрес исходного кода."""
        comp = self._component(externalReferences=[{"type": "website", "url": "https://example.org"}])
        assert checker.check_readiness(make_bom([comp])) == 1
        assert "репозиторий" in capsys.readouterr().out.lower()

    @pytest.mark.parametrize("url", ["TODO", "", "sbom-updater_generated_placeholder:"])
    def test_placeholder_urls_count_as_missing(self, url, capsys):
        comp = self._component(externalReferences=[{"type": "vcs", "url": url}])
        assert checker.check_readiness(make_bom([comp])) == 1

    def test_provided_by_replaces_repository(self, capsys):
        comp = self._component(externalReferences=[])
        comp["properties"].append({"name": "GOST:provided_by", "value": "КриптоПро CSP"})
        assert checker.check_readiness(make_bom([comp])) == 0

    def test_blank_container_purpose_reported(self, capsys):
        container = {
            "type": "container",
            "name": "app-image",
            "version": "1.0.0",
            "description": "   ",
            "properties": [
                {"name": "GOST:attack_surface", "value": "no"},
                {"name": "GOST:security_function", "value": "no"},
                {"name": "GOST:source_langs", "value": "C"},
                {"name": "GOST:provided_by", "value": "ООО Поставщик"},
            ],
        }
        assert checker.check_readiness(make_bom([container])) == 1
        assert "назначение" in capsys.readouterr().out.lower()

    def test_null_properties_do_not_crash(self, capsys):
        comp = self._component(properties=None)
        checker.check_readiness(make_bom([comp]))
        assert "Traceback" not in capsys.readouterr().out

    def test_limit_applies_to_warnings(self, capsys):
        components = []
        for index in range(5):
            comp = self._component(name=f"lib{index}", purl=f"pkg:pypi/lib{index}@1.0")
            comp["properties"] = [p for p in comp["properties"] if p["name"] != "GOST:source_langs"]
            components.append(comp)
        assert checker.check_readiness(make_bom(components), limit=2) == 5
        assert capsys.readouterr().out.count("WARNING:") == 2


class TestUniquenessCoverage:
    def _bom_with(self, **sections):
        bom = make_bom([complete_component()])
        bom.update(sections)
        return bom

    def test_duplicate_vulnerabilities_reported(self, write_json):
        vuln = {"id": "CVE-2024-0001", "affects": [{"ref": "pkg:pypi/requests@2.32.5"}]}
        path = write_json("bom.json", self._bom_with(vulnerabilities=[vuln, json.loads(json.dumps(vuln))]))
        assert checker.run(args_for(path)) == 1

    def test_duplicate_depends_on_reported(self, write_json):
        deps = [{"ref": "pkg:pypi/requests@2.32.5", "dependsOn": ["pkg:pypi/x@1.0", "pkg:pypi/x@1.0"]}]
        path = write_json("bom.json", self._bom_with(dependencies=deps))
        assert checker.run(args_for(path)) == 1

    def test_duplicates_found_at_any_depth(self, write_json):
        """Дубликаты во вложенных массивах — обычное дело для cdxgen и trivy."""
        inner = complete_component("вложенный")
        outer = complete_component("внешний")
        outer["components"] = [inner, json.loads(json.dumps(inner))]
        path = write_json("bom.json", make_bom([outer]))
        assert checker.run(args_for(path)) == 1

    def test_key_order_does_not_hide_duplicate(self):
        """Одинаковые по смыслу записи с разным порядком ключей — тоже дубликаты."""
        bom = {"dependencies": [{"ref": "a", "dependsOn": ["z"]}, {"dependsOn": ["z"], "ref": "a"}]}
        assert checker.check_uniqueness(bom)


class TestLinkCheckOutcomes:
    def _bom_with_source_dist(self):
        comp = complete_component()
        comp["externalReferences"].append(
            {"type": "source-distribution", "url": "https://example.org/requests-2.32.5.tar.gz"}
        )
        return make_bom([comp])

    def test_broken_archive_fails_the_run(self, write_json, monkeypatch):
        """Недоступный дистрибутив исходников обязан валить проверку, а не только печатать warning."""
        monkeypatch.setattr(checker, "load_cache", lambda kind: {})
        monkeypatch.setattr(checker, "dump_cache", lambda kind, data: None)
        monkeypatch.setattr(checker, "check_repo", lambda url: (True, ""))
        monkeypatch.setattr(checker, "is_archive_url", lambda session, url: (False, "не архив"))
        path = write_json("bom.json", self._bom_with_source_dist())
        assert checker.run(args_for(path, check_source_distribution=True)) == 1

    def test_exception_inside_parallel_check_is_reported(self, write_json, capsys, monkeypatch):
        """Ошибка внутри параллельной проверки не должна проглатываться — иначе ссылки не проверены."""
        monkeypatch.setattr(checker, "load_cache", lambda kind: {})
        monkeypatch.setattr(checker, "dump_cache", lambda kind, data: None)

        def boom(url):
            raise RuntimeError("сеть недоступна")

        monkeypatch.setattr(checker, "check_repo", boom)
        path = write_json("bom.json", make_bom([complete_component()]))
        code = checker.run(args_for(path, check_vcs=True))
        assert code == 1
        assert "exception" in capsys.readouterr().out.lower()

    def test_failed_checks_not_written_to_cache(self, write_json, monkeypatch):
        """Разовый сбой сети не должен навсегда оседать в кеше как «репозиторий битый»."""
        saved = {}
        monkeypatch.setattr(checker, "load_cache", lambda kind: {})
        monkeypatch.setattr(checker, "dump_cache", lambda kind, data: saved.update({kind: data}))
        monkeypatch.setattr(checker, "check_repo", lambda url: (False, "нет сети"))
        path = write_json("bom.json", make_bom([complete_component()]))
        checker.run(args_for(path, check_vcs=True))
        assert saved.get("vcs") == {}

    def test_leaf_only_checks_only_leaves(self, write_json, monkeypatch):
        """--check-vcs-leaf-only проверяет листья, а не узлы-контейнеры."""
        checked = []
        monkeypatch.setattr(checker, "load_cache", lambda kind: {})
        monkeypatch.setattr(checker, "dump_cache", lambda kind, data: None)
        monkeypatch.setattr(checker, "check_repo", lambda url: (checked.append(url), (True, ""))[1])

        leaf = complete_component("лист")
        leaf["externalReferences"] = [{"type": "vcs", "url": "https://github.com/example/leaf"}]
        parent = complete_component("родитель")
        parent["externalReferences"] = [{"type": "vcs", "url": "https://github.com/example/parent"}]
        parent["components"] = [leaf]
        path = write_json("bom.json", make_bom([parent]))

        checker.run(args_for(path, check_vcs_leaf_only=True))
        assert checked == ["https://github.com/example/leaf"]

    def test_check_vcs_visits_every_component(self, write_json, monkeypatch):
        checked = []
        monkeypatch.setattr(checker, "load_cache", lambda kind: {})
        monkeypatch.setattr(checker, "dump_cache", lambda kind, data: None)
        monkeypatch.setattr(checker, "check_repo", lambda url: (checked.append(url), (True, ""))[1])

        leaf = complete_component("лист")
        leaf["externalReferences"] = [{"type": "vcs", "url": "https://github.com/example/leaf"}]
        parent = complete_component("родитель")
        parent["externalReferences"] = [{"type": "vcs", "url": "https://github.com/example/parent"}]
        parent["components"] = [leaf]
        path = write_json("bom.json", make_bom([parent]))

        checker.run(args_for(path, check_vcs=True))
        assert sorted(checked) == ["https://github.com/example/leaf", "https://github.com/example/parent"]
