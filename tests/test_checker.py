# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

"""Тесты валидации SBOM по JSON Schema и проверок внешних ссылок."""

from types import SimpleNamespace

import pytest

from efc import checker

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
        path = write_json("bom.json", make_bom([gost_component("requests", "2.32.5")]))
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

        path = write_json("bom.json", make_bom([gost_component("requests", "2.32.5")]))
        checker.run(args_for(path, check_vcs=True))
        assert "файл корректный" in capsys.readouterr().out


class TestSourceDistributionCheck:
    def _bom_with_source_dist(self):
        comp = gost_component("requests", "2.32.5")
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
