# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

"""Тесты поиска VCS-ссылок. HTTP-запросы перехватываются responses, сеть не используется."""

import json
from types import SimpleNamespace

import pytest
import responses

from efs import updater
from efs.updater import RefFinder

from .conftest import make_bom, make_component


@pytest.fixture
def finder(monkeypatch, tmp_path):
    """RefFinder с изолированным кешем — без чтения и записи ~/.cache/efs."""
    monkeypatch.setattr(updater, "load_cache", lambda kind: {})
    monkeypatch.setattr(updater, "dump_cache", lambda kind, data: None)
    return RefFinder(str(tmp_path / "отсутствует.json"))


class TestPypiResolver:
    @responses.activate
    def test_prefers_source_over_homepage(self, finder):
        responses.get(
            "https://pypi.org/pypi/requests/json",
            json={
                "info": {
                    "project_urls": {
                        "Homepage": "https://requests.readthedocs.io",
                        "Source": "https://github.com/psf/requests",
                    }
                }
            },
        )
        assert finder._pypi_purl("pkg:pypi/requests@2.32.5")[0] == "https://github.com/psf/requests"

    @responses.activate
    def test_falls_back_to_home_page(self, finder):
        responses.get(
            "https://pypi.org/pypi/lonely/json",
            json={"info": {"project_urls": None, "home_page": "https://example.org/lonely"}},
        )
        assert finder._pypi_purl("pkg:pypi/lonely@1.0") == ["https://example.org/lonely"]

    @responses.activate
    def test_http_error_returns_empty(self, finder):
        responses.get("https://pypi.org/pypi/absent/json", status=404)
        assert finder._pypi_purl("pkg:pypi/absent@1.0") == []

    @responses.activate
    def test_connection_error_returns_empty(self, finder):
        responses.get("https://pypi.org/pypi/broken/json", body=ConnectionError("нет сети"))
        assert finder._pypi_purl("pkg:pypi/broken@1.0") == []


class TestNpmResolver:
    @responses.activate
    def test_normalizes_git_url(self, finder):
        responses.get(
            "https://registry.npmjs.org/left-pad",
            json={"repository": {"url": "git+https://github.com/stevemao/left-pad.git"}},
        )
        assert finder._npm_purl("pkg:npm/left-pad@1.3.0") == ["https://github.com/stevemao/left-pad"]

    @responses.activate
    def test_scoped_package_name_decoded(self, finder):
        responses.get(
            "https://registry.npmjs.org/@babel/runtime",
            json={"repository": {"url": "https://github.com/babel/babel"}},
        )
        assert finder._npm_purl("pkg:npm/%40babel/runtime@7.9.0") == ["https://github.com/babel/babel"]

    @responses.activate
    def test_homepage_added(self, finder):
        responses.get(
            "https://registry.npmjs.org/tiny",
            json={"repository": {}, "homepage": "https://example.org/tiny"},
        )
        assert finder._npm_purl("pkg:npm/tiny@1.0.0") == ["https://example.org/tiny"]


class TestDistroResolvers:
    def test_rpm_urls_are_guessed_without_network(self, finder):
        urls = finder._rpm_purl("pkg:rpm/fedora/curl@8.0.1")
        assert "https://src.fedoraproject.org/rpms/curl" in urls

    @responses.activate
    def test_deb_uses_sources_api_then_salsa(self, finder):
        responses.get(
            "https://sources.debian.org/api/src/curl/",
            json={"info": {"vcs_git": "https://salsa.debian.org/debian/curl.git"}},
        )
        urls = finder._deb_purl("pkg:deb/debian/curl@7.88.1")
        assert urls[0] == "https://salsa.debian.org/debian/curl"

    @responses.activate
    def test_deb_survives_api_failure(self, finder):
        responses.get("https://sources.debian.org/api/src/curl/", status=500)
        urls = finder._deb_purl("pkg:deb/debian/curl@7.88.1")
        assert "https://salsa.debian.org/debian/curl" in urls

    @responses.activate
    def test_ubuntu_adds_launchpad(self, finder):
        responses.get("https://sources.debian.org/api/src/curl/", status=404)
        urls = finder._deb_purl("pkg:deb/ubuntu/curl@7.88.1")
        assert "https://git.launchpad.net/ubuntu/+source/curl" in urls


class TestEcosystems:
    @responses.activate
    def test_returns_repository_registry_homepage(self, finder):
        responses.get(
            "https://packages.ecosyste.ms/api/v1/packages/lookup",
            json=[
                {
                    "repository_url": "https://github.com/psf/requests",
                    "registry_url": "https://pypi.org/project/requests",
                    "homepage": "https://requests.readthedocs.io",
                }
            ],
        )
        urls = finder._ecosystems("pkg:pypi/requests@2.32.5")
        assert urls[0] == "https://github.com/psf/requests"

    @responses.activate
    def test_empty_response_returns_empty_list(self, finder):
        responses.get("https://packages.ecosyste.ms/api/v1/packages/lookup", json=[])
        assert finder._ecosystems("pkg:pypi/absent@1.0") == []

    @responses.activate
    def test_non_list_response_returns_empty_list(self, finder):
        """API иногда отвечает объектом с ошибкой вместо списка."""
        responses.get("https://packages.ecosyste.ms/api/v1/packages/lookup", json={"error": "not found"})
        assert finder._ecosystems("pkg:pypi/absent@1.0") == []


class TestProcessPurl:
    @responses.activate
    def test_uses_preloaded_mapping_without_network(self, monkeypatch, tmp_path):
        monkeypatch.setattr(updater, "load_cache", lambda kind: {})
        mapping = tmp_path / "map.json"
        mapping.write_text('{"pkg:pypi/requests@2.32.5": "https://github.com/psf/requests"}', encoding="utf-8")
        finder = RefFinder(str(mapping))
        assert finder.process_purl("pkg:pypi/requests@2.32.5") == "https://github.com/psf/requests"

    @responses.activate
    def test_placeholder_when_nothing_found(self, finder, monkeypatch):
        responses.get("https://packages.ecosyste.ms/api/v1/packages/lookup", json=[])
        responses.get("https://pypi.org/pypi/unknown/json", status=404)
        assert finder.process_purl("pkg:pypi/unknown@1.0") == "sbom-updater_generated_placeholder:"

    @responses.activate
    def test_found_url_is_verified_as_repo(self, finder, monkeypatch):
        responses.get(
            "https://packages.ecosyste.ms/api/v1/packages/lookup",
            json=[{"repository_url": "https://github.com/psf/requests"}],
        )
        monkeypatch.setattr(updater, "check_repo", lambda url: (True, ""))
        assert finder.process_purl("pkg:pypi/requests@2.32.5") == "https://github.com/psf/requests"

    @responses.activate
    def test_result_is_cached_between_calls(self, finder, monkeypatch):
        responses.get(
            "https://packages.ecosyste.ms/api/v1/packages/lookup",
            json=[{"repository_url": "https://github.com/psf/requests"}],
        )
        checks = []
        monkeypatch.setattr(updater, "check_repo", lambda url: (checks.append(url), (True, ""))[1])
        finder.process_purl("pkg:pypi/requests@2.32.5")
        finder.process_purl("pkg:pypi/requests@2.32.5")
        assert len(checks) == 1


class TestIsRepo:
    def test_caches_negative_results(self, finder, monkeypatch):
        calls = []

        def fake_check(url):
            calls.append(url)
            return False, "ошибка"

        monkeypatch.setattr(updater, "check_repo", fake_check)
        assert finder.is_repo("https://example.org/x") is False
        finder.is_repo("https://example.org/x")
        assert len(calls) == 1


class TestRun:
    """Проверка команды `efs update` без обращения к сети (--ref не используется)."""

    def _args(self, tmp_path, input_path, **overrides):
        base = {
            "input": str(input_path),
            "output": str(tmp_path / "out.json"),
            "props": False,
            "app_name": None,
            "app_version": None,
            "manufacturer": None,
            "ref": False,
            "purl_to_vcs": None,
            "gost": False,
            "purl_to_gost": None,
            "extra_input": [],
            "fix_all": False,
            "update": None,
            "verbose": False,
        }
        base.update(overrides)
        return SimpleNamespace(**base)

    def _write_bom(self, tmp_path, components):
        path = tmp_path / "bom.json"
        path.write_text(json.dumps(make_bom(components), ensure_ascii=False), encoding="utf-8")
        return path

    def test_props_adds_gost_properties(self, tmp_path):
        path = self._write_bom(tmp_path, [make_component("requests", "2.32.5")])
        updater.run(self._args(tmp_path, path, props=True))

        data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
        props = {p["name"]: p["value"] for p in data["components"][0]["properties"]}
        assert props["GOST:attack_surface"] == "yes"
        assert props["GOST:security_function"] == "yes"

    def test_metadata_overridden(self, tmp_path):
        path = self._write_bom(tmp_path, [make_component("requests", "2.32.5")])
        updater.run(self._args(tmp_path, path, app_name="Продукт", app_version="9.9", manufacturer="ООО Изготовитель"))

        mc = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))["metadata"]["component"]
        assert mc["name"] == "Продукт"
        assert mc["version"] == "9.9"
        assert mc["manufacturer"]["name"] == "ООО Изготовитель"

    def test_gost_mapping_applied(self, tmp_path):
        mapping = tmp_path / "gost.json"
        mapping.write_text(
            json.dumps({"GOST:attack_surface": {"pkg:pypi/requests@2.32.5": "indirect"}}), encoding="utf-8"
        )
        path = self._write_bom(tmp_path, [make_component("requests", "2.32.5")])
        updater.run(self._args(tmp_path, path, gost=True, purl_to_gost=str(mapping)))

        data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
        props = {p["name"]: p["value"] for p in data["components"][0]["properties"]}
        assert props["GOST:attack_surface"] == "indirect"

    def test_missing_output_exits(self, tmp_path):
        path = self._write_bom(tmp_path, [make_component("requests", "2.32.5")])
        with pytest.raises(SystemExit):
            updater.run(self._args(tmp_path, path, output=None))

    def test_props_fills_language_from_purl(self, tmp_path):
        """--props должен давать перечень, проходящий efs check, включая язык."""
        path = self._write_bom(tmp_path, [make_component("requests", "2.32.5")])
        updater.run(self._args(tmp_path, path, props=True))

        data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
        langs = [p["value"] for p in data["components"][0]["properties"] if p["name"] == "GOST:source_langs"]
        assert langs == ["Python"]

    def test_language_not_invented_for_distro_packages(self, tmp_path):
        path = self._write_bom(tmp_path, [make_component("curl", "8.0.1", purl="pkg:deb/debian/curl@8.0.1")])
        updater.run(self._args(tmp_path, path, props=True))

        data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
        assert all(p["name"] != "GOST:source_langs" for p in data["components"][0]["properties"])

    def test_existing_language_preserved(self, tmp_path):
        comp = make_component("requests", "2.32.5", properties=[{"name": "GOST:source_langs", "value": "Python, Rust"}])
        path = self._write_bom(tmp_path, [comp])
        updater.run(self._args(tmp_path, path, props=True))

        data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
        langs = [p["value"] for p in data["components"][0]["properties"] if p["name"] == "GOST:source_langs"]
        assert langs == ["Python, Rust"]

    def test_gost_branch_also_fills_language(self, tmp_path):
        mapping = tmp_path / "gost.json"
        mapping.write_text(json.dumps({"GOST:attack_surface": {}}), encoding="utf-8")
        path = self._write_bom(tmp_path, [make_component("requests", "2.32.5")])
        updater.run(self._args(tmp_path, path, gost=True, purl_to_gost=str(mapping)))

        data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
        langs = [p["value"] for p in data["components"][0]["properties"] if p["name"] == "GOST:source_langs"]
        assert langs == ["Python"]
