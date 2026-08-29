# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

"""Тесты поиска VCS-ссылок. HTTP-запросы перехватываются responses, сеть не используется."""

import json
from types import SimpleNamespace

import pytest
import responses
from requests import adapters

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


def update_args(tmp_path, input_path, **overrides):
    """Аргументы команды `efs update` со всеми флагами выключенными."""
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


def write_bom(tmp_path, components, name="bom.json"):
    path = tmp_path / name
    path.write_text(json.dumps(make_bom(components), ensure_ascii=False), encoding="utf-8")
    return path


def read_out(tmp_path, name="out.json"):
    return json.loads((tmp_path / name).read_text(encoding="utf-8"))


class TestRun:
    """Проверка команды `efs update` без обращения к сети (--ref не используется)."""

    _args = staticmethod(update_args)
    _write_bom = staticmethod(write_bom)

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


class TestTimeoutAdapter:
    """Таймаут по умолчанию: без него запрос к недоступному хосту висит бесконечно."""

    def _send(self, monkeypatch, **kwargs):
        captured = {}

        def fake_send(self, *args, **kw):
            captured.update(kw)

        monkeypatch.setattr(adapters.HTTPAdapter, "send", fake_send)
        updater._TimeoutHTTPAdapter(timeout=7).send(None, **kwargs)
        return captured

    def test_default_applied_when_timeout_absent(self, monkeypatch):
        assert self._send(monkeypatch)["timeout"] == 7

    def test_default_applied_when_timeout_is_none(self, monkeypatch):
        assert self._send(monkeypatch, timeout=None)["timeout"] == 7

    def test_explicit_timeout_kept(self, monkeypatch):
        assert self._send(monkeypatch, timeout=1)["timeout"] == 1

    def test_session_mounts_adapter_with_timeout(self, finder):
        adapter = finder._session.get_adapter("https://example.org")
        assert isinstance(adapter, updater._TimeoutHTTPAdapter)
        assert adapter._default_timeout == updater._HTTP_TIMEOUT


class TestIsRepoCache:
    """Кеш должен возвращать сохранённое решение, а не пересчитывать и не искажать его."""

    def test_cached_positive_returned(self, finder, monkeypatch):
        monkeypatch.setattr(updater, "check_repo", lambda url: (True, ""))
        assert finder.is_repo("https://example.org/x") is True
        monkeypatch.setattr(updater, "check_repo", lambda url: (False, "не должен вызываться"))
        assert finder.is_repo("https://example.org/x") is True

    def test_cached_negative_returned(self, finder, monkeypatch):
        monkeypatch.setattr(updater, "check_repo", lambda url: (False, "нет такого"))
        assert finder.is_repo("https://example.org/x") is False
        monkeypatch.setattr(updater, "check_repo", lambda url: (True, ""))
        assert finder.is_repo("https://example.org/x") is False

    def test_preloaded_cache_used(self, monkeypatch, tmp_path):
        monkeypatch.setattr(updater, "load_cache", lambda kind: {"https://example.org/known": True})
        monkeypatch.setattr(updater, "check_repo", lambda url: (False, "не должен вызываться"))
        assert RefFinder(str(tmp_path / "нет.json")).is_repo("https://example.org/known") is True


class TestDumpRepos:
    """В кеш идут только подтверждённые репозитории: неудача может быть временной."""

    def _dumped(self, finder, monkeypatch):
        saved = {}
        monkeypatch.setattr(updater, "dump_cache", lambda kind, data: saved.setdefault(kind, data))
        finder.dump_repos()
        return saved

    def test_only_successful_checks_saved(self, finder, monkeypatch):
        monkeypatch.setattr(updater, "check_repo", lambda url: (url.endswith("good"), ""))
        finder.is_repo("https://example.org/good")
        finder.is_repo("https://example.org/bad")
        assert self._dumped(finder, monkeypatch)["vcs"] == {"https://example.org/good": True}

    def test_saved_under_vcs_key(self, finder, monkeypatch):
        monkeypatch.setattr(updater, "check_repo", lambda url: (True, ""))
        finder.is_repo("https://example.org/good")
        assert list(self._dumped(finder, monkeypatch)) == ["vcs"]


class TestAnalyseUrls:
    """Отбор кандидатов: возвращается только подтверждённый адрес."""

    def test_git_scheme_rewritten_to_https(self, finder, monkeypatch):
        checked = []
        monkeypatch.setattr(updater, "check_repo", lambda url: (checked.append(url), (True, ""))[1])
        assert finder._analyse_urls(["git://github.com/psf/requests"], "pkg:pypi/requests@1", "") == (
            "https://github.com/psf/requests"
        )
        assert checked == ["https://github.com/psf/requests"]

    def test_nothing_confirmed_returns_none(self, finder, monkeypatch):
        monkeypatch.setattr(updater, "check_repo", lambda url: (False, "не репозиторий"))
        assert finder._analyse_urls(["https://example.org/a", "https://example.org/b"], "pkg:pypi/x@1", "") is None

    def test_first_confirmed_wins(self, finder, monkeypatch):
        monkeypatch.setattr(updater, "check_repo", lambda url: (url.endswith("b"), ""))
        urls = ["https://example.org/a", "https://example.org/b", "https://example.org/c"]
        assert finder._analyse_urls(urls, "pkg:pypi/x@1", "") == "https://example.org/b"

    def test_non_string_candidates_skipped(self, finder, monkeypatch):
        monkeypatch.setattr(updater, "check_repo", lambda url: (True, ""))
        assert finder._analyse_urls([None, {"url": "x"}, "https://example.org/a"], "pkg:pypi/x@1", "") == (
            "https://example.org/a"
        )


class TestProcessPurlFallback:
    """Если ecosyste.ms не помог, подключается резолвер экосистемы — по префиксу purl."""

    @responses.activate
    def test_ecosystem_resolver_used_when_ecosystems_silent(self, finder, monkeypatch):
        responses.get("https://packages.ecosyste.ms/api/v1/packages/lookup", json=[])
        responses.get(
            "https://pypi.org/pypi/requests/json",
            json={"info": {"project_urls": {"Source": "https://github.com/psf/requests"}}},
        )
        monkeypatch.setattr(updater, "check_repo", lambda url: (True, ""))
        assert finder.process_purl("pkg:pypi/requests@2.32.5") == "https://github.com/psf/requests"

    @responses.activate
    def test_urls_found_but_none_is_repo_gives_placeholder(self, finder, monkeypatch):
        responses.get(
            "https://packages.ecosyste.ms/api/v1/packages/lookup",
            json=[{"repository_url": "https://example.org/dead", "homepage": "https://example.org/page"}],
        )
        responses.get("https://pypi.org/pypi/dead/json", status=404)
        monkeypatch.setattr(updater, "check_repo", lambda url: (False, "нет"))
        assert finder.process_purl("pkg:pypi/dead@1.0") == "sbom-updater_generated_placeholder:"

    @responses.activate
    def test_unknown_ecosystem_gives_placeholder(self, finder, monkeypatch):
        responses.get("https://packages.ecosyste.ms/api/v1/packages/lookup", json=[])
        monkeypatch.setattr(updater, "check_repo", lambda url: (False, "нет"))
        assert finder.process_purl("pkg:cargo/serde@1.0") == "sbom-updater_generated_placeholder:"


class TestEcosystemsRequest:
    @responses.activate
    def test_purl_lowercased_in_query(self, finder):
        responses.get("https://packages.ecosyste.ms/api/v1/packages/lookup", json=[])
        finder._ecosystems("pkg:maven/org.Apache/Commons-IO@2.11.0")
        assert "purl=pkg:maven/org.apache/commons-io@2.11.0" in responses.calls[0].request.url

    @responses.activate
    def test_candidate_order_is_repository_registry_homepage(self, finder):
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
        assert finder._ecosystems("pkg:pypi/requests@2.32.5") == [
            "https://github.com/psf/requests",
            "https://pypi.org/project/requests",
            "https://requests.readthedocs.io",
        ]


class TestPypiResolverKeys:
    """PyPI отдаёт ключи project_urls в произвольном регистре и с пробелами."""

    @responses.activate
    def test_lowercase_key_matched(self, finder):
        responses.get(
            "https://pypi.org/pypi/pkg/json",
            json={"info": {"project_urls": {"source code": "https://github.com/org/pkg"}}},
        )
        assert finder._pypi_purl("pkg:pypi/pkg@1.0") == ["https://github.com/org/pkg"]

    @responses.activate
    def test_spacing_ignored(self, finder):
        responses.get(
            "https://pypi.org/pypi/pkg/json",
            json={"info": {"project_urls": {"SourceCode": "https://github.com/org/pkg"}}},
        )
        assert finder._pypi_purl("pkg:pypi/pkg@1.0") == ["https://github.com/org/pkg"]

    @responses.activate
    def test_key_order_defines_priority(self, finder):
        responses.get(
            "https://pypi.org/pypi/pkg/json",
            json={
                "info": {
                    "project_urls": {
                        "homepage": "https://pkg.example.org",
                        "repository": "https://github.com/org/pkg",
                    }
                }
            },
        )
        assert finder._pypi_purl("pkg:pypi/pkg@1.0") == ["https://github.com/org/pkg", "https://pkg.example.org"]


class TestNpmRepositoryShapes:
    """npm допускает сокращённую строковую форму repository — она не должна ронять обработку."""

    @responses.activate
    def test_string_repository_does_not_crash(self, finder):
        responses.get(
            "https://registry.npmjs.org/tiny",
            json={"repository": "github:stevemao/tiny", "homepage": "https://example.org/tiny"},
        )
        assert finder._npm_purl("pkg:npm/tiny@1.0.0") == ["https://example.org/tiny"]

    @responses.activate
    def test_string_repository_survives_process_purl(self, finder, monkeypatch):
        responses.get("https://packages.ecosyste.ms/api/v1/packages/lookup", json=[])
        responses.get("https://registry.npmjs.org/tiny", json={"repository": "github:stevemao/tiny"})
        monkeypatch.setattr(updater, "check_repo", lambda url: (True, ""))
        assert finder.process_purl("pkg:npm/tiny@1.0.0") == "sbom-updater_generated_placeholder:"

    @responses.activate
    def test_git_protocol_url_normalized(self, finder):
        responses.get(
            "https://registry.npmjs.org/tiny",
            json={"repository": {"url": "git://github.com/stevemao/tiny.git"}},
        )
        assert finder._npm_purl("pkg:npm/tiny@1.0.0") == ["https://github.com/stevemao/tiny"]


class TestMavenResolver:
    def _solr(self, docs):
        responses.get(
            "https://search.maven.org/solrsearch/select",
            json={"response": {"docs": docs}},
        )

    @responses.activate
    def test_scm_url_taken_from_pom(self, finder):
        self._solr([{"latestVersion": "2.11.0"}])
        responses.get(
            "https://repo1.maven.org/maven2/commons-io/commons-io/2.11.0/commons-io-2.11.0.pom",
            body="<project><scm><url>https://github.com/apache/commons-io</url></scm></project>",
        )
        assert finder._maven_purl("pkg:maven/commons-io/commons-io@2.11.0") == ["https://github.com/apache/commons-io"]

    @responses.activate
    def test_scm_connection_prefix_stripped(self, finder):
        self._solr([{"latestVersion": "2.11.0"}])
        responses.get(
            "https://repo1.maven.org/maven2/commons-io/commons-io/2.11.0/commons-io-2.11.0.pom",
            body=(
                "<project><scm><connection>scm:git:git://github.com/apache/commons-io.git</connection></scm></project>"
            ),
        )
        assert finder._maven_purl("pkg:maven/commons-io/commons-io@2.11.0") == ["https://github.com/apache/commons-io"]

    @responses.activate
    def test_no_version_means_no_pom_request(self, finder):
        self._solr([{"a": "commons-io"}])
        assert finder._maven_purl("pkg:maven/commons-io/commons-io@2.11.0") == []

    @responses.activate
    def test_empty_docs_return_empty(self, finder):
        self._solr([])
        assert finder._maven_purl("pkg:maven/commons-io/commons-io@2.11.0") == []

    def test_purl_without_group_returns_empty(self, finder):
        assert finder._maven_purl("pkg:maven/commons-io@2.11.0") == []


class TestNugetResolver:
    def _index(self):
        responses.get(
            "https://api.nuget.org/v3/index.json",
            json={"resources": [{"@type": "PackageBaseAddress/3.0.0", "@id": "https://nuget.example/v3-flat/"}]},
        )

    @responses.activate
    def test_package_name_cut_from_purl(self, finder):
        self._index()
        responses.get(
            "https://nuget.example/v3-flat/newtonsoft.json/13.0.1/newtonsoft.json.nuspec",
            body="<package><metadata><projectUrl>https://www.newtonsoft.com/json</projectUrl></metadata></package>",
        )
        assert finder._nuget_purl("pkg:nuget/Newtonsoft.Json@13.0.1") == ["https://www.newtonsoft.com/json"]

    @responses.activate
    def test_repository_url_wins_over_project_url(self, finder):
        self._index()
        responses.get(
            "https://nuget.example/v3-flat/newtonsoft.json/13.0.1/newtonsoft.json.nuspec",
            body=(
                "<package><metadata><projectUrl>https://www.newtonsoft.com/json</projectUrl>"
                '<repository url="https://github.com/JamesNK/Newtonsoft.Json" /></metadata></package>'
            ),
        )
        assert finder._nuget_purl("pkg:nuget/Newtonsoft.Json@13.0.1")[0] == (
            "https://github.com/JamesNK/Newtonsoft.Json"
        )


class TestGemResolver:
    @responses.activate
    def test_source_code_uri_preferred(self, finder):
        responses.get(
            "https://rubygems.org/api/v2/rubygems/rails/versions/7.0.4.json",
            json={
                "homepage_uri": "https://rubyonrails.org",
                "metadata": {"source_code_uri": "https://github.com/rails/rails"},
            },
        )
        assert finder._gem_purl("pkg:gem/rails@7.0.4")[0] == "https://github.com/rails/rails"

    @responses.activate
    def test_falls_back_to_homepage(self, finder):
        responses.get(
            "https://rubygems.org/api/v2/rubygems/rails/versions/7.0.4.json",
            json={"homepage_uri": "https://rubyonrails.org", "metadata": {}},
        )
        assert finder._gem_purl("pkg:gem/rails@7.0.4") == ["https://rubyonrails.org"]

    @responses.activate
    def test_api_failure_returns_empty(self, finder):
        responses.get("https://rubygems.org/api/v2/rubygems/rails/versions/7.0.4.json", status=404)
        assert finder._gem_purl("pkg:gem/rails@7.0.4") == []


class TestDistroResolverDetails:
    def test_rpm_candidates_are_complete(self, finder):
        assert finder._rpm_purl("pkg:rpm/fedora/curl@8.0.1") == [
            "https://src.fedoraproject.org/rpms/curl",
            "https://gitlab.com/redhat/centos-stream/rpms/curl",
            "https://git.rockylinux.org/staging/rpms/curl",
        ]

    @responses.activate
    def test_deb_falls_back_to_versions_list(self, finder):
        responses.get(
            "https://sources.debian.org/api/src/curl/",
            json={"info": {}, "versions": [{"area": "main"}, {"vcs_git": "https://git.example.org/debian/curl.git"}]},
        )
        assert finder._deb_purl("pkg:deb/debian/curl@7.88.1")[0] == "https://git.example.org/debian/curl"

    @responses.activate
    def test_deb_altlinux_candidates_present(self, finder):
        responses.get("https://sources.debian.org/api/src/curl/", status=404)
        urls = finder._deb_purl("pkg:deb/debian/curl@7.88.1")
        assert "https://git.altlinux.org/gears/c/curl.git" in urls
        assert "https://git.altlinux.org/srpms/c/curl.git" in urls


class FakeRefFinder:
    """Подмена RefFinder: возвращает заранее заданные адреса, в сеть не ходит."""

    instances = []

    def __init__(self, purl_file=None):
        self.purl_file = purl_file
        self.seen = []
        self.dumped = False
        FakeRefFinder.instances.append(self)

    def process_purl(self, purl):
        self.seen.append(purl)
        return f"https://example.org/{purl.split('/')[-1].split('@')[0]}"

    def is_repo(self, url):
        return False

    def dump_repos(self):
        self.dumped = True


@pytest.fixture
def fake_finder(monkeypatch):
    FakeRefFinder.instances = []
    monkeypatch.setattr(updater, "RefFinder", FakeRefFinder)
    return FakeRefFinder


class TestSetProp:
    """Значение GOST-свойства заменяется, а не дублируется: повторный прогон не портит перечень."""

    def test_existing_value_replaced(self):
        props = [{"name": "GOST:attack_surface", "value": "no"}]
        updater._set_prop(props, "GOST:attack_surface", "yes")
        assert props == [{"name": "GOST:attack_surface", "value": "yes"}]

    def test_new_property_appended(self):
        props = [{"name": "GOST:security_function", "value": "no"}]
        updater._set_prop(props, "GOST:attack_surface", "yes")
        assert len(props) == 2

    def test_repeated_calls_do_not_duplicate(self):
        props = []
        for value in ("no", "yes", "indirect"):
            updater._set_prop(props, "GOST:attack_surface", value)
        assert props == [{"name": "GOST:attack_surface", "value": "indirect"}]


class TestGostMapResolution:
    """Приоритет источников: указанный в CLI файл важнее лежащего в рабочей директории."""

    def _write(self, path, value):
        path.write_text(json.dumps({"GOST:attack_surface": {"pkg:pypi/requests@2.32.5": value}}), encoding="utf-8")

    def test_cli_path_wins_over_cwd_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        self._write(tmp_path / ".purl_to_gost.json", "no")
        cli_map = tmp_path / "явный.json"
        self._write(cli_map, "indirect")
        assert updater._load_purl_to_gost(str(cli_map))["GOST:attack_surface"] == {
            "pkg:pypi/requests@2.32.5": "indirect"
        }

    def test_cwd_file_used_without_cli_path(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        self._write(tmp_path / ".purl_to_gost.json", "no")
        assert updater._load_purl_to_gost(None)["GOST:attack_surface"] == {"pkg:pypi/requests@2.32.5": "no"}

    def test_missing_cli_path_is_an_error(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            updater._resolve_purl_to_gost(str(tmp_path / "нет.json"))

    def test_no_sources_gives_empty_mapping(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert updater._load_purl_to_gost(None) == {}


class TestRunFixAll:
    """`--fix-all` дозаполняет пропуски, но не переписывает то, что уже заполнено."""

    def test_spec_version_normalized(self, tmp_path):
        bom = make_bom([make_component("requests", "2.32.5")])
        bom["specVersion"] = "1.4"
        path = tmp_path / "bom.json"
        path.write_text(json.dumps(bom), encoding="utf-8")
        updater.run(update_args(tmp_path, path, fix_all=True))
        assert json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))["specVersion"] == "1.6"

    def test_existing_product_name_kept(self, tmp_path):
        bom = make_bom([make_component("requests", "2.32.5")])
        bom["metadata"]["component"]["name"] = "МойПродукт"
        path = tmp_path / "bom.json"
        path.write_text(json.dumps(bom, ensure_ascii=False), encoding="utf-8")
        updater.run(update_args(tmp_path, path, fix_all=True))
        mc = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))["metadata"]["component"]
        assert mc["name"] == "МойПродукт"

    def test_missing_product_name_filled_with_placeholder(self, tmp_path):
        bom = make_bom([make_component("requests", "2.32.5")])
        del bom["metadata"]["component"]["name"]
        path = tmp_path / "bom.json"
        path.write_text(json.dumps(bom, ensure_ascii=False), encoding="utf-8")
        updater.run(update_args(tmp_path, path, fix_all=True))
        mc = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))["metadata"]["component"]
        assert mc["name"] == updater.DEFAULT_VALUE

    def test_existing_manufacturer_kept(self, tmp_path):
        bom = make_bom([make_component("requests", "2.32.5")])
        bom["metadata"]["component"]["manufacturer"] = {"name": "ООО Изготовитель"}
        path = tmp_path / "bom.json"
        path.write_text(json.dumps(bom, ensure_ascii=False), encoding="utf-8")
        updater.run(update_args(tmp_path, path, fix_all=True))
        mc = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))["metadata"]["component"]
        assert mc["manufacturer"]["name"] == "ООО Изготовитель"

    def test_missing_manufacturer_filled_with_placeholder(self, tmp_path):
        bom = make_bom([make_component("requests", "2.32.5")])
        del bom["metadata"]["component"]["manufacturer"]
        path = tmp_path / "bom.json"
        path.write_text(json.dumps(bom, ensure_ascii=False), encoding="utf-8")
        updater.run(update_args(tmp_path, path, fix_all=True))
        mc = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))["metadata"]["component"]
        assert mc["manufacturer"]["name"] == updater.DEFAULT_VALUE


class TestRunDocumentVersion:
    def test_version_incremented(self, tmp_path):
        path = write_bom(tmp_path, [make_component("requests", "2.32.5")])
        updater.run(update_args(tmp_path, path, props=True))
        assert json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))["version"] == 2

    def test_encoding_of_input_preserved(self, tmp_path):
        path = tmp_path / "bom.json"
        path.write_text(json.dumps(make_bom([make_component("requests", "2.32.5")])), encoding="utf-8-sig")
        updater.run(update_args(tmp_path, path, props=True))
        assert (tmp_path / "out.json").read_bytes().startswith(b"\xef\xbb\xbf")


class TestRunNestedComponents:
    """Вложенные компоненты контейнерных SBOM должны обрабатываться наравне с верхними."""

    def _nested_bom(self, tmp_path):
        child = make_component("urllib3", "2.2.0")
        parent = make_component("requests", "2.32.5")
        parent["components"] = [child]
        return write_bom(tmp_path, [parent])

    def _nested_props(self, tmp_path):
        data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
        nested = data["components"][0]["components"][0]
        return {p["name"]: p["value"] for p in nested["properties"]}

    def test_props_reaches_nested(self, tmp_path):
        updater.run(update_args(tmp_path, self._nested_bom(tmp_path), props=True))
        assert self._nested_props(tmp_path)["GOST:attack_surface"] == "yes"

    def test_gost_reaches_nested(self, tmp_path):
        mapping = tmp_path / "gost.json"
        mapping.write_text(
            json.dumps({"GOST:attack_surface": {"pkg:pypi/urllib3@2.2.0": "indirect"}}), encoding="utf-8"
        )
        updater.run(update_args(tmp_path, self._nested_bom(tmp_path), gost=True, purl_to_gost=str(mapping)))
        assert self._nested_props(tmp_path)["GOST:attack_surface"] == "indirect"


class TestRunGostDetails:
    def test_gost_wins_over_props(self, tmp_path):
        """`--gost` и `--props` взаимоисключающи: точный маппинг не затирается грубым «yes»."""
        mapping = tmp_path / "gost.json"
        mapping.write_text(
            json.dumps({"GOST:attack_surface": {"pkg:pypi/requests@2.32.5": "indirect"}}), encoding="utf-8"
        )
        path = write_bom(tmp_path, [make_component("requests", "2.32.5")])
        updater.run(update_args(tmp_path, path, gost=True, props=True, purl_to_gost=str(mapping)))
        data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
        props = {p["name"]: p["value"] for p in data["components"][0]["properties"]}
        assert props["GOST:attack_surface"] == "indirect"

    def test_provided_by_not_added_without_mapping(self, tmp_path):
        mapping = tmp_path / "gost.json"
        mapping.write_text(json.dumps({"GOST:attack_surface": {}}), encoding="utf-8")
        path = write_bom(tmp_path, [make_component("requests", "2.32.5")])
        updater.run(update_args(tmp_path, path, gost=True, purl_to_gost=str(mapping)))
        data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
        assert all(p["name"] != "GOST:provided_by" for p in data["components"][0]["properties"])

    def test_provided_by_added_from_mapping(self, tmp_path):
        mapping = tmp_path / "gost.json"
        mapping.write_text(
            json.dumps({"GOST:provided_by": {"pkg:pypi/requests@2.32.5": "СЗИ «Аврора»"}}), encoding="utf-8"
        )
        path = write_bom(tmp_path, [make_component("requests", "2.32.5")])
        updater.run(update_args(tmp_path, path, gost=True, purl_to_gost=str(mapping)))
        data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
        props = {p["name"]: p["value"] for p in data["components"][0]["properties"]}
        assert props["GOST:provided_by"] == "СЗИ «Аврора»"

    def test_repeated_run_does_not_duplicate_properties(self, tmp_path):
        mapping = tmp_path / "gost.json"
        mapping.write_text(
            json.dumps({"GOST:attack_surface": {"pkg:pypi/requests@2.32.5": "indirect"}}), encoding="utf-8"
        )
        path = write_bom(tmp_path, [make_component("requests", "2.32.5")])
        updater.run(update_args(tmp_path, path, gost=True, purl_to_gost=str(mapping)))
        updater.run(
            update_args(
                tmp_path,
                tmp_path / "out.json",
                output=str(tmp_path / "out2.json"),
                gost=True,
                purl_to_gost=str(mapping),
            )
        )
        data = json.loads((tmp_path / "out2.json").read_text(encoding="utf-8"))
        names = [p["name"] for p in data["components"][0]["properties"]]
        assert names.count("GOST:attack_surface") == 1


class TestRunRef:
    """Поиск VCS-ссылок: `--ref` работает сам по себе и не портит готовые ссылки."""

    def test_ref_alone_triggers_search(self, tmp_path, fake_finder):
        path = write_bom(tmp_path, [make_component("requests", "2.32.5")])
        updater.run(update_args(tmp_path, path, ref=True))
        data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
        assert data["components"][0]["externalReferences"] == [{"type": "vcs", "url": "https://example.org/requests"}]

    def test_existing_references_not_touched(self, tmp_path, fake_finder):
        comp = make_component("requests", "2.32.5")
        comp["externalReferences"] = [{"type": "vcs", "url": "https://github.com/psf/requests"}]
        path = write_bom(tmp_path, [comp])
        updater.run(update_args(tmp_path, path, ref=True))
        data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
        assert data["components"][0]["externalReferences"][0]["url"] == "https://github.com/psf/requests"
        assert fake_finder.instances[0].seen == []

    def test_component_without_purl_gets_no_reference(self, tmp_path, fake_finder):
        comp = {"type": "library", "name": "самописный модуль", "version": "1.0.0"}
        path = write_bom(tmp_path, [comp])
        updater.run(update_args(tmp_path, path, ref=True))
        data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
        assert "externalReferences" not in data["components"][0]

    def test_cache_dumped_after_search(self, tmp_path, fake_finder):
        path = write_bom(tmp_path, [make_component("requests", "2.32.5")])
        updater.run(update_args(tmp_path, path, ref=True))
        assert fake_finder.instances[0].dumped is True

    def test_nested_components_searched(self, tmp_path, fake_finder):
        parent = make_component("requests", "2.32.5")
        parent["components"] = [make_component("urllib3", "2.2.0")]
        path = write_bom(tmp_path, [parent])
        updater.run(update_args(tmp_path, path, ref=True))
        assert sorted(fake_finder.instances[0].seen) == ["pkg:pypi/requests@2.32.5", "pkg:pypi/urllib3@2.2.0"]

    def test_no_search_without_ref_flag(self, tmp_path, fake_finder):
        path = write_bom(tmp_path, [make_component("requests", "2.32.5")])
        updater.run(update_args(tmp_path, path, props=True))
        assert fake_finder.instances == []


class TestRunUpdate:
    """`--update` переносит уже выверенные данные из прежней ревизии перечня."""

    def _old_bom(self, tmp_path, components, metadata=None):
        bom = make_bom(components)
        if metadata:
            bom["metadata"]["component"].update(metadata)
        path = tmp_path / "old.json"
        path.write_text(json.dumps(bom, ensure_ascii=False), encoding="utf-8")
        return path

    def _result(self, tmp_path, new_components, old_path, **overrides):
        path = write_bom(tmp_path, new_components)
        updater.run(update_args(tmp_path, path, update=str(old_path), **overrides))
        return json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))

    def test_properties_carried_over(self, tmp_path):
        old = make_component("requests", "2.32.5", properties=[{"name": "GOST:attack_surface", "value": "indirect"}])
        data = self._result(tmp_path, [make_component("requests", "2.32.5")], self._old_bom(tmp_path, [old]))
        props = {p["name"]: p["value"] for p in data["components"][0]["properties"]}
        assert props["GOST:attack_surface"] == "indirect"

    def test_references_carried_over(self, tmp_path):
        old = make_component("requests", "2.32.5")
        old["externalReferences"] = [{"type": "vcs", "url": "https://github.com/psf/requests"}]
        data = self._result(tmp_path, [make_component("requests", "2.32.5")], self._old_bom(tmp_path, [old]))
        assert data["components"][0]["externalReferences"][0]["url"] == "https://github.com/psf/requests"

    def test_other_version_not_matched(self, tmp_path):
        old = make_component("requests", "2.31.0", properties=[{"name": "GOST:attack_surface", "value": "indirect"}])
        data = self._result(tmp_path, [make_component("requests", "2.32.5")], self._old_bom(tmp_path, [old]))
        assert "properties" not in data["components"][0]

    def test_new_component_left_alone(self, tmp_path):
        old = make_component("requests", "2.32.5", properties=[{"name": "GOST:attack_surface", "value": "indirect"}])
        data = self._result(tmp_path, [make_component("flask", "3.0.0")], self._old_bom(tmp_path, [old]))
        assert "properties" not in data["components"][0]

    def test_nested_components_matched(self, tmp_path):
        old_child = make_component("urllib3", "2.2.0", properties=[{"name": "GOST:attack_surface", "value": "yes"}])
        old_parent = make_component("requests", "2.32.5")
        old_parent["components"] = [old_child]
        new_parent = make_component("requests", "2.32.5")
        new_parent["components"] = [make_component("urllib3", "2.2.0")]
        data = self._result(tmp_path, [new_parent], self._old_bom(tmp_path, [old_parent]))
        nested = data["components"][0]["components"][0]
        assert nested["properties"] == [{"name": "GOST:attack_surface", "value": "yes"}]

    def test_product_name_taken_when_missing(self, tmp_path):
        old_path = self._old_bom(tmp_path, [], {"name": "Прежний продукт", "version": "1.0"})
        bom = make_bom([])
        del bom["metadata"]["component"]["name"]
        path = tmp_path / "bom.json"
        path.write_text(json.dumps(bom, ensure_ascii=False), encoding="utf-8")
        updater.run(update_args(tmp_path, path, update=str(old_path)))
        mc = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))["metadata"]["component"]
        assert mc["name"] == "Прежний продукт"

    def test_existing_product_name_not_overwritten(self, tmp_path):
        old_path = self._old_bom(tmp_path, [], {"name": "Прежний продукт"})
        data = self._result(tmp_path, [], old_path)
        assert data["metadata"]["component"]["name"] != "Прежний продукт"
