# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

"""Тесты общих утилит: загрузка JSON, разбор VCS-URL, проверка репозиториев."""

import json
import subprocess

import pytest
import requests

from efs import utils
from efs.utils import (
    combine_source_langs,
    get_prop,
    get_props,
    is_archive_url,
    opener,
    parse_repo_url,
    source_reference,
    validate_no_duplicate_keys,
)


class TestOpener:
    def test_reads_utf8(self, write_json):
        path = write_json("bom.json", {"название": "значение"})
        data, encoding = opener(str(path))
        assert data == {"название": "значение"}
        assert encoding is None

    def test_reads_utf8_with_bom_signature(self, write_json):
        raw = "﻿".encode() + json.dumps({"a": 1}).encode("utf-8")
        path = write_json("bom.json", None, raw=raw)
        data, encoding = opener(str(path))
        assert data == {"a": 1}
        assert encoding == "utf-8-sig"

    def test_duplicate_keys_rejected(self, write_json):
        path = write_json("bom.json", None, raw=b'{"name": "a", "name": "b"}')
        with pytest.raises(ValueError, match="Duplicate key"):
            opener(str(path), pairs=True)

    def test_duplicate_keys_allowed_without_pairs(self, write_json):
        path = write_json("bom.json", None, raw=b'{"name": "a", "name": "b"}')
        data, _ = opener(str(path))
        assert data == {"name": "b"}


class TestValidateNoDuplicateKeys:
    def test_lists_all_duplicates(self):
        with pytest.raises(ValueError, match="a, b"):
            validate_no_duplicate_keys([("a", 1), ("a", 2), ("b", 3), ("b", 4)])

    def test_returns_dict_when_unique(self):
        assert validate_no_duplicate_keys([("a", 1), ("b", 2)]) == {"a": 1, "b": 2}


class TestParseRepoUrl:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://github.com/psf/requests/tree/v2.32.5", ("https://github.com/psf/requests", "v2.32.5")),
            (
                "https://github.com/psf/requests/releases/tag/v2.32.5",
                ("https://github.com/psf/requests", "v2.32.5"),
            ),
            ("https://gitlab.com/g/p/-/commit/abc123", ("https://gitlab.com/g/p", "abc123")),
            ("https://example.org/repo?commit=deadbeef", ("https://example.org/repo", "deadbeef")),
            ("https://example.org/repo?tag=v1.0", ("https://example.org/repo", "v1.0")),
        ],
    )
    def test_splits_repo_and_revision(self, url, expected):
        assert parse_repo_url(url) == expected

    def test_returns_none_without_revision(self):
        assert parse_repo_url("https://github.com/psf/requests") is None


class TestGetProp:
    def test_finds_value(self):
        props = [{"name": "GOST:attack_surface", "value": "yes"}]
        assert get_prop(props, "GOST:attack_surface") == "yes"

    def test_missing_returns_empty_string(self):
        assert get_prop([{"name": "other", "value": "x"}], "GOST:attack_surface") == ""

    def test_empty_list(self):
        assert get_prop([], "any") == ""


class TestCombineSourceLangs:
    def test_merges_without_duplicates(self):
        assert combine_source_langs("C, Python", "Python, Rust") == "C, Python, Rust"

    def test_one_side_empty(self):
        assert combine_source_langs("", "Python") == "Python"
        assert combine_source_langs("Python", "") == "Python"


class TestCheckRepo:
    """check_repo обращается к git/svn/hg — все вызовы подменяются."""

    def test_git_success(self, monkeypatch):
        def fake_run(cmd, **kwargs):
            assert cmd.startswith("git ls-remote")
            assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"
            return subprocess.CompletedProcess(cmd, 0, stdout="ref", stderr="")

        monkeypatch.setattr(utils.subprocess, "run", fake_run)
        result, errors = utils.check_repo("https://github.com/psf/requests")
        assert result is True
        assert errors == ""

    def test_git_timeout_falls_back_to_http(self, monkeypatch):
        def fake_run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, 1)

        class FakeResponse:
            status_code = 200

        monkeypatch.setattr(utils.subprocess, "run", fake_run)
        monkeypatch.setattr(utils.requests, "head", lambda url, **kw: FakeResponse())
        result, _ = utils.check_repo("https://chromium.googlesource.com/chromium/src.git")
        assert result is True

    def test_git_timeout_http_error_reports_failure(self, monkeypatch):
        def fake_run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, 1)

        class FakeResponse:
            status_code = 404

        monkeypatch.setattr(utils.subprocess, "run", fake_run)
        monkeypatch.setattr(utils.requests, "head", lambda url, **kw: FakeResponse())
        result, errors = utils.check_repo("https://example.org/absent")
        assert result is False
        assert "404" in errors

    def test_falls_through_to_svn(self, monkeypatch):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            code = 0 if cmd.startswith("svn ls") else 1
            return subprocess.CompletedProcess(cmd, code, stdout="", stderr="err")

        monkeypatch.setattr(utils.subprocess, "run", fake_run)
        result, _ = utils.check_repo("https://svn.example.org/repo")
        assert result is True
        assert any(c.startswith("svn ls --non-interactive") for c in calls)

    def test_hg_called_non_interactively(self, monkeypatch):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            code = 0 if cmd.startswith("hg identify") else 1
            return subprocess.CompletedProcess(cmd, code, stdout="", stderr="err")

        monkeypatch.setattr(utils.subprocess, "run", fake_run)
        result, _ = utils.check_repo("https://hg.example.org/repo")
        assert result is True
        assert any("--noninteractive" in c for c in calls)


class TestIsArchiveUrl:
    def _session(self, headers, status=200):
        class FakeResponse:
            status_code = status

            def __init__(self):
                self.headers = headers

            def raise_for_status(self):
                pass

            def close(self):
                pass

        class FakeSession:
            def head(self, url, **kwargs):
                return FakeResponse()

            def get(self, url, **kwargs):
                return FakeResponse()

        return FakeSession()

    def test_archive_mime_type(self):
        session = self._session({"Content-Type": "application/zip"})
        result, _ = is_archive_url(session, "https://example.org/x")
        assert result is True

    def test_archive_detected_by_extension(self):
        session = self._session({"Content-Type": "text/html"})
        result, _ = is_archive_url(session, "https://example.org/pkg-1.0.tar.gz")
        assert result is True

    def test_not_an_archive(self):
        session = self._session({"Content-Type": "text/html"})
        result, errors = is_archive_url(session, "https://example.org/page")
        assert result is False
        assert "MIME" in errors

    def test_network_error_is_reported(self):
        class FailingSession:
            def head(self, url, **kwargs):
                raise requests.ConnectionError("нет сети")

        result, errors = is_archive_url(FailingSession(), "https://example.org/x")
        assert result is False
        assert "нет сети" in errors


class TestSourceReference:
    def test_vcs_url_used(self):
        comp = {"externalReferences": [{"type": "vcs", "url": "https://github.com/psf/requests"}]}
        assert source_reference(comp) == "Репозиторий: https://github.com/psf/requests"

    def test_source_distribution_used(self):
        comp = {"externalReferences": [{"type": "source-distribution", "url": "https://example.org/x.tar.gz"}]}
        assert "https://example.org/x.tar.gz" in source_reference(comp)

    def test_certified_product_named_when_no_link(self):
        """Компонент из состава СЗИ: вместо ссылки указывается само средство защиты."""
        comp = {"properties": [{"name": "GOST:provided_by", "value": "КриптоПро CSP"}]}
        assert source_reference(comp) == "Поставляется в составе сертифицированного СЗИ: КриптоПро CSP"

    def test_link_wins_over_certified_product(self):
        comp = {
            "externalReferences": [{"type": "vcs", "url": "https://github.com/x/y"}],
            "properties": [{"name": "GOST:provided_by", "value": "КриптоПро CSP"}],
        }
        assert source_reference(comp) == "Репозиторий: https://github.com/x/y"

    def test_placeholder_link_ignored(self):
        comp = {
            "externalReferences": [{"type": "vcs", "url": "TODO"}],
            "properties": [{"name": "GOST:provided_by", "value": "КриптоПро CSP"}],
        }
        assert "КриптоПро CSP" in source_reference(comp)

    def test_empty_when_nothing_known(self):
        assert source_reference({"name": "x"}) == ""


class FakeResponse:
    def __init__(self, headers=None, status=200, text=""):
        self.headers = headers or {}
        self.status_code = status
        self.text = text

    def raise_for_status(self):
        pass

    def close(self):
        pass


class RecordingSession:
    """Сессия, запоминающая аргументы запросов: проверяем не только результат, но и как спрашивали."""

    def __init__(self, head=None, get=None):
        self._head = head or FakeResponse()
        self._get = get or FakeResponse()
        self.calls = []

    def head(self, url, **kwargs):
        self.calls.append(("head", url, kwargs))
        return self._head

    def get(self, url, **kwargs):
        self.calls.append(("get", url, kwargs))
        return self._get


class TestArchiveDetection:
    def test_content_disposition_used_when_url_has_no_extension(self):
        """Дистрибутив часто отдаётся по «безрасширенному» адресу с именем файла в заголовке."""
        session = RecordingSession(
            head=FakeResponse(
                {"Content-Type": "text/html", "Content-Disposition": "attachment; filename=pkg-1.0.tar.gz"}
            )
        )
        result, _ = is_archive_url(session, "https://example.org/download?id=42")
        assert result is True

    def test_retry_with_get_when_head_not_allowed(self):
        session = RecordingSession(
            head=FakeResponse(status=405),
            get=FakeResponse({"Content-Type": "application/zip"}),
        )
        result, _ = is_archive_url(session, "https://example.org/x")
        assert result is True
        assert [call[0] for call in session.calls] == ["head", "get"]

    @pytest.mark.parametrize(
        "content_type",
        ["application/zip; charset=binary", "Application/Zip", "  application/zip  "],
    )
    def test_content_type_normalized(self, content_type):
        session = RecordingSession(head=FakeResponse({"Content-Type": content_type}))
        result, _ = is_archive_url(session, "https://example.org/x")
        assert result is True

    @pytest.mark.parametrize("mime", ["application/octet-stream", "application/x-rpm", "application/java-archive"])
    def test_common_archive_mimes_recognised(self, mime):
        session = RecordingSession(head=FakeResponse({"Content-Type": mime}))
        result, _ = is_archive_url(session, "https://example.org/x")
        assert result is True

    @pytest.mark.parametrize("suffix", [".whl", ".rpm", ".tar.gz", ".zip", ".src.rpm"])
    def test_archive_extensions_recognised(self, suffix):
        session = RecordingSession(head=FakeResponse({"Content-Type": "text/html"}))
        result, _ = is_archive_url(session, f"https://example.org/pkg-1.0{suffix}")
        assert result is True

    def test_uppercase_extension_recognised(self):
        session = RecordingSession(head=FakeResponse({"Content-Type": "text/html"}))
        result, _ = is_archive_url(session, "https://example.org/PKG-1.0.TAR.GZ")
        assert result is True

    def test_redirects_followed(self):
        """Архивы на зеркалах почти всегда за редиректом."""
        session = RecordingSession(head=FakeResponse({"Content-Type": "application/zip"}))
        is_archive_url(session, "https://example.org/x")
        assert session.calls[0][2].get("allow_redirects") is True


class TestRepositoryChecks:
    def _run_with(self, monkeypatch, results, head=None):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            for prefix, code in results.items():
                if cmd.startswith(prefix):
                    return subprocess.CompletedProcess(cmd, code, stdout="", stderr="err")
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="err")

        monkeypatch.setattr(utils.subprocess, "run", fake_run)
        if head is not None:
            monkeypatch.setattr(utils.requests, "head", head)
        return calls

    def test_git_asked_without_terminal_prompt(self, monkeypatch):
        """Переменная должна передаваться явно: полагаться на окружение процесса нельзя."""
        monkeypatch.delenv("GIT_TERMINAL_PROMPT", raising=False)
        calls = self._run_with(monkeypatch, {"git ls-remote": 0})
        utils.check_repo("https://github.com/psf/requests")
        env = calls[0][1]["env"]
        assert env["GIT_TERMINAL_PROMPT"] == "0"
        assert env["GIT_ASKPASS"] == ""

    def test_git_has_timeout(self, monkeypatch):
        calls = self._run_with(monkeypatch, {"git ls-remote": 0})
        utils.check_repo("https://github.com/psf/requests")
        assert calls[0][1]["timeout"] == utils.SP_TIMEOUT

    def test_http_fallback_strips_git_suffix(self, monkeypatch):
        asked = []

        def fake_run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, 1)

        def fake_head(url, **kwargs):
            asked.append((url, kwargs))
            return FakeResponse(status=200)

        monkeypatch.setattr(utils.subprocess, "run", fake_run)
        monkeypatch.setattr(utils.requests, "head", fake_head)
        result, _ = utils.check_repo("https://chromium.googlesource.com/chromium/src.git")
        assert result is True
        assert asked[0][0].endswith("/src")
        assert asked[0][1].get("allow_redirects") is True

    def test_fossil_requires_generated_footer(self, monkeypatch):
        """Страница, отдающая 200, ещё не fossil-репозиторий."""
        self._run_with(monkeypatch, {})
        monkeypatch.setattr(
            utils.requests, "get", lambda url, **kw: FakeResponse(status=200, text="<html>обычная страница</html>")
        )
        result, errors = utils.check_repo("https://example.org/что-то")
        assert result is False
        assert "FOSSIL" in errors

    def test_fossil_accepted_with_footer(self, monkeypatch):
        self._run_with(monkeypatch, {})
        footer = 'footer"> this page was generated in about 0.01s by fossil'
        monkeypatch.setattr(utils.requests, "get", lambda url, **kw: FakeResponse(status=200, text=footer))
        result, _ = utils.check_repo("https://fossil.example.org/repo")
        assert result is True


class TestRepoUrlParsing:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            (
                "https://bitbucket.org/team/proj/src/abc123",
                ("https://bitbucket.org/team/proj", "abc123"),
            ),
            (
                "https://codeberg.org/user/proj/src/branch/main",
                ("https://codeberg.org/user/proj", "main"),
            ),
            (
                "https://chromium.googlesource.com/chromium/src/+/refs/heads/main",
                ("https://chromium.googlesource.com/chromium/src", "main"),
            ),
        ],
    )
    def test_known_hosts_parsed(self, url, expected):
        assert parse_repo_url(url) == expected

    def test_multi_segment_revision_kept(self):
        """В ревизии остаётся путь к файлу целиком, а не только первый сегмент."""
        repo, revision = parse_repo_url("https://github.com/psf/requests/blob/main/src/requests/api.py")
        assert repo == "https://github.com/psf/requests"
        assert revision == "main/src/requests/api.py"

    def test_altlinux_defaults_to_head(self):
        repo, revision = parse_repo_url("https://git.altlinux.org/gears/c/curl.git?f=curl.spec")
        assert revision.startswith("HEAD/")

    def test_gitbox_project_from_query(self):
        repo, _ = parse_repo_url("https://gitbox.apache.org/repos/asf?p=maven.git;f=pom.xml;h=abc")
        assert repo.endswith("maven.git")


class TestPropertyHelpers:
    def test_get_prop_returns_first_occurrence(self):
        props = [
            {"name": "GOST:attack_surface", "value": "yes"},
            {"name": "GOST:attack_surface", "value": "no"},
        ]
        assert get_prop(props, "GOST:attack_surface") == "yes"

    def test_get_props_skips_empty_values(self):
        props = [
            {"name": "GOST:source_langs", "value": "Python"},
            {"name": "GOST:source_langs", "value": ""},
            {"name": "GOST:source_langs", "value": "C"},
        ]
        assert get_props(props, "GOST:source_langs") == ["Python", "C"]
