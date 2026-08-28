# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

"""Тесты общих утилит: загрузка JSON, разбор VCS-URL, проверка репозиториев."""

import json
import subprocess

import pytest
import requests

from efc import utils
from efc.utils import (
    combine_source_langs,
    get_prop,
    is_archive_url,
    opener,
    parse_repo_url,
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
