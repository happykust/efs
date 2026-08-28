# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

"""Тесты запуска сканеров. Внешние процессы не запускаются — subprocess подменяется."""

import json
import subprocess

import pytest

from efc import scanner


@pytest.fixture
def fake_subprocess(monkeypatch):
    """Подменяет subprocess.run и shutil.which, записывает вызовы."""
    calls = []

    def make(returncode=0, raise_timeout=False):
        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            if raise_timeout:
                raise subprocess.TimeoutExpired(cmd, 1)
            return subprocess.CompletedProcess(cmd, returncode, stdout="", stderr="ошибка")

        monkeypatch.setattr(scanner.subprocess, "run", fake_run)
        monkeypatch.setattr(scanner.shutil, "which", lambda tool: f"/usr/bin/{tool}")
        return calls

    return make


class TestRunCdxgen:
    def test_success(self, fake_subprocess, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        calls = fake_subprocess()
        assert scanner.run_cdxgen(".", "bom.json") is True
        assert calls[0] == ["cdxgen", "-o", "bom.json", "."]

    def test_writes_cdxgenrc_with_defaults(self, fake_subprocess, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        fake_subprocess()
        scanner.run_cdxgen(".", "bom.json")
        rc = json.loads((tmp_path / ".cdxgenrc").read_text(encoding="utf-8"))
        assert rc["spec-version"] == "1.6"
        assert rc["output"] == "bom.json"

    def test_options_override_defaults(self, fake_subprocess, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        fake_subprocess()
        scanner.run_cdxgen(".", "bom.json", {"profile": "research", "required-only": False})
        rc = json.loads((tmp_path / ".cdxgenrc").read_text(encoding="utf-8"))
        assert rc["profile"] == "research"
        assert rc["required-only"] is False

    def test_nonzero_exit_is_failure(self, fake_subprocess, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        fake_subprocess(returncode=1)
        assert scanner.run_cdxgen(".", "bom.json") is False

    def test_timeout_is_failure(self, fake_subprocess, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        fake_subprocess(raise_timeout=True)
        assert scanner.run_cdxgen(".", "bom.json") is False

    def test_missing_tool_is_failure(self, monkeypatch):
        monkeypatch.setattr(scanner.shutil, "which", lambda tool: None)
        assert scanner.run_cdxgen(".", "bom.json") is False


class TestRunTrivy:
    def test_default_command_is_fs(self, fake_subprocess):
        calls = fake_subprocess()
        assert scanner.run_trivy(".", "bom.json") is True
        assert calls[0] == ["trivy", "fs", "--format", "cyclonedx", "--output", "bom.json", "."]

    def test_custom_command_and_args(self, fake_subprocess):
        calls = fake_subprocess()
        scanner.run_trivy("img:latest", "bom.json", {"command": "image", "args": ["--scanners", "vuln"]})
        assert calls[0] == [
            "trivy",
            "image",
            "--format",
            "cyclonedx",
            "--output",
            "bom.json",
            "--scanners",
            "vuln",
            "img:latest",
        ]

    def test_timeout_is_failure(self, fake_subprocess):
        fake_subprocess(raise_timeout=True)
        assert scanner.run_trivy(".", "bom.json") is False


class TestRunScan:
    def test_dispatches_to_cdxgen(self, fake_subprocess, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        calls = fake_subprocess()
        assert scanner.run_scan("cdxgen", ".", "bom.json") is True
        assert calls[0][0] == "cdxgen"

    def test_dispatches_to_trivy(self, fake_subprocess):
        calls = fake_subprocess()
        assert scanner.run_scan("trivy", ".", "bom.json") is True
        assert calls[0][0] == "trivy"

    def test_unknown_tool_reports_failure(self):
        assert scanner.run_scan("syft", ".", "bom.json") is False
