# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

"""Тесты пошагового мастера. Вопросы questionary подменяются заготовленными ответами."""

import json

import pytest

from efs import init_wizard

from .conftest import make_bom, make_component


class FakeQuestion:
    def __init__(self, answer, log, kind, message):
        self._answer = answer
        log.append((kind, message))

    def ask(self):
        return self._answer


@pytest.fixture
def answers(monkeypatch):
    """Подменяет questionary: ответы берутся из очереди, вопросы записываются."""
    queue = []
    asked = []

    def make(kind):
        def factory(message, **kwargs):
            answer = queue.pop(0) if queue else None
            return FakeQuestion(answer, asked, kind, message)

        return factory

    for kind in ("select", "text", "confirm"):
        monkeypatch.setattr(init_wizard.questionary, kind, make(kind))

    return type("Answers", (), {"queue": queue, "asked": asked})()


class TestScannerChoice:
    def test_returns_tool_and_filename(self, answers):
        answers.queue.extend(["trivy", "sbom.json"])
        assert init_wizard._step_scanner_choice() == ("trivy", "sbom.json")

    def test_cancel_on_tool_returns_none(self, answers):
        answers.queue.append(None)
        assert init_wizard._step_scanner_choice() is None

    def test_cancel_on_filename_returns_none(self, answers):
        answers.queue.extend(["cdxgen", None])
        assert init_wizard._step_scanner_choice() is None


class TestScanStep:
    def test_runs_scanner_with_answers(self, answers, monkeypatch):
        calls = []
        monkeypatch.setattr(
            "efs.scanner.run_scan",
            lambda tool, target, output, options=None: calls.append((tool, target, output)) or True,
        )
        answers.queue.extend([True, "./src"])

        assert init_wizard._step_scan("trivy", "bom.json") is True
        assert calls == [("trivy", "./src", "bom.json")]

    def test_declined_scan_does_not_run_tool(self, answers, monkeypatch):
        called = []
        monkeypatch.setattr("efs.scanner.run_scan", lambda *a, **kw: called.append(1) or True)
        answers.queue.append(False)

        assert init_wizard._step_scan("cdxgen", "bom.json") is False
        assert called == []


class TestConfigStep:
    def test_creates_config_with_scanner_section(self, answers, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "bom.json").write_text(
            json.dumps(make_bom([make_component("requests", "2.32.5")]), ensure_ascii=False), encoding="utf-8"
        )
        answers.queue.append(True)

        init_wizard._step_config("bom.json", "trivy")

        config = json.loads((tmp_path / ".efs-config.json").read_text(encoding="utf-8"))
        assert config["scanner"] == {"tool": "trivy", "output": "bom.json", "target": ".", "options": {}}
        assert "pkg:pypi/requests" in config["components"]

    def test_declined_leaves_no_config(self, answers, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        answers.queue.append(False)

        init_wizard._step_config("bom.json", "cdxgen")
        assert not (tmp_path / ".efs-config.json").exists()

    def test_missing_sbom_reported_without_crash(self, answers, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        answers.queue.append(True)

        init_wizard._step_config("отсутствует.json", "cdxgen")

        assert "не найден" in capsys.readouterr().out
        assert not (tmp_path / ".efs-config.json").exists()


class TestVcsStep:
    def _prepare(self, tmp_path, config):
        (tmp_path / "bom.json").write_text(
            json.dumps(make_bom([make_component("requests", "2.32.5")]), ensure_ascii=False), encoding="utf-8"
        )
        (tmp_path / ".efs-config.json").write_text(json.dumps(config), encoding="utf-8")

    def test_found_url_written_to_config(self, answers, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        self._prepare(tmp_path, {"components": {}})
        monkeypatch.setattr("efs.updater.RefFinder", _FakeRefFinder("https://github.com/psf/requests"))
        answers.queue.append(True)

        init_wizard._step_vcs_refs("bom.json")

        config = json.loads((tmp_path / ".efs-config.json").read_text(encoding="utf-8"))
        assert config["components"]["pkg:pypi/requests"]["vcs"] == "https://github.com/psf/requests"

    def test_existing_vcs_not_overwritten(self, answers, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        self._prepare(tmp_path, {"components": {"pkg:pypi/requests": {"vcs": "https://example.org/mine"}}})
        monkeypatch.setattr("efs.updater.RefFinder", _FakeRefFinder("https://github.com/psf/requests"))
        answers.queue.append(True)

        init_wizard._step_vcs_refs("bom.json")

        config = json.loads((tmp_path / ".efs-config.json").read_text(encoding="utf-8"))
        assert config["components"]["pkg:pypi/requests"]["vcs"] == "https://example.org/mine"

    def test_placeholder_url_not_written(self, answers, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        self._prepare(tmp_path, {"components": {}})
        monkeypatch.setattr("efs.updater.RefFinder", _FakeRefFinder("sbom-updater_generated_placeholder:"))
        answers.queue.append(True)

        init_wizard._step_vcs_refs("bom.json")

        config = json.loads((tmp_path / ".efs-config.json").read_text(encoding="utf-8"))
        assert config["components"] == {}

    def test_missing_config_reported(self, answers, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "bom.json").write_text(json.dumps(make_bom([])), encoding="utf-8")
        answers.queue.append(True)

        init_wizard._step_vcs_refs("bom.json")

        assert "не найден" in capsys.readouterr().out


class TestPostprocessStep:
    def test_passes_answers_to_postprocess(self, answers, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "bom.json").write_text(
            json.dumps(make_bom([make_component("requests", "2.32.5")]), ensure_ascii=False), encoding="utf-8"
        )
        captured = {}
        monkeypatch.setattr("efs.postprocess.run", lambda args: captured.update(vars(args)))
        answers.queue.extend([True, "Продукт", "2.0", "ООО Тест", "result.json"])

        init_wizard._step_postprocess("bom.json")

        assert captured["app_name"] == "Продукт"
        assert captured["app_version"] == "2.0"
        assert captured["manufacturer"] == "ООО Тест"
        assert captured["output"].endswith("result.json")

    def test_empty_answers_become_none(self, answers, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "bom.json").write_text(json.dumps(make_bom([])), encoding="utf-8")
        captured = {}
        monkeypatch.setattr("efs.postprocess.run", lambda args: captured.update(vars(args)))
        answers.queue.extend([True, "", "", "", "out.json"])

        init_wizard._step_postprocess("bom.json")

        assert captured["app_name"] is None
        assert captured["manufacturer"] is None


class TestRunWizard:
    def test_cancel_on_first_step_stops(self, answers, capsys, monkeypatch):
        called = []
        monkeypatch.setattr(init_wizard, "_step_scan", lambda *a: called.append("scan"))
        answers.queue.append(None)

        init_wizard.run_wizard()

        assert called == []
        assert "Отменено" in capsys.readouterr().out

    def test_all_steps_called_in_order(self, answers, monkeypatch):
        order = []
        monkeypatch.setattr(init_wizard, "_step_scan", lambda tool, name: order.append("scan"))
        monkeypatch.setattr(init_wizard, "_step_config", lambda name, tool: order.append("config"))
        monkeypatch.setattr(init_wizard, "_step_vcs_refs", lambda name: order.append("vcs"))
        monkeypatch.setattr(init_wizard, "_step_postprocess", lambda name: order.append("postprocess"))
        answers.queue.extend(["cdxgen", "bom.json"])

        init_wizard.run_wizard()

        assert order == ["scan", "config", "vcs", "postprocess"]


class _FakeRefFinder:
    """Фабрика подменного RefFinder, возвращающего заданный URL."""

    def __init__(self, url):
        self._url = url

    def __call__(self, *args, **kwargs):
        url = self._url

        class Finder:
            def process_purl(self, purl):
                return url

            def dump_repos(self):
                pass

        return Finder()
