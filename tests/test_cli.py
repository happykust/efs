# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

"""Сквозные тесты CLI: каждая команда должна быть зарегистрирована и отрабатывать."""

import json

import pytest
from typer.testing import CliRunner

from efc.cli import app

from .conftest import make_bom, make_component

runner = CliRunner()


@pytest.fixture
def bom_file(tmp_path):
    path = tmp_path / "bom.json"
    bom = make_bom([make_component("requests", "2.32.5"), make_component("flask", "3.0.0")])
    path.write_text(json.dumps(bom, ensure_ascii=False), encoding="utf-8")
    return path


class TestHelp:
    def test_root_help_lists_all_commands(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        for command in ("check", "update", "merge", "postprocess", "scan", "export", "config", "init"):
            assert command in result.output

    @pytest.mark.parametrize(
        "command",
        [
            ["check", "--help"],
            ["update", "--help"],
            ["merge", "--help"],
            ["postprocess", "--help"],
            ["scan", "--help"],
            ["export", "csv", "--help"],
            ["export", "odt", "--help"],
            ["config", "init", "--help"],
            ["config", "migrate", "--help"],
            ["config", "status", "--help"],
            ["config", "find-vcs", "--help"],
        ],
    )
    def test_subcommand_help(self, command):
        assert runner.invoke(app, command).exit_code == 0


class TestCheck:
    def test_reports_valid_file(self, tmp_path):
        comp = make_component("requests", "2.32.5")
        comp["properties"] = [
            {"name": "GOST:attack_surface", "value": "no"},
            {"name": "GOST:security_function", "value": "no"},
            {"name": "GOST:source_langs", "value": "Python"},
        ]
        comp["externalReferences"] = [{"type": "vcs", "url": "https://github.com/psf/requests"}]
        path = tmp_path / "bom.json"
        path.write_text(json.dumps(make_bom([comp]), ensure_ascii=False), encoding="utf-8")

        result = runner.invoke(app, ["check", str(path)])
        assert result.exit_code == 0
        assert "файл корректный" in result.output


class TestPostprocess:
    def test_writes_processed_bom(self, bom_file, tmp_path):
        out = tmp_path / "result.json"
        result = runner.invoke(
            app,
            [
                "postprocess",
                str(bom_file),
                str(out),
                "--app-name",
                "Продукт",
                "--app-version",
                "1.0",
                "--manufacturer",
                "ООО Тест",
            ],
        )
        assert result.exit_code == 0, result.output

        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["metadata"]["component"]["name"] == "Продукт"
        for comp in data["components"]:
            names = {p["name"] for p in comp["properties"]}
            assert "GOST:attack_surface" in names
            assert "GOST:security_function" in names

    def test_config_applied(self, bom_file, tmp_path, monkeypatch):
        config_path = tmp_path / ".sbom-config.json"
        config_path.write_text(
            json.dumps(
                {
                    "defaults": {"provided_by": "ООО Поставщик"},
                    "components": {"pkg:pypi/requests": {"attack_surface": "yes"}},
                }
            ),
            encoding="utf-8",
        )
        out = tmp_path / "result.json"
        result = runner.invoke(
            app,
            ["postprocess", str(bom_file), str(out), "--app-name", "Продукт", "--config", str(config_path)],
        )
        assert result.exit_code == 0, result.output

        data = json.loads(out.read_text(encoding="utf-8"))
        by_name = {c["name"]: c for c in data["components"]}
        props = {p["name"]: p["value"] for p in by_name["requests"]["properties"]}
        assert props["GOST:attack_surface"] == "yes"
        assert props["GOST:provided_by"] == "ООО Поставщик"


class TestMerge:
    def test_requires_two_paths(self, bom_file):
        result = runner.invoke(
            app,
            ["merge", str(bom_file), "--app-name", "П", "--app-version", "1", "--manufacturer", "ООО"],
        )
        assert result.exit_code == 1
        assert "хотя бы один входной файл" in result.output

    def test_merges_two_boms(self, bom_file, tmp_path):
        second = tmp_path / "second.json"
        bom = make_bom([make_component("django", "5.0")])
        bom["metadata"]["component"]["name"] = "Второй сервис"
        second.write_text(json.dumps(bom, ensure_ascii=False), encoding="utf-8")
        out = tmp_path / "merged.json"

        result = runner.invoke(
            app,
            [
                "merge",
                str(bom_file),
                str(second),
                str(out),
                "--app-name",
                "Продукт",
                "--app-version",
                "1.0",
                "--manufacturer",
                "ООО Тест",
            ],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text(encoding="utf-8"))
        assert len(data["components"]) == 2


class TestExport:
    def test_csv(self, bom_file, tmp_path):
        out = tmp_path / "components.csv"
        result = runner.invoke(app, ["export", "csv", str(bom_file), str(out)])
        assert result.exit_code == 0, result.output
        content = out.read_text(encoding="utf-8")
        assert "requests" in content
        assert "flask" in content

    def test_odt(self, bom_file, tmp_path):
        out = tmp_path / "components.odt"
        result = runner.invoke(app, ["export", "odt", str(bom_file), str(out)])
        assert result.exit_code == 0, result.output
        assert out.stat().st_size > 0


class TestConfigCommands:
    def test_init_creates_config(self, bom_file, tmp_path):
        out = tmp_path / ".sbom-config.json"
        result = runner.invoke(app, ["config", "init", str(bom_file), "-o", str(out)])
        assert result.exit_code == 0, result.output
        config = json.loads(out.read_text(encoding="utf-8"))
        assert set(config["components"]) == {"pkg:pypi/requests", "pkg:pypi/flask"}

    def test_migrate_merges_legacy_files(self, tmp_path, monkeypatch):
        (tmp_path / ".purl_to_vcs.json").write_text(
            json.dumps({"pkg:pypi/requests": "https://github.com/psf/requests"}), encoding="utf-8"
        )
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["config", "migrate"])
        assert result.exit_code == 0, result.output
        config = json.loads((tmp_path / ".sbom-config.json").read_text(encoding="utf-8"))
        assert config["components"]["pkg:pypi/requests"]["vcs"] == "https://github.com/psf/requests"


class TestScan:
    def test_uses_tool_from_config(self, tmp_path, monkeypatch):
        config_path = tmp_path / ".sbom-config.json"
        config_path.write_text(
            json.dumps({"scanner": {"tool": "trivy", "target": ".", "output": "bom.json"}}), encoding="utf-8"
        )
        captured = {}

        def fake_run_scan(tool, target, output, options=None):
            captured.update(tool=tool, target=target, output=output)
            return True

        monkeypatch.setattr("efc.scanner.run_scan", fake_run_scan)
        result = runner.invoke(app, ["scan", "--config", str(config_path)])
        assert result.exit_code == 0, result.output
        assert captured["tool"] == "trivy"

    def test_cli_option_overrides_config(self, tmp_path, monkeypatch):
        config_path = tmp_path / ".sbom-config.json"
        config_path.write_text(json.dumps({"scanner": {"tool": "trivy"}}), encoding="utf-8")
        captured = {}

        monkeypatch.setattr(
            "efc.scanner.run_scan",
            lambda tool, target, output, options=None: captured.update(tool=tool) or True,
        )
        result = runner.invoke(app, ["scan", "--tool", "cdxgen", "--config", str(config_path)])
        assert result.exit_code == 0, result.output
        assert captured["tool"] == "cdxgen"


class TestCheckExitCodes:
    def _write(self, tmp_path, bom):
        path = tmp_path / "bom.json"
        path.write_text(json.dumps(bom, ensure_ascii=False), encoding="utf-8")
        return str(path)

    def _component(self, with_source_langs=True):
        comp = make_component("requests", "2.32.5")
        comp["properties"] = [
            {"name": "GOST:attack_surface", "value": "no"},
            {"name": "GOST:security_function", "value": "no"},
        ]
        if with_source_langs:
            comp["properties"].append({"name": "GOST:source_langs", "value": "Python"})
        comp["externalReferences"] = [{"type": "vcs", "url": "https://github.com/psf/requests"}]
        return comp

    def test_complete_listing_exits_zero(self, tmp_path):
        path = self._write(tmp_path, make_bom([self._component()]))
        result = runner.invoke(app, ["check", path])
        assert result.exit_code == 0

    def test_schema_error_exits_one(self, tmp_path):
        bom = make_bom([self._component()])
        del bom["specVersion"]
        result = runner.invoke(app, ["check", self._write(tmp_path, bom)])
        assert result.exit_code == 1

    def test_incomplete_listing_exits_two(self, tmp_path):
        path = self._write(tmp_path, make_bom([self._component(with_source_langs=False)]))
        result = runner.invoke(app, ["check", path])
        assert result.exit_code == 2

    def test_bundled_example_is_ready(self):
        result = runner.invoke(app, ["check", "examples/example-sbom.json"])
        assert result.exit_code == 0, result.output


class TestConfigStatusLanguages:
    def test_reports_components_without_language(self, tmp_path, monkeypatch):
        config_path = tmp_path / ".sbom-config.json"
        config_path.write_text(
            json.dumps(
                {
                    "components": {
                        "pkg:deb/debian/curl": {"vcs": "https://salsa.debian.org/debian/curl"},
                        "pkg:pypi/requests": {"vcs": "https://github.com/psf/requests"},
                    }
                }
            ),
            encoding="utf-8",
        )
        result = runner.invoke(app, ["config", "status", "--config", str(config_path)])
        assert result.exit_code == 0, result.output
        assert "pkg:deb/debian/curl" in result.output
        assert "язык" in result.output.lower()


class TestExportMultipleLanguages:
    def _bom_path(self, tmp_path):
        comp = make_component("cryptography", "42.0.0")
        comp["properties"] = [
            {"name": "GOST:attack_surface", "value": "no"},
            {"name": "GOST:security_function", "value": "yes"},
            {"name": "GOST:source_langs", "value": "Python"},
            {"name": "GOST:source_langs", "value": "C"},
        ]
        path = tmp_path / "bom.json"
        path.write_text(json.dumps(make_bom([comp]), ensure_ascii=False), encoding="utf-8")
        return str(path)

    def test_csv_lists_every_language(self, tmp_path):
        out = tmp_path / "components.csv"
        result = runner.invoke(app, ["export", "csv", self._bom_path(tmp_path), str(out)])
        assert result.exit_code == 0, result.output
        assert "Python, C" in out.read_text(encoding="utf-8")

    def test_odt_lists_every_language(self, tmp_path):
        out = tmp_path / "components.odt"
        result = runner.invoke(app, ["export", "odt", self._bom_path(tmp_path), str(out)])
        assert result.exit_code == 0, result.output

        import zipfile

        with zipfile.ZipFile(out) as archive:
            text = archive.read("content.xml").decode("utf-8")
        assert "Python, C" in text
