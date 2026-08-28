# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

"""Сквозные тесты CLI: каждая команда должна быть зарегистрирована и отрабатывать."""

import json

import pytest
from typer.testing import CliRunner

from efs.cli import app

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
        config_path = tmp_path / ".efs-config.json"
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
        config = json.loads((tmp_path / ".efs-config.json").read_text(encoding="utf-8"))
        assert config["components"]["pkg:pypi/requests"]["vcs"] == "https://github.com/psf/requests"


class TestScan:
    def test_uses_tool_from_config(self, tmp_path, monkeypatch):
        config_path = tmp_path / ".efs-config.json"
        config_path.write_text(
            json.dumps({"scanner": {"tool": "trivy", "target": ".", "output": "bom.json"}}), encoding="utf-8"
        )
        captured = {}

        def fake_run_scan(tool, target, output, options=None):
            captured.update(tool=tool, target=target, output=output)
            return True

        monkeypatch.setattr("efs.scanner.run_scan", fake_run_scan)
        result = runner.invoke(app, ["scan", "--config", str(config_path)])
        assert result.exit_code == 0, result.output
        assert captured["tool"] == "trivy"

    def test_cli_option_overrides_config(self, tmp_path, monkeypatch):
        config_path = tmp_path / ".efs-config.json"
        config_path.write_text(json.dumps({"scanner": {"tool": "trivy"}}), encoding="utf-8")
        captured = {}

        monkeypatch.setattr(
            "efs.scanner.run_scan",
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

    def test_incomplete_listing_exits_three(self, tmp_path):
        path = self._write(tmp_path, make_bom([self._component(with_source_langs=False)]))
        result = runner.invoke(app, ["check", path])
        assert result.exit_code == 3

    def test_bundled_example_is_ready(self):
        result = runner.invoke(app, ["check", "examples/example-sbom.json"])
        assert result.exit_code == 0, result.output


class TestConfigStatusLanguages:
    def test_reports_components_without_language(self, tmp_path, monkeypatch):
        config_path = tmp_path / ".efs-config.json"
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


class TestPostprocessAugmentsConfig:
    def _bom(self, tmp_path, components):
        path = tmp_path / "bom.json"
        path.write_text(json.dumps(make_bom(components), ensure_ascii=False), encoding="utf-8")
        return str(path)

    def _run(self, tmp_path, bom_path, config_path):
        return runner.invoke(
            app,
            ["postprocess", bom_path, str(tmp_path / "out.json"), "--app-name", "П", "--config", str(config_path)],
        )

    def test_new_components_added_to_config(self, tmp_path):
        config_path = tmp_path / ".efs-config.json"
        config_path.write_text(
            json.dumps({"components": {"pkg:pypi/requests": {"attack_surface": "yes"}}}), encoding="utf-8"
        )
        bom_path = self._bom(
            tmp_path,
            [make_component("requests", "2.32.5"), make_component("lodash", "4.17.21", purl="pkg:npm/lodash@4.17.21")],
        )

        result = self._run(tmp_path, bom_path, config_path)
        assert result.exit_code == 0, result.output

        config = json.loads(config_path.read_text(encoding="utf-8"))
        assert "pkg:npm/lodash" in config["components"]
        assert config["components"]["pkg:npm/lodash"]["source_langs"] == ["JavaScript"]

    def test_existing_settings_untouched(self, tmp_path):
        config_path = tmp_path / ".efs-config.json"
        config_path.write_text(
            json.dumps({"components": {"pkg:pypi/requests": {"attack_surface": "yes", "vcs": "https://x/y"}}}),
            encoding="utf-8",
        )
        bom_path = self._bom(tmp_path, [make_component("requests", "2.32.5")])

        self._run(tmp_path, bom_path, config_path)

        entry = json.loads(config_path.read_text(encoding="utf-8"))["components"]["pkg:pypi/requests"]
        assert entry["attack_surface"] == "yes"
        assert entry["vcs"] == "https://x/y"

    def test_excluded_components_not_dropped_from_config(self, tmp_path):
        """Исключённого компонента нет в результате, но его настройка должна остаться."""
        config_path = tmp_path / ".efs-config.json"
        config_path.write_text(json.dumps({"components": {"pkg:npm/eslint": {"exclude": True}}}), encoding="utf-8")
        bom_path = self._bom(
            tmp_path,
            [
                make_component("eslint", "8.0.0", purl="pkg:npm/eslint@8.0.0"),
                make_component("requests", "2.32.5"),
            ],
        )

        self._run(tmp_path, bom_path, config_path)

        config = json.loads(config_path.read_text(encoding="utf-8"))
        assert config["components"]["pkg:npm/eslint"] == {"exclude": True}

    def test_config_not_created_when_absent(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        bom_path = self._bom(tmp_path, [make_component("requests", "2.32.5")])
        result = runner.invoke(app, ["postprocess", bom_path, str(tmp_path / "out.json"), "--app-name", "П"])
        assert result.exit_code == 0, result.output
        assert not (tmp_path / ".efs-config.json").exists()


class TestArgumentValidation:
    def test_missing_file_reports_error_not_traceback(self, tmp_path):
        result = runner.invoke(app, ["check", str(tmp_path / "нет.json")])
        assert result.exit_code != 0
        assert "Traceback" not in result.output
        assert "does not exist" in result.output or "не существует" in result.output

    def test_unknown_format_rejected(self):
        result = runner.invoke(app, ["check", "examples/example-sbom.json", "--format", "bogus"])
        assert result.exit_code != 0
        assert "bogus" in result.output

    def test_unknown_scan_tool_rejected(self):
        result = runner.invoke(app, ["scan", "--tool", "syft"])
        assert result.exit_code != 0
        assert "syft" in result.output

    def test_unknown_gost_default_rejected(self, tmp_path):
        result = runner.invoke(
            app,
            ["postprocess", "examples/example-sbom.json", str(tmp_path / "o.json"), "--gost-default", "bogus"],
        )
        assert result.exit_code != 0

    def test_format_values_are_completable(self):
        """Значения перечисления должны быть видны typer — иначе автодополнение бесполезно."""
        result = runner.invoke(app, ["check", "--help"])
        assert "oss" in result.output and "container" in result.output


class TestReadinessExitCode:
    def test_incomplete_listing_uses_dedicated_code(self, tmp_path):
        comp = make_component("requests", "2.32.5")
        comp["properties"] = [
            {"name": "GOST:attack_surface", "value": "no"},
            {"name": "GOST:security_function", "value": "no"},
        ]
        comp["externalReferences"] = [{"type": "vcs", "url": "https://github.com/psf/requests"}]
        path = tmp_path / "bom.json"
        path.write_text(json.dumps(make_bom([comp]), ensure_ascii=False), encoding="utf-8")

        result = runner.invoke(app, ["check", str(path)])
        assert result.exit_code == 3

    def test_missing_input_rejected_for_every_command(self, tmp_path):
        absent = str(tmp_path / "нет.json")
        out = str(tmp_path / "out.json")
        commands = [
            ["postprocess", absent, out],
            ["export", "csv", absent, out],
            ["export", "odt", absent, out],
            ["update", absent, out],
            ["config", "init", absent],
        ]
        for command in commands:
            result = runner.invoke(app, command)
            assert result.exit_code != 0, command
            assert "Traceback" not in result.output, command


class TestExportCertifiedProduct:
    def _bom_path(self, tmp_path):
        comp = make_component("crypto-module", "1.0", purl="pkg:generic/crypto@1.0")
        comp["properties"] = [
            {"name": "GOST:attack_surface", "value": "no"},
            {"name": "GOST:security_function", "value": "yes"},
            {"name": "GOST:source_langs", "value": "C"},
            {"name": "GOST:provided_by", "value": "КриптоПро CSP"},
        ]
        path = tmp_path / "bom.json"
        path.write_text(json.dumps(make_bom([comp]), ensure_ascii=False), encoding="utf-8")
        return str(path)

    def test_csv_names_certified_product(self, tmp_path):
        """Графа источника не должна пустовать у компонента из состава СЗИ."""
        out = tmp_path / "components.csv"
        result = runner.invoke(app, ["export", "csv", self._bom_path(tmp_path), str(out)])
        assert result.exit_code == 0, result.output
        assert "КриптоПро CSP" in out.read_text(encoding="utf-8")

    def test_odt_names_certified_product(self, tmp_path):
        import zipfile

        out = tmp_path / "components.odt"
        result = runner.invoke(app, ["export", "odt", self._bom_path(tmp_path), str(out)])
        assert result.exit_code == 0, result.output
        with zipfile.ZipFile(out) as archive:
            text = archive.read("content.xml").decode("utf-8")
        assert "КриптоПро CSP" in text


class TestVersionOption:
    def test_version_printed(self):
        from efs import __version__

        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output

    def test_version_short_flag(self):
        assert runner.invoke(app, ["-V"]).exit_code == 0
