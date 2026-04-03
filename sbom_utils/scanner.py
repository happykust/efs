# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-License-Identifier: Apache-2.0

"""
Модуль запуска SBOM-сканеров (cdxgen, trivy).

Читает настройки из секции 'scanner' конфига .sbom-config.json
и запускает выбранный инструмент через subprocess.
"""

import json
import shutil
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()

SUPPORTED_TOOLS = ("cdxgen", "trivy")

_CDXGENRC_DEFAULTS = {
    "spec-version": "1.6",
    "profile": "generic",
    "required-only": True,
    "include-formulation": False,
    "include-crypto": False,
    "auto-compositions": False,
    "no-babel": True,
    "json-pretty": True,
}


def _check_tool(tool: str) -> bool:
    """Проверить, что инструмент доступен в PATH."""
    if not shutil.which(tool):
        console.print(f"[red]✗[/red] {tool} не найден в PATH.")
        if tool == "cdxgen":
            console.print("  Установите: npm install -g @cyclonedx/cdxgen")
        elif tool == "trivy":
            console.print("  Установите: https://aquasecurity.github.io/trivy/latest/getting-started/installation/")
        return False
    return True


def run_cdxgen(target: str, output: str, options: dict | None = None) -> bool:
    """Запустить cdxgen для генерации SBOM.

    Перед запуском создаёт/обновляет .cdxgenrc из options.
    """
    if not _check_tool("cdxgen"):
        return False

    options = options or {}

    # Записать .cdxgenrc
    cdxgenrc = _CDXGENRC_DEFAULTS.copy()
    cdxgenrc.update(options)
    cdxgenrc["output"] = output

    cdxgenrc_path = Path.cwd() / ".cdxgenrc"
    cdxgenrc_path.write_text(
        json.dumps(cdxgenrc, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    console.print(f"Запуск cdxgen: target={target}, output={output}")
    result = subprocess.run(
        ["cdxgen", "-o", output, target],
        capture_output=True,
        text=True,
    )

    if result.returncode == 0:
        console.print(f"[green]✓[/green] SBOM сохранён: {output}")
        return True

    console.print(f"[red]✗[/red] cdxgen завершился с ошибкой (код {result.returncode})")
    if result.stderr:
        console.print(result.stderr.strip())
    return False


def run_trivy(target: str, output: str, options: dict | None = None) -> bool:
    """Запустить trivy для генерации SBOM.

    options:
        command — подкоманда trivy (fs, image, repo, ...). По умолчанию 'fs'.
        args — список дополнительных аргументов.
    """
    if not _check_tool("trivy"):
        return False

    options = options or {}
    command = options.get("command", "fs")
    extra_args = options.get("args", [])

    cmd = [
        "trivy", command,
        "--format", "cyclonedx",
        "--output", output,
        *extra_args,
        target,
    ]

    console.print(f"Запуск trivy: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        console.print(f"[green]✓[/green] SBOM сохранён: {output}")
        return True

    console.print(f"[red]✗[/red] trivy завершился с ошибкой (код {result.returncode})")
    if result.stderr:
        console.print(result.stderr.strip())
    return False


def run_scan(tool: str, target: str, output: str, options: dict | None = None) -> bool:
    """Запустить сканирование выбранным инструментом."""
    if tool == "cdxgen":
        return run_cdxgen(target, output, options)
    elif tool == "trivy":
        return run_trivy(target, output, options)
    else:
        console.print(f"[red]✗[/red] Неизвестный инструмент: {tool}. Поддерживаются: {', '.join(SUPPORTED_TOOLS)}")
        return False
