# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

"""Общие фикстуры: минимальные SBOM и конфиги.

Сеть и внешние процессы в тестах не используются — всё через моки.
"""

import json

import pytest


def make_component(name, version="1.0.0", purl=None, **extra):
    """Минимальный компонент CycloneDX."""
    comp = {"type": "library", "name": name, "version": version}
    if purl is None:
        purl = f"pkg:pypi/{name}@{version}"
    if purl:
        comp["purl"] = purl
        comp["bom-ref"] = purl
    comp.update(extra)
    return comp


def make_bom(components=None, **extra):
    """Минимальный валидный SBOM CycloneDX 1.6."""
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": "2026-01-01T00:00:00+00:00",
            "component": {
                "type": "application",
                "name": "test-app",
                "version": "1.0.0",
                "manufacturer": {"name": "ООО Тест"},
            },
        },
        "components": components if components is not None else [],
    }
    bom.update(extra)
    return bom


@pytest.fixture
def bom():
    return make_bom([make_component("requests", "2.32.5")])


@pytest.fixture
def config():
    """Конфиг .sbom-config.json с типовым набором настроек."""
    return {
        "defaults": {
            "manufacturer": {"name": "ООО Умолчание"},
            "provided_by": "ООО Умолчание",
            "attack_surface": "no",
            "security_function": "no",
        },
        "components": {
            "pkg:pypi/requests": {
                "vcs": "https://github.com/psf/requests",
                "attack_surface": "yes",
            },
            "pkg:pypi/cryptography@42.0.0": {
                "vcs": "https://github.com/our-org/cryptography-fork",
                "security_function": "yes",
                "manufacturer": {"name": "ООО Форк"},
                "pedigree": {"notes": "Форк с ГОСТ-патчами"},
            },
            "pkg:npm/left-pad": {"exclude": True},
            "pkg:npm/ajv@6.12.6": {"exclude": "direct"},
        },
    }


@pytest.fixture
def write_json(tmp_path):
    """Записать объект в JSON-файл во временной директории и вернуть путь."""

    def _write(name, data, encoding="utf-8", raw=None):
        path = tmp_path / name
        if raw is not None:
            path.write_bytes(raw)
        else:
            path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding=encoding)
        return path

    return _write
