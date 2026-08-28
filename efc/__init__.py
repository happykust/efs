# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

"""efc — Easy FSTEC Certification.

Инструменты генерации, проверки и обогащения SBOM в формате CycloneDX
с расширениями ГОСТ для требований ФСТЭК.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("efc")
except PackageNotFoundError:
    __version__ = "0.0.0.dev0"

__all__ = ["__version__"]
