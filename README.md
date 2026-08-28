# efs — Easy FSTEC SBOMs

[![CI](https://github.com/happykust/efs/actions/workflows/ci.yml/badge.svg)](https://github.com/happykust/efs/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/efs-sbom.svg)](https://pypi.org/project/efs-sbom/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)

CLI-приложение для подготовки перечня заимствованных программных компонентов под требования ФСТЭК России и ГОСТ Р 56939-2024: генерация SBOM, валидация, обогащение ссылками на исходный код и ГОСТ-свойствами, объединение и экспорт в CSV/ODT.

Формат — CycloneDX 1.6 (JSON) с расширениями ГОСТ (`GOST:attack_surface`, `GOST:security_function`, `GOST:source_langs`, `GOST:provided_by`).

## Требования

* Python 3.12 или выше
* [cdxgen](https://github.com/CycloneDX/cdxgen) или [trivy](https://github.com/aquasecurity/trivy) — для генерации SBOM
* git, subversion, mercurial — опционально, для проверки ссылок на репозитории

## Установка

```bash
uv tool install efs-sbom     # или: pip install efs-sbom
```

Из исходников:

```bash
git clone https://github.com/happykust/efs.git
cd efs
uv sync
```

## Быстрый старт

```bash
efs scan                                  # сгенерировать SBOM (cdxgen или trivy)
efs config init bom.json                  # создать конфиг из SBOM
                                          # отредактировать .efs-config.json
efs postprocess bom.json result.json \
  --app-name "МойПродукт" --app-version "1.0.0" --manufacturer "ООО МояКомпания"
efs check result.json                     # проверить схему и заполненность
efs export odt result.json perechen.odt   # выгрузить документ
```

Или пройти всё через интерактивный мастер:

```bash
efs init
```

`efs check` возвращает `0`, если перечень готов, `1` при ошибках схемы и `2`, если перечень не заполнен, — команда годится для проверки в CI.

## Документация

| Документ | О чём |
|----------|-------|
| [Подготовка перечня под ФСТЭК](docs/fstec.md) | Путь от исходников до готового документа: что требуется, что заполняется автоматически, а что руками |
| [Справочник команд](docs/commands.md) | Все команды с аргументами и примерами |
| [Конфиг `.efs-config.json`](docs/config.md) | Структура конфига, ГОСТ-свойства, исключения, pedigree, языки |

Пример заполненного перечня — [`examples/example-sbom.json`](examples/example-sbom.json); он проходит `efs check` и годится как образец.

## Разработка

```bash
uv sync              # зависимости, включая dev-группу
uv run pytest        # тесты
uv run ruff check .  # линтер
uv run ruff format . # форматирование
```

Как оформлять изменения и выпускать релизы — в [CONTRIBUTING.md](CONTRIBUTING.md). Об уязвимостях сообщайте по процедуре из [SECURITY.md](SECURITY.md), не через публичный issue. Правила общения — в [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Происхождение

Проект является производной работой от [sbom-checker](https://gitlab.community.ispras.ru/sdl-tools/sbom-checker), разработанного в Институте системного программирования РАН (ИСП РАН) и распространяемого на условиях Apache License 2.0. Атрибуция приведена в файле [NOTICE](NOTICE).

## Лицензия

[Apache-2.0](LICENSE)
