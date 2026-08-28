# efc — Easy FSTEC Certification

[![CI](https://github.com/happykust/efc/actions/workflows/ci.yml/badge.svg)](https://github.com/happykust/efc/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/efc.svg)](https://pypi.org/project/efc/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)

CLI-приложение для подготовки перечня заимствованных программных компонентов под требования ФСТЭК России и ГОСТ Р 56939-2024: генерация SBOM, его валидация, обогащение VCS-ссылками и ГОСТ-свойствами, объединение и экспорт в CSV/ODT.

Формат — CycloneDX JSON с расширениями ГОСТ (`GOST:attack_surface`, `GOST:security_function`, `GOST:source_langs`, `GOST:provided_by`).

## Требования

* Python 3.12 или выше
* [uv](https://docs.astral.sh/uv/) (рекомендуемый менеджер пакетов)
* Для `--check-vcs`: git, subversion, mercurial (опционально)
* Для `efc scan`: [cdxgen](https://github.com/CycloneDX/cdxgen) или [trivy](https://github.com/aquasecurity/trivy)

## Установка

```bash
# Через uv
uv tool install efc

# Или через pip
pip install efc
```

Установка из исходников для разработки:

```bash
git clone https://github.com/happykust/efc.git
cd efc
uv sync
```

После установки доступна CLI-утилита `efc`:

```bash
efc <команда> [аргументы]
```

Запуск без установки:
```bash
python -m efc.cli <команда> [аргументы]
```

## Быстрый старт

Типичный рабочий процесс:

```bash
# 1. Сгенерировать SBOM (cdxgen или trivy — настраивается в конфиге)
efc scan

# 2. Создать конфиг из SBOM (для нового проекта)
efc config init bom.json

# 3. Отредактировать .sbom-config.json — настроить компоненты, форки, исключения

# 4. Постобработка SBOM с применением конфига
efc postprocess bom.json result.json \
  --app-name "МойПродукт" --app-version "1.0.0" --manufacturer "ООО МояКомпания"

# 5. Валидация результата
efc check result.json
```

Или воспользуйтесь интерактивным мастером:
```bash
efc init
```

## Единый конфиг `.sbom-config.json`

Единый файл конфигурации заменяет три отдельных файла (`.purl_to_vcs.json`, `.purl_to_gost.json`, `.purl_exclude.json`) и добавляет поддержку **pedigree** (CycloneDX) и **manufacturer** per-component.

### Структура конфига

```json
{
  "scanner": {
    "tool": "cdxgen",
    "output": "bom.json",
    "target": ".",
    "options": {}
  },
  "defaults": {
    "manufacturer": {"name": "ООО МояКомпания"},
    "provided_by": "ООО МояКомпания",
    "attack_surface": "no",
    "security_function": "no"
  },
  "components": {
    "pkg:pypi/cryptography": {
      "vcs": "https://github.com/our-org/cryptography-fork",
      "attack_surface": "yes",
      "security_function": "yes",
      "provided_by": "ООО МояКомпания",
      "manufacturer": {"name": "ООО МояКомпания"},
      "pedigree": {
        "ancestors": [{
          "type": "library",
          "name": "cryptography",
          "version": "42.0.0",
          "purl": "pkg:pypi/cryptography@42.0.0",
          "externalReferences": [{"type": "vcs", "url": "https://github.com/pyca/cryptography"}]
        }],
        "notes": "Форк с патчами для совместимости с ГОСТ-криптографией"
      }
    },
    "pkg:pypi/requests": {
      "vcs": "https://github.com/psf/requests",
      "attack_surface": "yes"
    },
    "pkg:pypi/pytest": {
      "exclude": true
    }
  }
}
```

### Поля конфига

**scanner** — настройки инструмента генерации SBOM:

| Поле | Описание |
|------|----------|
| `tool` | Инструмент: `cdxgen` или `trivy` |
| `output` | Имя выходного SBOM-файла |
| `target` | Путь к исходникам или имя Docker-образа |
| `options` | Специфичные для инструмента параметры |

**defaults** — значения по умолчанию для всех компонентов:

| Поле | Описание |
|------|----------|
| `manufacturer` | Организация-изготовитель (объект `{"name": "..."}`) |
| `provided_by` | Поставщик компонента (строка) |
| `attack_surface` | GOST:attack_surface по умолчанию (`yes`/`no`/`indirect`) |
| `security_function` | GOST:security_function по умолчанию (`yes`/`no`/`indirect`) |

**components** — настройки для конкретных компонентов. Ключ — purl без версии (матчит все версии) или с версией (точечное переопределение):

| Поле | Описание |
|------|----------|
| `vcs` | URL репозитория (для externalReferences) |
| `attack_surface` | GOST:attack_surface |
| `security_function` | GOST:security_function |
| `provided_by` | GOST:provided_by |
| `manufacturer` | Организация-изготовитель компонента |
| `exclude` | `true` — исключить компонент и те его транзитивные зависимости, которые не нужны другим компонентам; `"direct"` — только сам компонент, зависимости остаются. Ключ без версии убирает все версии, с версией — только её (`pkg:npm/ajv@6.12.6` не тронет `ajv@8.20.0`) |
| `pedigree` | Объект CycloneDX pedigree (см. ниже) |

#### Как работает каскадное исключение

При `exclude: true` строится граф зависимостей и удаляется всё, что достижимо из исключённого компонента и не достижимо ни от одной верхнеуровневой зависимости продукта. Так исключение `pkg:npm/eslint` убирает и его собственные пакеты (`espree`, `acorn` и прочие), но оставляет библиотеку, которой пользуется ещё кто-то.

Верхнеуровневыми считаются корень SBOM и компоненты, на которые никто не ссылается: после удаления компонентов-манифестов (`uv.lock`, `package-lock.json`) реальные рантайм-зависимости остаются без входящих связей, и каскад не должен принимать их за ненужные.

Если зависимости исключаемого компонента нужно сохранить — используйте `exclude: "direct"`.

### Pedigree — описание форкнутых библиотек

Механизм [CycloneDX pedigree](https://cyclonedx.org/use-cases/pedigree/) позволяет документировать происхождение модифицированных компонентов, что необходимо для выполнения требований ФСТЭК к описанию заимствованных компонентов.

```json
{
  "pedigree": {
    "ancestors": [{
      "type": "library",
      "name": "original-lib",
      "version": "1.0.0",
      "purl": "pkg:pypi/original-lib@1.0.0",
      "externalReferences": [{"type": "vcs", "url": "https://github.com/org/original-lib"}]
    }],
    "patches": [{
      "type": "unofficial",
      "diff": {"url": "https://github.com/our-org/fork/compare/v1.0.0...our-patches.diff"},
      "resolves": [{"type": "security", "id": "CVE-2024-XXXXX"}]
    }],
    "notes": "Форк с патчами для совместимости с ГОСТ-криптографией"
  }
}
```

| Поле | Описание |
|------|----------|
| `ancestors` | Оригинальные компоненты, от которых произведён форк |
| `descendants` | Потомки компонента |
| `variants` | Связанные компоненты без точного отношения предок/потомок |
| `commits` | Коммиты, описывающие изменения |
| `patches` | Патчи с описанием (`unofficial`/`monkey`/`backport`/`cherry-pick`) |
| `notes` | Свободный текст с описанием причин модификации |

### Управление конфигом

```bash
# Сгенерировать конфиг из SBOM (добавит все purl, сохранит существующие настройки)
efc config init bom.json
efc config init bom.json -o my-config.json
efc config init bom.json -i extra1.json -i extra2.json

# Мигрировать из старых файлов
efc config migrate
efc config migrate --vcs .purl_to_vcs.json --gost .purl_to_gost.json --exclude .purl_exclude.json
```

## Команды

### efc check

Валидация SBOM по JSON Schema (CycloneDX 1.6) с опциональной проверкой VCS-URL и source-distribution.

```bash
efc check <file.json> [--check-vcs] [--check-vcs-leaf-only] [--check-source-distribution]
           [--format oss|container] [-e N] [-v]
```

| Аргумент | Описание |
|----------|----------|
| `file.json` | Входной файл CycloneDX JSON |
| `--check-vcs` | Проверка URL типа vcs на git/svn/hg/fossil-репозиторий |
| `--check-vcs-leaf-only` | То же, но только для листовых компонентов |
| `--check-source-distribution` | Проверка URL типа source-distribution |
| `--format FORMAT` | `oss` (по умолчанию) или `container` |
| `-e, --errors N` | Максимум ошибок для вывода (0 = все, по умолчанию 10) |
| `-v, --verbose` | Подробный вывод |

```bash
efc check sbom.json
efc check sbom.json --check-vcs --format=oss -e 0
```

#### Проверка готовности перечня

Схема CycloneDX не требует ни ГОСТ-свойств, ни ссылки на исходный код, поэтому формально корректный файл может оказаться непригодным для сдачи. `efc check` дополнительно проверяет заполненность и в конце печатает сводку по видам замечаний:

- заглушки `TODO` в названии, версии и организации-изготовителе продукта;
- компоненты без `GOST:attack_surface` или `GOST:security_function`;
- компоненты без `GOST:source_langs`;
- компоненты, у которых нет ни ссылки на репозиторий, ни `GOST:provided_by` — ссылка-заглушка `TODO` считается отсутствующей.

Отдельного флага для этой проверки нет, различить результат можно по коду возврата:

| Код | Значение |
|-----|----------|
| `0` | Файл соответствует схеме и заполнен — перечень готов |
| `1` | Ошибки схемы или недоступные ссылки при `--check-vcs` / `--check-source-distribution` |
| `2` | Схема в порядке, но перечень не заполнен |

### efc postprocess

Постобработка вывода [cdxgen](https://github.com/CycloneDX/cdxgen): очистка лишних полей, нормализация GOST-свойств, применение конфига.

```bash
efc postprocess <input.json> <output.json> [--config PATH]
                 [--app-name X] [--app-version Y] [--manufacturer Z]
                 [--gost-default yes|no|indirect] [--strip-only] [--keep-all-fields]
                 [--provided-by NAME] [--purl-to-vcs FILE] [--purl-to-gost FILE]
                 [--purl-exclude FILE] [--init-exclude] [--pretty/--no-pretty]
```

| Аргумент | Описание |
|----------|----------|
| `input` | Входной файл BOM (JSON) |
| `output` | Выходной файл |
| `--config PATH` | Путь к `.sbom-config.json` (по умолчанию ищется в CWD) |
| `--app-name` | Название продукта |
| `--app-version` | Версия продукта |
| `--manufacturer` | Организация-изготовитель |
| `--gost-default` | Значение ГОСТ-свойств по умолчанию (`no`) |
| `--strip-only` | Только очистить лишние поля |
| `--keep-all-fields` | Не удалять необязательные поля |
| `--provided-by NAME` | GOST:provided_by для leaf-компонентов |
| `--purl-to-vcs FILE` | Маппинг purl→VCS (старый формат) |
| `--purl-to-gost FILE` | Маппинг purl→GOST (старый формат) |
| `--purl-exclude FILE` | Список purl для исключения (старый формат) |
| `--init-exclude` | Сгенерировать шаблон `.purl_exclude.json` |

При наличии `.sbom-config.json` в текущей директории конфиг подхватывается автоматически. Конфиг имеет приоритет над отдельными файлами маппингов.

```bash
# С конфигом (рекомендуется)
efc postprocess bom.json result.json --app-name "App" --app-version "1.0" --manufacturer "Org"

# Со старыми файлами (обратная совместимость)
efc postprocess bom.json result.json --purl-to-vcs .purl_to_vcs.json --purl-to-gost .purl_to_gost.json
```

### efc update

Обогащение SBOM: поиск VCS-ссылок через ecosystems.ms / NuGet / RubyGems, добавление GOST-свойств, перенос метаинформации из предыдущей версии SBOM.

```bash
efc update <input.json> [output.json] [--ref] [--props] [--gost] [--fix-all]
            [--app-name X] [--app-version Y] [--manufacturer Z]
            [--purl-to-vcs PATH] [--purl-to-gost PATH]
            [--init-gost-map] [--init-purl-map] [-i EXTRA...] [--update OLD]
```

| Аргумент | Описание |
|----------|----------|
| `input` | Входной файл CycloneDX JSON |
| `output` | Выходной файл (обязателен без `--init-*` флагов) |
| `--ref` | Заполнить externalReferences на основе purl |
| `--props` | Добавить GOST:attack_surface и GOST:security_function |
| `--gost` | Установить GOST-свойства из файла маппинга |
| `--fix-all` | Применить все опции (пустые поля → `"TODO"`) |
| `--init-purl-map` | Сгенерировать шаблон `.purl_to_vcs.json` |
| `--init-gost-map` | Сгенерировать шаблон `.purl_to_gost.json` |
| `--update OLD` | Перенести метаинформацию из предыдущей версии SBOM |

```bash
efc update input.json output.json --fix-all
efc update input.json --init-purl-map --init-gost-map
efc update new.json updated.json --update old.json
```

### efc merge

Объединение нескольких SBOM в один с агрегацией GOST-свойств (`yes` > `indirect` > `no`).

```bash
efc merge <in1.json> [in2.json ...] <out.json> --app-name X --app-version Y --manufacturer Z
```

```bash
efc merge sbom1.json sbom2.json merged.json \
  --app-name "МойПродукт" --app-version "1.0.0" --manufacturer "ООО Компания"
```

#### Режим обычных SBOM

Каждый входной файл превращается в один компонент результирующего перечня: берётся его `metadata.component`, а GOST-свойства агрегируются из компонентов файла по правилу `yes` > `indirect` > `no`. Так собирается перечень уровня продукта из перечней отдельных сервисов.

#### Режим сырых отчётов trivy

Если все входные файлы — сырые отчёты trivy (определяется по записи об инструменте в `metadata.tools`), объединение идёт иначе: компоненты, зависимости и уязвимости сливаются в один SBOM без предварительного `efc postprocess`.

```bash
trivy fs --format cyclonedx --output frontend.json ./frontend
trivy fs --format cyclonedx --output backend.json ./backend
efc merge frontend.json backend.json merged.json \
  --app-name "МойПродукт" --app-version "1.0.0" --manufacturer "ООО Компания"
```

Что происходит при слиянии:

| Операция | Поведение |
|----------|-----------|
| Компоненты-манифесты | Удаляются (`package-lock.json`, `uv.lock` и подобные — trivy добавляет их как `application` без purl) |
| Дедупликация | По `purl`; разные версии одного пакета остаются отдельными компонентами |
| Свойства дубликатов | Объединяются, свойства `aquasecurity:trivy:*` сохраняются без изменений |
| Уязвимости | Дедуплицируются по идентификатору CVE, списки `affects` объединяются |
| Зависимости | Ссылки на схлопнутые дубликаты пересопоставляются, записи с одинаковым `ref` объединяются |
| Висячие ссылки | Отбрасываются: ссылки на удалённые манифесты и на корни входных файлов не остаются в результате |

Смешивать сырые отчёты trivy и обычные SBOM в одном вызове нельзя — команда завершится с ошибкой. Результат объединения trivy-отчётов — сырой SBOM: чтобы получить перечень под требования ФСТЭК, пропустите его через `efc postprocess`.

### efc export csv / odt

Экспорт SBOM в CSV или ODT.

```bash
efc export csv <input.json> <output.csv>
efc export odt <input.json> <output.odt> [--format oss|container] [-t]
```

| Аргумент | Описание |
|----------|----------|
| `-t, --pa-fb-ontop` | Помещение записей «ПА» и «ФБ» в начало таблицы (только ODT) |
| `--format FORMAT` | `oss` (по умолчанию) или `container` (только ODT) |

### efc scan

Генерация SBOM с помощью cdxgen или trivy. Читает настройки из секции `scanner` конфига `.sbom-config.json`. Если конфиг не найден — запускает `efc init`.

```bash
efc scan [--tool cdxgen|trivy] [--target PATH] [--output FILE] [--config PATH]
```

| Аргумент | Описание |
|----------|----------|
| `--tool` | Инструмент: `cdxgen` или `trivy` (из конфига по умолчанию) |
| `--target` | Путь к исходникам или имя образа (из конфига по умолчанию) |
| `--output` | Выходной файл SBOM (из конфига по умолчанию) |
| `--config` | Путь к `.sbom-config.json` |

Секция `scanner` в конфиге:

```json
{
  "scanner": {
    "tool": "trivy",
    "output": "bom.json",
    "target": ".",
    "options": {
      "command": "fs",
      "args": ["--scanners", "license"]
    }
  }
}
```

Для cdxgen `options` записываются в `.cdxgenrc`. Для trivy: `command` — подкоманда (`fs`, `image`, `repo`), `args` — дополнительные флаги CLI.

```bash
efc scan                        # всё из конфига
efc scan --tool trivy           # переопределить инструмент
efc scan --target ./src         # переопределить цель
efc scan --output my-bom.json   # переопределить выходной файл
```

### efc init

Интерактивный мастер инициализации SBOM-проекта: выбор инструмента (cdxgen/trivy), генерация SBOM, создание конфига, поиск VCS-ссылок.

```bash
efc init
```

## GOST-свойства

Инструменты поддерживают расширения CycloneDX для ГОСТ (ГОСТ Р 56939-2024, требования ФСТЭК):

| Свойство | Допустимые значения | Описание |
|----------|---------------------|----------|
| `GOST:attack_surface` | `yes`, `no`, `indirect` | Принадлежность к поверхности атаки |
| `GOST:security_function` | `yes`, `no`, `indirect` | Реализует функцию безопасности |
| `GOST:source_langs` | строка | Языки программирования |
| `GOST:provided_by` | строка | Поставщик компонента |

## Обратная совместимость

Старые файлы маппингов (`.purl_to_vcs.json`, `.purl_to_gost.json`, `.purl_exclude.json`) продолжают работать. Если в текущей директории есть `.sbom-config.json`, он имеет приоритет. Для миграции:

```bash
efc config migrate
```

## Структура проекта

```
efc/
├── cli.py                  # Единая CLI-точка входа (typer)
├── config.py               # Единый конфиг .sbom-config.json
├── scanner.py              # Запуск SBOM-сканеров (cdxgen, trivy)
├── checker.py              # Валидация SBOM
├── updater.py              # Обогащение SBOM (VCS через API)
├── unifier.py              # Объединение SBOM
├── postprocess.py          # Постобработка вывода cdxgen/trivy
├── to_csv.py               # Экспорт в CSV
├── to_odt.py               # Экспорт в ODT
├── init_wizard.py          # Интерактивный мастер
├── utils.py                # Общие утилиты (opener, check_repo, кеш)
├── schemas/                # JSON Schema (CycloneDX 1.6)
├── additional_schemas/     # Внешние схемы (SPDX, JSF)
└── odt_templates/          # Шаблоны ODT-документов
```

## Разработка

```bash
uv sync              # установить зависимости, включая dev-группу
uv run pytest        # запустить тесты
uv run ruff check .  # линтер
uv run ruff format . # форматирование
```

Пример готового перечня — `examples/example-sbom.json`; он проходит `efc check` и годится как образец заполнения ГОСТ-свойств.

Как оформлять изменения, писать тесты и выпускать релизы — в [CONTRIBUTING.md](CONTRIBUTING.md). Об уязвимостях сообщайте по процедуре из [SECURITY.md](SECURITY.md), не через публичный issue. Правила общения — в [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Происхождение

Проект является производной работой от [sbom-checker](https://gitlab.community.ispras.ru/sdl-tools/sbom-checker), разработанного в Институте системного программирования РАН (ИСП РАН) и распространяемого на условиях Apache License 2.0. Атрибуция приведена в файле [NOTICE](NOTICE).

## Лицензия

[Apache-2.0](LICENSE)
