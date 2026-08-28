# sbom-utils

Набор CLI-инструментов для валидации, обогащения, объединения и экспорта SBOM-файлов (Software Bill of Materials) в формате CycloneDX JSON с поддержкой расширений ГОСТ.

## Требования

* Python 3.12 или выше
* [uv](https://docs.astral.sh/uv/) (рекомендуемый менеджер пакетов)
* Для `--check-vcs`: git, subversion, mercurial (опционально)

## Установка

```bash
# Через uv (рекомендуется)
uv pip install -e .

# Или через pip
pip install -e .
```

После установки доступна единая CLI-утилита `sbom`:

```bash
sbom <команда> [аргументы]
```

Запуск без установки:
```bash
python -m sbom_utils.cli <команда> [аргументы]
```

## Быстрый старт

Типичный рабочий процесс:

```bash
# 1. Сгенерировать SBOM (cdxgen или trivy — настраивается в конфиге)
sbom scan

# 2. Создать конфиг из SBOM (для нового проекта)
sbom config init bom.json

# 3. Отредактировать .sbom-config.json — настроить компоненты, форки, исключения

# 4. Постобработка SBOM с применением конфига
sbom postprocess bom.json result.json \
  --app-name "МойПродукт" --app-version "1.0.0" --manufacturer "ООО МояКомпания"

# 5. Валидация результата
sbom check result.json
```

Или воспользуйтесь интерактивным мастером:
```bash
sbom init
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
| `exclude` | `true` — исключить компонент и его транзитивные зависимости; `"direct"` — только сам компонент. Ключ без версии убирает все версии, с версией — только её (`pkg:npm/ajv@6.12.6` не тронет `ajv@8.20.0`) |
| `pedigree` | Объект CycloneDX pedigree (см. ниже) |

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
sbom config init bom.json
sbom config init bom.json -o my-config.json
sbom config init bom.json -i extra1.json -i extra2.json

# Мигрировать из старых файлов
sbom config migrate
sbom config migrate --vcs .purl_to_vcs.json --gost .purl_to_gost.json --exclude .purl_exclude.json
```

## Команды

### sbom check

Валидация SBOM по JSON Schema (CycloneDX 1.6) с опциональной проверкой VCS-URL и source-distribution.

```bash
sbom check <file.json> [--check-vcs] [--check-vcs-leaf-only] [--check-source-distribution]
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
sbom check sbom.json
sbom check sbom.json --check-vcs --format=oss -e 0
```

### sbom postprocess

Постобработка вывода [cdxgen](https://github.com/CycloneDX/cdxgen): очистка лишних полей, нормализация GOST-свойств, применение конфига.

```bash
sbom postprocess <input.json> <output.json> [--config PATH]
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
sbom postprocess bom.json result.json --app-name "App" --app-version "1.0" --manufacturer "Org"

# Со старыми файлами (обратная совместимость)
sbom postprocess bom.json result.json --purl-to-vcs .purl_to_vcs.json --purl-to-gost .purl_to_gost.json
```

### sbom update

Обогащение SBOM: поиск VCS-ссылок через ecosystems.ms / NuGet / RubyGems, добавление GOST-свойств, перенос метаинформации из предыдущей версии SBOM.

```bash
sbom update <input.json> [output.json] [--ref] [--props] [--gost] [--fix-all]
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
sbom update input.json output.json --fix-all
sbom update input.json --init-purl-map --init-gost-map
sbom update new.json updated.json --update old.json
```

### sbom merge

Объединение нескольких SBOM в один с агрегацией GOST-свойств (`yes` > `indirect` > `no`).

```bash
sbom merge <in1.json> [in2.json ...] <out.json> --app-name X --app-version Y --manufacturer Z
```

```bash
sbom merge sbom1.json sbom2.json merged.json \
  --app-name "МойПродукт" --app-version "1.0.0" --manufacturer "ООО Компания"
```

### sbom export csv / odt

Экспорт SBOM в CSV или ODT.

```bash
sbom export csv <input.json> <output.csv>
sbom export odt <input.json> <output.odt> [--format oss|container] [-t]
```

| Аргумент | Описание |
|----------|----------|
| `-t, --pa-fb-ontop` | Помещение записей «ПА» и «ФБ» в начало таблицы (только ODT) |
| `--format FORMAT` | `oss` (по умолчанию) или `container` (только ODT) |

### sbom scan

Генерация SBOM с помощью cdxgen или trivy. Читает настройки из секции `scanner` конфига `.sbom-config.json`. Если конфиг не найден — запускает `sbom init`.

```bash
sbom scan [--tool cdxgen|trivy] [--target PATH] [--output FILE] [--config PATH]
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
sbom scan                        # всё из конфига
sbom scan --tool trivy           # переопределить инструмент
sbom scan --target ./src         # переопределить цель
sbom scan --output my-bom.json   # переопределить выходной файл
```

### sbom init

Интерактивный мастер инициализации SBOM-проекта: выбор инструмента (cdxgen/trivy), генерация SBOM, создание конфига, поиск VCS-ссылок.

```bash
sbom init
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
sbom config migrate
```

## Структура проекта

```
sbom_utils/
├── cli.py                  # Единая CLI-точка входа (typer)
├── config.py               # Единый конфиг .sbom-config.json
├── scanner.py              # Запуск SBOM-сканеров (cdxgen, trivy)
├── checker.py              # Валидация SBOM
├── updater.py              # Обогащение SBOM (VCS через API)
├── unifier.py              # Объединение SBOM
├── to_csv.py               # Экспорт в CSV
├── to_odt.py               # Экспорт в ODT
├── cdxgen_postprocess.py   # Постобработка cdxgen
├── init_wizard.py          # Интерактивный мастер
├── sbom_utils.py           # Общие утилиты
├── schemas/                # JSON Schema (CycloneDX 1.6)
├── additional_schemas/     # Внешние схемы (SPDX, JSF)
├── odt_templates/          # Шаблоны ODT-документов
└── purl_to_vcs.json        # Встроенный маппинг purl → VCS
```

## Лицензия

Apache-2.0
