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

После установки доступны следующие команды:

| Команда              | Описание                                         |
|----------------------|--------------------------------------------------|
| `sbom-checker`       | Валидация SBOM по JSON Schema (CycloneDX 1.6)   |
| `sbom-updater`       | Обогащение SBOM: VCS-ссылки, GOST-свойства      |
| `sbom-unifier`       | Объединение нескольких SBOM в один               |
| `sbom-to-csv`        | Экспорт SBOM в CSV                               |
| `sbom-to-odt`        | Экспорт SBOM в ODT (LibreOffice)                 |
| `cdxgen-postprocess`  | Постобработка вывода cdxgen                      |

Запуск без установки:
```bash
python -m sbom_utils.checker <file.json>
```

## Использование

### sbom-checker

Валидация SBOM по JSON Schema с опциональной проверкой VCS-URL и source-distribution.

```
sbom-checker [-h] [-e ERRORS] [--check-vcs] [--check-vcs-leaf-only]
             [--check-source-distribution] [--format FORMAT] [-v]
             filename
```

| Аргумент                       | Описание                                                                                                |
|--------------------------------|---------------------------------------------------------------------------------------------------------|
| `filename`                     | Входной файл в формате CycloneDX JSON для проверки                                                     |
| `-e, --errors ERRORS`          | Максимальное число ошибок для вывода; по умолчанию 10; установите 0 для вывода всех ошибок              |
| `--check-vcs`                  | Проверка URL типа vcs на git/svn/hg/fossil-репозиторий (требуется доступ к Интернет)                    |
| `--check-vcs-leaf-only`        | То же, что и `--check-vcs`, но проверяются только URL в листовых компонентах                            |
| `--check-source-distribution`  | Проверка URL типа source-distribution: существование ссылки и что она указывает на архив                |
| `--format FORMAT`              | `oss` (по умолчанию) — перечень OSS-компонентов; `container` — перечень образов контейнеров             |
| `-v, --verbose`                | Подробный вывод                                                                                         |

Примеры:
```bash
sbom-checker sbom.json
sbom-checker sbom.json --check-vcs --format=oss -e 0
sbom-checker sbom.json --check-vcs-leaf-only --check-source-distribution
```

### sbom-updater

Обогащение SBOM: поиск VCS-ссылок через ecosystems.ms / NuGet / RubyGems, добавление GOST-свойств, перенос метаинформации из предыдущей версии SBOM.

```
sbom-updater [-h] [--props] [--app-name APP_NAME] [--app-version APP_VERSION]
             [--manufacturer MANUFACTURER] [--ref] [--purl-to-vcs FILE]
             [--gost] [--purl-to-gost FILE] [--init-gost-map] [--init-purl-map]
             [--fix-all] [--update OLD_SBOM] [-v]
             input [output]
```

| Аргумент                          | Описание                                                                                                     |
|-----------------------------------|--------------------------------------------------------------------------------------------------------------|
| `input`                           | Входной файл в формате CycloneDX JSON                                                                       |
| `output`                          | Выходной файл (обязателен, если не указаны `--init-purl-map` / `--init-gost-map`)                           |
| `--props`                         | Добавить GOST:attack_surface и GOST:security_function (по умолчанию `"yes"`) при их отсутствии              |
| `--app-name APP_NAME`             | Установить название продукта                                                                                 |
| `--app-version APP_VERSION`       | Установить версию продукта                                                                                   |
| `--manufacturer MANUFACTURER`     | Установить название организации-изготовителя                                                                 |
| `--ref`                           | Заполнить externalReferences на основе purl компонента                                                       |
| `--purl-to-vcs FILE`              | Путь к файлу маппинга purl → VCS                                                                            |
| `--gost`                          | Установить GOST-свойства на основе файла маппинга purl → GOST                                               |
| `--purl-to-gost FILE`             | Путь к файлу маппинга purl → GOST                                                                           |
| `--init-purl-map`                 | Сгенерировать шаблон `.purl_to_vcs.json` из purl компонентов                                                |
| `--init-gost-map`                 | Сгенерировать шаблон `.purl_to_gost.json` из purl компонентов                                               |
| `--fix-all`                       | Применить все вышеописанные опции; если значение не указано — используется `"TODO"`                          |
| `--update OLD_SBOM`               | Предыдущая версия SBOM для переноса метаинформации                                                           |
| `-v, --verbose`                   | Подробный вывод                                                                                               |

Примеры:
```bash
sbom-updater input.json output.json --fix-all
sbom-updater input.json output.json --ref --props
sbom-updater input.json --init-purl-map
sbom-updater input.json output.json --gost --purl-to-gost custom_gost.json
sbom-updater new.json updated.json --update old.json
```

#### purl_to_vcs.json

Файл маппинга purl → URL репозитория для заполнения поля `externalReferences` при использовании `--ref` или `--fix-all`.

Приоритет поиска: аргумент `--purl-to-vcs` → локальный `.purl_to_vcs.json` → встроенный файл пакета.

Пример содержания:
```json
{
  "pkg:gem/aasm@5.5.0": "https://github.com/aasm/aasm",
  "pkg:nuget/NLog.Extensions.Logging@5.3.12": "https://github.com/NLog/NLog.Extensions.Logging"
}
```

#### purl_to_gost.json

Файл маппинга purl → GOST-свойства для заполнения при использовании `--gost`. Шаблон можно сгенерировать с помощью `--init-gost-map`.

### sbom-unifier

Объединение нескольких SBOM в один с агрегацией GOST-свойств. Значения GOST-свойств объединяются по приоритету: `yes` > `indirect` > `no`.

```
sbom-unifier [-h] --app-name APP_NAME --app-version APP_VERSION
             --manufacturer MANUFACTURER
             input [input ...] output
```

| Аргумент                          | Описание                                                     |
|-----------------------------------|--------------------------------------------------------------|
| `input`                           | Один или несколько входных файлов в формате CycloneDX JSON   |
| `output`                          | Выходной файл с объединённым перечнем                        |
| `--app-name APP_NAME`             | Название продукта (обязательный)                             |
| `--app-version APP_VERSION`       | Версия продукта (обязательный)                               |
| `--manufacturer MANUFACTURER`     | Название организации-изготовителя (обязательный)             |

Примеры:
```bash
sbom-unifier sbom1.json sbom2.json merged.json \
  --app-name "МойПродукт" --app-version "1.0.0" --manufacturer "ООО Рога и Копыта"
```

### sbom-to-csv

Экспорт SBOM в таблицу CSV.

```
sbom-to-csv [-h] input output
```

| Аргумент  | Описание                                     |
|-----------|----------------------------------------------|
| `input`   | Входной файл в формате CycloneDX JSON        |
| `output`  | Выходной файл в формате CSV                  |

Столбцы CSV: № п/п, Наименование компонента, Версия, Язык(и) программирования, Принадлежность к ПА/ФБ, Адрес веб-ресурса.

### sbom-to-odt

Экспорт SBOM в документ формата ODT (LibreOffice Writer).

```
sbom-to-odt [-h] [-t] [--format FORMAT] input output
```

| Аргумент           | Описание                                                                          |
|--------------------|-----------------------------------------------------------------------------------|
| `input`            | Входной файл в формате CycloneDX JSON                                            |
| `output`           | Выходной файл в формате ODT                                                      |
| `-t, --pa-fb-ontop`| Помещение записей «ПА» и «ФБ» в начало таблицы                                   |
| `--format FORMAT`  | `oss` (по умолчанию) — OSS-компоненты; `container` — образы контейнеров           |

### cdxgen-postprocess

Постобработка вывода [cdxgen](https://github.com/CycloneDX/cdxgen): очистка лишних полей, нормализация GOST-свойств, заполнение метаданных.

```
cdxgen-postprocess [-h] [--app-name APP_NAME] [--app-version APP_VERSION]
                   [--manufacturer MANUFACTURER] [--gost-default {yes,no,indirect}]
                   [--strip-only] [--keep-all-fields] [--provided-by NAME]
                   [--purl-to-vcs FILE] [--purl-to-gost FILE] [--pretty]
                   input output
```

| Аргумент                          | Описание                                                                    |
|-----------------------------------|-----------------------------------------------------------------------------|
| `input`                           | Входной файл BOM (JSON) от cdxgen                                          |
| `output`                          | Выходной файл с обработанным BOM                                           |
| `--app-name APP_NAME`             | Название продукта                                                           |
| `--app-version APP_VERSION`       | Версия продукта                                                             |
| `--manufacturer MANUFACTURER`     | Организация-изготовитель                                                    |
| `--gost-default {yes,no,indirect}`| Значение ГОСТ-свойств по умолчанию (по умолчанию `no`)                     |
| `--strip-only`                    | Только очистить лишние поля, не изменяя metadata                            |
| `--keep-all-fields`               | Не удалять необязательные поля компонентов                                  |
| `--provided-by NAME`              | Установить GOST:provided_by для листовых компонентов                        |
| `--purl-to-vcs FILE`              | Путь к файлу маппинга purl → VCS (по умолчанию `.purl_to_vcs.json`)        |
| `--purl-to-gost FILE`             | Путь к файлу маппинга purl → GOST (по умолчанию `.purl_to_gost.json`)      |
| `--pretty`                        | Форматировать JSON (включено по умолчанию)                                  |

Примеры:
```bash
cdxgen-postprocess bom.json clean.json --app-name "App" --app-version "1.0" --manufacturer "Org"
cdxgen-postprocess bom.json clean.json --strip-only
cdxgen-postprocess bom.json clean.json --gost-default=indirect --provided-by "ООО Поставщик"
```

## GOST-свойства

Инструменты поддерживают расширения CycloneDX для ГОСТ:

| Свойство                  | Допустимые значения       | Описание                           |
|---------------------------|---------------------------|------------------------------------|
| `GOST:attack_surface`     | `yes`, `no`, `indirect`   | Принадлежность к поверхности атаки |
| `GOST:security_function`  | `yes`, `no`, `indirect`   | Функция безопасности               |
| `GOST:source_langs`       | строка                    | Языки программирования             |
| `GOST:provided_by`        | строка                    | Поставщик компонента               |

## Структура проекта

```
sbom_utils/
├── checker.py              # Валидация SBOM
├── updater.py              # Обогащение SBOM
├── unifier.py              # Объединение SBOM
├── to_csv.py               # Экспорт в CSV
├── to_odt.py               # Экспорт в ODT
├── cdxgen_postprocess.py   # Постобработка cdxgen
├── sbom_utils.py           # Общие утилиты
├── schemas/                # JSON Schema (CycloneDX 1.6)
├── additional_schemas/     # Внешние схемы (SPDX, JSF)
├── odt_templates/          # Шаблоны ODT-документов
└── purl_to_vcs.json        # Встроенный маппинг purl → VCS
```

## Лицензия

Apache-2.0
