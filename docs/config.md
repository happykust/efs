# Конфиг `.efs-config.json`

Конфиг — место, где вы один раз описываете решения по компонентам: какие относятся к поверхности атаки, что исключить из перечня, где искать исходники форков. При каждом обновлении SBOM решения применяются заново, так что переделывать их не нужно.

Файл ищется в текущей рабочей директории. Прежнее имя `.sbom-config.json` продолжает читаться — проекты, созданные до переименования, работают без изменений. `efs config init` переносит настройки из старого файла в новый.

Конфиг заменяет три отдельных файла прежних версий (`.purl_to_vcs.json`, `.purl_to_gost.json`, `.purl_exclude.json`) и добавляет pedigree и manufacturer на уровне компонента. Перенести старые файлы: `efs config migrate`.

## Структура

```json
{
  "metadata": {
    "name": "МойПродукт",
    "version": "1.0.0",
    "manufacturer": {"name": "ООО МояКомпания"}
  },
  "scanner": {
    "tool": "cdxgen",
    "output": "bom.json",
    "target": ".",
    "options": {}
  },
  "defaults": {
    "attack_surface": "no",
    "security_function": "no",
    "manufacturer": {"name": "ООО МояКомпания"}
  },
  "components": {
    "pkg:pypi/requests": {
      "vcs": "https://github.com/psf/requests",
      "attack_surface": "yes"
    },
    "pkg:pypi/cryptography": {
      "vcs": "https://github.com/our-org/cryptography-fork",
      "security_function": "yes",
      "source_langs": ["Python", "C"],
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
    "pkg:generic/crypto-module": {
      "provided_by": "КриптоПро CSP"
    },
    "pkg:pypi/pytest": {
      "exclude": true
    }
  }
}
```

## Секции

### metadata

Данные о продукте, попадающие в `metadata.component` перечня. Используются, если не переданы аргументами `--app-name`, `--app-version`, `--manufacturer`.

| Поле | Описание |
|------|----------|
| `name` | Название продукта |
| `version` | Версия продукта |
| `manufacturer` | Организация-изготовитель, объект `{"name": "..."}` |
| `type` | Тип корневого компонента, по умолчанию `application` |
| `pedigree` | Pedigree самого продукта |

### scanner

Настройки генерации SBOM для команды `efs scan`.

| Поле | Описание |
|------|----------|
| `tool` | `cdxgen` или `trivy` |
| `output` | Имя выходного SBOM-файла |
| `target` | Путь к исходникам или имя образа |
| `options` | Параметры инструмента: для cdxgen попадают в `.cdxgenrc`, для trivy — `command` и `args` |

### defaults

Значения, применяемые к компонентам, у которых нет собственной настройки.

| Поле | Описание |
|------|----------|
| `attack_surface` | `GOST:attack_surface` по умолчанию (`yes`/`no`/`indirect`) |
| `security_function` | `GOST:security_function` по умолчанию |
| `provided_by` | Название сертифицированного СЗИ по умолчанию |
| `source_langs` | Язык для компонентов, где он не выводится из purl (deb, rpm) |
| `manufacturer` | Организация-изготовитель по умолчанию |

### components

Настройки конкретных компонентов. Ключ — purl: без версии он действует на все версии пакета, с версией — только на неё.

```json
"pkg:npm/ajv": { "attack_surface": "yes" },
"pkg:npm/ajv@6.12.6": { "exclude": true }
```

| Поле | Описание |
|------|----------|
| `vcs` | URL репозитория с исходным кодом; попадает в `externalReferences` типа `vcs` |
| `attack_surface` | `GOST:attack_surface`: `yes`, `no`, `indirect` |
| `security_function` | `GOST:security_function`: `yes`, `no`, `indirect` |
| `provided_by` | `GOST:provided_by` — название сертифицированного СЗИ, в составе которого поставляется компонент |
| `source_langs` | Языки: список `["Python", "C"]` или строка `"Python, C"` |
| `manufacturer` | Организация-изготовитель компонента |
| `exclude` | `true` — с каскадом, `"direct"` — только сам компонент |
| `pedigree` | Объект CycloneDX pedigree |

## Языки программирования

По требованиям ФСТЭК каждый язык указывается **отдельным свойством** `GOST:source_langs`, а не списком через запятую. В конфиге язык задаётся как удобно — списком или строкой, — а в перечень попадает по одному свойству на язык:

```json
"pkg:pypi/cryptography": { "source_langs": ["Python", "C"] }
```

```json
"properties": [
  {"name": "GOST:source_langs", "value": "Python"},
  {"name": "GOST:source_langs", "value": "C"}
]
```

Для большинства компонентов заполнять ничего не нужно — язык следует из экосистемы purl:

| Тип purl | Язык | Тип purl | Язык |
|----------|------|----------|------|
| `pypi` | Python | `gem` | Ruby |
| `npm` | JavaScript | `nuget` | C# |
| `maven`, `gradle` | Java | `composer` | PHP |
| `cargo` | Rust | `conan` | C++ |
| `golang` | Go | `swift` | Swift |
| `cocoapods` | Objective-C | `hex` | Elixir |
| `cran` | R | `pub` | Dart |

Для `deb` и `rpm` язык не выводится: в дистрибутивных пакетах он произвольный, а перечень идёт регулятору. Такие компоненты заполняются вручную или через `defaults.source_langs`.

Приоритет: значение компонента → язык из экосистемы → `defaults.source_langs`. Именно в таком порядке — иначе общий `defaults` подменял бы язык, выведенный из purl. Значение, уже проставленное в SBOM, автоопределение не затирает; явно заданное в конфиге — заменяет.

## Исключение компонентов

Тестовые, сборочные и линтерные зависимости в перечень не входят — их убирают через `exclude`.

```json
"pkg:pypi/pytest": { "exclude": true },
"pkg:npm/eslint": { "exclude": true },
"pkg:pypi/our-internal-module": { "exclude": "direct" }
```

### Как работает каскад

При `exclude: true` вместе с компонентом уходят те его зависимости, которые больше никто не тянет: компонент удаляется, только если **все** его родители в графе тоже помечены `exclude`. Если хоть один родитель остаётся в перечне, зависимость поставляется в составе продукта и должна быть задекларирована — каскад её не трогает.

Компоненты без родителей каскад не удаляет никогда: после удаления компонентов-манифестов (`uv.lock`, `package-lock.json`) реальные рантайм-зависимости остаются без входящих связей, и принимать их за ненужные нельзя.

Правило намеренно консервативное — оно снимает ровно один слой. Чтобы убрать глубокую цепочку dev-зависимостей целиком, пометьте `exclude` и промежуточные пакеты. Лишний компонент в перечне — недочёт, недостающий — нарушение.

`exclude: "direct"` убирает только сам компонент — его зависимости остаются в перечне **полностью**, включая те, которые тянет он один.

Это правильный режим для собственного кода: ваш модуль заимствованным не является и в перечень не входит, а всё, что он за собой тянет, — сторонние компоненты в поставке, и они подлежат декларированию. Для собственных пакетов используйте именно `"direct"`, а не `true`.

Версии учитываются: ключ `pkg:npm/ajv@6.12.6` уберёт только эту версию и не тронет `ajv@8.20.0`.

## Pedigree — описание форков

Если заимствованный компонент модифицирован, происхождение документируется через [CycloneDX pedigree](https://cyclonedx.org/use-cases/pedigree/).

```json
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
```

| Поле | Описание |
|------|----------|
| `ancestors` | Оригинальные компоненты, от которых произведён форк |
| `descendants` | Потомки компонента |
| `variants` | Связанные компоненты без точного отношения предок/потомок |
| `commits` | Коммиты с изменениями |
| `patches` | Патчи: `unofficial`, `monkey`, `backport`, `cherry-pick` |
| `notes` | Причины модификации в свободной форме |

Поле `pedigree` переживает очистку компонента при `efs postprocess` — оно не удаляется вместе с прочими необязательными полями.

## Работа с конфигом

```bash
efs config init bom.json                  # собрать или обновить конфиг из SBOM
efs config init bom.json -i extra.json    # несколько SBOM в один конфиг
efs config status                         # что осталось незаполненным
efs config find-vcs                       # найти ссылки на репозитории
efs config migrate                        # перенести старые файлы маппингов
```
