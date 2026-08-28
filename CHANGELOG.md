# Changelog

Все значимые изменения проекта фиксируются в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
проект следует [семантическому версионированию](https://semver.org/lang/ru/).

## [Unreleased]

### Изменено (breaking)

- Проект переименован в **efc** (Easy FSTEC Certification).
  - Python-пакет: `sbom_utils` → `efc`.
  - CLI-команда: `sbom` → `efc`.
  - Модуль `sbom_utils.sbom_utils` → `efc.utils`.
  - Модуль `sbom_utils.cdxgen_postprocess` → `efc.postprocess` (обрабатывает вывод
    и cdxgen, и trivy, прежнее имя вводило в заблуждение).
  - Каталог кеша: `~/.cache/sbom-checker` → `~/.cache/efc`. Прежний кеш не
    переносится — при первом запуске проверки выполняются заново.
  - Имя файла конфигурации `.sbom-config.json` не изменилось.
- Удалён неиспользуемый слой argparse из модулей (`configure_parser()`, `main()`,
  `if __name__ == '__main__'`). Прямой вызов модулей вида
  `python -m sbom_utils.updater` больше не поддерживается — используйте `efc update`.
- Удалён `requirements.txt`: зависимости описаны в `pyproject.toml`, версии
  зафиксированы в `uv.lock`.

### Добавлено

- Набор тестов на pytest и конфигурация ruff.
- `NOTICE` с атрибуцией ИСП РАН как автора исходного проекта sbom-checker.
- Поддержка значения `exclude: "direct"` в конфиге — исключение самого компонента
  без каскадного удаления его транзитивных зависимостей.
- Резолверы VCS-ссылок для PyPI, npm, Maven, RPM и Deb в `efc update`.
- Параллельная обработка purl при поиске VCS-ссылок.

### Исправлено

- Сопоставление purl в `exclude` учитывает версию: запись `pkg:npm/ajv@6.12.6`
  больше не удаляет из SBOM все версии `ajv`.
- HTTP-фоллбэк при таймауте `git ls-remote` — крупные репозитории (например,
  chromium) больше не помечаются как недоступные.
- Неинтерактивный режим для `svn ls` и `hg identify` — проверка VCS не зависает
  в ожидании ввода учётных данных.
- Тайм-ауты для всех HTTP-запросов в `efc update`.

## [1.0.0]

Первая версия под именем `sbom-utils`: единая CLI-точка входа, единый конфиг
`.sbom-config.json`, команды `check`, `update`, `merge`, `postprocess`, `scan`,
`export`, `config`, `init`.

[Unreleased]: https://github.com/happykust/efc/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/happykust/efc/releases/tag/v1.0.0
