# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

import concurrent.futures
import json
import logging
from collections import Counter
from pathlib import Path

import jsonschema
from referencing import Registry, Resource
from requests import Session

from .utils import check_repo, dump_cache, get_prop, is_archive_url, load_cache, opener, parse_repo_url

_PKG_DIR = Path(__file__).parent.resolve()

_PLACEHOLDER_URLS = {"TODO", "", "sbom-updater_generated_placeholder:", None}
_REQUIRED_GOST_PROPS = ("GOST:attack_surface", "GOST:security_function")


def _iter_components(components):
    """Обойти компоненты вместе с вложенными."""
    stack = list(components)
    while stack:
        comp = stack.pop(0)
        stack += comp.get("components", [])
        yield comp


def _has_usable_vcs(comp):
    refs = comp.get("externalReferences", [])
    if not isinstance(refs, list):
        return False
    for ref in refs:
        if isinstance(ref, dict) and ref.get("type") == "vcs" and ref.get("url") not in _PLACEHOLDER_URLS:
            return True
    return False


def check_readiness(bom, limit=0):
    """Проверить, что перечень заполнен и годится для сдачи.

    Схема CycloneDX не требует ни ГОСТ-свойств, ни ссылки на исходный код, поэтому
    формально корректный файл может оказаться непригодным. Возвращает число замечаний.
    """
    issues = []

    meta = bom.get("metadata", {}).get("component", {})
    for field in ("name", "version"):
        if meta.get(field, "") in ("", "TODO"):
            issues.append((f"metadata.component.{field} не заполнено", f"metadata.component.{field}: TODO"))
    if meta.get("manufacturer", {}).get("name", "") in ("", "TODO"):
        issues.append(
            ("metadata.component.manufacturer.name не заполнено", "metadata.component.manufacturer.name: TODO")
        )

    for comp in _iter_components(bom.get("components", [])):
        title = f"{comp.get('name', '?')} {comp.get('version', '')}".strip()
        props = comp.get("properties", []) or []
        if comp.get("type") == "container" and not comp.get("description", "").strip():
            issues.append(("не указано назначение образа", f"{title}: не указано назначение (description)"))
        for prop in _REQUIRED_GOST_PROPS:
            if not get_prop(props, prop):
                issues.append((f"отсутствует {prop}", f"{title}: отсутствует {prop}"))
        if not get_prop(props, "GOST:source_langs"):
            issues.append(("отсутствует GOST:source_langs", f"{title}: отсутствует GOST:source_langs"))
        if not _has_usable_vcs(comp) and not get_prop(props, "GOST:provided_by"):
            issues.append(
                (
                    "нет ссылки на репозиторий и не указан GOST:provided_by",
                    f"{title}: нет ссылки на репозиторий и не указан GOST:provided_by",
                )
            )

    for number, (_kind, message) in enumerate(issues, 1):
        if limit and number > limit:
            break
        print(f"WARNING: {message}")
        print("-" * 50)

    if issues:
        counts = Counter(kind for kind, _ in issues)
        print("не заполнено для сдачи:")
        for kind, number in counts.most_common():
            print(f"  {kind}: {number}")

    return len(issues)


def run(args):
    if getattr(args, "verbose", False):
        logging.basicConfig(format="%(message)s", level="INFO")

    registry = None
    with open(_PKG_DIR / "additional_schemas" / "spdx.schema.json") as f:
        resource1 = Resource.from_contents(json.load(f))
    with open(_PKG_DIR / "additional_schemas" / "jsf-0.82.schema.json") as f:
        resource2 = Resource.from_contents(json.load(f))
    registry = Registry().with_resources(
        [
            ("spdx.schema.json", resource1),
            ("jsf-0.82.schema.json", resource2),
        ],
    )

    # encoding and duplicate keys detection
    data, encoding = opener(args.filename, pairs=True)

    with open(args.filename, encoding=encoding) as f:
        parsed_file = json.load(f)
    try:
        with open(
            _PKG_DIR / "schemas" / ("schema_container.json" if args.format == "container" else "schema.json")
        ) as f:
            schema = json.load(f)
        cls = jsonschema.validators.validator_for(schema)
        cls.check_schema(schema)
        if registry:
            validator = cls(schema, format_checker=cls.FORMAT_CHECKER, registry=registry)
        else:
            validator = cls(schema, format_checker=cls.FORMAT_CHECKER)
        errors = validator.iter_errors(parsed_file)
        count = 0
        limit = args.errors
        for err in errors:
            count += 1
            if err.message.endswith(" has non-unique elements"):
                arr = err.instance
                dups = []
                for n, i in enumerate(arr):
                    if i in arr[n + 1 :] and i not in dups:
                        dups.append(i)
                inst = ""
                for line in str(err).split("\n"):
                    if line.startswith("On instance"):
                        inst = line[:-1]
                        break
                print(f"ERROR: {inst} non-unique elements:\n" + "\n".join([str(x) for x in dups]))
            elif err.message.startswith("Additional properties are not allowed"):
                print(f"ERROR: {err.message}\n\nOn {jsonschema.exceptions._pretty(err.instance, 16 * ' ')}")
            else:
                print("ERROR: " + str(err))
            print("-" * 50)
            if limit and count == limit:
                break
        if args.format == "container":
            values = {"yes": 2, "indirect": 1, "no": 0}
            for container in parsed_file.get("components", []):
                attack_surface = get_prop(container.get("properties", []), "GOST:attack_surface")
                security_function = get_prop(container.get("properties", []), "GOST:security_function")
                stack = container.get("components", []).copy()
                eq_as = eq_sf = False
                while stack:
                    component = stack.pop(0)
                    components_value = component.get("components", [])
                    if components_value:
                        stack += components_value
                    component_attack_surface = get_prop(component.get("properties", []), "GOST:attack_surface")
                    component_security_function = get_prop(component.get("properties", []), "GOST:security_function")
                    if values[component_attack_surface] > values[attack_surface]:
                        count += 1
                        print(
                            f'ERROR: контейнер "{container["name"]}" содержит компонент "{component["name"]}" с бóльшим значением поверхности атаки ({component_attack_surface} > {attack_surface})'
                        )
                        print("-" * 50)
                    elif not eq_as and values[component_attack_surface] == values[attack_surface]:
                        eq_as = True
                    if limit and count >= limit:
                        break
                    if values[component_security_function] > values[security_function]:
                        count += 1
                        print(
                            f'ERROR: контейнер "{container["name"]}" содержит компонент "{component["name"]}" с бóльшим значением функции безопасности ({component_security_function} > {security_function})'
                        )
                        print("-" * 50)
                    elif not eq_sf and values[component_security_function] == values[security_function]:
                        eq_sf = True
                    if limit and count >= limit:
                        break
                else:
                    if not eq_as:
                        count += 1
                        print(
                            f'ERROR: контейнер "{container["name"]}" не содержит компонентов со значением его поверхности атаки ({attack_surface})'
                        )
                        print("-" * 50)
                    if limit and count >= limit:
                        break
                    if not eq_sf:
                        count += 1
                        print(
                            f'ERROR: контейнер "{container["name"]}" не содержит компонентов со значением его функции безопасности ({security_function})'
                        )
                        print("-" * 50)
                    if limit and count >= limit:
                        break
                    continue
                break
        not_repos = 0
        not_arch_url = 0
        if args.check_vcs or args.check_vcs_leaf_only or args.check_source_distribution:
            import os

            os.environ["GIT_TERMINAL_PROMPT"] = "0"
            stack = parsed_file.get("components", []).copy()
            repo_dict = load_cache("vcs")
            src_list = set()
            src_results = load_cache("source-distribution")
            refs_to_check = dict()
            while stack:
                component = stack.pop(0)
                components_value = component.get("components", [])
                if components_value:
                    stack += components_value
                if args.check_vcs_leaf_only and components_value:
                    continue
                refs = component.get("externalReferences", [])
                if isinstance(refs, list):
                    for ref in refs:
                        if isinstance(ref, dict) and ref.get("type", "") == "vcs":
                            url = ref.get("url", "")
                            res = parse_repo_url(url)
                            if res and res[1]:
                                url = res[0]
                            ex_str = ""
                            if url not in repo_dict:
                                if url not in refs_to_check:
                                    refs_to_check[url] = set()
                                refs_to_check[url].add(ref.get("url", ""))
                        if args.check_source_distribution:
                            if isinstance(ref, dict) and ref.get("type", "") == "source-distribution":
                                url = ref.get("url", "")
                                if url not in src_results:
                                    src_list.add(url)
            session = Session()
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future_to_url = {executor.submit(check_repo, url): ("vcs", url) for url in refs_to_check.keys()}
                future_to_url.update(
                    {executor.submit(is_archive_url, session, url): ("source-distribution", url) for url in src_list}
                )
                total_links = len(future_to_url)
                done_links = 0
                if total_links:
                    print(f"Проверка ссылок: {total_links}")
                for future in concurrent.futures.as_completed(future_to_url):
                    done_links += 1
                    if total_links > 20 and done_links % 20 == 0:
                        print(f"  проверено {done_links} из {total_links}")
                    ref_type, url = future_to_url[future]
                    try:
                        if ref_type == "vcs":
                            repo_dict[url], ex_str = future.result()
                        elif ref_type == "source-distribution":
                            src_results[url], ex_str = future.result()
                    except Exception as exc:
                        count += 1
                        print(f"ERROR: {url!r} generated an exception: {exc}")
                    else:
                        if ref_type == "vcs" and not repo_dict[url]:
                            not_repos += len(refs_to_check[url])
                            for u in sorted(list(refs_to_check[url])):
                                logging.info(ex_str)
                                print(
                                    f"WARNING: {u} не подходит под шаблон и не является git/svn/hg/fossil-репозиторием"
                                )
                                print("-" * 50)
                        if ref_type == "source-distribution" and not src_results[url]:
                            not_arch_url += 1
                            logging.info(ex_str)
                            print(f"WARNING: {url} не указывает на архив или не существует")
                            print("-" * 50)
            dump_cache("vcs", {k: v for k, v in repo_dict.items() if v})
            dump_cache("source-distribution", {k: v for k, v in src_results.items() if v})

        not_ready = check_readiness(parsed_file, limit)

        if count or not_repos or not_arch_url:
            return 1
        if not_ready:
            print(f"файл соответствует схеме, но перечень не готов к сдаче: замечаний {not_ready}")
            return 3
        print("файл корректный")
        return 0
    except jsonschema.exceptions.SchemaError as se:
        print("ошибка в файле-спецификации:")
        print(se)
        return 1
