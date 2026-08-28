# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

import concurrent.futures
import datetime
import json
import logging
import os
from pathlib import Path
import sys
import threading
from requests import Session, adapters
import xml.etree.ElementTree as ET

from .utils import opener, check_repo, load_cache, dump_cache

_PURL_TO_VCS_FILENAME = '.purl_to_vcs.json'
_PURL_TO_GOST_FILENAME = '.purl_to_gost.json'

_GOST_PROPS = ('GOST:attack_surface', 'GOST:security_function')
_GOST_ALLOWED_VALUES = {'yes', 'no', 'indirect'}
_GOST_DEFAULT_VALUE = 'no'

DEFAULT_VALUE = "TODO"

_HTTP_TIMEOUT = 30


def _resolve_purl_to_vcs(cli_path=None):
    """Определить путь к purl_to_vcs.json.

    Порядок поиска:
    1. Явно указанный через CLI (--purl-to-vcs)
    2. .purl_to_vcs.json в текущей рабочей директории
    3. None (маппинг не используется)
    """
    if cli_path:
        p = Path(cli_path)
        if p.is_file():
            return p
        raise FileNotFoundError(f"Указанный файл не найден: {cli_path}")

    cwd_file = Path.cwd() / _PURL_TO_VCS_FILENAME
    if cwd_file.is_file():
        return cwd_file

    return None


def _resolve_purl_to_gost(cli_path=None):
    """Определить путь к purl_to_gost.json.

    Порядок поиска:
    1. Явно указанный через CLI (--purl-to-gost)
    2. .purl_to_gost.json в текущей рабочей директории
    """
    if cli_path:
        p = Path(cli_path)
        if p.is_file():
            return p
        raise FileNotFoundError(f"Указанный файл не найден: {cli_path}")

    cwd_file = Path.cwd() / _PURL_TO_GOST_FILENAME
    if cwd_file.is_file():
        return cwd_file

    return None


def _load_purl_to_gost(cli_path=None):
    """Загрузить маппинг purl→GOST-свойства."""
    resolved = _resolve_purl_to_gost(cli_path)
    if resolved is None:
        return {}
    try:
        with open(resolved) as f:
            data = json.load(f)
        logging.info(f"используется файл purl→GOST: {resolved}")
        return data
    except Exception as e:
        logging.warning(f"не удалось загрузить {resolved}: {e}")
        return {}


def _set_prop(props, name, value):
    """Установить значение GOST-свойства в массиве properties (заменить существующее или добавить)."""
    for elem in props:
        if elem.get('name', '') == name:
            elem['value'] = value
            return
    props.append({'name': name, 'value': value})


def _apply_gost_props(component, purl_to_gost):
    """Применить GOST-свойства к компоненту на основе маппинга.

    Формат маппинга: {"GOST:attack_surface": {"purl": "yes/indirect"}, ...}
    По умолчанию GOST:attack_surface и GOST:security_function устанавливаются в "no".
    Если purl компонента есть в соответствующей секции — берётся значение оттуда.
    """
    if 'properties' not in component:
        component['properties'] = []

    purl = component.get('purl', '')

    for prop_name in _GOST_PROPS:
        value = purl_to_gost.get(prop_name, {}).get(purl, _GOST_DEFAULT_VALUE) if purl else _GOST_DEFAULT_VALUE
        if value not in _GOST_ALLOWED_VALUES:
            logging.warning(f"недопустимое значение '{value}' для {prop_name} (purl: {purl}), используется '{_GOST_DEFAULT_VALUE}'")
            value = _GOST_DEFAULT_VALUE
        _set_prop(component['properties'], prop_name, value)

    # GOST:provided_by — устанавливается только если указано в маппинге
    provided_by = purl_to_gost.get('GOST:provided_by', {}).get(purl, '') if purl else ''
    if provided_by:
        _set_prop(component['properties'], 'GOST:provided_by', provided_by)


def has_prop(arr, name):
    for elem in arr:
        if elem.get('name', '') == name:
            return True
    return False

def get_website(ref_arr):
    for elem in ref_arr:
        if elem['type'] == 'website':
            return elem
    return False

class _TimeoutHTTPAdapter(adapters.HTTPAdapter):
    """HTTPAdapter с таймаутом по умолчанию."""

    def __init__(self, *args, timeout=_HTTP_TIMEOUT, **kwargs):
        self._default_timeout = timeout
        super().__init__(*args, **kwargs)

    def send(self, *args, **kwargs):
        if kwargs.get('timeout') is None:
            kwargs['timeout'] = self._default_timeout
        return super().send(*args, **kwargs)


class RefFinder(object):
    def __init__(self, purl_file=None):
        self._placeholder_url = 'sbom-updater_generated_placeholder:'
        self._nuget_addr = None
        self._lock = threading.Lock()
        self._session = Session()
        adapter = _TimeoutHTTPAdapter(max_retries=5, pool_connections=10, pool_maxsize=10)
        self._session.mount('http://', adapter=adapter)
        self._session.mount('https://', adapter=adapter)
        self._prefixes = {
            'pkg:nuget/': self._nuget_purl,
            'pkg:gem/': self._gem_purl,
            'pkg:pypi/': self._pypi_purl,
            'pkg:npm/': self._npm_purl,
            'pkg:maven/': self._maven_purl,
            'pkg:rpm/': self._rpm_purl,
            'pkg:deb/': self._deb_purl,
        }
        self._purl_to_url = dict()
        try:
            with open(purl_file) as f:
                self._purl_to_url = json.load(f)
        except Exception:
            pass
        self._repo_dict = load_cache('vcs')
        os.environ['GIT_TERMINAL_PROMPT'] = '0'

    def is_repo(self, url):
        with self._lock:
            if url in self._repo_dict:
                return self._repo_dict[url]
        result, ex_str = check_repo(url)
        with self._lock:
            self._repo_dict[url] = result
        if not result:
            logging.info(ex_str)
        return result

    def dump_repos(self):
        dump_cache('vcs', {k:v for k,v in self._repo_dict.items() if v})

    def process_purl(self, purl):
        with self._lock:
            if purl in self._purl_to_url:
                return self._purl_to_url[purl]
        logging.info(f'обработка purl {purl}')

        urls = self._ecosystems(purl)
        url = self._analyse_urls(urls, purl, 'ecosyste.ms: ')
        if not url:
            for k, f in self._prefixes.items():
                if purl.startswith(k):
                    urls = f(purl)
                    url = self._analyse_urls(urls, purl, '')
                    break
            else:
                logging.info(f'не удалось найти репозиторий для purl {purl}')
        logging.info('-'*50)
        result = url if url else self._placeholder_url
        with self._lock:
            self._purl_to_url[purl] = result
        return result

    def _analyse_urls(self, urls, purl, log_prefix):
        for url in urls:
            if type(url) == str:
                if url.startswith('git://'):
                    url = "https" + url[3:]
                if self.is_repo(url):
                    logging.info(f'{log_prefix}найден репозиторий {url} среди {urls}')
                    return url
        logging.info(f'{log_prefix}ни одна из {urls} не является git-репозиторием')
        return None

    def _ecosystems(self, purl):
        try:
            with self._session.get(f"https://packages.ecosyste.ms/api/v1/packages/lookup?purl={purl.lower()}") as res:
                ecosystems_data = res.json()
        except Exception:
            return []
        if isinstance(ecosystems_data, list) and ecosystems_data:
            ecosystems_data = ecosystems_data[0]
            return [ecosystems_data.get("repository_url", ''), ecosystems_data.get("registry_url", ''), ecosystems_data.get("homepage", '')]
        return []

    def _nuget_purl(self, purl):
        id, version = purl.split("@") if '@' in purl else (purl, '')
        id = id[10:]
        if not self._nuget_addr:
            with self._session.get("https://api.nuget.org/v3/index.json") as res:
                for resource in res.json().get("resources", []):
                    if resource["@type"].startswith("PackageBaseAddress"):
                        self._nuget_addr = resource["@id"]
        package_address = f"{self._nuget_addr}{id.lower()}/{version.lower()}/{id.lower()}.nuspec"
        root = []
        with self._session.get(package_address) as res:
            root = ET.fromstring(res.text)
        urls = []
        for child in root:
            if child.tag.endswith("metadata"):
                for child2 in child:
                    if child2.tag.endswith("projectUrl"):
                        if not child2.text in urls:
                            urls.append(child2.text)
                    elif child2.tag.endswith("repository"):
                        if child2.attrib.get("url", ''):
                            if not child2.attrib['url'] in urls:
                                urls.append(child2.attrib['url'])
        return list(reversed(urls))

    def _gem_purl(self, purl):
        id, version = purl.split("@") if '@' in purl else (purl, '')
        id = id[8:]
        gem_data = dict()
        urls = []
        kws = ['source_code_uri', 'project_uri', 'homepage_uri']
        try:
            with self._session.get(f'https://rubygems.org/api/v2/rubygems/{id.lower()}/versions/{version.lower()}.json') as res:
                gem_data = res.json()
        except Exception:
            return []
        md = gem_data.get('metadata', dict())
        for kw in kws:
            url = gem_data.get(kw, '')
            if url and not url in urls:
                urls.append(url)
            url = md.get(kw, '')
            if url and not url in urls:
                urls.append(url)
        return urls

    def _pypi_purl(self, purl):
        """Поиск VCS через PyPI JSON API."""
        name = purl.split("@")[0][9:]
        try:
            with self._session.get(f'https://pypi.org/pypi/{name}/json') as res:
                if res.status_code != 200:
                    return []
                data = res.json()
        except Exception:
            return []
        urls = []
        project_urls = data.get('info', {}).get('project_urls') or {}
        for key in ('Source', 'Source Code', 'Repository', 'Code', 'GitHub', 'Homepage'):
            for purl_key, purl_url in project_urls.items():
                if purl_key.lower().replace(' ', '') == key.lower().replace(' ', '') and purl_url:
                    if purl_url not in urls:
                        urls.append(purl_url)
        home_page = data.get('info', {}).get('home_page', '')
        if home_page and home_page not in urls:
            urls.append(home_page)
        return urls

    def _npm_purl(self, purl):
        """Поиск VCS через npm registry API."""
        name_ver = purl[8:]
        name = name_ver.split("@")[-2] if name_ver.count("@") >= 2 else name_ver.split("@")[0]
        if name.startswith('%40'):
            name = '@' + name[3:]
        try:
            with self._session.get(f'https://registry.npmjs.org/{name}') as res:
                if res.status_code != 200:
                    return []
                data = res.json()
        except Exception:
            return []
        urls = []
        repo = data.get('repository', {})
        if isinstance(repo, dict):
            repo_url = repo.get('url', '')
            if repo_url:
                for prefix in ('git+https://', 'git+http://', 'git://'):
                    if repo_url.startswith(prefix):
                        repo_url = 'https://' + repo_url[len(prefix):]
                        break
                if repo_url.endswith('.git'):
                    repo_url = repo_url[:-4]
                if repo_url not in urls:
                    urls.append(repo_url)
        homepage = data.get('homepage', '')
        if homepage and homepage not in urls:
            urls.append(homepage)
        return urls

    def _maven_purl(self, purl):
        """Поиск VCS через Maven Central API."""
        parts = purl[10:]
        name_part = parts.split("@")[0]
        if '/' in name_part:
            group_id, artifact_id = name_part.split('/', 1)
        else:
            return []
        try:
            with self._session.get(
                f'https://search.maven.org/solrsearch/select?q=g:{group_id}+AND+a:{artifact_id}&rows=1&wt=json'
            ) as res:
                if res.status_code != 200:
                    return []
                data = res.json()
        except Exception:
            return []
        urls = []
        docs = data.get('response', {}).get('docs', [])
        if not docs:
            return []
        doc = docs[0]
        version = doc.get('latestVersion', '')
        if version:
            group_path = group_id.replace('.', '/')
            pom_url = f'https://repo1.maven.org/maven2/{group_path}/{artifact_id}/{version}/{artifact_id}-{version}.pom'
            try:
                with self._session.get(pom_url) as res:
                    if res.status_code == 200:
                        root = ET.fromstring(res.text)
                        ns = ''
                        if root.tag.startswith('{'):
                            ns = root.tag[:root.tag.index('}') + 1]
                        scm = root.find(f'{ns}scm')
                        if scm is not None:
                            scm_url = scm.findtext(f'{ns}url', '')
                            scm_conn = scm.findtext(f'{ns}connection', '')
                            if scm_url and scm_url not in urls:
                                urls.append(scm_url)
                            if scm_conn:
                                conn = scm_conn
                                for prefix in ('scm:git:', 'scm:svn:', 'scm:'):
                                    if conn.startswith(prefix):
                                        conn = conn[len(prefix):]
                                        break
                                if conn.startswith('git://'):
                                    conn = 'https://' + conn[6:]
                                if conn.endswith('.git'):
                                    conn = conn[:-4]
                                if conn and conn not in urls:
                                    urls.append(conn)
                        proj_url = root.findtext(f'{ns}url', '')
                        if proj_url and proj_url not in urls:
                            urls.append(proj_url)
            except Exception:
                pass
        return urls

    def _rpm_purl(self, purl):
        """Поиск VCS через Fedora/CentOS/РЕД ОС/Rocky Linux."""
        name_part = purl[8:]
        name_part = name_part.split("@")[0]
        if '/' in name_part:
            name_part = name_part.split('/', 1)[-1]
        urls = []
        urls.append(f'https://src.fedoraproject.org/rpms/{name_part}')
        urls.append(f'https://gitlab.com/redhat/centos-stream/rpms/{name_part}')
        urls.append(f'https://git.rockylinux.org/staging/rpms/{name_part}')
        return urls

    def _deb_purl(self, purl):
        """Поиск VCS через Debian Sources API и салса (salsa.debian.org)."""
        name_part = purl[8:]
        name_part = name_part.split("@")[0]
        distro = ''
        if '/' in name_part:
            distro, name_part = name_part.split('/', 1)
        urls = []
        try:
            with self._session.get(f'https://sources.debian.org/api/src/{name_part}/') as res:
                if res.status_code == 200:
                    data = res.json()
                    vcs_git = data.get('info', {}).get('vcs_git', '') if isinstance(data.get('info'), dict) else ''
                    if not vcs_git and isinstance(data.get('versions'), list):
                        for ver in data['versions']:
                            if isinstance(ver, dict):
                                vcs_git = ver.get('vcs_git', '')
                                if vcs_git:
                                    break
                    if vcs_git:
                        if vcs_git.endswith('.git'):
                            vcs_git = vcs_git[:-4]
                        if vcs_git not in urls:
                            urls.append(vcs_git)
        except Exception:
            pass
        urls.append(f'https://salsa.debian.org/debian/{name_part}')
        urls.append(f'https://git.altlinux.org/gears/{name_part[0]}/{name_part}.git')
        urls.append(f'https://git.altlinux.org/srpms/{name_part[0]}/{name_part}.git')
        if distro == 'ubuntu':
            urls.append(f'https://git.launchpad.net/ubuntu/+source/{name_part}')
        return urls


def _has_provided_by(component):
    """Проверить наличие свойства GOST:provided_by у компонента."""
    for p in component.get('properties', []):
        if p.get('name') == 'GOST:provided_by' and p.get('value'):
            return True
    return False


def _extract_purls(filenames, skip_provided_by=False, purl_to_gost=None):
    """Извлечь все purl из списка SBOM-файлов.

    Если skip_provided_by=True, пропускает компоненты, у которых установлено
    свойство GOST:provided_by (в properties компонента или в маппинге purl_to_gost).
    """
    provided_by_purls = set()
    if skip_provided_by and purl_to_gost:
        provided_by_purls = {k for k, v in purl_to_gost.get('GOST:provided_by', {}).items() if v}

    purls = set()
    for fn in filenames:
        data, _ = opener(fn)
        stack = data.get('components', []).copy()
        while stack:
            comp = stack.pop(0)
            if 'components' in comp:
                stack += comp['components']
            purl = comp.get('purl', '')
            if not purl:
                continue
            if skip_provided_by:
                if _has_provided_by(comp) or purl in provided_by_purls:
                    continue
            purls.add(purl)
    return sorted(purls)


def run(args, progress_callback=None):
    if getattr(args, 'verbose', False):
        logging.basicConfig(format='%(message)s', level="INFO")

    if not args.init_purl_map and not args.init_gost_map and not args.output:
        print('ошибка: аргумент output обязателен (если не используется --init-purl-map или --init-gost-map)')
        sys.exit(1)

    extra = getattr(args, 'extra_input', None) or []

    if args.init_gost_map:
        purls = _extract_purls([args.input] + extra)
        out_path = Path.cwd() / _PURL_TO_GOST_FILENAME
        existing = {}
        if out_path.is_file() and out_path.stat().st_size > 0:
            with open(out_path) as f:
                existing = json.load(f)
        purl_set = set(purls)
        # Гарантировать наличие секций
        for prop_name in _GOST_PROPS:
            if prop_name not in existing:
                existing[prop_name] = {}
        if 'GOST:provided_by' not in existing:
            existing['GOST:provided_by'] = {}
        # Удалить purl, которых нет во входном файле
        removed = 0
        for prop_name in list(existing.keys()):
            section = existing[prop_name]
            if not isinstance(section, dict):
                continue
            to_del = [k for k in section if k not in purl_set]
            removed += len(to_del)
            for k in to_del:
                del section[k]
        # Добавить новые purl со значением "no" (только для attack_surface и security_function)
        added = 0
        for purl in purls:
            for prop_name in _GOST_PROPS:
                if purl not in existing[prop_name]:
                    existing[prop_name][purl] = _GOST_DEFAULT_VALUE
                    added += 1
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(existing, f, indent=2, ensure_ascii=False)
        total = len(purls)
        non_default = 0
        for prop_name in _GOST_PROPS:
            non_default += sum(1 for v in existing[prop_name].values() if v != _GOST_DEFAULT_VALUE)
        non_default += sum(1 for v in existing.get('GOST:provided_by', {}).values() if v)
        print(f"Записано в {out_path}: {total} purl")
        print(f"  Нестандартных значений: {non_default}")
        if removed:
            print(f"  Удалено устаревших записей: {removed}")
        if not args.init_purl_map:
            return

    if args.init_purl_map:
        purl_to_gost = _load_purl_to_gost(getattr(args, 'purl_to_gost', None))
        purls = _extract_purls([args.input] + extra, skip_provided_by=True, purl_to_gost=purl_to_gost)
        out_path = Path.cwd() / _PURL_TO_VCS_FILENAME
        existing = {}
        if out_path.is_file() and out_path.stat().st_size > 0:
            with open(out_path) as f:
                existing = json.load(f)
        purl_set = set(purls)
        removed = [k for k in existing if k not in purl_set]
        for k in removed:
            del existing[k]
        for purl in purls:
            if purl not in existing:
                existing[purl] = ""
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(existing, f, indent=2, ensure_ascii=False)
        filled = sum(1 for v in existing.values() if v)
        total = len(existing)
        print(f"Записано в {out_path}: {total} purl ({filled} заполнено, {total - filled} пусто)")
        if removed:
            print(f"  Удалено лишних: {len(removed)}")
        return

    input_data, encoding = opener(args.input)

    if args.fix_all:
        if input_data['specVersion'] != '1.6':
            logging.info(f"смена 'specVersion' с {input_data['specVersion']} на 1.6")
            logging.info('-'*50)
            input_data['specVersion'] = '1.6'

    if args.gost or args.fix_all:
        purl_to_gost = _load_purl_to_gost(args.purl_to_gost)
        stack = input_data.get('components', []).copy()
        while stack:
            component = stack.pop()
            _apply_gost_props(component, purl_to_gost)
            if 'components' in component:
                stack += component['components']
    elif args.props:
        stack = input_data.get('components', []).copy()
        while stack:
            component = stack.pop()
            if not 'properties' in component:
                component['properties'] = []
            if not has_prop(component['properties'], 'GOST:attack_surface'):
                component['properties'].append({'name': 'GOST:attack_surface', 'value': 'yes'})
            if not has_prop(component['properties'], 'GOST:security_function'):
                component['properties'].append({'name': 'GOST:security_function', 'value': 'yes'})
            if 'components' in component:
                stack += component['components']

    if not args.app_name is None or args.fix_all:
        if not 'metadata' in input_data:
            input_data['metadata'] = dict()
        if not 'component' in input_data['metadata']:
            input_data['metadata']['component'] = dict()
        if not args.app_name is None:
            if 'name' in input_data['metadata']['component']:
                logging.info(f"смена названия продукта {input_data['metadata']['component']['name']} -> {args.app_name}")
                logging.info('-'*50)
            input_data['metadata']['component']['name'] = args.app_name
        elif not 'name' in input_data['metadata']['component']:
            input_data['metadata']['component']['name'] = DEFAULT_VALUE

    if not args.app_version is None or args.fix_all:
        if not 'metadata' in input_data:
            input_data['metadata'] = dict()
        if not 'component' in input_data['metadata']:
            input_data['metadata']['component'] = dict()
        if not args.app_version is None:
            if 'version' in input_data['metadata']['component']:
                logging.info(f"смена версии продукта {input_data['metadata']['component']['version']} -> {args.app_version}")
                logging.info('-'*50)
            input_data['metadata']['component']['version'] = args.app_version
        elif not 'version' in input_data['metadata']['component']:
            input_data['metadata']['component']['version'] = DEFAULT_VALUE

    if not args.manufacturer is None or args.fix_all:
        if not 'metadata' in input_data:
            input_data['metadata'] = dict()
        if not 'component' in input_data['metadata']:
            input_data['metadata']['component'] = dict()
        if not 'manufacturer' in input_data['metadata']['component']:
            input_data['metadata']['component']['manufacturer'] = dict()
        if not args.manufacturer is None:
            if 'name' in input_data['metadata']['component']['manufacturer']:
                logging.info(f"смена названия организации {input_data['metadata']['component']['manufacturer']['name']} -> {args.manufacturer}")
                logging.info('-'*50)
            input_data['metadata']['component']['manufacturer']['name'] = args.manufacturer
        elif not 'name' in input_data['metadata']['component']['manufacturer']:
            input_data['metadata']['component']['manufacturer']['name'] = DEFAULT_VALUE

    if args.ref or args.fix_all:
        purl_file = _resolve_purl_to_vcs(args.purl_to_vcs)
        logging.info(f"используется файл purl→vcs: {purl_file}")
        ref_finder = RefFinder(purl_file)
        flat_components = []
        stack = input_data.get('components', []).copy()
        while stack:
            component = stack.pop(0)
            if 'components' in component:
                stack += component['components']
            flat_components.append(component)
        total = len(flat_components)

        _progress_lock = threading.Lock()
        _progress_completed = [0]

        def _process_component(component):
            result = {'component': component, 'vcs_url': None, 'website_fix': None}
            if 'purl' in component and 'externalReferences' not in component:
                result['vcs_url'] = ref_finder.process_purl(component['purl'])
            website_ref = get_website(component.get('externalReferences', []))
            if website_ref and ref_finder.is_repo(website_ref['url']):
                result['website_fix'] = website_ref
            if progress_callback:
                with _progress_lock:
                    _progress_completed[0] += 1
                    idx = _progress_completed[0]
                name = component.get('name', component.get('purl', '?'))
                progress_callback(idx, total, name)
            return result

        max_workers = min(8, total) if total > 0 else 1
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            for result in executor.map(_process_component, flat_components):
                component = result['component']
                if result['vcs_url']:
                    component['externalReferences'] = [{'type': 'vcs', 'url': result['vcs_url']}]
                if result['website_fix']:
                    result['website_fix']['type'] = 'vcs'
                    logging.info(f"смена типа с 'website' на 'vcs' для {result['website_fix']['url']}")
                    logging.info('-' * 50)
        ref_finder.dump_repos()

    if args.update:
        with open(args.update) as f:
            old_data = json.load(f)
        stack = old_data.get('components', [])
        old_data_dict = dict()
        while stack:
            component = stack.pop(0)
            old_data_dict[(component['name'], component['version'])] = dict()
            old_data_dict[(component['name'], component['version'])]['properties'] = component.get('properties', [])
            old_data_dict[(component['name'], component['version'])]['purl'] = component.get('purl', '')
            old_data_dict[(component['name'], component['version'])]['externalReferences'] = component.get('externalReferences', [])
            if 'components' in component:
                stack += component['components']

        stack = input_data.get('components', []).copy()
        while stack:
            component = stack.pop(0)
            key = (component['name'], component['version'])
            if key in old_data_dict:
                if any(old_data_dict[key].values()):
                    logging.info(f"для компонента {component} присвоение полю")
                if old_data_dict[key]['properties']:
                    logging.info(f"\"properties\" значения:\n{old_data_dict[key]['properties']}")
                    component['properties'] = old_data_dict[key]['properties']
                if old_data_dict[key]['purl']:
                    logging.info(f"\"purl\" значения:\n{old_data_dict[key]['purl']}")
                    component['purl'] = old_data_dict[key]['purl']
                if old_data_dict[key]['externalReferences']:
                    logging.info(f"\"externalReferences\" значения:\n{old_data_dict[key]['externalReferences']}")
                    component['externalReferences'] = old_data_dict[key]['externalReferences']
                if any(old_data_dict[key].values()):
                    logging.info('-'*50)
            if 'components' in component:
                stack += component['components']

        if 'metadata' in old_data and 'component' in old_data['metadata'] and 'name' in old_data['metadata']['component']:
            old_name = old_data['metadata']['component']['name']
            if not 'metadata' in input_data:
                input_data['metadata'] = dict()
            if not 'component' in input_data['metadata']:
                input_data['metadata']['component'] = dict()
            if not 'name' in input_data['metadata']['component']:
                logging.info(f"перенос названия продукта: {old_name}")
                logging.info('-'*50)
                input_data['metadata']['component']['name'] = old_name
        if 'metadata' in old_data and 'component' in old_data['metadata'] and 'version' in old_data['metadata']['component']:
            old_version = old_data['metadata']['component']['version']
            if not 'metadata' in input_data:
                input_data['metadata'] = dict()
            if not 'component' in input_data['metadata']:
                input_data['metadata']['component'] = dict()
            if not 'version' in input_data['metadata']['component']:
                logging.info(f"перенос версии продукта: {old_version}")
                logging.info('-'*50)
                input_data['metadata']['component']['version'] = old_version
        if 'metadata' in old_data and 'component' in old_data['metadata'] and 'manufacturer' in old_data['metadata']['component'] and \
            'name' in old_data['metadata']['component']['manufacturer']:
            old_manufacturer = old_data['metadata']['component']['manufacturer']['name']
            if not 'metadata' in input_data:
                input_data['metadata'] = dict()
            if not 'component' in input_data['metadata']:
                input_data['metadata']['component'] = dict()
            if not 'manufacturer' in input_data['metadata']['component']:
                input_data['metadata']['component']['manufacturer'] = dict()
            if not 'name' in input_data['metadata']['component']['manufacturer']:
                logging.info(f"перенос названия организации: {old_manufacturer}")
                logging.info('-'*50)
                input_data['metadata']['component']['manufacturer']['name'] = old_manufacturer

    if 'metadata' in input_data:
        input_data['metadata']['timestamp'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if 'version' in input_data:
        input_data['version'] += 1
    with open(args.output, 'w', encoding=encoding) as f:
        json.dump(input_data, f, indent=2, ensure_ascii=False)
