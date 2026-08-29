# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

import json
import os
import re
import subprocess
import urllib.parse
from collections import Counter
from urllib.parse import unquote

import platformdirs
import requests

SP_TIMEOUT = 60  # timeout for subpocess

pattern_dict = {
    "bitbucket.org": [[["commits"], ["src"], ["branch"]], 2],
    "codeberg.org": [[["src", "branch"], ["src", "commit"], ["src", "tag"], ["releases", "tag"], ["commit"]], 2],
    "github.com": [[["releases", "tag"], ["commit"], ["blob"], ["tree"]], 2],
    "hg.code.sf.net": [[["file"], ["rev"], ["shortlog"]], 3],
    "opendev.org": [[["src", "branch"], ["src", "commit"], ["src", "tag"], ["releases", "tag"], ["commit"]], 2],
    "src.libcode.org": [[["src"], ["commit"]], 2],
    "hg.openjdk.org": [[["file"], ["rev"], ["shortlog"]], 2],
    "chromium.googlesource.com": [[["+", "refs", "heads"], ["+"]], 1],
    "webrtc.googlesource.com": [[["+", "refs", "heads"], ["+"]], 1],
}


def parse_repo_url(url):
    parsed_url = urllib.parse.urlparse(url)
    path = parsed_url.path.strip("/")
    query = urllib.parse.parse_qs(parsed_url.query)
    if "commit" in query:
        return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + path), query["commit"][0]
    if "tag" in query:
        return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + path), query["tag"][0]
    if parsed_url.netloc == "git.altlinux.org":
        query = urllib.parse.parse_qs(parsed_url.query, separator=";")
        fpath = ""
        commit = ""
        if "f" in query:
            fpath = query["f"][0]
        if "h" in query:
            commit = query["h"][0]
        elif "hb" in query:
            commit = query["hb"][0]
        if fpath:
            if not commit:
                commit = "HEAD"
            return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + path), commit + "/" + fpath
        else:
            return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + path), commit
    if parsed_url.netloc == "git.netfilter.org":
        query = urllib.parse.parse_qs(parsed_url.query)
        commit = ""
        if "id" in query:
            commit = query["id"][0]
        elif "h" in query:
            commit = query["h"][0]
        path_split = path.split("/")
        if len(path_split) <= 2:
            return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + path_split[0]), commit
        if not commit:
            commit = "HEAD"
        return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + path_split[0]), commit + "/" + "/".join(
            path_split[2:]
        )
    if parsed_url.netloc == "gitbox.apache.org":
        try:
            query = urllib.parse.parse_qs(parsed_url.query, separator=";")
        except Exception:
            query = urllib.parse.parse_qs(parsed_url.query)
        fpath = ""
        commit = ""
        if "p" in query:
            path = os.path.join(path, query["p"][0])
        if "f" in query:
            fpath = query["f"][0]
        if "h" in query:
            commit = query["h"][0]
        elif "hb" in query:
            commit = query["hb"][0]
        if fpath:
            if not commit:
                commit = "HEAD"
            return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + path), commit + "/" + fpath
        else:
            return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + path), commit
    path_split = path.split("/")
    idx = [-1, -1]
    prefix = 2
    if parsed_url.netloc in pattern_dict:
        prefix = pattern_dict[parsed_url.netloc][1]
        for s in pattern_dict[parsed_url.netloc][0]:
            for i in range(len(path_split[prefix:])):
                if path_split[prefix:][i : i + len(s)] == s:
                    idx = [prefix + i, prefix + i + len(s)]
                    break
            else:
                continue
            break
    else:
        for s in [
            ["-", "commit"],
            ["-", "commits"],
            ["-", "tags"],
            ["-", "tree"],
            ["-", "blob"],
            ["-", "releases"],
            ["releases", "tag"],
            ["commit"],
            ["blob"],
            ["tree"],
        ]:
            for i in range(len(path_split[prefix:])):
                if path_split[prefix:][i : i + len(s)] == s:
                    idx = [prefix + i, prefix + i + len(s)]
                    break
            else:
                continue
            break
    if idx[0] > 0:
        return (parsed_url.scheme + "://" + parsed_url.netloc + "/" + "/".join(path_split[: idx[0]])), "/".join(
            path_split[idx[1] :]
        )
    return None


def check_repo(url):
    result = False
    exc_list = []
    _no_prompt_env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": ""}
    try:
        res0 = subprocess.run(
            f"git ls-remote {url}", shell=True, capture_output=True, text=True, timeout=SP_TIMEOUT, env=_no_prompt_env
        )
        if res0.returncode != 0:
            exc_list.append(f"ERROR/GIT: {res0.stderr}")
            result = False
        else:
            result = True
    except subprocess.TimeoutExpired:
        try:
            check_url = url[:-4] if url.endswith(".git") else url
            resp = requests.head(check_url, timeout=SP_TIMEOUT, allow_redirects=True)
            if resp.status_code == 200:
                result = True
            else:
                exc_list.append(f"ERROR/GIT: git ls-remote timed out, HTTP-проверка вернула код {resp.status_code}")
                result = False
        except Exception as e2:
            exc_list.append(f"ERROR/GIT: git ls-remote timed out, HTTP-фоллбэк не сработал: {e2}")
            result = False
    except Exception as e:
        exc_list.append(f"ERROR/GIT: {e}")
        result = False
    if not result:
        try:
            res1 = subprocess.run(
                f"svn ls --non-interactive {url}", shell=True, capture_output=True, text=True, timeout=SP_TIMEOUT
            )
            if res1.returncode != 0:
                exc_list.append(f"ERROR/SVN: {res1.stderr}")
                result = False
            else:
                result = True
        except Exception as e:
            exc_list.append(f"ERROR/SVN: {e}")
            result = False
    if not result:
        try:
            res2 = subprocess.run(
                f"hg identify --noninteractive {url}", shell=True, capture_output=True, text=True, timeout=SP_TIMEOUT
            )
            if res2.returncode != 0:
                exc_list.append(f"ERROR/HG: {res2.stderr}")
                result = False
            else:
                result = True
        except Exception as e:
            exc_list.append(f"ERROR/HG: {e}")
            result = False
    if not result:
        try:
            res3 = requests.get(url, timeout=SP_TIMEOUT)
            if res3.status_code == 200:
                if re.search(
                    r"footer\"?>\sthis\spage\swas\sgenerated\sin\sabout\s(\d+\.\d+)s\sby\sfossil", res3.text, re.I
                ):
                    result = True
                else:
                    exc_list.append("ERROR/FOSSIL: didn't find autogenerated fossil footer on this page")
                    result = False
            else:
                exc_list.append(f"ERROR/FOSSIL: {url} returned code {res3.status_code}")
                result = False
        except Exception as e:
            exc_list.append(f"ERROR/FOSSIL: {e}")
            result = False
    return result, "\n".join(exc_list)


def validate_no_duplicate_keys(list_of_pairs):
    key_count = Counter(k for k, v in list_of_pairs)
    duplicate_keys = ", ".join(k for k, v in key_count.items() if v > 1)

    if len(duplicate_keys) != 0:
        raise ValueError(f"Duplicate key(s) in file: {duplicate_keys}")
    return dict(list_of_pairs)


def opener(filename, pairs=False):
    encoding = None
    try:
        with open(filename) as f:
            data = json.load(f, object_pairs_hook=(validate_no_duplicate_keys if pairs else None))
    except UnicodeDecodeError:
        with open(filename, encoding="utf-8") as f:  # duplicate keys detection
            data = json.load(f, object_pairs_hook=(validate_no_duplicate_keys if pairs else None))
        encoding = "utf-8"
    except json.decoder.JSONDecodeError:
        with open(filename, encoding="utf-8-sig") as f:  # duplicate keys detection
            data = json.load(f, object_pairs_hook=(validate_no_duplicate_keys if pairs else None))
        encoding = "utf-8-sig"
    return data, encoding


def load_cache(type):
    cache_file = platformdirs.user_cache_path("efs", ensure_exists=True) / f"check_{type.replace('-', '_')}.json"
    if os.path.isfile(cache_file):
        with open(cache_file) as f:
            return json.load(f)
    return dict()


def dump_cache(type, data):
    cache_file = platformdirs.user_cache_path("efs", ensure_exists=True) / f"check_{type.replace('-', '_')}.json"
    with open(cache_file, "w") as f:
        json.dump(data, f)


def is_archive_url(session, url, timeout=10):
    """Проверяет, является ли URL архивом"""
    archive_mime_types = {
        "application/zip",
        "application/x-rar-compressed",
        "application/x-7z-compressed",
        "application/x-tar",
        "application/gzip",
        "application/x-bzip2",
        "application/x-xz",
        "application/x-zip-compressed",
        "application/octet-stream",
        "application/x-msdownload",
        "application/x-rpm",
        "application/java-archive",
        "application/vnd.rar",
        "application/zstd",
    }

    archive_extensions = {
        ".zip",
        ".rar",
        ".7z",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".tgz",
        ".tbz2",
        ".tar.gz",
        ".tar.bz2",
        ".tar.xz",
        ".zipx",
        ".iso",
        ".cab",
        ".arj",
        ".src.rpm",
        ".jar",
        ".tar.lz",
        ".tlz",
        ".tar.Z",
        ".Z",
        ".tar.lzma",
        ".whl",
        ".rpm",
        ".src.rock",
        ".cpio",
        ".tzr.zst",
        ".zst",
    }
    exc_list = []
    result = False
    try:
        # Пробуем HEAD запрос
        response = session.head(url, allow_redirects=True, timeout=timeout)
        # Если HEAD возвращает 405 (Method Not Allowed), пробуем GET
        if response.status_code == 405:
            response = session.get(
                url, stream=True, timeout=timeout, allow_redirects=True, headers={"Range": "bytes=0-1024"}
            )
        response.raise_for_status()

        # Проверка Content-Type
        content_type = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if content_type not in archive_mime_types:
            exc_list.append(f"ERROR: MIME тип содержимого не соответствует типу архива: {content_type}")
            result = False
        else:
            result = True

        # Проверка расширения в URL
        if not result:
            parsed_url = urllib.parse.urlparse(url)
            path = parsed_url.path
            filename = path.split("/")[-1].lower() if path else ""
            if not any(filename.endswith(ext) for ext in archive_extensions):
                exc_list.append("ERROR: Расширение файла в URL не соответствует расширению архива.")
                result = False
            else:
                result = True

        # Проверка Content-Disposition
        if not result:
            content_disposition = response.headers.get("Content-Disposition", "")
            if content_disposition:
                # Извлечение имени файла
                filenames = re.findall(
                    r'filename\*?=["\']?(?:UTF-\d["\']?)?([^;"\'\n]+)', content_disposition, re.IGNORECASE
                )
                if not filenames:
                    filenames = re.findall(r'filename=["\']?([^;"\'\n]+)', content_disposition, re.IGNORECASE)
                for name in filenames:
                    name = name.strip().lower()
                    if not any(name.endswith(ext) for ext in archive_extensions):
                        exc_list.append(
                            "ERROR: Расширение файла в Content-Disposition не соответствует расширению архива."
                        )
                        result = False
                    else:
                        result = True
        return result, "\n".join(exc_list)

    except Exception as e:
        exc_list.append(f"ERROR: {str(e)}")
        result = False
        return result, "\n".join(exc_list)
    finally:
        if "response" in locals():
            response.close()


_VERSION_TAIL = re.compile(r"^v?\d")
_PURL_SEP = re.compile(r"@|%40", re.IGNORECASE)


def purl_strip_qualifiers(purl):
    """Отбросить квалификаторы и якорь: pkg:npm/ajv@8.20.0?arch=x64 → pkg:npm/ajv@8.20.0."""
    return purl.split("?", 1)[0].split("#", 1)[0]


def purl_without_version(purl):
    """Убрать версию из purl: pkg:pypi/pytest@8.0.0 → pkg:pypi/pytest.

    Разделитель ищем с конца и в обеих формах — `@` и `%40`: trivy кодирует его
    по-разному даже в одном файле (`color-name%401.1.3` рядом с `runtime@7.9.0`).
    Отбрасываем только то, что похоже на версию: у npm-пакета со скоупом первый
    разделитель принадлежит имени (pkg:npm/@babel/runtime@7.9.0), а для вложенных
    зависимостей trivy пишет в purl весь путь
    (pkg:npm/@babel/highlight/chalk@chalk@2.4.2 — тут `@chalk` тоже часть имени).

    Возвращаем срез ИСХОДНОЙ строки: результат идёт ключом в конфиг, и приведение
    `%40`→`@` плодило бы дубли рядом с уже существующими. Для сравнения — `purl_key`.
    """
    base = purl_strip_qualifiers(purl)
    for match in reversed(list(_PURL_SEP.finditer(base))):
        start = match.start()
        if start == 0 or base[start - 1] == "/":
            continue
        if _VERSION_TAIL.match(unquote(base[match.end() :])):
            return base[:start]
    return base


def purl_key(purl):
    """purl, приведённый для СРАВНЕНИЯ: скоуп npm пишут и `%40babel`, и `@babel`."""
    return unquote(purl_strip_qualifiers(purl))


def get_prop(arr, name):
    for elem in arr:
        if elem.get("name", "") == name:
            return elem.get("value", "")
    return ""


def get_props(arr, name):
    """Все значения свойства с указанным именем.

    ФСТЭК требует по отдельному свойству GOST:source_langs на каждый язык,
    поэтому одного get_prop недостаточно.
    """
    return [elem.get("value", "") for elem in arr if elem.get("name", "") == name and elem.get("value", "")]


_PLACEHOLDER_URLS = {"TODO", "", "sbom-updater_generated_placeholder:", None}

_SOURCE_REF_LABELS = {
    "vcs": "Репозиторий",
    "source-distribution": "Дистрибутив исходного кода",
}


def source_reference(component):
    """Сведения об источнике компонента для колонки отчётной формы.

    Если ссылки на исходный код нет, но компонент поставляется в составе
    сертифицированного СЗИ, указывается это средство — иначе в документе
    остаётся пустая графа.
    """
    refs = component.get("externalReferences", [])
    if isinstance(refs, list):
        for ref_type, label in _SOURCE_REF_LABELS.items():
            for ref in refs:
                if not isinstance(ref, dict) or ref.get("type") != ref_type:
                    continue
                url = ref.get("url")
                if url not in _PLACEHOLDER_URLS:
                    return f"{label}: {url}"

    provided_by = get_prop(component.get("properties", []), "GOST:provided_by")
    if provided_by:
        return f"Поставляется в составе сертифицированного СЗИ: {provided_by}"
    return ""


def combine_source_langs(sl1, sl2):
    if sl1 and not sl2 or not sl1 and sl2:
        return sl1 or sl2
    result = [sl.strip() for sl in sl1.split(",")]
    for sl in sl2.split(","):
        sl = sl.strip()
        if sl not in result:
            result.append(sl)
    return ", ".join(result)
