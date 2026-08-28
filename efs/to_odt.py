# SPDX-FileCopyrightText: 2024 Ekaterina Shastun, ISPRAS
# SPDX-FileCopyrightText: 2026 Kirill Nikolaevskiy
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

from odf.opendocument import load
from odf.style import TextProperties
from odf.table import Table, TableCell, TableRow
from odf.text import P

from .utils import combine_source_langs, get_prop, get_props, opener, source_reference

_PKG_DIR = Path(__file__).parent.resolve()


def get_ext_ref(er_list):
    for er in er_list:
        if er["type"] in ["vcs", "source-distribution"]:
            return er["url"]
    return ""


def run(args):
    input_data, encoding = opener(args.input)

    idx = 1
    added_elements = set()
    components = list()
    if args.format == "oss":
        doc = load(_PKG_DIR / "odt_templates" / "template.odt")
        stack = input_data.get("components", []).copy()
        for item in doc.getElementsByType(Table):
            while stack:
                comp = stack.pop(0)
                if "components" in comp:
                    stack += comp["components"]
                components.append(comp)
            if args.pa_fb_ontop:
                components = sorted(
                    components,
                    key=lambda x: (
                        get_prop(x.get("properties", []), "GOST:attack_surface") in {"yes", "indirect"},
                        get_prop(x.get("properties", []), "GOST:security_function") in {"yes", "indirect"},
                    ),
                    reverse=True,
                )
            while components:
                comp = components.pop(0)
                props = comp.get("properties", [])
                element = (
                    comp.get("name", ""),
                    comp.get("version", ""),
                    combine_source_langs(
                        ", ".join(get_props(props, "GOST:source_langs")), get_prop(props, "source_langs")
                    ),
                    get_prop(props, "GOST:attack_surface"),
                    get_prop(props, "GOST:security_function"),
                    get_ext_ref(comp.get("externalReferences", [])) or source_reference(comp),
                )
                if element in added_elements:
                    continue
                added_elements.add(element)
                tr = TableRow(stylename="Table3.1")
                tc = TableCell(stylename="Table3.A1")
                tc.addElement(P(text=str(idx), stylename="P3"))
                tr.addElement(tc)
                tc = TableCell(stylename="Table3.A1")
                tc.addElement(P(text=element[0], stylename="P3"))
                tr.addElement(tc)
                tc = TableCell(stylename="Table3.A1")
                tc.addElement(P(text=element[1], stylename="P3"))
                tr.addElement(tc)
                tc = TableCell(stylename="Table3.A1")
                tc.addElement(P(text=element[2], stylename="P3"))
                tr.addElement(tc)
                _as_text = ""
                _as = element[3]
                if _as == "yes":
                    _as_text = "поверхность атаки"
                elif _as == "indirect":
                    _as_text = "косвенная поверхность атаки"
                _sf_text = ""
                _sf = element[4]
                if _sf == "yes":
                    _sf_text = "функция безопасности"
                elif _sf == "indirect":
                    _sf_text = "поддерживающая функции безопасности"
                tc = TableCell(stylename="Table3.A1")
                tc.addElement(
                    P(
                        text=(", ".join([_as_text, _sf_text]) if _as_text and _sf_text else (_as_text + _sf_text)),
                        stylename="P3",
                    )
                )
                tr.addElement(tc)
                tc = TableCell(stylename="Table3.A1")
                tc.addElement(P(text=element[5], stylename="P3"))
                tr.addElement(tc)
                item.addElement(tr)
                idx += 1
    else:
        doc = load(_PKG_DIR / "odt_templates" / "template_container.odt")
        for item in doc.getElementsByType(Table):
            st = doc.getStyleByName("P4")
            st.addElement(TextProperties(attributes={"fontsize": "10pt"}))
            components = input_data.get("components", []).copy()
            if args.pa_fb_ontop:
                components = sorted(
                    components,
                    key=lambda x: (
                        get_prop(x.get("properties", []), "GOST:attack_surface") in {"yes", "indirect"},
                        get_prop(x.get("properties", []), "GOST:security_function") in {"yes", "indirect"},
                    ),
                    reverse=True,
                )
            for comp in components:
                stack = comp.get("components", []).copy()
                deps = []
                while stack:
                    dep = stack.pop(0)
                    if "components" in dep:
                        stack += dep["components"]
                    value = dep.get("name", "") + " " + dep.get("version", "")
                    if value not in deps:
                        deps.append(value)
                element = (
                    comp.get("name", ""),
                    comp.get("description", ""),
                    get_prop(comp.get("properties", []), "GOST:attack_surface"),
                    get_prop(comp.get("properties", []), "GOST:security_function"),
                )
                tr = TableRow(stylename="Table2")
                tc = TableCell(stylename="Table2.A1")
                tc.addElement(P(text=str(idx), stylename=st))
                tr.addElement(tc)
                tc = TableCell(stylename="Table2.A1")
                tc.addElement(P(text=element[0], stylename=st))
                tr.addElement(tc)
                tc = TableCell(stylename="Table2.A1")
                tc.addElement(P(text=element[1], stylename=st))
                tr.addElement(tc)
                tc = TableCell(stylename="Table2.A1")
                tc.addElement(P(text="\n".join(deps), stylename=st))
                tr.addElement(tc)
                _as_text = ""
                _as = element[2]
                if _as == "yes":
                    _as_text = "поверхность атаки"
                elif _as == "indirect":
                    _as_text = "косвенная поверхность атаки"
                _sf_text = ""
                _sf = element[3]
                if _sf == "yes":
                    _sf_text = "функция безопасности"
                elif _sf == "indirect":
                    _sf_text = "поддерживающая функции безопасности"
                tc = TableCell(stylename="Table2.A1")
                tc.addElement(
                    P(
                        text=(", ".join([_as_text, _sf_text]) if _as_text and _sf_text else (_as_text + _sf_text)),
                        stylename=st,
                    )
                )
                tr.addElement(tc)
                item.addElement(tr)
                idx += 1

    doc.save(args.output)
