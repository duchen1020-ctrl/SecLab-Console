# -*- coding: utf-8 -*-
"""HTML 表单解析（供 SQL 注入 / 命令注入 / 盲打等模块复用）。"""

import re
from urllib.parse import urljoin

FORM_RE = re.compile(r"<form\b([^>]*)>([\s\S]*?)</form>", re.I)
INPUT_RE = re.compile(r"<(input|textarea|select)\b([^>]*)>", re.I)
ATTR_RE = re.compile(r"([\w:-]+)\s*=\s*[\"']([^\"']*)[\"']")
OPTION_RE = re.compile(r"<option\b([^>]*)>([^<]*)</option>", re.I)


def parse_forms(html_text: str, page_url: str, limit: int = 10) -> list[dict]:
    """解析页面中的所有表单，返回 method / action / 字段默认值。"""
    forms: list[dict] = []
    for match in FORM_RE.finditer(html_text):
        attrs = dict(ATTR_RE.findall(match.group(1)))
        body = match.group(2)
        fields: dict[str, str] = {}
        kinds: dict[str, str] = {}
        for im in INPUT_RE.finditer(body):
            tag = im.group(1).lower()
            fattrs = dict(ATTR_RE.findall(im.group(2)))
            name = fattrs.get("name")
            if not name:
                continue
            kinds[name] = tag if tag != "input" else (fattrs.get("type") or "text").lower()
            if tag == "select":
                options = OPTION_RE.findall(im.group(2))
                if options:
                    selected = next((item for item in options if "selected" in item[0].lower()),
                                    options[0])
                    fields[name] = selected[1].strip()
                else:
                    fields[name] = ""
            elif tag == "textarea":
                fields[name] = ""
            else:
                ftype = kinds[name]
                if ftype in ("checkbox", "radio"):
                    if "checked" in im.group(2).lower():
                        fields[name] = fattrs.get("value", "on")
                elif ftype in ("submit", "button", "reset"):
                    fields[name] = fattrs.get("value", "Submit")
                else:
                    fields[name] = fattrs.get("value", "")
        if not fields:
            continue
        action = attrs.get("action") or page_url
        if action.strip() in ("", "#"):
            action = page_url
        forms.append({
            "index": len(forms),
            "method": (attrs.get("method") or "GET").upper(),
            "action": urljoin(page_url, action),
            "fields": fields,
            "kinds": kinds,
            "names": list(fields.keys()),
        })
        if len(forms) >= limit:
            break
    return forms


def parse_form(html_text: str, param: str, page_url: str) -> dict | None:
    """返回包含指定参数的表单。"""
    for form in parse_forms(html_text, page_url):
        if param in form["fields"]:
            return form
    return None
