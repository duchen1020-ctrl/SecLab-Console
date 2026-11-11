# -*- coding: utf-8 -*-
"""统一 HTTP 请求引擎：参数定位、延迟节流、响应特征比较。"""

import difflib
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlparse

import requests


class HTTPError(RuntimeError):
    pass


@dataclass
class Resp:
    status: int
    text: str
    elapsed: float
    url: str
    headers: dict = field(default_factory=dict)

    @property
    def length(self) -> int:
        return len(self.text)

    @property
    def preview(self) -> str:
        return " ".join(self.text.split())[:180]


def similarity(a: str, b: str) -> float:
    """页面相似度（0~1），用于布尔差异判断。"""
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    if abs(len(a) - len(b)) > max(len(a), len(b)) * 0.6:
        return 0.0
    return difflib.SequenceMatcher(None, a[:8000], b[:8000], autojunk=False).quick_ratio()


def looks_like_login(resp: "Resp") -> bool:
    low = resp.text.lower()
    return "login.php" in resp.url.lower() or (
        "name=\"username\"" in low and "name=\"password\"" in low and "login" in low
    )


class Agent:
    """带 Cookie / 方法 / 参数定位的请求器。"""

    def __init__(self, target: dict):
        self.raw_url = target["url"]
        self.method = target.get("method", "GET").upper()
        self.cookie = target.get("cookie", "")
        self.timeout = float(target.get("timeout", 10))
        self.delay = float(target.get("delay", 0.15))
        parsed = urlparse(self.raw_url)
        self.base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        self.query = {k: v[-1] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        self.form = dict(target.get("data") or {})
        self.requests_sent = 0
        self.session = requests.Session()
        proxy = (target.get("proxy") or "").strip()
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        headers = {
            "User-Agent": (target.get("ua") or "").strip() or (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Cache-Control": "no-cache",
        }
        if self.cookie:
            # 写入 CookieJar 而不是固定请求头，保证服务端 Set-Cookie（如 DVWA 的 id）能回传
            for part in self.cookie.split(";"):
                if "=" in part:
                    name, value = part.split("=", 1)
                    name = name.strip()
                    if name:
                        self.session.cookies.set(name, value.strip())
        for k, v in (target.get("headers") or {}).items():
            headers[str(k)] = str(v)
        self.session.headers.update(headers)

    # ---- 参数管理 ----
    @property
    def params(self) -> dict:
        merged = {}
        merged.update(self.query)
        merged.update(self.form)
        return merged

    def place_of(self, name: str) -> str:
        return "form" if name in self.form else "query"

    def send(self, overrides: dict | None = None, timeout: float | None = None) -> Resp:
        overrides = overrides or {}
        query = dict(self.query)
        form = dict(self.form)
        for key, value in overrides.items():
            if self.method == "GET":
                # GET 目标的参数一律落在 query，data 里的字段也合并进 query
                query[key] = value
            elif key in form:
                form[key] = value
            elif key in query:
                query[key] = value
            else:
                form[key] = value
        started = time.time()
        try:
            if self.method == "POST":
                resp = self.session.post(self.base, params=query or None, data=form or None,
                                         timeout=timeout or self.timeout)
            else:
                merged = dict(form)
                merged.update(query)
                resp = self.session.get(self.base, params=merged or None,
                                        timeout=timeout or self.timeout)
        except requests.RequestException as exc:
            raise HTTPError(f"请求失败：{exc.__class__.__name__} / {exc}") from exc
        elapsed = time.time() - started
        self._fix_encoding(resp)
        self.requests_sent += 1
        if self.delay:
            time.sleep(self.delay)
        return Resp(resp.status_code, resp.text, elapsed, resp.url, dict(resp.headers))

    @staticmethod
    def _fix_encoding(resp):
        """部分靶场声明 utf-8 实际输出 GBK，出现替换符时按内容重新解码。"""
        try:
            sample = resp.text[:4000]
        except Exception:  # noqa: BLE001
            return
        if "\ufffd" in sample:
            alt = resp.apparent_encoding
            if alt and alt.lower() not in ("ascii", "utf-8"):
                resp.encoding = alt

    def baseline(self) -> Resp:
        return self.send()

    def raw(self, method: str, url: str, data: dict | None = None,
            params: dict | None = None, timeout: float | None = None) -> Resp:
        """直接请求指定 URL（用于存储型 XSS 的提交 / 校验等跨路径场景）。"""
        started = time.time()
        try:
            resp = self.session.request(method.upper(), url, params=params, data=data,
                                        timeout=timeout or self.timeout)
        except requests.RequestException as exc:
            raise HTTPError(f"请求失败：{exc.__class__.__name__} / {exc}") from exc
        elapsed = time.time() - started
        self._fix_encoding(resp)
        self.requests_sent += 1
        if self.delay:
            time.sleep(self.delay)
        return Resp(resp.status_code, resp.text, elapsed, resp.url, dict(resp.headers))
