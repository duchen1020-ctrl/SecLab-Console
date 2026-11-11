# -*- coding: utf-8 -*-
"""全模块回归 / 环境自检。

一次任务里顺跑四个模块的最小验证链路，用来回答两个问题：
1. 目标、Cookie、难度切换后，四个模块是否都还通；
2. 走代理（Burp / mitmproxy）时链路是否仍然成立。

只做探测级动作：SQL 只确认注入点，XSS 只跑 8 条基础向量，
命令注入只确认连接符与 whoami，弱口令只识别登录表单（不真的爆破）。
"""

import socket
import time
from urllib.parse import urlparse

from .brute import BruteEngine
from .cmdi import CmdiEngine
from .forms import parse_forms
from .guard import TargetError, normalize_target
from .httpclient import Agent, HTTPError
from .sqli import SqliEngine
from .xss import XssEngine

MODULES = (
    ("sqli", "SQL 注入", "id"),
    ("xss", "XSS", "name"),
    ("cmdi", "命令注入", "ip"),
    ("brute", "弱口令", "username"),
)


class RegressEngine:
    def __init__(self, task):
        self.t = task

    # ---------- 代理自检 ----------
    def _check_proxy(self, proxy: str) -> dict:
        started = time.time()
        parsed = urlparse(proxy if "://" in proxy else f"http://{proxy}")
        host, port = parsed.hostname, parsed.port or 8080
        if not host:
            return {"module": "代理", "key": "proxy", "state": "fail",
                    "detail": f"代理地址解析失败：{proxy}", "elapsed": 0, "requests": 0}
        try:
            with socket.create_connection((host, port), timeout=4):
                pass
        except OSError as exc:
            self.t.warn(f"代理不可达：{proxy}（{exc.__class__.__name__}）")
            return {"module": "代理", "key": "proxy", "state": "fail",
                    "detail": f"{host}:{port} 无法连接，请确认 Burp / mitmproxy 已启动且监听该端口",
                    "elapsed": round(time.time() - started, 2), "requests": 0}
        self.t.ok(f"代理端口可连接：{host}:{port}")
        return {"module": "代理", "key": "proxy", "state": "ok",
                "detail": f"{host}:{port} 可连接，后续模块请求均经过该代理",
                "elapsed": round(time.time() - started, 2), "requests": 0}

    # ---------- 单模块 ----------
    def _row(self, key: str, label: str, state: str, detail: str,
             started: float, requests: int = 0, short: str = "") -> dict:
        return {"module": label, "key": key, "state": state, "detail": detail,
                "short": short or detail[:28],
                "elapsed": round(time.time() - started, 2), "requests": requests}

    def _run_module(self, key: str, label: str, cfg: dict, param: str,
                    opts: dict) -> dict:
        started = time.time()
        try:
            target = normalize_target(cfg)
        except TargetError as exc:
            self.t.err(f"{label}：{exc}")
            return self._row(key, label, "fail", str(exc), started)

        agent = Agent(target)
        try:
            base = agent.baseline()
        except HTTPError as exc:
            self.t.err(f"{label}：{exc}")
            return self._row(key, label, "fail", str(exc), started)

        if "login.php" in base.url.lower():
            self.t.warn(f"{label}：响应跳到登录页")
            return self._row(key, label, "fail",
                             "响应跳转 login.php，Cookie 失效或未登录", started,
                             agent.requests_sent)

        level = ""
        for part in (target.get("cookie") or "").split(";"):
            if "security=" in part:
                level = part.split("security=")[-1].strip()

        self.t.log(f"── {label} · {base.status} / {base.length}B", "step")
        try:
            if key == "sqli":
                detail = self._inspect_sqli(agent, param)
            elif key == "xss":
                detail = self._inspect_xss(agent, param)
            elif key == "cmdi":
                detail = self._inspect_cmdi(agent, param)
            else:
                detail = self._inspect_brute(agent, param)
        except RuntimeError as exc:
            self.t.warn(f"{label}：{exc}")
            return self._row(key, label, "fail", str(exc), started, agent.requests_sent)
        except HTTPError as exc:
            self.t.err(f"{label}：{exc}")
            return self._row(key, label, "fail", str(exc), started, agent.requests_sent)

        good = detail.pop("good", True)
        text = detail.pop("text")
        short = detail.pop("short", "")
        if level:
            text += f" · security={level}"
        self.t.ok(f"{label}：{text}") if good else self.t.warn(f"{label}：{text}")
        return self._row(key, label, "ok" if good else "warn", text,
                         started, agent.requests_sent, short)

    def _inspect_sqli(self, agent, param: str) -> dict:
        engine = SqliEngine(agent, self.t)
        result = engine.probe([param])
        if not result.get("vulnerable"):
            return {"good": False, "text": "未探测到 SQL 注入（检查参数名 / 难度）",
                    "short": "无注入"}
        best = result.get("best") or {}
        tech = best.get("technique")
        return {"good": True,
                "short": f"{best.get('param')} · {tech}",
                "text": f"注入点 {best.get('param')} / {tech} / "
                        f"{SqliEngine.quote_label(best.get('quote'))}"}

    def _inspect_xss(self, agent, param: str) -> dict:
        engine = XssEngine(agent, self.t)
        result = engine.analyze(param)
        count = len(result.get("executable") or [])
        lv = (result.get("level") or "unknown").upper()
        return {"good": count > 0,
                "short": f"{lv} · {count} 条",
                "text": f"{result.get('level_text')} · 可用载荷 {count} 条"}

    def _inspect_cmdi(self, agent, param: str) -> dict:
        engine = CmdiEngine(agent, self.t)
        result = engine.probe([param])
        if not result.get("vulnerable"):
            return {"good": False, "text": "未确认命令拼接（可能过滤较强）", "short": "不可用"}
        best = result.get("best") or {}
        who = best.get("whoami") or "未取到 whoami"
        return {"good": True, "short": f"{best.get('name')}",
                "text": f"连接符 {best.get('name')} · {who}"}

    def _inspect_brute(self, agent, param: str) -> dict:
        page = agent.raw("GET", agent.base, params=agent.query or None)
        forms = parse_forms(page.text, page.url)
        form = next((f for f in forms if param in f["fields"]), None)
        if not form:
            return {"good": False, "text": f"未找到包含 {param} 的登录表单"}
        tokens = [n for n in form["names"] if "token" in n.lower()]
        text = f"{form['method']} {form['action']} · 字段 {', '.join(form['names'])}"
        if tokens:
            text += f" · 轮换 token（{tokens[0]}）"
        return {"good": True, "text": text}

    # ---------- 难度矩阵 ----------
    MATRIX_MODULES = (("sqli", "SQL 注入", "id"),
                      ("xss", "XSS", "name"),
                      ("cmdi", "命令注入", "ip"))

    def run_matrix(self, targets: dict, levels: list[str]) -> dict:
        self.t.step_msg(f"难度矩阵：{' / '.join(levels)}")
        active = [(k, label, param) for k, label, param in self.MATRIX_MODULES
                  if isinstance(targets.get(k), dict) and (targets[k].get("url") or "").strip()]
        if not active:
            raise RuntimeError("没有可用的目标配置")
        total = len(active) * len(levels)
        done = 0
        modules = []
        for key, label, param in active:
            cells = {}
            for level in levels:
                self.t.check_stop()
                cfg = dict(targets[key])
                cfg["cookie"] = self._with_security(cfg.get("cookie") or "", level)
                row = self._run_module(key, label, cfg, param, {"level": level})
                cells[level] = {"state": row["state"], "short": row.get("short", ""),
                                "detail": row["detail"]}
                done += 1
                self.t.set_progress(done / total, f"{label} / {level}")
            modules.append({"key": key, "label": label, "cells": cells})

        ok = sum(1 for m in modules for c in m["cells"].values() if c["state"] == "ok")
        self.t.step_msg(f"矩阵完成：{ok}/{total} 个格子可用")
        return {
            "levels": levels,
            "modules": modules,
            "total": total,
            "passed": ok,
            "summary": f"难度矩阵：{ok}/{total} 个组合可用",
            "severity": "info",
        }

    @staticmethod
    def _with_security(cookie: str, level: str) -> str:
        """把 Cookie 里的 security= 替换成指定难度。"""
        parts = [p.strip() for p in (cookie or "").split(";") if p.strip()]
        out, hit = [], False
        for part in parts:
            if part.lower().startswith("security="):
                out.append(f"security={level}")
                hit = True
            else:
                out.append(part)
        if not hit:
            out.append(f"security={level}")
        return "; ".join(out)

    # ---------- 批量扫描 ----------
    BATCH_MODULES = {"sqli": ("SQL 注入", "id"),
                     "xss": ("XSS", "name"),
                     "cmdi": ("命令注入", "ip")}

    def run_batch(self, module: str, urls: list[str], params: list[str],
                  cookie: str, delay: float) -> dict:
        label, default_param = self.BATCH_MODULES[module]
        param = params[0] if params else default_param
        total = len(urls)
        self.t.step_msg(f"批量扫描 {total} 个目标 · {label} · 参数 {param}")
        rows = []
        for index, url in enumerate(urls, 1):
            self.t.check_stop()
            self.t.log(f"[{index}/{total}] {url}", "step")
            row = self._run_module(module, label,
                                   {"url": url, "cookie": cookie, "delay": delay}, param, {})
            row["target"] = url
            row["param"] = param
            rows.append(row)
            self.t.set_progress(index / total, f"{index}/{total} 个目标")

        passed = sum(1 for r in rows if r["state"] == "ok")
        failed = sum(1 for r in rows if r["state"] == "fail")
        self.t.step_msg(f"批量完成：{passed}/{total} 可用")
        if failed:
            self.t.warn(f"{failed} 个目标失败或被阻断")
        return {"module": module, "param": param, "rows": rows, "total": total,
                "passed": passed, "failed": failed,
                "summary": f"批量扫描 {total} 个目标 · {passed} 个可用 / {failed} 个失败",
                "severity": "high" if passed else "info"}

    # ---------- 主流程 ----------
    def run(self, targets: dict, opts: dict) -> dict:
        self.t.step_msg("全模块回归开始")
        rows: list[dict] = []

        proxies = sorted({(cfg.get("proxy") or "").strip()
                          for cfg in targets.values() if isinstance(cfg, dict)
                          and (cfg.get("proxy") or "").strip()})
        if proxies:
            for proxy in proxies:
                rows.append(self._check_proxy(proxy))
                self.t.set_progress(0.05, "代理自检")
        else:
            rows.append({"module": "代理", "key": "proxy", "state": "skip",
                         "detail": "当前为直连模式，如要抓包请在右上角配置 HTTP 代理",
                         "elapsed": 0, "requests": 0})

        active = [(key, label, param) for key, label, param in MODULES
                  if isinstance(targets.get(key), dict) and (targets[key].get("url") or "").strip()]
        if not active:
            raise RuntimeError("没有可用的目标配置")

        for index, (key, label, param) in enumerate(active, 1):
            self.t.check_stop()
            rows.append(self._run_module(key, label, targets[key], param, opts))
            self.t.set_progress(index / len(active), f"{index}/{len(active)} 模块")

        ok = sum(1 for r in rows if r["state"] == "ok")
        warn = sum(1 for r in rows if r["state"] == "warn")
        fail = sum(1 for r in rows if r["state"] == "fail")
        skip = sum(1 for r in rows if r["state"] == "skip")
        self.t.step_msg(f"回归完成：{ok} 通过 / {warn} 警告 / {fail} 失败 / {skip} 跳过")
        if fail:
            self.t.warn("存在失败项，请按结论列的提示检查 Cookie、难度或服务状态")
        return {
            "rows": rows,
            "passed": ok,
            "warned": warn,
            "failed": fail,
            "summary": f"全模块回归：{ok} 通过 / {warn} 警告 / {fail} 失败",
            "severity": "info" if not fail else "low",
        }
