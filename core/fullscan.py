# -*- coding: utf-8 -*-
"""一键全流程：用同一套目标配置，把四个模块的完整检测串起来，产出一份汇总结果。

和「全模块回归」的区别：
- 回归是轻量连通性 / 探测检查，30 秒出结论，用来确认环境还通；
- 全流程是完整检测：SQLi 会探列数、回显列、指纹、库列表；XSS 会判定等级并挑出可用载荷；
  命令注入会确认连接符与 whoami；弱口令可选跑一小份字典（默认关闭，避免误触锁定）。
"""

import time

from .brute import BruteEngine
from .cmdi import CmdiEngine
from .guard import TargetError, normalize_target
from .httpclient import Agent, HTTPError
from .sqli import SqliEngine
from .xss import XssEngine

QUICK_USERS = ["admin", "administrator", "root", "gordonb", "pablo"]
QUICK_PASSWORDS = ["password", "123456", "admin", "letmein", "abc123"]


class FullScanEngine:
    def __init__(self, task):
        self.t = task

    # ---------- 各模块 ----------
    def _sqli(self, cfg: dict, params: list[str]) -> dict:
        started = time.time()
        target = normalize_target(cfg)
        agent = Agent(target)
        engine = SqliEngine(agent, self.t)
        probe = engine.probe(params)
        detail = {"probe": probe}
        if probe.get("vulnerable"):
            ctx = dict(probe["best"])
            try:
                detail["columns"] = engine.count_columns(ctx)
                detail["display"] = engine.find_display(ctx)
                detail["fingerprint"] = engine.fingerprint(ctx)
                detail["databases"] = engine.databases(ctx)
            except (HTTPError, RuntimeError) as exc:
                self.t.warn(f"SQL 深入枚举中断：{exc}")
                detail["error"] = str(exc)
            best = probe.get("best") or {}
            text = (f"注入点 {best.get('param')} / {best.get('technique')} / "
                    f"{SqliEngine.quote_label(best.get('quote'))}"
                    f" / {detail.get('columns', {}).get('columns', '?')} 列"
                    f" / {len(detail.get('databases') or [])} 个库")
            good = True
        else:
            text, good = "未发现 SQL 注入", False
        return {"key": "sqli", "label": "SQL 注入", "state": "ok" if good else "warn",
                "short": "可利用" if good else "无注入", "detail_text": text,
                "detail": detail, "elapsed": round(time.time() - started, 2),
                "requests": agent.requests_sent}

    def _xss(self, cfg: dict, param: str) -> dict:
        started = time.time()
        target = normalize_target(cfg)
        agent = Agent(target)
        engine = XssEngine(agent, self.t)
        result = engine.analyze(param)
        count = len(result.get("executable") or [])
        return {"key": "xss", "label": "XSS", "state": "ok" if count else "warn",
                "short": f"{(result.get('level') or '').upper()} · {count} 条",
                "detail_text": f"{result.get('level_text')} · 可用载荷 {count} 条",
                "detail": result, "elapsed": round(time.time() - started, 2),
                "requests": agent.requests_sent}

    def _cmdi(self, cfg: dict, param: str) -> dict:
        started = time.time()
        target = normalize_target(cfg)
        agent = Agent(target)
        engine = CmdiEngine(agent, self.t)
        result = engine.probe([param])
        if result.get("vulnerable"):
            best = result.get("best") or {}
            text = f"连接符 {best.get('name')} · {best.get('whoami') or '未取到 whoami'}"
            state = "ok"
            short = f"{best.get('name')}"
        else:
            text, state, short = "未确认命令拼接", "warn", "不可用"
        return {"key": "cmdi", "label": "命令注入", "state": state, "short": short,
                "detail_text": text, "detail": result,
                "elapsed": round(time.time() - started, 2),
                "requests": agent.requests_sent}

    def _brute(self, cfg: dict) -> dict:
        started = time.time()
        target = normalize_target(cfg)
        agent = Agent(target)
        engine = BruteEngine(agent, self.t)
        result = engine.run({
            "usernames": "\n".join(QUICK_USERS),
            "passwords": "\n".join(QUICK_PASSWORDS),
            "user_field": "username", "pass_field": "password",
            "submit_field": "Login", "submit_value": "Login",
            "mode": "smart", "max_attempts": 25, "delay": 0.05,
        })
        found = result.get("found") or []
        text = (", ".join(f"{f['username']}/{f['password']}" for f in found)
                if found else f"{result.get('attempts', 0)} 次尝试，无命中")
        return {"key": "brute", "label": "弱口令", "state": "ok" if found else "warn",
                "short": f"命中 {len(found)} 组" if found else "无命中",
                "detail_text": text, "detail": result,
                "elapsed": round(time.time() - started, 2),
                "requests": agent.requests_sent}

    # ---------- 主流程 ----------
    def run(self, targets: dict, opts: dict) -> dict:
        opts = opts or {}
        raw_params = opts.get("params") or "id,name,ip,id"
        if isinstance(raw_params, str):
            params = [p.strip() for p in raw_params.split(",") if p.strip()]
        else:
            params = [str(p).strip() for p in raw_params if str(p).strip()]
        while len(params) < 4:
            params.append(["id", "name", "ip", "id"][len(params)])
        run_brute = bool(opts.get("brute"))
        skip = {str(k) for k in (opts.get("skip") or [])}

        plan = [("sqli", "SQL 注入"), ("xss", "XSS"), ("cmdi", "命令注入")]
        if run_brute:
            plan.append(("brute", "弱口令"))
        plan = [(key, label) for key, label in plan if key not in skip]
        if not plan:
            raise RuntimeError("没有要执行的模块")

        self.t.step_msg(f"一键全流程：{len(plan)} 个模块")
        rows = []
        for index, (key, label) in enumerate(plan, 1):
            self.t.check_stop()
            cfg = targets.get(key) or {}
            if not (cfg.get("url") or "").strip():
                rows.append({"key": key, "label": label, "state": "skip",
                             "short": "未配置", "detail_text": "没有填写目标地址",
                             "detail": {}, "elapsed": 0, "requests": 0})
                self.t.warn(f"{label}：未配置目标，跳过")
                continue
            self.t.log(f"── [{index}/{len(plan)}] {label}", "step")
            try:
                if key == "sqli":
                    row = self._sqli(cfg, [params[0]])
                elif key == "xss":
                    row = self._xss(cfg, params[1])
                elif key == "cmdi":
                    row = self._cmdi(cfg, params[2])
                else:
                    row = self._brute(cfg)
            except TargetError as exc:
                row = {"key": key, "label": label, "state": "fail", "short": "被拦截",
                       "detail_text": str(exc), "detail": {}, "elapsed": 0, "requests": 0}
                self.t.err(f"{label}：{exc}")
            except HTTPError as exc:
                row = {"key": key, "label": label, "state": "fail", "short": "请求失败",
                       "detail_text": str(exc), "detail": {}, "elapsed": 0, "requests": 0}
                self.t.err(f"{label}：{exc}")
            except RuntimeError as exc:
                row = {"key": key, "label": label, "state": "fail", "short": "中断",
                       "detail_text": str(exc), "detail": {}, "elapsed": 0, "requests": 0}
                self.t.warn(f"{label}：{exc}")
            rows.append(row)
            if row["state"] == "ok":
                self.t.ok(f"{label}：{row['detail_text']}")
            elif row["state"] != "skip":
                self.t.warn(f"{label}：{row['detail_text']}")
            self.t.set_progress(index / len(plan), f"{index}/{len(plan)} 个模块")

        ok = sum(1 for r in rows if r["state"] == "ok")
        self.t.step_msg(f"全流程完成：{ok}/{len(rows)} 个模块有发现")
        return {
            "rows": rows,
            "passed": ok,
            "total": len(rows),
            "params": params,
            "summary": f"全流程：{ok}/{len(rows)} 个模块有发现",
            "severity": "critical" if ok >= 2 else ("high" if ok else "info"),
        }
