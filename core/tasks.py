# -*- coding: utf-8 -*-
"""轻量后台任务系统：线程执行 + 日志增量拉取 + 中止开关。"""

import json
import os
import threading
import time
import traceback
import uuid

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")
MAX_LOGS = 4000


class TaskStopped(Exception):
    pass


class Task:
    def __init__(self, kind: str, title: str, meta: dict | None = None):
        self.id = uuid.uuid4().hex[:10]
        self.kind = kind
        self.title = title
        self.meta = meta or {}
        self.status = "running"
        self.progress = 0.0
        self.step = ""
        self.logs: list[dict] = []
        self.result = None
        self.error = None
        self.started = time.time()
        self.ended = None
        self.stop_event = threading.Event()
        self.lock = threading.Lock()

    # ---- 日志 ----
    def log(self, message: str, level: str = "info"):
        with self.lock:
            if len(self.logs) < MAX_LOGS:
                self.logs.append({"t": time.time(), "level": level, "msg": str(message)})

    def info(self, msg): self.log(msg, "info")
    def ok(self, msg): self.log(msg, "ok")
    def warn(self, msg): self.log(msg, "warn")
    def err(self, msg): self.log(msg, "err")
    def data(self, msg): self.log(msg, "data")
    def step_msg(self, msg):
        self.step = msg
        self.log(f"▶ {msg}", "step")

    def set_progress(self, value: float, step: str | None = None):
        self.progress = max(0.0, min(1.0, float(value)))
        if step:
            self.step = step

    def set_result(self, payload):
        self.result = payload
        self.progress = 1.0

    def check_stop(self):
        if self.stop_event.is_set():
            raise TaskStopped()

    def to_dict(self, offset: int = 0, limit: int = 400) -> dict:
        with self.lock:
            total = len(self.logs)
            logs = self.logs[offset: offset + limit]
        return {
            "id": self.id,
            "kind": self.kind,
            "title": self.title,
            "status": self.status,
            "progress": round(self.progress, 4),
            "step": self.step,
            "started": self.started,
            "ended": self.ended,
            "logs": logs,
            "log_offset": offset + len(logs),
            "log_total": total,
            "result": self.result if self.status in ("done", "stopped", "error") else None,
            "error": self.error,
            "meta": self.meta,
        }


class TaskManager:
    def __init__(self):
        self.tasks: dict[str, Task] = {}
        self.lock = threading.Lock()
        os.makedirs(DATA_DIR, exist_ok=True)

    def start(self, kind: str, title: str, fn, meta: dict | None = None) -> Task:
        task = Task(kind, title, meta)
        with self.lock:
            self.tasks[task.id] = task
            # 只保留最近 60 个任务
            if len(self.tasks) > 60:
                for key in list(self.tasks.keys())[: len(self.tasks) - 60]:
                    self.tasks.pop(key, None)

        def runner():
            try:
                fn(task)
                if task.status == "running":
                    task.status = "done"
            except TaskStopped:
                task.status = "stopped"
                task.log("任务已被手动中止", "warn")
            except Exception as exc:  # noqa: BLE001
                task.status = "error"
                task.error = f"{exc.__class__.__name__}: {exc}"
                task.log(f"执行失败：{task.error}", "err")
                task.log(traceback.format_exc(limit=3), "err")
            finally:
                task.ended = time.time()
                if task.status == "running":
                    task.status = "done"
                self._archive(task)

        thread = threading.Thread(target=runner, daemon=True)
        thread.start()
        return task

    def get(self, task_id: str) -> Task | None:
        return self.tasks.get(task_id)

    def stop(self, task_id: str) -> bool:
        task = self.tasks.get(task_id)
        if not task or task.status != "running":
            return False
        task.stop_event.set()
        task.log("收到中止指令，正在收尾…", "warn")
        return True

    # ---- 历史归档 ----
    def _archive(self, task: Task):
        if not task.result or not isinstance(task.result, dict):
            return
        summary = task.result.get("summary")
        if not summary:
            return
        record = {
            "id": task.id,
            "kind": task.kind,
            "title": task.title,
            "status": task.status,
            "started": task.started,
            "ended": task.ended,
            "duration": round((task.ended or time.time()) - task.started, 2),
            "summary": summary,
            "target": task.meta.get("url", ""),
            "severity": task.result.get("severity", "info"),
            "rows": len(task.result.get("rows") or []),
        }
        try:
            blob = json.dumps(task.result, ensure_ascii=False)
            if len(blob) <= 80000:
                record["detail"] = task.result
            else:
                record["detail"] = {
                    "summary": summary,
                    "truncated": True,
                    "note": "结果超过 80KB，仅保存摘要",
                    "keys": list(task.result.keys()),
                }
        except (TypeError, ValueError):
            record["detail"] = {"summary": summary}
        try:
            history = self.read_history(detail=True)
            history.insert(0, record)
            history = history[:100]
            tmp = HISTORY_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(history, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, HISTORY_FILE)
        except Exception:  # noqa: BLE001
            pass

    def read_history(self, detail: bool = False) -> list:
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            return []
        if not isinstance(data, list):
            return []
        if detail:
            return data
        return [{key: value for key, value in item.items() if key != "detail"}
                for item in data]

    def get_record(self, record_id: str) -> dict | None:
        for item in self.read_history(detail=True):
            if item.get("id") == record_id:
                return item
        return None

    def clear_history(self):
        try:
            with open(HISTORY_FILE, "w", encoding="utf-8") as fh:
                json.dump([], fh)
        except OSError:
            pass


MANAGER = TaskManager()
