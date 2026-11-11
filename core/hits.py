# -*- coding: utf-8 -*-
"""盲打 XSS 命中收集（仅记录页面 URL / UA / 来源，不采集 Cookie）。"""

import json
import os
import threading
import time
import uuid

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
HITS_FILE = os.path.join(DATA_DIR, "xss_hits.json")


class HitStore:
    def __init__(self, path: str = HITS_FILE, limit: int = 200):
        self.path = path
        self.limit = limit
        self.lock = threading.Lock()
        self.items = self._load()

    def _load(self) -> list:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, list) else []
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.items, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
        except OSError:
            pass

    def add(self, token: str, page: str, referer: str, ua: str, ip: str) -> dict:
        record = {
            "id": uuid.uuid4().hex[:8],
            "time": time.time(),
            "token": (token or "")[:40],
            "page": (page or "")[:600],
            "referer": (referer or "")[:400],
            "ua": (ua or "")[:220],
            "ip": (ip or "")[:60],
        }
        with self.lock:
            self.items.insert(0, record)
            self.items = self.items[: self.limit]
            self._save()
        return record

    def list(self) -> list:
        with self.lock:
            return list(self.items)

    def clear(self):
        with self.lock:
            self.items = []
            self._save()
