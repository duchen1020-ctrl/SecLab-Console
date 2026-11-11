# -*- coding: utf-8 -*-
"""目标护栏：默认只允许本机 / 内网靶场地址，防止误伤公网资产。"""

import ipaddress
import socket
from urllib.parse import urlparse


class TargetError(ValueError):
    pass


ALIASES = {
    "localhost", "dvwa", "host.docker.internal", "gateway.docker.internal",
    "mysql", "web", "target", "victim", "lab", "testphp.vulnweb.com.local",
}


def _private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def is_lab_host(host: str) -> bool:
    h = (host or "").strip("[]").lower()
    if not h:
        return False
    if h in ALIASES:
        return True
    if h.endswith((".local", ".lab", ".test", ".internal", ".localhost")):
        return True
    if _private_ip(h):
        return True
    try:
        infos = socket.getaddrinfo(h, None)
    except socket.gaierror:
        raise TargetError(f"无法解析主机名：{h}")
    if not infos:
        return False
    # 所有解析结果都必须是内网地址，避免 DNS 指向公网
    return all(_private_ip(info[4][0]) for info in infos)


def normalize_target(cfg: dict, allow_public: bool = False) -> dict:
    """校验并规范化目标配置，返回新的 dict。"""
    if not isinstance(cfg, dict):
        raise TargetError("目标配置格式错误")
    url = (cfg.get("url") or "").strip()
    if not url:
        raise TargetError("目标 URL 不能为空")
    if not url.lower().startswith(("http://", "https://")):
        raise TargetError("目标 URL 必须以 http:// 或 https:// 开头")
    parsed = urlparse(url)
    if not parsed.hostname:
        raise TargetError("目标 URL 缺少主机名")

    allow_public = bool(allow_public or cfg.get("allow_public"))
    if not allow_public and not is_lab_host(parsed.hostname):
        raise TargetError(
            f"安全护栏已拦截：{parsed.hostname} 不是本机 / 内网地址。"
            "本工具仅面向授权靶场，如需测试公网资产请确认授权后勾选「授权公网目标」。"
        )

    method = (cfg.get("method") or "GET").upper()
    if method not in ("GET", "POST"):
        raise TargetError("请求方法仅支持 GET / POST")

    data = cfg.get("data") or {}
    if not isinstance(data, dict):
        raise TargetError("POST 数据必须是键值对象")

    proxy = (cfg.get("proxy") or "").strip()
    if proxy and not proxy.lower().startswith(("http://", "https://", "socks5://", "socks4://")):
        raise TargetError("代理地址需以 http:// 或 socks5:// 开头")
    if len(proxy) > 200:
        raise TargetError("代理地址过长")

    return {
        "url": url,
        "method": method,
        "cookie": (cfg.get("cookie") or "").strip(),
        "headers": cfg.get("headers") or {},
        "data": {str(k): str(v) for k, v in data.items()},
        "proxy": proxy,
        "ua": (cfg.get("ua") or "").strip()[:200],
        "timeout": max(3.0, min(float(cfg.get("timeout") or 10), 60.0)),
        "delay": max(0.0, min(float(cfg.get("delay") or 0.15), 5.0)),
        "allow_public": allow_public,
    }


def scope_label(url: str) -> str:
    host = urlparse(url).hostname or "?"
    return "内网/本机靶场" if is_lab_host(host) else "公网目标（已授权）"
