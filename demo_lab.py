#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""演示靶场（仅用于本工具自测，监听 127.0.0.1:9999）。

它刻意复刻 DVWA 四个模块的响应特征，但数据库使用 SQLite，并做了一层
MySQL 语法兼容转换（VERSION()/DATABASE()/GROUP_CONCAT ... SEPARATOR 等）。
这不是一个真实站点，只用于验证控制台的探测、枚举与导出流程。
"""

import html
import re
import sqlite3
import time
from urllib.parse import parse_qs

from flask import Flask, request

app = Flask(__name__)
LOCK = __import__("threading").Lock()

USERS = [
    (1, "admin", "admin", "admin", "password", "/hackable/users/admin.jpg"),
    (2, "Gordon", "Brown", "gordonb", "abc123", "/hackable/users/gordonb.jpg"),
    (3, "Hack", "Me", "1337", "charley", "/hackable/users/1337.jpg"),
    (4, "Pablo", "Picasso", "pablo", "letmein", "/hackable/users/pablo.jpg"),
    (5, "Bob", "Smith", "smithy", "password", "/hackable/users/smithy.jpg"),
]

CMD_OUTPUT = {
    "whoami": "www-data",
    "id": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
    "pwd": "/var/www/html",
    "ls": "dvwa  hackable  index.php  vulnerabilities",
    "ls -la": ("total 36\ndrwxr-xr-x 1 root     root     4096 Nov  7 15:10 .\n"
               "drwxr-xr-x 1 root     root     4096 Nov  7 15:10 ..\n"
               "-rw-r--r-- 1 www-data www-data 1024 Nov  7 15:10 index.php\n"
               "drwxr-xr-x 1 www-data www-data 4096 Nov  7 15:10 vulnerabilities"),
    "uname -a": "Linux dvwa-demo 5.15.0-lab #1 SMP x86_64 GNU/Linux",
    "hostname": "dvwa-demo",
    "cat /etc/passwd": ("root:x:0:0:root:/root:/bin/bash\n"
                        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                        "mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false"),
    "ipconfig": "Windows IP Configuration",
    "date": "Sat Nov  7 16:58:00 CST 2026",
}


def db():
    conn = sqlite3.connect(":memory:")
    conn.execute("ATTACH DATABASE ':memory:' AS dvwa")
    conn.executescript("""
        CREATE TABLE dvwa.users (
            user_id INTEGER PRIMARY KEY, first_name TEXT, last_name TEXT,
            user TEXT, password TEXT, avatar TEXT
        );
        CREATE TABLE dvwa.guestbook (comment_id INTEGER PRIMARY KEY, comment TEXT, name TEXT);
    """)
    conn.executemany("INSERT INTO dvwa.users VALUES (?,?,?,?,?,?)", USERS)
    conn.execute("INSERT INTO dvwa.guestbook VALUES (1,'This is a test comment.','test')")

    conn.execute("ATTACH DATABASE ':memory:' AS information_schema")
    conn.executescript("""
        CREATE TABLE information_schema.schemata (schema_name TEXT);
        CREATE TABLE information_schema.tables (table_schema TEXT, table_name TEXT);
        CREATE TABLE information_schema.columns (
            table_schema TEXT, table_name TEXT, column_name TEXT, ordinal_position INTEGER
        );
    """)
    schemas = ["information_schema", "dvwa", "mysql", "performance_schema", "sys"]
    conn.executemany("INSERT INTO information_schema.schemata VALUES (?)",
                     [(s,) for s in schemas])
    conn.executemany("INSERT INTO information_schema.tables VALUES (?,?)",
                     [("dvwa", "users"), ("dvwa", "guestbook")])
    conn.executemany("INSERT INTO information_schema.columns VALUES (?,?,?,?)", [
        ("dvwa", "users", "user_id", 1), ("dvwa", "users", "first_name", 2),
        ("dvwa", "users", "last_name", 3), ("dvwa", "users", "user", 4),
        ("dvwa", "users", "password", 5), ("dvwa", "users", "avatar", 6),
        ("dvwa", "guestbook", "comment_id", 1), ("dvwa", "guestbook", "comment", 2),
        ("dvwa", "guestbook", "name", 3),
    ])
    conn.create_function("concat_ws", -1,
                         lambda sep, *args: sep.join("" if a is None else str(a) for a in args))
    conn.create_function("concat", -1,
                         lambda *args: "".join("" if a is None else str(a) for a in args))
    conn.create_function("sleep", 1, lambda n: (time.sleep(float(n)), 0)[1])
    return conn


def shim(sql: str) -> str:
    """把 MySQL 写法转换为 SQLite 可执行形式（仅测试用途）。"""
    sql = sql.replace("@@character_set_database", "'utf8'").replace("@@hostname", "'dvwa-demo'")
    sql = re.sub(r"\bVERSION\(\)", "sqlite_version()", sql)
    sql = re.sub(r"\bDATABASE\(\)", "'dvwa'", sql)
    sql = re.sub(r"\bUSER\(\)", "'root@localhost'", sql)
    sql = re.sub(r"\bSLEEP\(", "sleep(", sql)
    sql = sql.replace("0x4e554c4c", "'NULL'").replace("0x7c3b3b7c", "'|;;|'")
    sql = re.sub(r"=\s*0x([0-9a-fA-F]+)",
                 lambda m: "= '" + bytes.fromhex(m.group(1)).decode("utf-8") + "'", sql)
    sql = re.sub(r"GROUP_CONCAT\((.*?)\s+SEPARATOR\s+'?([^')]+)'?\)",
                 lambda m: f"GROUP_CONCAT({m.group(1)}, '{m.group(2)}')", sql)
    return sql


PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>DVWA Demo - {title}</title>
<style>body{{background:#111;color:#ddd;font-family:monospace;padding:30px}}
h1{{color:#f60}}pre{{background:#1b1b1b;padding:14px;border-left:3px solid #f60}}
a{{color:#6cf}}input{{padding:6px;margin:3px}}</style></head><body>
<h1>{title}</h1>{body}</body></html>"""


def page(title: str, body: str) -> str:
    return PAGE.format(title=title, body=body)


def security_level() -> str:
    raw = request.cookies.get("security", "") or request.args.get("security", "") or "low"
    return raw if raw in ("low", "medium", "high") else "low"


@app.get("/")
@app.get("/index.php")
def index():
    links = "".join(f"<li><a href='{path}'>{path}</a></li>" for path in (
        "/vulnerabilities/sqli/?id=1&Submit=Submit",
        "/vulnerabilities/xss_r/?name=test",
        "/vulnerabilities/exec/?ip=127.0.0.1",
        "/vulnerabilities/brute/?username=admin&password=password&Login=Login",
    ))
    return page("DVWA Demo Lab", f"<ul>{links}</ul><p>本地自测靶场 · 仅监听 127.0.0.1</p>")


@app.get("/login.php")
def login():
    return page("Login", "<form>Login required</form>")


@app.get("/vulnerabilities/sqli/")
def sqli():
    raw = request.args.get("id", "1")
    sql = shim(f"SELECT first_name, last_name FROM dvwa.users WHERE user_id = '{raw}'")
    body = ""
    try:
        with LOCK:
            conn = db()
            rows = conn.execute(sql).fetchall()
            conn.close()
        if rows:
            first, last = rows[0][0], rows[0][1]
            body = f"<pre>ID: {html.escape(raw)}<br>First name: {html.escape(str(first))}<br>Surname: {html.escape(str(last))}</pre>"
        else:
            body = "<pre>ID: " + html.escape(raw) + "<br>User ID is MISSING from the database.</pre>"
    except Exception as exc:  # noqa: BLE001
        body = f"<pre>You have an error in your SQL syntax; check the manual. ({html.escape(str(exc))})</pre>"
    form = """<form method="get"><input name="id" value="1"><input type="submit" name="Submit" value="Submit"></form>"""
    return page("SQL Injection", form + body)


@app.get("/vulnerabilities/xss_r/")
def xss_r():
    level = security_level()
    name = request.args.get("name", "")
    if level == "medium":
        name = re.sub(r"(?i)<script", "", name)
    elif level == "high":
        name = html.escape(name, quote=True).replace("&#x27;", "&#039;")
    form = """<form method="get"><input name="name" value=""><input type="submit" value="Submit"></form>"""
    return page("XSS Reflected", form + f"<pre>Hello {name}</pre>")


@app.get("/vulnerabilities/exec/")
def exec_cmd():
    ip = request.args.get("ip", "127.0.0.1")
    output = f"PING {ip} (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: seq=0 ttl=64 time=0.041 ms"
    match = re.search(r"(?:;|&&|\|\||\||`|\$\(|\n|&)\s*([^`)$&\n|;]+)", ip)
    if match:
        cmd = match.group(1).strip().strip("`")
        if cmd.startswith("echo "):
            output += "\n" + cmd[5:].strip()
        else:
            output += "\n" + CMD_OUTPUT.get(cmd, f"sh: 1: {cmd}: not found")
    form = """<form method="get"><input name="ip" value="127.0.0.1"><input type="submit" value="Submit"></form>"""
    return page("Command Injection", form + f"<pre>{html.escape(output)}</pre>")


@app.get("/vulnerabilities/brute/")
def brute():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    valid = any(u[3] == username and u[4] == password for u in USERS)
    form = """<form method="get"><input name="username" placeholder="username">
              <input name="password" type="password" placeholder="password">
              <input type="submit" name="Login" value="Login"></form>"""
    message = ("<p>Welcome to the password protected area " + html.escape(username) + "</p>"
               if valid else "<p>Username and/or password incorrect.</p>")
    return page("Brute Force", form + message)


if __name__ == "__main__":
    print("演示靶场: http://127.0.0.1:9999")
    app.run(host="127.0.0.1", port=9999, debug=False, threaded=True)
