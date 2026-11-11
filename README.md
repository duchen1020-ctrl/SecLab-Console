# SecLab Console

本地授权靶场攻防控制台。把 SQL 注入、XSS、命令注入、弱口令四类验证整合成一个菜单式 Web 工作台，带实时日志、任务队列、数据浏览与报告归档。

![Python](https://img.shields.io/badge/Python-3.9%2B-3776ab?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-000000?logo=flask&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

> ## ⚠️ 使用边界
>
> 本项目**只用于** DVWA、自建靶场、CTF 赛事或**已取得书面授权**的测试环境。
> 服务默认只监听 `127.0.0.1`，并对公网目标做硬拦截（需手动勾选「授权公网目标」并二次确认）。
> 未经授权对他人系统进行探测、爆破或数据提取，可能违反《网络安全法》《刑法》第 285 / 286 条。
> 请自行确认授权范围，并做好测试数据隔离。作者不对任何滥用行为负责。

---

## 功能一览

| 模块 | 能做什么 |
| --- | --- |
| **SQL 注入** | 自动识别引号上下文与注释符；布尔 / 报错 / 时间三种检测；`ORDER BY` 探列 → `UNION` 定位回显列 → `~z~` 标记精确取值 → `GROUP_CONCAT` 批量枚举库表字段 → 按行导出；UNION 不可用时自动降级为布尔 / 时间盲注，支持整库拖库；数据浏览器支持过滤与 JSON / CSV 导出。 |
| **XSS** | 8 种基础向量矩阵，区分「原样反射 / 编码 / 部分改写 / 拦截」并识别反射上下文；18 条深度向量（SVG / MathML / autofocus / srcdoc / 伪协议）；存储型模式自动提交留言并回读校验；DOM 型静态数据流分析；POC 生成（链接 / HTML / Markdown）；响应头与 CSP 审计（A–D 评分）。 |
| **命令注入** | 自动抓取表单（method / action / token）；8 种连接符覆盖 Linux 与 Windows；唯一 `echo` 标记确认生效；无回显时用 `ping` / `sleep` 延迟做盲命令探测；内置 Linux / Windows 速查；只读命令白名单。 |
| **弱口令** | 双字典；智能 / 标准 / 密码喷洒三种策略；字典导入、成功正则、429 自动退避；实时速率与命中 CSV 导出。 |

平台能力：

- **一键全流程**：四个模块用当前配置串起来跑完，输出汇总 Markdown 报告，弱口令可选（默认关闭）。
- **靶场自动登录**：填登录页 + 账号密码，自动带 CSRF token 登录，抓取新 Cookie 并写入四个模块；难度档位按顶栏 SEC 强制写入。
- **难度矩阵**：同一套目标自动跑 LOW / MEDIUM / HIGH，输出「模块 × 难度」总览并导出 Markdown。
- **全模块回归**：四个模块各跑一次探测级验证，附带代理端口连通性检查。
- **批量扫描**：粘贴 URL 清单（每行一个，最多 20 个），顺序跑同一模块的最小验证。
- **任务中心 / 任务记录**：实时进度、日志回放、STOP 中止；结果自动归档，可回看证据 JSON、导出 Markdown 与可离线打印的 HTML 总报告。
- **配置档**：四个模块的地址 / Cookie / 参数 / method / POST data / 延迟打包保存，可导出导入 JSON。
- **Cookie 巡检**：进页面查一次，之后每 5 分钟及切回标签页时再查，失效可一键重登。
- **代理联调**：右上角「直连 / PROXY」把流量转到 Burp Suite 或 mitmproxy。

## 快速开始

### Windows

双击 `start.bat`：自动创建虚拟环境、安装依赖、启动演示靶场并打开浏览器。

手动启动：

```bat
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe demo_lab.py      :: 可选：内置演示靶场 9999
.venv\Scripts\python.exe app.py
```

### Linux / macOS

```bash
bash start.sh
```

或手动：

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
./.venv/bin/python demo_lab.py &          # 可选
./.venv/bin/python app.py
```

打开 <http://127.0.0.1:8848>。

依赖只有两个：`flask>=3.0`、`requests>=2.31`。

## 先跑内置演示靶场

手边没有 DVWA 时，`demo_lab.py` 会在 `127.0.0.1:9999` 复刻四个模块的响应特征（SQLite + MySQL 语法兼容层），把界面里的地址改成下表即可：

| 模块 | 地址 |
| --- | --- |
| SQL 注入 | `http://127.0.0.1:9999/vulnerabilities/sqli/?id=1&Submit=Submit` |
| XSS | `http://127.0.0.1:9999/vulnerabilities/xss_r/` |
| 命令注入 | `http://127.0.0.1:9999/vulnerabilities/exec/` |
| 弱口令 | `http://127.0.0.1:9999/vulnerabilities/brute/` |

演示账号：`admin / password`、`gordonb / abc123`、`1337 / charley`、`pablo / letmein`、`smithy / password`。

## 接真实 DVWA

1. 目标地址填成你的 DVWA，例如 `http://127.0.0.1/vulnerabilities/sqli/?id=1&Submit=Submit`；
2. Cookie 填 `PHPSESSID=xxxx; security=low`（`security` 决定靶场防护级别），或直接在「直连 → 靶场自动登录」里用账号密码自动获取；
3. 点「连接测试」，看到 `HTTP 200` 且没有「跳转到登录页」提示即打通；
4. 先跑一次「全模块回归」或「难度矩阵」，确认四模块与三档难度是否都可测。

> DVWA 必须登录，未带有效 Cookie 会被重定向到 `login.php`，界面会明确提示。

## 目录结构

```
seclab-console/
├─ app.py                 Flask 入口与 API
├─ demo_lab.py            内置演示靶场（自测用）
├─ core/
│  ├─ guard.py            目标护栏（仅本机 / 内网）
│  ├─ httpclient.py       请求引擎与页面相似度
│  ├─ sqli.py             SQL 注入引擎
│  ├─ xss.py              XSS 引擎
│  ├─ cmdi.py             命令注入引擎
│  ├─ brute.py            弱口令引擎
│  ├─ regress.py          全模块回归 / 难度矩阵 / 批量扫描
│  ├─ fullscan.py         一键全流程（四模块串联 + 汇总）
│  ├─ forms.py            表单识别（method / action / token）
│  ├─ hits.py             盲打 XSS 命中接收
│  └─ tasks.py            任务队列与归档
├─ web/
│  ├─ index.html          菜单式工作台
│  └─ assets/             style.css / app.js
├─ data/                  运行时归档（history.json / xss_hits.json，已 gitignore）
├─ requirements.txt
├─ start.bat / start.sh
└─ README.md
```

## 安全护栏

- Web 服务仅绑定 `127.0.0.1:8848`；
- 目标默认必须是 loopback / 内网 IP / `.local` 等靶场域名，公网目标需勾选「授权公网目标」并二次确认；
- XSS 只用 `alert(1)`，命令注入默认白名单且禁止危险连接符，SQL 仅做只读查询；
- 所有请求带可调延迟，避免压垮靶场；
- `data/` 下的运行记录包含靶场地址、Cookie 与命中凭证，已在 `.gitignore` 中排除，**请勿提交到公开仓库**。

## 常见问题

**连接测试 502 / 超时**：靶场没启动，或地址 / 端口写错。

**提示 Cookie 失效**：不用再 F12 复制。点右上角「直连」→「靶场自动登录」，填登录页地址 + 账号密码，点「登录并同步 Cookie」，四个模块一起更新（难度按顶栏 SEC 设置）。

**SQL 注入探测不到**：确认参数名、靶场安全级别；Medium 及以上 DVWA 的 sqli 模块会转义引号，工具会自动切 POST 表单 / session-input，如果仍不行先跑一次「难度矩阵」看是哪一档被拦。

**端口被占用**：改 `app.py` 末尾的 `port=8848`，或结束占用进程。

**能否测公网资产**：仅在你有明确书面授权时勾选「授权公网目标」。工具会记录域名与确认时间并写进导出报告。

## 版本演进

### v12

- 一键全流程（总览页 03 面板）：SQLi 探注入点 → 列数 → 回显列 → 指纹 → 库列表；XSS 判定等级并列出可用载荷；命令注入确认连接符与 `whoami`；弱口令可选。
- 一键全流程报告：汇总成一份 Markdown，含总览表、注入上下文、指纹、库列表、可用 XSS 载荷、命中凭证。
- 目标配置档：设置弹窗内保存 / 应用 / 删除，支持导出 / 导入 JSON。
- 公网授权确认：勾选后弹二次确认，记录域名与时间并写入报告。
- 设置弹窗内容过长时改为 `max-height: 86vh` 可滚动。

### v11

- Cookie 失效巡检（进页面 / 每 5 分钟 / 切回标签页 / 任务报错时），可一键用上次账号重登并同步四模块。
- 难度矩阵导出 Markdown；批量扫描页（最多 20 个 URL，结果可载入模块继续深挖）。

### v10

- 靶场自动登录：抓 `user_token`、提交登录、拿新 `PHPSESSID`，一键写入四个模块，并把 `security` Cookie 强制改成所选档位。
- 难度矩阵：用现有配置自动跑三档轻量探测，输出「模块 × 难度」表格。
- HTML 总报告：把归档渲染成可离线打开、可直接打印的单文件报告。

### v9

- 盲注拖库：`GROUP_CONCAT` + 盲注枚举库 / 表 / 字段，再按 `CONV` 逐行逐列提取，取值走 `HEX()` 避免中文截断；支持单表与整库。
- 存储型 XSS「深度向量」开关，一次提交 19 条载荷并逐条回读判定。
- 全模块回归 + 代理端口连通性检查。

### v8

- 18 条 XSS 解析器差异向量库；UNION 失败自动降级布尔 / 时间盲注；支持 `sqli_blind` 的 LOW / MEDIUM / HIGH；改用 CookieJar 管理会话。

### v7（难度自适应）

- 顶栏 SEC 切换 LOW / MEDIUM / HIGH，自动改写四个模块 Cookie 的 `security`。
- SQLi 自动发现 `session-input.php`；Medium 自动跟随 POST 表单；命令注入增加 `whoami` 回显校验；弱口令每轮刷新 `user_token`。

### v3 – v6

- 盲注 ASCII 二分提取、存储型 XSS 与 POC 提交页、各模块 Markdown 报告、HTTP 代理、全局中止。
- 整库导出与 CSV、时间盲注、XSS 多参数、DOM 静态分析、弱口令喷洒 / 正则 / 字典导入。
- 响应头与 CSP 审计、盲命令探测、历史详情、限速退避、数据过滤。
- 表单自动识别、盲打 XSS 接收端、任务中心。

## 支持矩阵（参考）

DVWA 各版本实现差异较大，下表是常见实现下的参考结果，实际以工具回显为准：

| 模块 | LOW | MEDIUM | HIGH |
| --- | --- | --- | --- |
| SQL 注入 | ✅ | ✅ 自动 POST | ✅ session-input |
| 反射型 XSS | ✅ | ✅ img / svg | ✅ img / svg（script 被剥离） |
| 存储型 XSS | ✅ | ✅ | ✅ |
| 命令注入 | ✅ | ✅ `\|` | ✅ `\|\|` + whoami |
| 弱口令 | ✅ | ✅（失败 sleep 2s） | ✅（token 自动刷新，sleep 3s） |

> 若目标确实做了 `htmlspecialchars` + 八位 IP 校验，工具会如实报告不可利用，不会伪造结果。

## License

[MIT](LICENSE)
