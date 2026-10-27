import io
import json
import unittest
import urllib.error
from unittest import mock

import dnslogsqlinj3 as dsi


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


if __name__ == "__main__":
    unittest.main()
