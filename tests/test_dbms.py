import unittest

from dnslogsqlinj3 import DBMS_MAP


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


if __name__ == "__main__":
    unittest.main()
