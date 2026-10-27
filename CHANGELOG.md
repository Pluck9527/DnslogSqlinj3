# Changelog

## 3.0.0 — 2026-10-27

首次以 DnslogSqlinj 3 名义发布，相对原版 DnslogSqlinj（2019，py2 + ceye 硬编码）完全重写。

### 新增
- Python 3.8+，单文件，零第三方依赖
- Provider 抽象：dnslog.cn / DNSLog-GO / ceye.io / 自定义 shell 命令
- DBMS 原语：MySQL / MSSQL / Oracle / PostgreSQL
- 三种技术：`dns`（HEX 整块带外）、`--blind`（DNS 布尔）、`--technique time`（SLEEP）
- `--check` 联通性体检：领域名 → 探针解析 → 平台确认，含 fake-ip 识别与 DoH 兜底
- `--self-test` 离线自检
- `--prefix` / `--suffix` / `--encode` / `--http-timeout` / `--sleep-delay` / `--samples`

### 修复（实战踩坑）
- **WAF 编码**：`urllib.parse.quote(s, safe="")` 会把 `/ " ( )` 编码成 `%2F %22 %28`，
  被 phpStudy 一类 WAF 直接断连。默认改为白名单编码，`--encode strict` 可退回旧行为。
- **反斜杠 UNC 不触发解析**：部分 Windows + MySQL 组合下 `\\host\share\a` 直接返回 NULL，
  只有 `//host/share/x.txt` 才发起 DNS 查询。MySQL 模板改成正斜杠。
- **payload 拼接**：`%PAYLOAD%` 只替换表达式，拼出 `id='1'(SELECT …)` 语法错。新增 `--prefix`（默认 `AND `）。
- dnslog.cn 记录结构变为 `[[name, ip, time]]`，解析器已兼容嵌套列表 / dict / 字符串。
- ceye 用 404 返回错误，改为解析 body 中的 `meta.code` 并翻译成人话。
- 平台偶发 5xx/超时不再中断整轮 dump。
