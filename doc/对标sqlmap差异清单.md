# SuperSQLInjectionV2 对标 sqlmap 未实现差异决策清单

- 生成时间：2026-09-19
- 比对基准：sqlmap master（agent.py / payloads xml / 官方选项文档），已逐项核对本工具代码现状
- 已实现不再列出：六类注入技术（B/E/U/S/T/Q）、where=1/2/3（含 Parameter replace vector 取数）、level 1-5 / risk 1-3、boundary 矩阵、errors.xml 指纹、banner 确认、页面相似度引擎、时间自适应延时、二次注入、DNS 外带、tamper 脚本引擎（JS/Python/C#）、Token/CSRF/随机值、HPP、Union 微调（列数/填充字符/from）、MySQL UDF、取数模板 UI、注入记录、MCP 工具、国产库（DM/Kingbase/openGauss）、连接池全异步

## 优先级定义

- **P0** 核心链路缺口：不做则在常见实战场景直接"测不了/取不到"，建议立即做
- **P1** 高价值增强：显著提升检出率/效率/利用深度，建议 P0 完成后做
- **P2** 覆盖补充：特定场景有用，按需要做
- **P3** 小众可选：投入产出比低，有需求再做
- **N** 建议不做：与工具定位不符或已有更优替代

---

## 一、P0 核心链路缺口（5 项）

### 1. base64 参数注入（sqlmap `--base64=`）
- **为什么做**：`Agent.payload` 有专门的 base64 分支——参数值先 base64 解码、注入、再编码回写。现代 API/前后端分离站点大量用 base64 包装参数（如 `?q=MS5hbmQg...`），不识别则这类注入点完全测不了
- **优点**：自动识别 + 手工指定双模式；与现有 `$sql$` 标记体系兼容（编码块内再套一层 base64 变换即可）
- **场景**：REST API 查询参数、JWT-like 伪编码参数、WAF 后端的 base64 包装传参

### 2. HTTP 认证支持（sqlmap `--auth-type/--auth-cred/--auth-file`）
- **为什么做**：Basic/Digest/NTLM/客户端证书。内网系统、域环境站点普遍要 NTLM 认证，当前工具连请求都发不出去，检测无从谈起
- **优点**：HTTP 层统一接入，检测/取数/文件命令全链路自动受益；NTLM 用 `HttpClient` 的 `Credentials` 即可，Basic/Digest 实现量小
- **场景**：域控内网 IIS 站点（NTLM）、老 Tomcat 管理台（Basic）、双向 TLS 系统（证书）

### 3. 布尔命中全量反证（sqlmap `checkFalsePositives`）
- **为什么做**：sqlmap 对所有布尔命中做 and/or 反证（真值命中后再发一个恒假变体确认页面确实受控）；我们仅 where=1 数字型做了 invalid-bignum 反证，字符串型、where=2/3 命中没有反证，存在"页面本身随参数变化"造成的误报窗口
- **优点**：实现量小（TryBoolean 命中后追加一轮反证请求），直接降低误报率
- **场景**：搜索结果页、列表页等参数天然影响页面内容的目标

### 4. 全用户哈希枚举（sqlmap `--users/--passwords`）
- **为什么做**：当前只有 vers 模板里的 root/SYS 单条 hash；sqlmap 可枚举全部数据库用户及其口令哈希并按格式识别哈希类型。拿哈希→离线爆破是注入后最标准的横向动作
- **优点**：纯模板+枚举逻辑，复用现有库表列取数链路；各库模板已有 user 表查询基础
- **场景**：MySQL `mysql.user`、MSSQL `sys.sql_logins`、PG `pg_shadow`、Oracle `dba_users` 全量哈希导出

### 5. UDF 痕迹清理（sqlmap `--cleanup`）
- **为什么做**：UDF 命令执行会在目标库留下 `sys_eval`/`sys_exec` 函数和 plugin 目录二进制文件，实战收尾必须清理；当前工具只建不删
- **优点**：实现量小（drop function + 已有堆叠/命令通道）；合规与隐蔽性双重要求
- **场景**：授权测试收尾、红队行动痕迹清除

---

## 二、P1 高价值增强（7 项）

### 6. `--smart` 智能检测模式
- **为什么做**：指纹命中后只跑该库相关用例并压缩检测面。我们 DbmsMatch 已过滤 dbms 专属用例，但通用用例仍全量跑，level 5 下发包量巨大
- **优点**：检测提速 50%+；实现只是矩阵过滤策略加一个开关
- **场景**：目标明确、时间敏感的红队快打；批量目标初筛

### 7. `--null-connection` 空连接布尔比对
- **为什么做**：不读响应体，仅凭 Content-Length/HEAD 头做真假比对。盲注大页面（几百 KB）时每个请求只传响应头，提速数倍且降低带宽特征
- **优点**：HTTP 层加一个"只读头"模式 + 判定器按长度比对，改动集中
- **场景**：内容型站点（新闻/ CMS）布尔盲注取数、慢网环境

### 8. `--search` 按名搜索库/表/列
- **为什么做**：大库（几百张表）里找 user/admin/config 表是高频动作，现在只能整库枚举后人工翻
- **优点**：复用枚举模板加 LIKE 条件即可，实现量小
- **场景**：大型业务库定向找敏感表/敏感列（password、token、idcard）

### 9. URI 路径段注入（sqlmap `PLACE.URI`）
- **为什么做**：RESTful 风格 `/api/user/1/detail` 的注入点在路径段里，自动检测目前只认 query/body/cookie/header，路径段识别不了（手工 `$sql$` 标记可绕过）
- **优点**：ParamPlace 加 URI 枚举 + 检测引擎按 `*` 位替换，与现有标记体系同构
- **场景**：Spring/JAX-RS 风格 REST 接口、伪静态路由（`/news/1.html`）

### 10. `--privileges/--roles` 权限角色枚举
- **为什么做**：判断当前注入账户能干什么（能否读文件/写文件/执行命令/提权）是利用链决策的关键输入，现在只能逐个功能试错
- **优点**：纯模板枚举；结果可直接驱动 UI 上"文件/命令"功能的可用性提示
- **场景**：注入后评估利用面、写报告时的权限证据

### 11. MySQL/SQLServer 补 is-dba 模板
- **为什么做**：PG/Oracle/DM/HSQLDB 已有"是否DBA"，主流两库反而缺
- **优点**：加两行 vers 模板的事（MySQL `select super_priv from mysql.user...`，MSSQL `IS_SRVROLEMEMBER('sysadmin')`）
- **场景**：同 #10，低成本补齐

### 12. PostgreSQL UDF 命令执行（sqlmap `lib_postgresqludf_sys`）
- **为什么做**：PG 命令执行目前只有 COPY FROM PROGRAM（需 9.3+ 且 superuser），9.2 及以下老 PG 无通道；sqlmap 提供 PG UDF 二进制（与 MySQL UDF 同套路）
- **优点**：复用已实现的 MySQL UDF 框架（内嵌二进制 + Union 写库 + create function）
- **场景**：老版本 PG（9.2-）目标、COPY PROGRAM 被禁用的加固环境

---

## 三、P2 覆盖补充（9 项）

### 13. `--test-filter/--test-skip` 用例过滤
- **为什么做**：按用例标题正则包含/排除（如"只测 MySQL 用例""跳过时间类"），level 5 全量 369 个用例下精准控制发包
- **优点**：SqlmapPayloadLoader.GetTests 加一个正则过滤参数，10 行级改动
- **场景**：已知库型复测、绕过特定 WAF 时排除特征明显的用例

### 14. SOAP/XML 结构化注入
- **为什么做**：`POST_HINT.SOAP/XML`——XML 体自动解析节点为可注入参数。当前 JSON 已支持，XML 需手工 `$sql$` 标记
- **优点**：BodyJson 的解析逻辑平移到 XML DOM 即可
- **场景**：老 WebService 接口、银行/政务 SOAP 网关

### 15. dump 精细化开关
- **为什么做**：`--first-char/--last-char`（截取字段部分字符）、`--start/--limit-stop`（行范围已有雏形）、`--where`（dump 过滤条件）、`--binary-fields`（二进制字段 hex 处理）、`--no-cast/no-escape`
- **优点**：取数模板已参数化，多数是 UI 暴露 + 模板占位符传参
- **场景**：超长字段分段取、二进制（hash/图片头）字段、只 dump 满足条件的行

### 16. 全库字典猜解（sqlmap `--common-tables/--common-columns`）
- **为什么做**：目前只 Access 有字典猜解；当 information_schema 不可用（权限受限/MySQL 8 某些配置）时，其他库也需要字典兜底
- **优点**：Access 猜解链路现成，把字典+存在性判断模板推广到各库即可
- **场景**：低权限注入点、information_schema 被禁用/过滤的目标

### 17. `--os-shell` 交互式命令 shell
- **为什么做**：当前命令执行是单条发+回显，交互 shell 保持工作目录/环境上下文，体验更接近真实 shell
- **优点**：UI 上加一个伪终端页签，底层复用现有命令通道
- **场景**：UDF/COPY PROGRAM 打通后的连续操作（cd、查看多文件）

### 18. `--chunked` 分块传输
- **为什么做**：HTTP 分块编码可绕过部分 WAF 的 body 检测，sqlmap 作为独立开关；我们可并入 tamper/绕过体系
- **优点**：HTTP 发送层支持 Transfer-Encoding: chunked 即可
- **场景**：body 内容检测型 WAF 前的 POST 注入

### 19. Host 头自动检测（sqlmap level 5）
- **为什么做**：sqlmap level 5 测 Host 头注入（虚拟主机路由到后端的场景）；我们 Header place 框架已有，自动检测未纳入 Host
- **优点**：DetectParam 的 Header 分支加 Host 候选即可
- **场景**：反代/CDN 后端直连、虚拟主机混淆的内部系统

### 20. `--random-agent` UA 池
- **为什么做**：检测过程 UA 固定易被日志/WAF 标记；随机 UA 是低成本降噪
- **优点**：内置 UA 列表 + 每请求轮换，实现量极小
- **场景**：有日志审计/流控的目标、批量检测

### 21. Cookie 管理增强
- **为什么做**：`--drop-set-cookie`（忽略响应 Set-Cookie）、`--load-cookies`（Netscape cookie 文件导入）、`--cookie-del`（自定义分隔符）
- **优点**：均为请求组装层小改动
- **场景**：会话状态异常的目标、从浏览器导出 cookie 直接开测

---

## 四、P3 小众可选（8 项）

### 22. `--invalid-logical/--invalid-bignum/--invalid-string`
- where=2 负值替换的三个变体（逻辑否定/大数/随机串），用于原查询对负数仍有结果的特殊场景。当前固定负随机数已覆盖 95% 场景

### 23. Union 高级变体
- `kb.unionTemplate`（Derby 等严格类型库逐列类型模板）、multipleUnions（长度受限多段 UNION）、limited union（单子查询列）、`--union-values`。Derby 等库过于小众

### 24. `--predict-output` 盲注预测模型
- 对常见值用历史序列预测减少请求数。实现复杂、收益不稳定

### 25. `--fingerprint` 深度版本指纹
- 版本级函数主动探测（如 `@@version_comment`、特有函数存在性）。现有 errors.xml + banner 确认已够用

### 26. `--comments/--statements/--common-files/--sql-file`
- 库表注释枚举、当前执行语句、常见文件存在性、SQL 文件批量执行。均为低频需求

### 27. Windows 注册表操作（`--reg-read/write/add/del`）
- MSSQL + Windows 专属，xp_regread 系列。CTF/极特定场景

### 28. `--shared-lib` 自定义 UDF 库 / `--web-root` 相对路径写 shell
- 内嵌 UDF 二进制已覆盖主流；绝对路径写文件已够用

### 29. `--skip-static/--param-exclude/--scope/--os` 手动指定
- 参数过滤与 OS 手工指定。当前"告警不跳过"与 sqlmap 默认一致，OS 可由文件/命令模板选择隐式覆盖

---

## 五、N 建议不做（3 类）

### 30. Metasploit 集成（`--os-pwn/--os-smbrelay/--os-bof`）
- 依赖 MSF 外部进程，与跨平台单文件 GUI 定位冲突；命令执行打通后用户可自行上马

### 31. 目标获取族（`--crawl/--forms/-m 批量/-l Burp 日志/-g dork/--har`）
- 爬虫/表单识别/批量目标/日志导入是"扫描器"定位，与"注入利用工具"定位不同；报文格式转换（复杂/POST/GET）已覆盖 `-r` 核心场景。如确需批量，只做 `-m` 多 URL 顺序检测即可（P3）

### 32. 检测进度级断点续扫（sqlmap session sqlite）
- 我们已有注入点级持久化（inject_records.json）；检测过程级断点续扫收益低、状态复杂

---

## 六、实施路线建议

| 批次 | 内容 | 预计影响 |
|------|------|---------|
| 第一批（P0） | base64 参数、HTTP 认证、布尔全量反证、全用户哈希、UDF cleanup | 消灭"测不了/取不到/收不了尾"三类硬伤，可宣布检测利用链路全面对标 |
| 第二批（P1） | --smart、--null-connection、--search、URI 路径段、--privileges、is-dba 补全、PG UDF | 检出率与效率补齐，利用深度对齐 sqlmap  enumeration 全家桶 |
| 第三批（P2） | 用例过滤、SOAP/XML、dump 精细化、全库字典、os-shell、chunked、Host 头、UA 池、Cookie 管理 | 场景覆盖补全 |
| 按需（P3/N） | 其余 | 有实际案例驱动再做 |
