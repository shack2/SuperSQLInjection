---
name: supersqlinjectionv2-cmd
description: 使用 SuperSQLInjectionV2.Cmd 命令行工具（SuperSQLInjectionV2 CLI）对授权目标执行 SQL 注入检测与数据利用。支持 Bool盲注/报错/Union/时间盲注/堆叠/DNS外带检测，枚举库表列、dump 表数据、自定义 SQL、Hash/权限读取、读文件、写文件、OS 命令执行，覆盖 MySQL/SQLServer/PostgreSQL/SQLite/Oracle/Access/DB2/达梦。当用户要求对某个 URL、接口或 HTTP 报文做 SQL 注入测试、注入点检测、拖库/取数、读文件或命令执行，且目标属于授权测试范围（本地靶场、自有系统、授权渗透）时使用。
---

# SuperSQLInjectionV2.Cmd — SQL 注入检测与利用命令行

SuperSQLInjectionV2.Cmd 是 SuperSQLInjectionV2 的命令行版，Native AOT 单文件，无需 .NET 运行时。仅限授权目标使用。

## 运行二进制

按操作系统选择本 skill 内置的二进制（`<SKILL_DIR>` 为本 SKILL.md 所在目录）：

- Windows：`<SKILL_DIR>/assets/bin/win-x64/SuperSQLInjectionV2.Cmd.exe`
- Linux x64：`<SKILL_DIR>/assets/bin/linux-x64/SuperSQLInjectionV2.Cmd`（先 `chmod +x`）
- macOS arm64：未内置；见 `<SKILL_DIR>/assets/bin/README-osx.md`

二进制依赖同目录 `config/`（取数模板/检测用例/字典），必须保持目录结构完整。在二进制所在目录作为工作目录执行，输出写入 `output/<host>_<port>/`。

## 核心工作流

1. **检测**：`SuperSQLInjectionV2.Cmd -u "URL" [--level 2] [--risk 1]` —— 检出注入点、类型、数据库（含 Fork 衍生库如 MariaDB/TiDB/金仓/openGauss）；结果摘要打印在末尾，并落盘 `session.json`。
2. **会话复用**：同一目标+同一报文+同一检测参数再次运行时自动复用 `session.json` 跳过检测直接取数（免重复发包）；检测参数变化自动失效重测，`--flush-session` 强制重测。
3. **取数**：检出注入后同一条命令追加动作即可，工具自动复用检出的注入点：
   - `--banner --current-user --current-db --is-dba` 环境信息；`--env` 全部环境变量
   - `--dbs` → `--tables -D 库` → `--columns -D 库 -T 表` → `--dump -D 库 -T 表 [-C 列] [--start/--stop] [--where]`
   - `--sql-query="SQL"` 自定义查询；`--passwords` Hash；`--privileges` 权限角色
4. **文件/命令**：`--file-read=远程路径`、`--file-write=本地文件 --file-dest=远程路径`、`--os-cmd=命令`（自动按数据库类型选择 UDF/xp_cmdshell 等通道）。
5. **批量检测**：`-m urls.txt`（逐行一个 URL，`#` 注释），仅检测不取数；`--parallel --threads 5` 多目标并发；末尾输出汇总报告，各目标会话分别落盘。
6. **结果回收**：dump 同时打印 ASCII 表格并保存 CSV 到 output 目录；向用户汇报时给出 CSV 绝对路径。

## 关键规则

- 报文级目标（复杂头/Cookie/JSON/XML 注入点）：让用户提供原始报文存成文件，用 `-r 文件 [-p 参数]`。
- 检测失败再逐步升级：先 `--level 2`，仍无结果加 `--dbms` 收窄 + `--exhaustive`；疑似 WAF 加 `--tamper`（内置编码工具链）或 `--random-agent --delay`。注意：检测参数（level/risk/technique/dbms/tamper 等）变化会使会话指纹失效自动重测，无需手动清理。
- 重复跑同一目标想强制重测用 `--flush-session`；换动作（先 `--dbs` 后 `--dump`）不会触发重测。
- 盲注慢时加 `--threads 5`；中文乱码加 `--hex`。
- 完整参数与场景示例见 [references/cli-reference.md](references/cli-reference.md)。
