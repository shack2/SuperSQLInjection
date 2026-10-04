namespace SuperSQLInjectionV2.Cmd;

/// <summary>
/// 命令行参数解析。
/// </summary>
public sealed class CliOptions
{
    // ---- 目标 ----
    public string? Url;                    // -u / --url
    public string? RequestFile;            // -r
    public string? BatchFile;              // -m / --batch-file（批量目标URL列表，逐行一个，仅检测）
    public string? Data;                   // --data（POST 表单体）
    public string? Cookie;                 // --cookie
    public List<string> Headers = [];      // --header（可多次，"Name: value"）
    public string? Method;                 // --method
    public string? TestParam;              // -p 指定测试参数

    // ---- 检测 ----
    public int Level = 1;                  // --level 1-5
    public int Risk = 1;                   // --risk 1-3
    public string? Technique;              // --technique BEUTSDQ
    public string? Dbms;                   // --dbms mysql/sqlserver/...
    public bool Smart;                     // --smart（默认已开启，该参数仅为兼容保留）
    public bool NoSmart;                   // --no-smart 关闭智能模式（头注入/写入型低Level目标全量重测用）
    public bool Exhaustive;                // --exhaustive 穷举模式
    public bool Parallel;                  // --parallel 多参数并行检测
    public bool StopOnWaf;                 // --stop-waf WAF拦截5次停止检测
    public bool KeepTesting;               // --keep-testing 检出注入后仍继续检测其余参数（关闭默认开启的检出即停）
    public bool FlushSession;              // --flush-session 忽略历史检测会话强制重新检测（默认同目标同报文同参数自动复用会话）
    public string? DnsDomain;              // --dns-domain（DNS外带）
    public string? DnsToken;               // --dns-token

    // ---- 请求 ----
    public string? Proxy;                  // --proxy http://127.0.0.1:8080 / socks5://...
    public int Timeout = 15;               // --timeout 秒
    public int Retries = 1;                // --retries
    public int DelayMs = 0;                // --delay 毫秒
    public int Threads = 1;                // --threads
    public bool RandomAgent;               // --random-agent
    public string? UserAgent;              // --user-agent
    public string? Tamper;                 // --tamper 逗号分隔编码工具名
    public string? RulesDir;               // --rules-dir 规则库目录（默认 config/rules/）
    public bool FollowRedirects;           // --follow-redirects

    // ---- 取数动作 ----
    public bool Banner;                    // --banner 版本
    public bool CurrentUser;               // --current-user
    public bool CurrentDb;                 // --current-db
    public bool Hostname;                  // --hostname
    public bool IsDba;                     // --is-dba
    public bool AllEnv;                    // --env 全部环境变量
    public bool Passwords;                 // --passwords Hash读取
    public bool Privileges;                // --privileges 权限角色
    public bool Dbs;                       // --dbs
    public bool Tables;                    // --tables
    public bool Columns;                   // --columns
    public bool Dump;                      // --dump
    public string? Db;                     // -D
    public string? Table;                  // -T
    public string? ColumnList;             // -C 逗号分隔
    public int Start = 1;                  // --start（1 起）
    public int? Stop;                      // --stop
    public string? Where;                  // --where
    public string? SqlQuery;               // --sql-query
    public string? FileRead;               // --file-read
    public string? FileWrite;              // --file-write 本地文件
    public string? FileDest;               // --file-dest 远端路径
    public string? FileMethod;             // --file-method 文件操作方式（模糊匹配GUI下拉项，如"大对象读文件"/"日志写WebShell"）
    public string? OsCmd;                  // --os-cmd
    public string? CmdMethod;              // --cmd-method 命令执行方式（模糊匹配GUI下拉项，如"sp_OACreate"）
    public string? OsShell;                // 占位：--os-shell 交互（v1 不支持）
    public bool NoCast;                    // --no-cast
    public bool HexDecode;                 // --hex 中文识别

    // ---- 输出/其他 ----
    public string? OutputDir;              // --output-dir
    public bool Batch = true;              // --batch（CLI 默认非交互）
    public bool ShowHelp;                  // -h/--help
    public bool ShowVersion;               // --version
    public bool SelfTest;                  // --selftest（加载 QuickJS 执行 JS 探针，CI 冒烟用）

    public bool HasAction =>
        Banner || CurrentUser || CurrentDb || Hostname || IsDba || AllEnv || Passwords || Privileges ||
        Dbs || Tables || Columns || Dump || SqlQuery != null || FileRead != null || FileWrite != null || OsCmd != null;

    /// <summary>批量检测子目标克隆：浅拷贝共享只读字段（Headers等），替换目标URL并清除报文文件（批量仅支持URL列表）</summary>
    public CliOptions CloneForUrl(string url)
    {
        var c = (CliOptions)MemberwiseClone();
        c.Url = url;
        c.RequestFile = null;
        return c;
    }

    public static CliOptions Parse(string[] args)
    {
        var o = new CliOptions();
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            string Next() => i + 1 < args.Length ? args[++i] : throw new ArgumentException($"参数 {a} 缺少值");
            string Val()
            {
                int eq = a.IndexOf('=', StringComparison.Ordinal);
                return eq >= 0 ? a[(eq + 1)..] : Next();
            }

            if (a.StartsWith("--", StringComparison.Ordinal))
            {
                switch (a.Split('=')[0])
                {
                    case "--url": o.Url = Val(); break;
                    case "--batch-file": o.BatchFile = Val(); break;
                    case "--data": o.Data = Val(); break;
                    case "--cookie": o.Cookie = Val(); break;
                    case "--header": o.Headers.Add(Val()); break;
                    case "--method": o.Method = Val().ToUpperInvariant(); break;
                    case "--level": o.Level = int.Parse(Val()); break;
                    case "--risk": o.Risk = int.Parse(Val()); break;
                    case "--technique": o.Technique = Val().ToUpperInvariant(); break;
                    case "--dbms": o.Dbms = Val(); break;
                    case "--smart": o.Smart = true; break;
                    case "--no-smart": o.NoSmart = true; break;
                    case "--exhaustive": o.Exhaustive = true; break;
                    case "--parallel": o.Parallel = true; break;
                    case "--stop-waf": o.StopOnWaf = true; break;
                    case "--keep-testing": o.KeepTesting = true; break;
                    case "--flush-session": o.FlushSession = true; break;
                    case "--dns-domain": o.DnsDomain = Val(); break;
                    case "--dns-token": o.DnsToken = Val(); break;
                    case "--proxy": o.Proxy = Val(); break;
                    case "--timeout": o.Timeout = int.Parse(Val()); break;
                    case "--retries": o.Retries = int.Parse(Val()); break;
                    case "--delay": o.DelayMs = (int)(double.Parse(Val()) * (a.Contains('.', StringComparison.Ordinal) ? 1000 : 1)); break;
                    case "--threads": o.Threads = int.Parse(Val()); break;
                    case "--random-agent": o.RandomAgent = true; break;
                    case "--user-agent": o.UserAgent = Val(); break;
                    case "--tamper": o.Tamper = Val(); break;
                    case "--rules-dir": o.RulesDir = Val(); break;
                    case "--follow-redirects": o.FollowRedirects = true; break;
                    case "--banner": o.Banner = true; break;
                    case "--current-user": o.CurrentUser = true; break;
                    case "--current-db": o.CurrentDb = true; break;
                    case "--hostname": o.Hostname = true; break;
                    case "--is-dba": o.IsDba = true; break;
                    case "--env": o.AllEnv = true; break;
                    case "--passwords": o.Passwords = true; break;
                    case "--privileges": o.Privileges = true; break;
                    case "--dbs": o.Dbs = true; break;
                    case "--tables": o.Tables = true; break;
                    case "--columns": o.Columns = true; break;
                    case "--dump": o.Dump = true; break;
                    case "--start": o.Start = int.Parse(Val()); break;
                    case "--stop": o.Stop = int.Parse(Val()); break;
                    case "--where": o.Where = Val(); break;
                    case "--sql-query": o.SqlQuery = Val(); break;
                    case "--file-read": o.FileRead = Val(); break;
                    case "--file-write": o.FileWrite = Val(); break;
                    case "--file-dest": o.FileDest = Val(); break;
                    case "--file-method": o.FileMethod = Val(); break;
                    case "--os-cmd": o.OsCmd = Val(); break;
                    case "--cmd-method": o.CmdMethod = Val(); break;
                    case "--os-shell": o.OsShell = ""; break;
                    case "--no-cast": o.NoCast = true; break;
                    case "--hex": o.HexDecode = true; break;
                    case "--output-dir": o.OutputDir = Val(); break;
                    case "--batch": o.Batch = true; break;
                    case "--help": o.ShowHelp = true; break;
                    case "--version": o.ShowVersion = true; break;
                    case "--selftest": o.SelfTest = true; break;
                    default: throw new ArgumentException($"未知参数: {a}");
                }
            }
            else
            {
                switch (a)
                {
                    case "-u": o.Url = Next(); break;
                    case "-r": o.RequestFile = Next(); break;
                    case "-m": o.BatchFile = Next(); break;
                    case "-p": o.TestParam = Next(); break;
                    case "-D": o.Db = Next(); break;
                    case "-T": o.Table = Next(); break;
                    case "-C": o.ColumnList = Next(); break;
                    case "-h": o.ShowHelp = true; break;
                    case "-v": _ = Next(); break; // 兼容冗余级别，忽略
                    default:
                        if (a.StartsWith("-u=", StringComparison.Ordinal)) o.Url = a[3..];
                        else if (a.StartsWith("-p", StringComparison.Ordinal)) o.TestParam = a[2..];
                        else throw new ArgumentException($"未知参数: {a}");
                        break;
                }
            }
        }
        return o;
    }

    public const string HelpText = """
        SuperSQLInjectionV2.Cmd — SuperSQLInjectionV2 命令行版（SQL 注入检测与利用）

        用法: SuperSQLInjectionV2.Cmd -u <URL> [选项] [动作]

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
          --dbms=DBMS             指定数据库（mysql/pgsql/sqlserver/sqlite/oracle/...）
          --smart                 智能模式（默认已开启，该参数仅为兼容保留；非动态+无指纹参数 Level<3 跳过、Level≥3 仅保留时间/堆叠）
          --no-smart              关闭智能模式（非动态参数也全量检测，头注入/写入型低Level目标用）
          --exhaustive            穷举模式（同技术测完全部用例）
          --parallel              多参数并行检测（并发度取 --threads，上限 10）
          --stop-waf              WAF 拦截累计 5 次即停止检测（防持续触发封禁）
          --keep-testing          检出注入后仍继续检测其余参数（默认检出即停，sqlmap同款）
          --flush-session         强制重新检测（默认同目标+同报文+同检测参数自动复用 output 下的会话文件，免重复发包）
          --dns-domain=D          DNS 外带接收域名（配合 --dns-token）

        请求:
          --proxy=PROXY           代理（http:// 或 socks5://host:port）
          --timeout=N             超时秒数（默认 15）
          --retries=N             超时重试（默认 1）
          --delay=N               每次请求前延时（毫秒）
          --threads=N             盲注并发线程（默认 1，建议 ≤10）
          --random-agent          随机 User-Agent
          --user-agent=UA         指定 User-Agent
          --tamper=A,B            编码处理工具链（内置名/key 或 rules 目录中的自定义脚本名）
          --rules-dir=DIR         规则库目录（默认 config/rules/，与 GUI 共用：自定义tamper/动态规则/字符替换/代理池）
          --follow-redirects      跟随 302 重定向

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
          --start=N --stop=N      dump 行范围（1 起）
          --where=COND            dump 行过滤条件
          --sql-query=SQL         执行自定义 SQL
          --file-read=PATH        读取服务器文件（--file-method=名 指定方式，模糊匹配如"大对象"/"二进制下载"）
          --file-write=LOCAL --file-dest=REMOTE   上传文件（--file-method 同上，如"日志写WebShell"/"二进制上传"）
                                  二进制下载：--file-read=远端路径 --file-method=二进制下载 --file-dest=本地保存路径
          --os-cmd=CMD            执行系统命令（UDF/xp_cmdshell 等；--cmd-method=名 指定方式，如"sp_OACreate"）
          --no-cast               取数不使用 CAST 转换
          --hex                   中文识别（HEX 包装防乱码）

        输出:
          --output-dir=DIR        结果保存目录（默认 output/<host>_<port>/）
          --batch                 非交互模式（默认）
          --version               显示版本
          --selftest              自检：真实加载 QuickJS 原生库执行 JS 探针（CI 冒烟用）
          -h, --help              显示帮助

        示例:
          SuperSQLInjectionV2.Cmd -u "http://127.0.0.1:8090/JVApp/mysql.jsp?id=1"
          SuperSQLInjectionV2.Cmd -u "http://127.0.0.1:8090/JVApp/mysql.jsp?id=1" --dbs
          SuperSQLInjectionV2.Cmd -u "http://127.0.0.1:8090/JVApp/mysql.jsp?id=1" -D sqli_test -T users --dump
          SuperSQLInjectionV2.Cmd -u "http://127.0.0.1:8090/JVApp/mysql.jsp?id=1" --sql-query="select version"
        """;
}
