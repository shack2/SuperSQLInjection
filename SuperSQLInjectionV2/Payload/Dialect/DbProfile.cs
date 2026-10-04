using SuperSQLInjectionV2.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace SuperSQLInjectionV2.Payload
{
    /// <summary>
    /// 数据库档案统一注册表：每库一条声明，集中承载——
    /// DBMS名称（检测用例dbms匹配/指纹反推）、取数模板路径、环境变量词表路径、
    /// 检测语法兼容族（CompatDb）、fork/衍生库别名、取数方言选项。
    /// 新增数据库只需在此登记一条，检测/取数/模板管理/环境变量各处自动生效。
    /// </summary>
    public sealed class DbProfile
    {
        /// <summary>本工具数据库类型枚举</summary>
        public DBType DbType { get; }

        /// <summary>DBMS名称（sqlmap风格，检测用例dbms属性匹配与错误指纹反推用）</summary>
        public string DbmsName { get; }

        /// <summary>取数模板文件相对路径（config/payload/xx.txt）</summary>
        public string TemplatePath { get; }

        /// <summary>环境变量词表文件名（config/vers/xx.txt）；null=该库不支持环境变量读取（如Access无环境变量函数）</summary>
        public string? VersFile { get; }

        /// <summary>检测语法兼容族：用例库无本库专属用例时，按兼容库过滤/匹配用例（达梦→Oracle，金仓/openGauss→PG）</summary>
        public DBType CompatDb { get; }

        /// <summary>fork/衍生库名（归一化小写无符号）：错误指纹/名称识别命中后映射到本库，取数直接复用本库模板</summary>
        public string[] Forks { get; }

        /// <summary>取数方言选项工厂</summary>
        public Func<DialectOptions> CreateOptions { get; }

        /// <summary>fork化模式：true=本库不作为独立取数库型，识别/取数归一到族宿主（CompatDb）+Fork名，取数=族模板+fork overlay差异文件</summary>
        public bool ForkMode { get; }

        private DbProfile(DBType dbType, string dbmsName, string templatePath, string? versFile,
            DBType compatDb, string[] forks, Func<DialectOptions> createOptions, bool forkMode = false)
        {
            DbType = dbType;
            DbmsName = dbmsName;
            TemplatePath = templatePath;
            VersFile = versFile;
            CompatDb = compatDb;
            Forks = forks;
            CreateOptions = createOptions;
            ForkMode = forkMode;
        }

        // ────────────────────── 注册表（新增数据库在此登记一条） ──────────────────────

        private static readonly DbProfile[] All =
        {
            new DbProfile(DBType.MySQL, "MySQL", "config/payload/mysql.txt", "mysql.txt",
                DBType.MySQL,
                //mariadb/percona/drizzle/tidb/doris/starrocks/memsql 已实测兼容；
                //oceanbase(MySQL模式)/tdsql/goldendb/polardb(MySQL版) 按公开驱动与协议兼容登记，指纹未经靶场实测
                new[] { "mariadb", "percona", "drizzle", "tidb", "doris", "starrocks", "memsql",
                        "oceanbase", "tdsql", "goldendb", "polardb" },
                () => new DialectOptions()),
            new DbProfile(DBType.SQLServer, "Microsoft SQL Server", "config/payload/sqlserver.txt", "sqlserver.txt",
                DBType.SQLServer, Array.Empty<string>(),
                () => new DialectOptions
                {
                    MarkerEncoder = LiteralEncoder.CharPlus,
                    ConcatOp = "+",
                    JoinWithMarker = true,
                    SingleColumnCast = true,
                    //库/表枚举模板（[{db}]..[sysobjects]、object_id('{db}..{table}')）均为标识符/限定名上下文，
                    //不能用默认Hex编码（0x...会被当成字面库名导致枚举为空）
                    IdentEncoder = LiteralEncoder.None,
                    DataIndexOffset = 1
                }),
            new DbProfile(DBType.Oracle, "Oracle", "config/payload/oracle.txt", "oracle.txt",
                //dmdatabase：达梦banner"DM Database Server"归一化后含此串（指纹/名称识别命中归一到Oracle族+Fork名DM）
                DBType.Oracle, new[] { "dmdatabase" }, CreateOracleOptions),
            //达梦兼容Oracle语法（方言/检测用例复用Oracle）；fork化：取数归一到Oracle族+fork_dmdatabase.txt差异模板
            new DbProfile(DBType.DM, "DM", "config/payload/fork_dmdatabase.txt", "fork_dmdatabase.txt",
                DBType.Oracle, Array.Empty<string>(), CreateOracleOptions, true),
            new DbProfile(DBType.PostgreSQL, "PostgreSQL", "config/payload/postgresql.txt", "postgresql.txt",
                DBType.PostgreSQL,
                //cockroachdb/yugabytedb/cratedb 已实测兼容；
                //gaussdb/mogdb/highgo/vastbase 为PG系国产库，按公开兼容性登记，指纹未经靶场实测；
                //kingbasees/opengauss 为fork化变体（识别归一到PG族+Fork名，取数走fork overlay差异模板）
                new[] { "cockroachdb", "yugabytedb", "cratedb", "gaussdb", "mogdb", "highgo", "vastbase",
                        "kingbasees", "opengauss" },
                CreatePgOptions),
            //人大金仓兼容PostgreSQL语法（方言/检测用例复用PG）；fork化：取数归一到PG族+fork_kingbasees.txt差异模板
            new DbProfile(DBType.Kingbase, "KingbaseES", "config/payload/fork_kingbasees.txt", "fork_kingbasees.txt",
                DBType.PostgreSQL, Array.Empty<string>(), CreatePgOptions, true),
            //openGauss基于PostgreSQL 9.2，共用PG检测用例；fork化：取数归一到PG族+fork_opengauss.txt差异模板
            new DbProfile(DBType.OpenGauss, "openGauss", "config/payload/fork_opengauss.txt", "fork_opengauss.txt",
                DBType.PostgreSQL, Array.Empty<string>(), CreatePgOptions, true),
            new DbProfile(DBType.Access, "Microsoft Access", "config/payload/access.txt", null,
                DBType.Access, Array.Empty<string>(),
                () => new DialectOptions
                {
                    MarkerEncoder = LiteralEncoder.ChrAmp,
                    ConcatOp = "&",
                    JoinWithMarker = true,
                    TableIndexOffset = 1,
                    DataIndexOffset = 1,
                    MinValueChain = true
                }),
            new DbProfile(DBType.DB2, "IBM DB2", "config/payload/db2.txt", "db2.txt",
                DBType.DB2, Array.Empty<string>(),
                () => new DialectOptions
                {
                    MarkerEncoder = LiteralEncoder.Chr,
                    ConcatOp = "||",
                    JoinWithMarker = true,
                    IdentEncoder = LiteralEncoder.Chr,
                    UpperDbName = true,
                    UpperTableName = true,
                    EnumIndexOffset = 1,
                    DataIndexOffset = 1
                }),
            new DbProfile(DBType.SQLite, "SQLite", "config/payload/sqlite.txt", "sqlite.txt",
                DBType.SQLite, Array.Empty<string>(),
                () => new DialectOptions
                {
                    MarkerEncoder = LiteralEncoder.CharBar,
                    ConcatOp = "||",
                    JoinWithMarker = true,
                    IdentEncoder = LiteralEncoder.CharBar
                }),
            new DbProfile(DBType.Informix, "Informix", "config/payload/informix.txt", "informix.txt",
                DBType.Informix, Array.Empty<string>(),
                () => new DialectOptions
                {
                    MarkerEncoder = LiteralEncoder.ToChar,
                    ConcatOp = "||",
                    JoinWithMarker = true,
                    IdentEncoder = LiteralEncoder.None,
                    QuoteTableName = true
                }),
            new DbProfile(DBType.H2, "H2", "config/payload/h2.txt", "h2.txt",
                DBType.H2, Array.Empty<string>(),
                () => new DialectOptions
                {
                    MarkerEncoder = LiteralEncoder.CharBar,
                    ConcatOp = "||",
                    JoinWithMarker = true,
                    IdentEncoder = LiteralEncoder.CharBar,
                    UpperTableName = true
                }),
            new DbProfile(DBType.HSQLDB, "HSQLDB", "config/payload/hsqldb.txt", "hsqldb.txt",
                DBType.HSQLDB, Array.Empty<string>(),
                () => new DialectOptions
                {
                    MarkerEncoder = LiteralEncoder.Chr,
                    ConcatOp = "||",
                    JoinWithMarker = true,
                    IdentEncoder = LiteralEncoder.Chr,
                    UpperTableName = true
                }),
            new DbProfile(DBType.ClickHouse, "ClickHouse", "config/payload/clickhouse.txt", "clickhouse.txt",
                DBType.ClickHouse, Array.Empty<string>(),
                () => new DialectOptions
                {
                    MarkerEncoder = LiteralEncoder.Quote,
                    ConcatOp = ",",
                    JoinWithMarker = true,
                    SingleColumnCast = true,
                    IdentEncoder = LiteralEncoder.None,
                    ErrorViaDataValue = true,
                    DerivedTableError = true
                }),
        };

        private static DialectOptions CreateOracleOptions()
        {
            return new DialectOptions
            {
                MarkerEncoder = LiteralEncoder.Chr,
                ConcatOp = "||",
                JoinWithMarker = true,
                //枚举模板（owner={db}）为字符串上下文，Oracle/DM无0x十六进制字面量，
                //默认Hex会编成0x535953...导致owner匹配失败（表/列枚举为空）
                IdentEncoder = LiteralEncoder.Chr,
                //数据字典中的owner/table_name均为大写存储，用户输入小写时枚举会落空
                UpperDbName = true,
                UpperTableName = true,
                DataIndexOffset = 1
            };
        }

        private static DialectOptions CreatePgOptions()
        {
            return new DialectOptions
            {
                MarkerEncoder = LiteralEncoder.Chr,
                ConcatOp = "||",
                JoinWithMarker = true,
                IdentEncoder = LiteralEncoder.Chr
            };
        }

        // ────────────────────── 查询接口 ──────────────────────

        /// <summary>
        /// 族→fork精确识别探针表（sqlmap fingerprint fork探针同款）：
        /// Family=族宿主库；BannerScalar=banner标量表达式；MatchWord=banner特征词（不区分大小写包含匹配）；ForkName=fork显示名。
        /// Union/报错通道直取banner匹配；布尔盲注通道包成 "{BannerScalar} like '%{MatchWord}%'" 探针判定。
        /// fork化后识别结果一律为族宿主库型+Fork名（取数=族模板+fork overlay差异文件），识别失败保持空Fork名
        /// </summary>
        public static readonly (DBType Family, string BannerScalar, string MatchWord, string ForkName)[] ForkProbes =
        {
            //金仓version()含"KingbaseES V008R006..."；openGauss含"openGauss x.x"；MogDB为openGauss衍生（同缺COPY FROM PROGRAM）
            //瀚高version()含"HighGo"（PostgreSQL衍生，如 "PostgreSQL 12.x (HighGo 4.5.x ...)"）
            (DBType.PostgreSQL, "version()", "KingbaseES", "KingbaseES"),
            (DBType.PostgreSQL, "version()", "openGauss", "openGauss"),
            (DBType.PostgreSQL, "version()", "MogDB", "MogDB"),
            (DBType.PostgreSQL, "version()", "HighGo", "瀚高Highgo"),
            //达梦v$version banner含"DM Database Server"，与Oracle banner（"Oracle Database..."）不冲突
            (DBType.Oracle, "(select banner from v$version where rownum=1)", "DM Database", "DM"),
        };

        /// <summary>fork名归一化键→显示名（banner匹配/Fork下拉/文件名解析共用；未登记的首字母大写兜底）</summary>
        public static readonly IReadOnlyDictionary<string, string> ForkDisplayNames =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["mariadb"] = "MariaDB", ["percona"] = "Percona", ["drizzle"] = "Drizzle",
                ["tidb"] = "TiDB", ["doris"] = "Doris", ["starrocks"] = "StarRocks", ["memsql"] = "SingleStore",
                ["oceanbase"] = "OceanBase", ["tdsql"] = "TDSQL", ["goldendb"] = "GoldenDB", ["polardb"] = "PolarDB",
                ["cockroachdb"] = "CockroachDB", ["yugabytedb"] = "YugabyteDB", ["cratedb"] = "CrateDB",
                ["gaussdb"] = "GaussDB", ["mogdb"] = "MogDB", ["highgo"] = "瀚高Highgo", ["vastbase"] = "Vastbase",
                ["kingbasees"] = "KingbaseES", ["opengauss"] = "openGauss", ["dmdatabase"] = "DM"
            };

        /// <summary>fork显示名→归一化键（fork overlay文件名=fork_&lt;键&gt;.txt；优先反查显示名注册表，未登记按归一化兜底）</summary>
        public static string ForkKeyOf(string forkDisplayName)
        {
            foreach (KeyValuePair<string, string> kv in ForkDisplayNames)
            {
                if (kv.Value.Equals(forkDisplayName, StringComparison.OrdinalIgnoreCase))
                {
                    return kv.Key;
                }
            }
            return NormName(forkDisplayName ?? "");
        }

        /// <summary>
        /// fork化归一：forkMode库（金仓/openGauss/达梦）归一到族宿主库型+Fork显示名；其余返回自身+空串。
        /// 识别结果落配置/记录/上下文前统一过此方法，保证取数只按族库型+fork overlay
        /// </summary>
        public static (DBType Family, string ForkName) ToFamilyFork(DBType dbType)
        {
            DbProfile p = Get(dbType);
            if (p.ForkMode && p.CompatDb != dbType && p.CompatDb != DBType.UnKnow)
            {
                return (p.CompatDb, p.DbmsName);
            }
            return (dbType, "");
        }

        /// <summary>族的全部fork显示名（forkMode变体的DbmsName + Forks注册的衍生库显示名），Fork下拉选项用</summary>
        public static IReadOnlyList<string> ForkDisplayNamesOf(DBType family)
        {
            List<string> names = new List<string>();
            foreach (DbProfile p in All)
            {
                if (p.ForkMode && p.CompatDb == family)
                {
                    names.Add(p.DbmsName);
                }
            }
            foreach (string f in Get(family).Forks)
            {
                if (ForkDisplayNames.TryGetValue(f, out string? display) && !names.Contains(display))
                {
                    names.Add(display);
                }
            }
            return names;
        }

        private static readonly Dictionary<DBType, DbProfile> ByType = All.ToDictionary(p => p.DbType);

        /// <summary>fork/衍生库名（归一化后）→ 宿主库类型，由注册表Forks自动汇总</summary>
        public static readonly IReadOnlyDictionary<string, DBType> ForkMap = BuildForkMap();

        private static Dictionary<string, DBType> BuildForkMap()
        {
            Dictionary<string, DBType> map = new Dictionary<string, DBType>();
            foreach (DbProfile p in All)
            {
                foreach (string f in p.Forks)
                {
                    map[f] = p.DbType;
                }
            }
            return map;
        }

        /// <summary>取数据库档案；未知类型回落MySQL档案（与历史默认行为一致）</summary>
        public static DbProfile Get(DBType dbType)
        {
            return ByType.TryGetValue(dbType, out DbProfile? p) ? p : ByType[DBType.MySQL];
        }

        /// <summary>DBType → DBMS名称</summary>
        public static string DbmsNameOf(DBType dbType)
        {
            return Get(dbType).DbmsName;
        }

        /// <summary>检测语法兼容族（达梦→Oracle、金仓/openGauss→PG，其余为自身）</summary>
        public static DBType CompatOf(DBType dbType)
        {
            return Get(dbType).CompatDb;
        }

        /// <summary>族的衍生/变体库清单（CompatDb=族且非族宿主本身，如PostgreSQL族→Kingbase/OpenGauss）</summary>
        public static IReadOnlyList<DBType> VariantsOf(DBType family)
        {
            return All.Where(p => p.CompatDb == family && p.DbType != family).Select(p => p.DbType).ToList();
        }

        /// <summary>族宿主库的版本banner标量表达式（Fork识别探针用；null=该族无banner可探）</summary>
        public static string? BannerScalarOf(DBType family)
        {
            return family switch
            {
                DBType.MySQL or DBType.PostgreSQL => "version()",
                DBType.SQLServer => "@@version",
                DBType.Oracle => "(select banner from v$version where rownum=1)",
                _ => null
            };
        }

        /// <summary>取数模板文件相对路径</summary>
        public static string TemplatePathOf(DBType dbType)
        {
            return Get(dbType).TemplatePath;
        }

        /// <summary>环境变量词表相对路径（/config/vers/xx.txt）；null=该库不支持环境变量读取</summary>
        public static string? VersPathOf(DBType dbType)
        {
            string? f = Get(dbType).VersFile;
            return f == null ? null : "/config/vers/" + f;
        }

        /// <summary>取数方言选项（每次新建实例，调用方可安全修改）</summary>
        public static DialectOptions OptionsFor(DBType dbType)
        {
            return Get(dbType).CreateOptions();
        }

        /// <summary>DBMS名称归一化：仅留小写字母数字（"Microsoft SQL Server"→"microsoftsqlserver"）</summary>
        public static string NormName(string name)
        {
            return Regex.Replace(name ?? "", "[^a-z0-9]", "", RegexOptions.IgnoreCase).ToLowerInvariant();
        }

        /// <summary>
        /// DBMS名称 → 数据库类型：fork/衍生库精确映射优先（如mariadb→MySQL，防止包含匹配落空或错配），
        /// 其后按归一化名称双向包含匹配（兼容"Microsoft SQL Server"与"SQLServer"等写法）
        /// </summary>
        public static DBType DbTypeForName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                return DBType.UnKnow;
            }
            string n = NormName(name);
            //归一化后过短的名称（如中文文件名被剥成"2"）不参与包含匹配，避免"db2".Contains("2")式误判
            if (n.Length < 2)
            {
                return DBType.UnKnow;
            }
            if (ForkMap.TryGetValue(n, out DBType fork))
            {
                return fork;
            }
            foreach (DbProfile p in All)
            {
                string m = NormName(p.DbmsName);
                if (n.Contains(m, StringComparison.Ordinal) || m.Contains(n, StringComparison.Ordinal))
                {
                    return p.DbType;
                }
            }
            return DBType.UnKnow;
        }
    }
}
