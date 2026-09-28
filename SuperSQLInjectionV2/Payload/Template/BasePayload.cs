using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Tools;
using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Linq;
using System.Runtime.Intrinsics.Arm;
using System.Text;
using System.Xml.Linq;

namespace SuperSQLInjectionV2.Payload
{
    public class BasePayload
    {
        public Dictionary<string, string> PayLoadSQL { get; } =new();

        /// <summary>
        /// 取数模板文件相对路径（供UI模板管理与加载共用，保证一致）
        /// </summary>
        public static string GetTemplateRelativePath(DBType dBType)
        {
            return dBType switch
            {
                DBType.MySQL => "config/payload/mysql.txt",
                DBType.SQLServer => "config/payload/sqlserver.txt",
                DBType.PostgreSQL => "config/payload/postgresql.txt",
                DBType.Oracle => "config/payload/oracle.txt",
                DBType.DB2 => "config/payload/db2.txt",
                DBType.Informix => "config/payload/informix.txt",
                DBType.SQLite => "config/payload/sqlite.txt",
                DBType.Access => "config/payload/access.txt",
                DBType.DM => "config/payload/dm.txt",
                DBType.Kingbase => "config/payload/kingbase.txt",
                DBType.OpenGauss => "config/payload/opengauss.txt",
                DBType.H2 => "config/payload/h2.txt",
                DBType.HSQLDB => "config/payload/hsqldb.txt",
                DBType.ClickHouse => "config/payload/clickhouse.txt",
                _ => "config/payload/mysql.txt"
            };
        }

        /// <summary>
        /// 取数逻辑必需的模板key（缺失会导致取数异常，UI保存时据此校验提示）
        /// </summary>
        public static readonly string[] RequiredKeys = new string[]
        {
            "DBNames","TableNames","ColumnNames","DBName","TableName","ColumnName",
            "DBCount","TableCount","ColumnCount","DataCount",
            "DataStartStr","DataEndStr","DataSplitStr","UnionFillStr",
            "BoolData","Cast","Hex","Ascii","Substr","Length",
            "IfNull","Concat","UnionAll","DataValue","UnionData"
        };

        /// <summary>
        /// 模板key用途描述（key不区分大小写；未登记的key视为自定义/扩展项）。
        /// 占位符为命名风格（见 TemplateRenderer 词汇表）：expr/start/len/value/cond/sleep/alias/
        /// cols/db/table/rowIndex/where/batchSize/fill/index/split/startMark/endMark
        /// </summary>
        public static readonly Dictionary<string, string> KeyDescriptions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            //库表列枚举
            ["DBCount"] = "库数量查询（无占位符），枚举数据库前先取总数",
            ["DBName"] = "按序号取库名，{index}=库索引（limit {index},1）",
            ["DBNames"] = "一次性聚合取全部库名（Union/报错通道用，如group_concat）",
            ["TableCount"] = "表数量查询，{db}=库名（按方言编码）",
            ["TableName"] = "按序号取表名，{db}=库名 {index}=表索引",
            ["TableNames"] = "一次性聚合取某库全部表名，{db}=库名",
            ["ColumnCount"] = "列数量查询，{db}=库名 {table}=表名（均按方言编码）",
            ["ColumnName"] = "按序号取列名，{db}=库名 {table}=表名 {index}=列索引",
            ["ColumnNames"] = "一次性聚合取某表全部列名，{db}=库名 {table}=表名",
            //数据读取
            ["DataCount"] = "数据行数查询，{db}=库名 {table}=表名 {where}=where过滤片段",
            ["DataValue"] = "单行取数标量子查询（盲注/报错通道），{cols}=列列表 {db}=库名 {table}=表名 {rowIndex}=行索引 {where}=where过滤",
            ["UnionData"] = "Union取数内层SELECT，{cols}=填充后列串 {db}=库名 {table}=表名 {rowIndex}=行索引 {where}=where过滤",
            ["UnionDataRows"] = "Union批量取数（可选）：聚合函数把多行拼成单行一次回显，{cols}=行表达式 {db}=库名 {table}=表名 {rowIndex}=起始行索引(0基) {where}=where过滤 {batchSize}=批量行数 {fill}=外层填充列串(数据位为聚合别名sqli_agg)",
            ["UnionAll"] = "Union整体包装语句，{cols}=填充后列串（union all select ...）",
            ["UnionFillStr"] = "Union列占位填充值（如NULL），用于凑齐列数并把数据放到回显列",
            //回显定位与拼接
            ["DataStartStr"] = "数据起始标记，包裹取数结果用于从响应中正则定位边界",
            ["DataEndStr"] = "数据结束标记，与起始标记配对定位",
            ["DataSplitStr"] = "多列数据分隔符，取回后按它拆分各列值",
            ["Concat"] = "多列拼接函数模板，{split}=分隔符字面量 {startMark}=起始标记字面量 {cols}=列串 {endMark}=结束标记字面量（字面量按方言编码）",
            //盲注逐位函数
            ["Substr"] = "截子串函数，{expr}=表达式 {start}=起始位置 {len}=长度（盲注逐位取字符）",
            ["Ascii"] = "取字符编码值函数，{expr}=表达式（布尔/时间盲注按码值比较）",
            ["Length"] = "取长度函数，{expr}=表达式（盲注先取数据长度）",
            ["Cast"] = "类型转换包装，{expr}=表达式（Union取数统一列类型，防类型不一致报错）",
            ["IfNull"] = "空值替换包装，{expr}=表达式（避免NULL导致拼接结果整体为空）",
            ["Hex"] = "hex编码包装，{expr}=表达式（盲注hex通道取数、文件读取load_file等）",
            //注入通道触发
            ["BoolData"] = "布尔盲注判断表达式，{expr}=值表达式 {value}=比较值（如{expr}>{value}，按页面真假差异判定）",
            ["ErrorData"] = "报错注入触发函数，{cols}=拼接后的数据表达式（如updatexml/extractvalue；MySQL8下floor(rand)已失效）",
            //报错方式变体（报错方式下拉可切换，替代ErrorData作为触发函数；应对MySQL 8 floor(rand)失效等场景）
            ["ErrorData@UpdateXml"] = "报错变体-UpdateXml：MySQL 5.5+通用，{cols}=拼接后的数据表达式，回显长度约32字符",
            ["ErrorData@ExtractValue"] = "报错变体-ExtractValue：MySQL 5.1+可用，{cols}=拼接后的数据表达式，回显长度约64字符",
            ["ErrorData@FloorRand"] = "报错变体-FloorRand：floor(rand(0)*2)双查询报错，仅MySQL 5.x有效，MySQL 8已失效",
            ["ErrorData@GtidSubset"] = "报错变体-GtidSubset：GTID_SUBSET触发报错，MySQL 5.6+（需GTID开启），{cols}=拼接后的数据表达式",
            ["SleepBoolData"] = "时间盲注延迟判断（可选），{cond}=条件 {sleep}=延迟秒数 {alias}=别名；部分库不支持可为空",
            ["ErrorChunkLen"] = "报错回显单片净数据长度（可选，默认0=不分片）。报错回显有长度上限时（如MySQL updatexml约32字符含标记），超长数据按此步长分片取回再拼接",
            //通道能力与盲注策略声明
            ["BlindStrategy"] = "盲注读取策略声明：ord=MySQL字节打包值 unicode=SQLServer unicode() unicodechar=按字符读码值(Access/HSQLDB) codepoint=真码点(PG系/SQLite/H2) hex=hex编码兜底",
            ["DnsChannel"] = "DNS外带通道声明：yes=DB自身能触发DNS解析把数据带出（MySQL load_file/Oracle utl_inaddr/PG dblink/SQLServer xp_dirtree），no或不写=不支持",
            //字典猜解（Access无元数据默认走此链路，其他库低权限点可手动开启）
            ["exists_table"] = "表存在性判断（字典猜解表名），{table}=候选表名",
            ["exists_column"] = "列存在性判断（字典猜解字段名），{cols}=候选列名 {table}=表名",
            //命令执行（堆叠注入：SQLServer xp_cmdshell / PostgreSQL COPY FROM PROGRAM，输出落临时表ssqlinjection再取回）
            ["CmdExec"] = "命令执行堆叠payload（建临时表执行命令并把输出写入），{cmd}=命令（SQLServer为hex形式0x..，PG为明文字符串）",
            ["CmdData"] = "按行取命令输出，{index}=行序号",
            ["CmdDataCount"] = "命令输出行数查询",
            ["CmdCreateTable"] = "建临时表ssqlinjection（PG命令执行/文件读写的准备工作）",
            ["CmdDropTable"] = "删除临时表ssqlinjection（清理痕迹）",
            //文件读写（堆叠注入）
            ["FileReadFso"] = "SQLServer FileSystemObject读文件（OLE Automation），{path}=文件路径",
            ["FileReadBulk"] = "SQLServer BULK INSERT读文件（Windows/Linux通用，需sysadmin或bulkadmin），{path}=文件路径",
            ["FileReadCopy"] = "PostgreSQL COPY FROM读文件（需superuser或pg_read_server_files），{path}=文件路径",
            ["FileWriteFso"] = "SQLServer FileSystemObject写文件（OLE Automation），{data}=内容hex {path}=文件路径",
            ["FileWriteWebTask"] = "SQLServer sp_makewebtask写文件，{data}=内容hex {path}=文件路径",
            ["FileWriteBackup"] = "SQLServer 备份写文件（先建库表写内容再backup到目标路径），{data}=内容hex {path}=备份路径声明",
            ["FileWriteCopy"] = "PostgreSQL COPY TO写文件（需superuser或pg_write_server_files），{path}=文件路径",
            ["FileInsertLine"] = "PostgreSQL 逐行写入临时表（写文件前把内容行插入ssqlinjection），{content}=单行内容",
            ["FileBackupCreateDb"] = "SQLServer 备份写文件准备：建库ssqlinjection",
            ["FileBackupCreateTable"] = "SQLServer 备份写文件准备：建表[ssqlinjection]..[data]",
            ["FileBackupDrop"] = "SQLServer 备份写文件清理：删表删库",
            ["FileContent"] = "读文件结果聚合标量（临时表内容拼成单值，盲注/Union/报错三通道取数）",
            ["FileContentCount"] = "读文件临时表行数查询（PG按行取回用）",
            ["FileContentData"] = "读文件按行取回，{index}=行序号",
            ["NocastUnicodeValue"] = "SQLServer unicode盲注取单字符码值（不套cast，unicode通道逐字符二分），{data}=表达式 {index}=字符位置(1基)",
        };

        /// <summary>
        /// 获取模板key的用途描述，未登记的key返回扩展项说明
        /// </summary>
        public static string GetKeyDescription(string key)
        {
            if (!string.IsNullOrWhiteSpace(key) && KeyDescriptions.TryGetValue(key.Trim(), out string? desc))
            {
                return desc;
            }
            if (!string.IsNullOrWhiteSpace(key) && key.Trim().StartsWith(ErrorVariantPrefix, StringComparison.OrdinalIgnoreCase))
            {
                return $"报错注入方式变体[{key.Trim().Substring(ErrorVariantPrefix.Length)}]：报错方式下拉可选中本项替代ErrorData作为报错触发函数，{{cols}}=拼接后的数据表达式";
            }
            return "自定义/扩展项（当前取数代码未直接引用，可通过Get(key)方式在扩展逻辑中使用）";
        }

        public BasePayload(DBType dBType) {
            string configPath = GetTemplateRelativePath(dBType);
            PayLoadSQL=FileTool.ReadSQLPayload(configPath);
            DBNames = PayLoadSQL["DBNames"];
            TableNames = PayLoadSQL["TableNames"];
            ColumnNames= PayLoadSQL["ColumnNames"];
            DBName = PayLoadSQL["DBName"];
            TableName = PayLoadSQL["TableName"];
            ColumnName = PayLoadSQL["ColumnName"];
            DBCount = PayLoadSQL["DBCount"];
            TableCount = PayLoadSQL["TableCount"];
            ColumnCount = PayLoadSQL["ColumnCount"];
            DataCount = PayLoadSQL["DataCount"];
            DataStartStr = PayLoadSQL["DataStartStr"];
            DataEndStr = PayLoadSQL["DataEndStr"];
            DataSplitStr = PayLoadSQL["DataSplitStr"];
            UnionFillStr = PayLoadSQL["UnionFillStr"];
            BoolData = PayLoadSQL["BoolData"];
            //报错注入触发函数（可选）：SQLite cast不报错、HSQLDB/DB2/DM/Access报错不回显值，
            //这些库模板不含ErrorData行，缺失时置空（UI会隐藏报错通道）
            PayLoadSQL.TryGetValue("ErrorData", out string? errorData);
            ErrorData = errorData ?? "";
            Cast = PayLoadSQL["Cast"];
            Hex = PayLoadSQL["Hex"];
            Ascii = PayLoadSQL["Ascii"];
            Substr = PayLoadSQL["Substr"];
            Length = PayLoadSQL["Length"];
            IFNull = PayLoadSQL["IfNull"];
            Concat = PayLoadSQL["Concat"];
            UnionAll= PayLoadSQL["UnionAll"];
            DataValue = PayLoadSQL["DataValue"];
            UnionData = PayLoadSQL["UnionData"];
            //Union批量取数模板（可选）：聚合函数多行拼单行，缺失时取数侧自动回退逐行
            PayLoadSQL.TryGetValue("UnionDataRows", out string? unionDataRows);
            UnionDataRows = unionDataRows ?? "";
            //延时盲注payload模板，仅部分数据库支持，不存在时置空
            PayLoadSQL.TryGetValue("SleepBoolData", out string? sleepBoolData);
            SleepBoolData = sleepBoolData ?? "";
            //报错回显单片净数据长度（可选），>0时超长报错数据自动分片拼接
            if (PayLoadSQL.TryGetValue("ErrorChunkLen", out string? chunkLenStr) && int.TryParse(chunkLenStr, out int chunkLen))
            {
                ErrorChunkLen = chunkLen;
            }
            //盲注读取策略声明（可选）：ord/unicode/unicodechar/codepoint/hex，
            //未声明时回退：无Hex函数的库按字符读码值（unicodechar），其余hex（多字节安全兜底）
            if (PayLoadSQL.TryGetValue("BlindStrategy", out string? blindStrategy))
            {
                BlindStrategy = (blindStrategy ?? "").Trim().ToLowerInvariant();
            }
            if (string.IsNullOrEmpty(BlindStrategy))
            {
                BlindStrategy = string.IsNullOrEmpty(Hex) ? "unicodechar" : "hex";
            }
            //DNS外带通道声明（可选）：yes=DB自身能触发DNS解析把数据带出
            if (PayLoadSQL.TryGetValue("DnsChannel", out string? dnsChannel))
            {
                DnsChannel = string.Equals((dnsChannel ?? "").Trim(), "yes", StringComparison.OrdinalIgnoreCase);
            }
            //报错方式变体：模板中 ErrorData@方法名 形式的扩展行（如ErrorData@UpdateXml），供报错方式下拉实时切换
            ErrorDataDefault = ErrorData;
            foreach (var kv in PayLoadSQL)
            {
                if (kv.Key.StartsWith(ErrorVariantPrefix, StringComparison.OrdinalIgnoreCase) && kv.Key.Length > ErrorVariantPrefix.Length)
                {
                    ErrorDataVariants[kv.Key.Substring(ErrorVariantPrefix.Length)] = kv.Value;
                }
            }
        }

        /// <summary>报错方式变体key前缀（模板行：ErrorData@方法名:触发函数模板）</summary>
        public const string ErrorVariantPrefix = "ErrorData@";

        /// <summary>报错方式下拉中的默认项名称（=模板ErrorData key）</summary>
        public const string DefaultErrorMethodName = "默认";

        /// <summary>模板ErrorData key原始值，切换报错方式时用于恢复默认</summary>
        public string ErrorDataDefault { get; private set; } = "";

        /// <summary>报错方式变体：方法名→报错触发函数模板（来自模板文件 ErrorData@方法名 行）</summary>
        public Dictionary<string, string> ErrorDataVariants { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// 切换报错方式：空/默认恢复ErrorData key，否则使用对应变体替换ErrorData；返回是否命中
        /// </summary>
        public bool SetErrorMethod(string? method)
        {
            if (string.IsNullOrWhiteSpace(method) || method.Equals(DefaultErrorMethodName, StringComparison.OrdinalIgnoreCase))
            {
                ErrorData = ErrorDataDefault;
                return true;
            }
            if (ErrorDataVariants.TryGetValue(method, out string? variant))
            {
                ErrorData = variant;
                return true;
            }
            return false;
        }

        public string Get(string key)
        {
            return PayLoadSQL[key];
        }
        public string DBNames { get; set; } = "";

        public string TableNames { get; set; } = "";

        public string ColumnNames { get; set; } = "";

        public string DBName { get; set; } = "";

        public string TableName { get; set; } = "";

        public string ColumnName { get; set; } = "";

        public string DBCount { get; set; } = "";

        public string TableCount { get; set; } = "";

        public string ColumnCount { get; set; } = "";
        public string DataCount { get; set; } = "";

        public string DataStartStr { get; set; } = "";

        public string DataEndStr { get; set; } = "";

        public string DataSplitStr { get; set; } = "";

        public string UnionFillStr { get; set; } = "";

        public string BoolData { get; set; } = "";

        public string ErrorData { get; set; } = "";

        public string UnionAll { get; set; } = "";
        public string UnionData { get; set; } = "";

        /// <summary>
        /// Union批量取数模板（可选）：聚合函数（group_concat/string_agg/LISTAGG/FOR XML）把rowCount行拼成单行一次回显，
        /// 每行自带起始/结束标记，客户端按标记切块还原行；为空表示该库未配置批量模板，取数侧回退逐行
        /// </summary>
        public string UnionDataRows { get; set; } = "";

        /// <summary>
        /// 延时盲注payload模板，{0}=条件，{1}=延时秒数，{2}=随机字符串，仅MySQL/SQLServer/PostgreSQL/Informix支持
        /// </summary>
        public string SleepBoolData { get; set; } = "";

        /// <summary>
        /// 报错回显单片净数据长度（不含标记），>0时超长报错数据自动分片取回拼接；0=不分片（模板key：ErrorChunkLen）
        /// </summary>
        public int ErrorChunkLen { get; set; } = 0;
        
        /// <summary>
        /// 盲注读取策略（模板 BlindStrategy 行声明）：ord=MySQL字节打包 unicode=SQLServer unicode
        /// unicodechar=按字符读码值（Access/HSQLDB） codepoint=真码点（PG系/SQLite/H2） hex=hex编码兜底
        /// </summary>
        public string BlindStrategy { get; set; } = "";

        /// <summary>DNS外带通道是否可用（模板 DnsChannel 行声明：yes/no）</summary>
        public bool DnsChannel { get; set; }

        public string Cast { get; set; } = "";

        public string Hex { get; set; } = "";
        public string Ascii { get; set; } = "";

        public string Substr { get; set; } = "";
        public string Length { get; set; } = "";

        public string IFNull { get; set; } = "";

        public string Concat { get; set; } = "";
        public string DataValue { get; set; } = "";

    }
}
