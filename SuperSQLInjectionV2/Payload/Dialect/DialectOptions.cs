namespace SuperSQLInjectionV2.Payload
{
    /// <summary>
    /// 字符串字面量/标识符的编码方言（防引号过滤、WAF 绕过）。
    /// 各数据库对字符串字面量的表达能力不同：MySQL 支持 0x 十六进制字面量，
    /// Oracle/PG 系用 chr，SQLServer/SQLite 用 char，Access 用 chr&amp; 拼接，
    /// Informix 无 chr 函数退化为 to_char(数字)，ClickHouse 不支持 0x 字面量只能用单引号。
    /// </summary>
    public enum LiteralEncoder
    {
        /// <summary>原样输出（Informix 库名、ClickHouse 标识符）</summary>
        None,
        /// <summary>0x...（MySQL 系）</summary>
        Hex,
        /// <summary>chr(n)||chr(n)（Oracle/PostgreSQL/HSQLDB/DB2）</summary>
        Chr,
        /// <summary>char(n)||char(n)（SQLite、H2）</summary>
        CharBar,
        /// <summary>char(n)+char(n)（SQLServer）</summary>
        CharPlus,
        /// <summary>chr(n)&amp;chr(n)（Access）</summary>
        ChrAmp,
        /// <summary>to_char(数字)（Informix，无 chr 函数，标记必须是数字）</summary>
        ToChar,
        /// <summary>'原样'（ClickHouse，不支持 0x 字面量）</summary>
        Quote
    }

    /// <summary>
    /// 方言行为开关：<see cref="TemplateDialect"/> 按此配置渲染模板。
    /// 槽位布局差异（模板有无 {db}/{table}/{index} 槽位）由命名占位符模板自身表达，不再需要开关；
    /// 这里只保留模板表达不了的行为差异（字面量编码、索引基数、报错改写）。
    /// </summary>
    public sealed class DialectOptions
    {
        /// <summary>数据标记（DataSplitStr/DataStartStr/DataEndStr）的字面量编码方式</summary>
        public LiteralEncoder MarkerEncoder = LiteralEncoder.Hex;

        /// <summary>列与分隔标记之间的拼接符：","（concat_ws 系）、"||"、"&amp;"、"+"</summary>
        public string ConcatOp = ",";

        /// <summary>列之间是否夹分隔标记：MySQL 用 concat_ws 列间只放 ","；其余库列间放 "拼接符+标记+拼接符"</summary>
        public bool JoinWithMarker;

        /// <summary>单列时套 Cast 模板显式转字符串（SQLServer + 拼接不做隐式转换；ClickHouse 单列需 toString）</summary>
        public bool SingleColumnCast;

        /// <summary>库表枚举时库名/表名参数的编码方式</summary>
        public LiteralEncoder IdentEncoder = LiteralEncoder.Hex;

        /// <summary>枚举时库名转大写（DB2 元数据大写存储）</summary>
        public bool UpperDbName;

        /// <summary>枚举时表名转大写（DB2/H2/HSQLDB 元数据大写存储）</summary>
        public bool UpperTableName;

        /// <summary>枚举时表名加单引号原样输出（Informix）</summary>
        public bool QuoteTableName;

        /// <summary>枚举索引偏移（DB2 的 rownumber/limit 从 1 开始）</summary>
        public int EnumIndexOffset;

        /// <summary>表枚举索引额外偏移（Access 字典猜解从第 1 个候选词开始）</summary>
        public int TableIndexOffset;

        /// <summary>
        /// 逐行取数的行索引偏移：limit/offset/skip 系为 0（0基）；top/rownumber 系为 1
        /// （select top N / sqli_rn=N 的 N 从 1 开始，0基直传会导致首行 top 0 / rn=0 永远取空）
        /// </summary>
        public int DataIndexOffset;

        /// <summary>ErrorData(dp) 走 DataValue 子查询物化（ClickHouse 新分析器惰性求值需要）</summary>
        public bool ErrorViaDataValue;

        /// <summary>报错 payload 派生表改写（ClickHouse：toInt32 必须推进派生表内作用于物化列）</summary>
        public bool DerivedTableError;

        /// <summary>MIN 值链分页（Access：TOP 并列语义导致行索引分页在标量子查询中不可用）</summary>
        public bool MinValueChain;
    }
}
