using SuperSQLInjectionV2.Models;

namespace SuperSQLInjectionV2.Payload
{
    /// <summary>
    /// 方言工厂：DBType → <see cref="DialectOptions"/> 映射。
    /// 选项值逐库 diff 原 PaylaodTool 实现提取，保证合并后行为零变化；
    /// DM 复用 Oracle 方言、Kingbase/OpenGauss 复用 PostgreSQL 方言（SQL 模板仍来自各自 txt）。
    /// </summary>
    public static class DialectFactory
    {
        public static IDbDialect Create(DBType dbType, BasePayload bp)
        {
            return new TemplateDialect(bp, OptionsFor(dbType));
        }

        public static DialectOptions OptionsFor(DBType dbType)
        {
            switch (dbType)
            {
                case DBType.SQLServer:
                    return new DialectOptions
                    {
                        MarkerEncoder = LiteralEncoder.CharPlus,
                        ConcatOp = "+",
                        JoinWithMarker = true,
                        SingleColumnCast = true,
                        //库/表枚举模板（[{db}]..[sysobjects]、object_id('{db}..{table}')）均为标识符/限定名上下文，
                        //不能用默认Hex编码（0x...会被当成字面库名导致枚举为空）
                        IdentEncoder = LiteralEncoder.None,
                        DataIndexOffset = 1
                    };
                case DBType.Oracle:
                case DBType.DM:
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
                case DBType.PostgreSQL:
                case DBType.Kingbase:
                case DBType.OpenGauss:
                    return new DialectOptions
                    {
                        MarkerEncoder = LiteralEncoder.Chr,
                        ConcatOp = "||",
                        JoinWithMarker = true,
                        IdentEncoder = LiteralEncoder.Chr
                    };
                case DBType.DB2:
                    return new DialectOptions
                    {
                        MarkerEncoder = LiteralEncoder.Chr,
                        ConcatOp = "||",
                        JoinWithMarker = true,
                        IdentEncoder = LiteralEncoder.Chr,
                        UpperDbName = true,
                        UpperTableName = true,
                        EnumIndexOffset = 1,
                        DataIndexOffset = 1
                    };
                case DBType.Informix:
                    return new DialectOptions
                    {
                        MarkerEncoder = LiteralEncoder.ToChar,
                        ConcatOp = "||",
                        JoinWithMarker = true,
                        IdentEncoder = LiteralEncoder.None,
                        QuoteTableName = true
                    };
                case DBType.Access:
                    return new DialectOptions
                    {
                        MarkerEncoder = LiteralEncoder.ChrAmp,
                        ConcatOp = "&",
                        JoinWithMarker = true,
                        TableIndexOffset = 1,
                        DataIndexOffset = 1,
                        MinValueChain = true
                    };
                case DBType.SQLite:
                    return new DialectOptions
                    {
                        MarkerEncoder = LiteralEncoder.CharBar,
                        ConcatOp = "||",
                        JoinWithMarker = true,
                        IdentEncoder = LiteralEncoder.CharBar
                    };
                case DBType.H2:
                    return new DialectOptions
                    {
                        MarkerEncoder = LiteralEncoder.CharBar,
                        ConcatOp = "||",
                        JoinWithMarker = true,
                        IdentEncoder = LiteralEncoder.CharBar,
                        UpperTableName = true
                    };
                case DBType.HSQLDB:
                    return new DialectOptions
                    {
                        MarkerEncoder = LiteralEncoder.Chr,
                        ConcatOp = "||",
                        JoinWithMarker = true,
                        IdentEncoder = LiteralEncoder.Chr,
                        UpperTableName = true
                    };
                case DBType.ClickHouse:
                    return new DialectOptions
                    {
                        MarkerEncoder = LiteralEncoder.Quote,
                        ConcatOp = ",",
                        JoinWithMarker = true,
                        SingleColumnCast = true,
                        IdentEncoder = LiteralEncoder.None,
                        ErrorViaDataValue = true,
                        DerivedTableError = true
                    };
                case DBType.MySQL:
                default:
                    //默认 MySQL 方言：0x 字面量、concat_ws 列间只放 ","
                    return new DialectOptions();
            }
        }
    }
}
