using System.Collections.Generic;

namespace SuperSQLInjectionV2.Payload
{
    /// <summary>
    /// 数据库方言抽象：所有取数SQL拼接的统一入口。
    /// 原 14 个 PaylaodTool 实现已合并为单一的 <see cref="TemplateDialect"/>（模板驱动 + DialectOptions 方言开关），
    /// 新接入数据库只需提供 config/payload/xx.txt 模板并在 <see cref="DialectFactory"/> 登记方言选项。
    /// </summary>
    public interface IDbDialect
    {
        /// <summary>当前方言绑定的取数模板</summary>
        BasePayload Payload { get; }

        string ErrorData(DumpDataParam dataParam);

        string ErrorDataSubstr(string paylaod, int start, int end);

        string ErrorData(string payload);

        string DataLen(string payload);

        string CheckBoolData(string payload, int checkValue);

        string BoolDataValue(string payload, int index);

        string DataCount(DumpDataParam dp);

        string DataValue(DumpDataParam dp);

        string UnionData(DumpDataParam dp);

        string UnionAll(string paylaod, int sumCount, int showIndex, string unionFill = "");

        string ConcatData(List<string> columns);

        string GetTableNames(string dbName);

        string GetColumnNames(string dbName, string tableName);

        string GetDBName(int index);

        string GetTableName(string dbName, int index);

        string GetColumnName(string dbName, string tableName, int index);

        string GetTableCount(string dbName);

        string GetColumnCount(string dbName, string tableName);

        string GetDataCount(string dbName, string tableName, string where = "");

        /// <summary>
        /// MIN 值链分页（Access 专用）：Jet 标量子查询中 TOP+ORDER BY 对重复值按并列全部返回，
        /// 触发 "At most one record can be returned by this subquery"，行索引分页不可用（实测）；
        /// 改用 sqlmap 风格 MIN(col)>last 值链，逐列顺序取回 distinct 值
        /// </summary>
        bool MinValueChainPaging { get; }

        /// <summary>MIN 值链取数表达式：lastValue=null 取首值（无链条件），否则取 &gt;lastValue 的最小值</summary>
        string DataValueChain(DumpDataParam dp, string? lastValue);

        /// <summary>distinct 计数（MIN 值链的行数口径，与 DataValueChain 的去重语义一致）</summary>
        string DataCountDistinct(DumpDataParam dp);
    }
}
