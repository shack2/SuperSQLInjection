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

        string UnionAll(string paylaod, int sumCount, int showIndex);

        string ConcatData(List<string> columns);

        string GetTableNames(string dbName);

        string GetColumnNames(string dbName, string tableName);

        string GetDBName(int index);

        string GetTableName(string dbName, int index);

        string GetColumnName(string dbName, string tableName, int index);

        string GetTableCount(string dbName);

        string GetColumnCount(string dbName, string tableName);

        string GetDataCount(string dbName, string tableName, string where = "");
    }
}
