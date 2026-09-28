using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Text;
using System.Text.Json.Serialization;

namespace SuperSQLInjectionV2.Models;

[JsonConverter(typeof(JsonStringEnumConverter<DBType>))]
public enum DBType
{
    [Description("未知")] UnKnow,
    [Description("Access")] Access,
    [Description("MySQL")] MySQL,
    [Description("SQLServer")] SQLServer,
    [Description("Oracle")] Oracle,
    [Description("PostgreSQL")] PostgreSQL,
    [Description("DB2")] DB2,
    [Description("SQLite")] SQLite,
    [Description("Informix")] Informix,
    [Description("达梦DM")] DM,
    [Description("人大金仓KingbaseES")] Kingbase,
    [Description("openGauss")] OpenGauss,
    [Description("H2")] H2,
    [Description("HSQLDB")] HSQLDB,
    [Description("ClickHouse")] ClickHouse
}