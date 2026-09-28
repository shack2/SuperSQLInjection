using SuperSQLInjectionV2.Payload;
using SuperSQLInjectionV2.Tools;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace SuperSQLInjectionV2.Models;

/// <summary>
/// 各数据库注入通道能力表（模板声明驱动 + 缓存）。
/// 报错通道能力 = 模板是否配置 ErrorData 行（报错注入的本质是"数据库把表达式求值结果带进错误消息"，
/// SQLite/HSQLDB/DB2/DM/Access/Informix 等错误机制不携带值，模板不配置该行，任何工具都无法报错取数）；
/// DNS通道能力 = 模板 DnsChannel 行声明（yes/no）。
/// UnKnow 回退 MySQL 模板（未识别时全量展示，交由用户判断）。
/// </summary>
public static class DbCapabilities
{
    private static readonly ConcurrentDictionary<DBType, (bool Error, bool Dns)> Cache = new();

    private static (bool Error, bool Dns) Get(DBType db)
    {
        return Cache.GetOrAdd(db, static t =>
        {
            Dictionary<string, string> dict = FileTool.ReadSQLPayload(BasePayload.GetTemplateRelativePath(t));
            bool error = dict.TryGetValue("ErrorData", out string? ed) && !string.IsNullOrWhiteSpace(ed);
            bool dns = dict.TryGetValue("DnsChannel", out string? dc)
                && string.Equals(dc.Trim(), "yes", System.StringComparison.OrdinalIgnoreCase);
            return (error, dns);
        });
    }

    /// <summary>
    /// 报错注入通道是否可用（错误消息会回显表达式求值结果）。
    /// 实测可用：MySQL(updatexml等)、SQLServer(convert回显)、Oracle(xmltype/utl_inaddr等)、
    /// PostgreSQL系(cast回显)、H2(cast as int回显)、ClickHouse(toInt32解析失败回显原串，需套标量子查询)。
    /// 不可用：SQLite(cast永不报错)、HSQLDB/DB2(cast报错不回显值)、DM(utl_inaddr报错不回显值)、
    /// Access(类型不匹配报错不回显值)、Informix(报错不回显值)。
    /// </summary>
    public static bool HasErrorChannel(DBType db) => Get(db).Error;

    /// <summary>
    /// DNS外带通道是否可用（DB自身能触发DNS解析把数据带出）。
    /// 可用：MySQL(load_file，Windows目标)、Oracle/达梦(utl_inaddr)、PostgreSQL/Kingbase(dblink)、
    /// SQLServer(xp_dirtree，堆叠)。
    /// </summary>
    public static bool HasDnsChannel(DBType db) => Get(db).Dns;
}
