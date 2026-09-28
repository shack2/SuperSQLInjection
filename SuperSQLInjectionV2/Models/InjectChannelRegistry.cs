using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace SuperSQLInjectionV2.Models
{
    /// <summary>
    /// 注入通道注册表：同目标同参数的多条注入记录（Union/Error/Blind/Time…）集中登记，
    /// 供"取数自动通道升级"查询更快通道（盲注/时间取数前探测同参数Union/Error是否可用）。
    /// GUI注入记录新增/加载时登记，检测引擎命中时也可直接登记。
    /// </summary>
    public static class InjectChannelRegistry
    {
        private static readonly ConcurrentDictionary<string, List<InjectRecord>> _map
            = new ConcurrentDictionary<string, List<InjectRecord>>();

        private static string Key(string? host, int port, string? pname)
        {
            return (host ?? "") + ":" + port + "|" + (pname ?? "");
        }

        public static void Register(string? host, int port, InjectRecord record)
        {
            if (record == null || string.IsNullOrEmpty(record.PName))
            {
                return;
            }
            var list = _map.GetOrAdd(Key(host, port, record.PName), _ => new List<InjectRecord>());
            lock (list)
            {
                list.RemoveAll(r => r.InjectType == record.InjectType && r.BoolInjectType == record.BoolInjectType);
                list.Add(record);
            }
        }

        /// <summary>查同目标同参数的更快通道记录（Union优先，Error次之；排除excludeType）</summary>
        public static InjectRecord? FindFasterChannel(string host, int port, string pname, params InjectType[] excludeTypes)
        {
            if (!_map.TryGetValue(Key(host, port, pname), out List<InjectRecord>? list))
            {
                return null;
            }
            lock (list)
            {
                return list.Where(r => !excludeTypes.Contains(r.InjectType))
                    .OrderByDescending(r => r.InjectType == InjectType.Union ? 2 : r.InjectType == InjectType.Error ? 1 : 0)
                    .FirstOrDefault(r => r.InjectType == InjectType.Union || r.InjectType == InjectType.Error);
            }
        }
    }
}
