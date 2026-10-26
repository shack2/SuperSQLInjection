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

        public static void Register(InjectRecord record, bool isSsl = false)
        {
            if (record == null || string.IsNullOrEmpty(record.PName)) return;
            if (isSsl) record.IsSSL = true;
            string key = TargetFingerprint.ForRecord(record);
            var list = _map.GetOrAdd(key, _ => new List<InjectRecord>());
            lock (list)
            {
                list.RemoveAll(r => r.InjectType == record.InjectType && r.BoolInjectType == record.BoolInjectType);
                list.Add(record);
            }
        }

        /// <summary>查同请求会话、同参数的更快通道记录（Union优先，Error次之）。</summary>
        public static InjectRecord? FindFasterChannel(AppConfig config, string pname, params InjectType[] excludeTypes)
        {
            if (!_map.TryGetValue(TargetFingerprint.ForConfig(config, pname), out List<InjectRecord>? list)) return null;
            lock (list)
            {
                return list.Where(r => !excludeTypes.Contains(r.InjectType))
                    .OrderByDescending(r => r.InjectType == InjectType.Union ? 2 : r.InjectType == InjectType.Error ? 1 : 0)
                    .FirstOrDefault(r => r.InjectType == InjectType.Union || r.InjectType == InjectType.Error);
            }
        }

        /// <summary>查同请求会话、同参数指定类型的通道记录。</summary>
        public static InjectRecord? FindByType(AppConfig config, string? pname, InjectType type)
        {
            if (!_map.TryGetValue(TargetFingerprint.ForConfig(config, pname), out List<InjectRecord>? list)) return null;
            lock (list)
            {
                return list.FirstOrDefault(r => r.InjectType == type);
            }
        }

        /// <summary>目标报文或会话变化后显式清理对应通道缓存。</summary>
        public static void Clear(AppConfig config, string? parameter = null)
        {
            _map.TryRemove(TargetFingerprint.ForConfig(config, parameter), out _);
        }
    }
}
