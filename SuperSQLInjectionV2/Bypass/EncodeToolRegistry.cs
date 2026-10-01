using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Tools;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SuperSQLInjectionV2.Bypass
{
    /// <summary>编码工具条目（JS实现，QuickJS池化执行）</summary>
    public sealed class EncodeTool
    {
        /// <summary>唯一键（=磁盘脚本文件名主干 scripts/&lt;key&gt;.js，与sqlmap tamper同名）</summary>
        public required string Key { get; init; }
        /// <summary>显示名（英文键名兜底；中文名以磁盘脚本 //@name 为准，经CnNames运行时缓存解析，见DisplayName）</summary>
        public required string Name { get; init; }
        /// <summary>功能说明</summary>
        public required string Description { get; init; }
        /// <summary>JS实现（function tamper(payload)），磁盘脚本缺失时的内嵌兜底，经ScriptTamperEngine池化执行</summary>
        public required string JsCode { get; init; }
        /// <summary>作用域（payload级/请求报文级）</summary>
        public ScriptScope Scope { get; init; } = ScriptScope.Payload;

        /// <summary>运行时显示名：CnNames（磁盘脚本 //@name 解析缓存）优先，未收录按Name/Key显示</summary>
        public string DisplayName => EncodeToolRegistry.CnName(Key);
    }

    /// <summary>
    /// 编码工具注册表（sqlmap tamper对齐的JS实现内嵌兜底，见BuiltinTampers）：
    /// 事实源为磁盘脚本 config/rules/scripts/&lt;key&gt;.js（可见可改可删，一脚本一文件），
    /// 注册表仅在脚本文件缺失时补写/兜底执行；独有能力（urlencode/hex/altcase/unicode/includecomment）
    /// 已迁移为纯磁盘脚本（SeedScripts种子），不在注册表内。
    /// </summary>
    public static class EncodeToolRegistry
    {
        /// <summary>
        /// tamper中文显示名运行时缓存（初始为空；RuleStore 解析磁盘脚本 //@name 头时逐项填充，
        /// 事实源为磁盘脚本元数据，代码不写死）。Key/磁盘文件名保持sqlmap原名不变；未收录的按注册表Name/Key显示。
        /// </summary>
        private static readonly Dictionary<string, string> CnNames = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>登记磁盘脚本解析出的显示名（RuleStore 读取 //@name 时调用；空名忽略，已存在则刷新）</summary>
        public static void RegisterCnName(string key, string? name)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                return;
            }
            lock (CnNames)
            {
                CnNames[key] = name;
            }
        }

        /// <summary>显示名解析：CnNames磁盘缓存 → 注册表Name → Key</summary>
        public static string CnName(string key)
        {
            lock (CnNames)
            {
                if (CnNames.TryGetValue(key, out string? cn))
                {
                    return cn;
                }
            }
            return All.TryGetValue(key, out EncodeTool? t) ? t.Name : key;
        }

        public static IReadOnlyDictionary<string, EncodeTool> All { get; } = Build();

        public static bool TryGet(string key, out EncodeTool tool)
        {
            return All.TryGetValue(key ?? "()", out tool!);
        }

        /// <summary>
        /// 按Key/Name启用或停用编码链脚本：列表中不存在且为启用操作时，按磁盘脚本（注册表兜底）补建
        /// （追加到列表末尾，对base64encode这类必须链尾执行的工具天然有序）。已处于目标状态时不动。
        /// 返回本次是否发生了状态变更（检测期临时启用的调用方据此决定是否需要还原）。
        /// </summary>
        public static bool SetEnabled(AppConfig config, string key, bool enable, string? logReason = null)
        {
            EncodeToolModel? item = config.ByPassConfig.EncodeTools.FirstOrDefault(s =>
                string.Equals(s.Key, key, StringComparison.OrdinalIgnoreCase)
                || string.Equals(s.Name, key, StringComparison.OrdinalIgnoreCase));
            if (item == null && enable)
            {
                item = RuleStore.LoadToolByKey(key);
                if (item != null)
                {
                    config.ByPassConfig.EncodeTools.Add(item);
                }
            }
            if (item == null || item.Enable == enable)
            {
                return false;
            }
            item.Enable = enable;
            if (enable && !string.IsNullOrEmpty(logReason))
            {
                Log.Show(logReason);
            }
            return true;
        }

        private static Dictionary<string, EncodeTool> Build()
        {
            var d = new Dictionary<string, EncodeTool>(StringComparer.OrdinalIgnoreCase);
            //注册表Name固定为英文键名（兜底）；中文显示名由磁盘脚本 //@name 解析填充CnNames，经DisplayName呈现
            foreach (var bt in BuiltinTampers.All.Values)
            {
                d[bt.Name] = new EncodeTool { Key = bt.Name, Name = bt.Name, Description = bt.Description, JsCode = bt.JsCode, Scope = bt.Scope };
            }
            return d;
        }
    }
}
