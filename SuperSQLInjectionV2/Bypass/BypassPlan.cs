using System;
using System.Collections.Generic;
using System.Linq;
using SuperSQLInjectionV2.Models;

namespace SuperSQLInjectionV2.Bypass
{
    /// <summary>
    /// 绕过执行计划（P0-2）：配置修订号键控的编译快照。
    /// 热路径（盲注逐字符高并发发包）不再做 ToList 拷贝/Contains 判定/重复启用过滤，
    /// 配置任何变更都会递增 ByPassConfig.Revision 使旧计划失效重建。
    /// 计划内委托与模型引用均只读使用，并发共享安全。
    /// </summary>
    public sealed class BypassPlan
    {
        /// <summary>Payload级变换步骤（编码工具模型，按列表顺序；统一QuickJS池化执行）</summary>
        public readonly struct PayloadStep
        {
            public PayloadStep(EncodeToolModel js) { Js = js; }
            /// <summary>编码工具项（统一走ScriptTamperEngine的QuickJS池化执行）</summary>
            public EncodeToolModel Js { get; }
        }

        /// <summary>构建时的配置修订号</summary>
        public required long Revision { get; init; }

        /// <summary>替换项步骤（已启用且Src非空，按列表顺序）</summary>
        public required (string Src, string Target)[] ReplaceSteps { get; init; }

        /// <summary>Payload级编码工具步骤（已启用且可执行，按列表顺序）</summary>
        public required PayloadStep[] PayloadSteps { get; init; }

        /// <summary>是否有启用的urlencode工具（决定Encode块是否做兜底URL编码）</summary>
        public required bool HasUrlEncodeItem { get; init; }

        /// <summary>报文级编码工具（已启用且可执行，发送前按序执行）</summary>
        public required EncodeToolModel[] RequestTools { get; init; }

        //---- 传输层（每轮重试执行）----
        public required int DelayMs { get; init; }
        public required int SafeFreq { get; init; }
        public required bool RandomUa { get; init; }
        /// <summary>UA池快照：自定义池非空时为自定义，空数组=用内置池</summary>
        public required string[] CustomUaPool { get; init; }
        public required bool RandomIpEnabled { get; init; }

        public static BypassPlan Build(ByPassConfig bp)
        {
            var payloadSteps = new List<PayloadStep>();
            var requestTools = new List<EncodeToolModel>();
            bool hasUrlEncode = false;
            foreach (EncodeToolModel tool in bp.EncodeTools)
            {
                if (!tool.Enable)
                {
                    continue;
                }
                //解析可执行体：Code非空（磁盘脚本物化）即可执行；空则按Key（兼容Name）须能命中注册表内嵌兜底
                bool executable = !string.IsNullOrWhiteSpace(tool.Code);
                if (!executable)
                {
                    string key = !string.IsNullOrEmpty(tool.Key) ? tool.Key : tool.Name;
                    executable = EncodeToolRegistry.TryGet(key, out _);
                }
                if (!executable)
                {
                    continue;
                }
                if (tool.Scope == ScriptScope.Request)
                {
                    requestTools.Add(tool);
                    continue;
                }
                //urlencode脚本启用时抑制Encode块兜底URL编码（脚本文件名主干/种子重生成名称双兼容）
                if ((string.Equals(tool.Key, "urlencode", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(tool.Name, "urlencode", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(tool.Key, "url编码", StringComparison.OrdinalIgnoreCase)) && tool.Enable)
                {
                    hasUrlEncode = true;
                }
                payloadSteps.Add(new PayloadStep(tool));
            }

            return new BypassPlan
            {
                Revision = bp.Revision,
                ReplaceSteps = bp.ReplaceItems
                    .Where(i => i.Enable && !string.IsNullOrEmpty(i.Src))
                    .Select(i => (i.Src, i.Target ?? ""))
                    .ToArray(),
                PayloadSteps = payloadSteps.ToArray(),
                HasUrlEncodeItem = hasUrlEncode,
                RequestTools = requestTools.ToArray(),
                DelayMs = bp.DelayMs,
                SafeFreq = bp.SafeFreq,
                RandomUa = bp.RandomUa,
                CustomUaPool = bp.AllUaStrings().ToArray(),
                RandomIpEnabled = bp.RandomIpEnabled
            };
        }
    }
}
