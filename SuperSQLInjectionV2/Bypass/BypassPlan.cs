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
        /// <summary>Payload级变换步骤（内置C#委托或自定义JS模型，按列表顺序、DoCount已展开）</summary>
        public readonly struct PayloadStep
        {
            public PayloadStep(Func<string, string> impl) { Impl = impl; Js = null; }
            public PayloadStep(EncodeToolModel js) { Impl = null; Js = js; }
            /// <summary>内置实现（非空时直接调用）</summary>
            public Func<string, string>? Impl { get; }
            /// <summary>自定义JS项（Impl为空时走ScriptTamperEngine）</summary>
            public EncodeToolModel? Js { get; }
        }

        /// <summary>构建时的配置修订号</summary>
        public required long Revision { get; init; }

        /// <summary>替换项步骤（已启用且Src非空，按列表顺序）</summary>
        public required (string Src, string Target)[] ReplaceSteps { get; init; }

        /// <summary>Payload级编码工具步骤（已启用且可执行，按列表顺序，DoCount已展开）</summary>
        public required PayloadStep[] PayloadSteps { get; init; }

        /// <summary>是否有启用的urlencode工具（决定Encode块是否做兜底URL编码）</summary>
        public required bool HasUrlEncodeItem { get; init; }

        /// <summary>报文级编码工具（已启用且可执行，发送前按序执行；不展开DoCount——报文级变换重复执行无意义且副作用大）</summary>
        public required EncodeToolModel[] RequestTools { get; init; }

        //---- 传输层（每轮重试执行）----
        public required int DelayMs { get; init; }
        public required int SafeFreq { get; init; }
        public required bool RandomUa { get; init; }
        /// <summary>UA池快照：自定义池非空时为自定义，空数组=用内置池</summary>
        public required string[] CustomUaPool { get; init; }
        public required bool HppEnabled { get; init; }
        public required bool ChunkedEnabled { get; init; }
        public required bool RandomIpEnabled { get; init; }
        public required bool ParamCaseRandEnabled { get; init; }

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
                //解析可执行体：内置按Key（兼容旧数据按Name），自定义需Code非空
                Func<string, string>? impl = null;
                if (tool.Builtin)
                {
                    string key = !string.IsNullOrEmpty(tool.Key) ? tool.Key : tool.Name;
                    if (EncodeToolRegistry.TryGet(key, out EncodeTool? registered))
                    {
                        impl = registered.Impl;
                    }
                }
                bool executable = impl != null || !string.IsNullOrWhiteSpace(tool.Code);
                if (!executable)
                {
                    continue;
                }
                if (tool.Scope == ScriptScope.Request)
                {
                    requestTools.Add(tool);
                    continue;
                }
                if (string.Equals(tool.Key, "urlencode", StringComparison.OrdinalIgnoreCase) && tool.Enable)
                {
                    hasUrlEncode = true;
                }
                int count = Math.Max(1, tool.DoCount);
                for (int i = 0; i < count; i++)
                {
                    payloadSteps.Add(impl != null ? new PayloadStep(impl) : new PayloadStep(tool));
                }
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
                HppEnabled = bp.HppEnabled,
                ChunkedEnabled = bp.ChunkedEnabled,
                RandomIpEnabled = bp.RandomIpEnabled,
                ParamCaseRandEnabled = bp.ParamCaseRandEnabled
            };
        }
    }
}
