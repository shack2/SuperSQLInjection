using CommunityToolkit.Mvvm.ComponentModel;
using SuperSQLInjectionV2.Bypass;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text.Json.Serialization;

namespace SuperSQLInjectionV2.Models
{
    /// <summary>
    /// tamper脚本作用域（枚举值显式固定：按数字持久化，勿复用删除值）：
    /// Payload级=在Encode块内payload上执行（tamper语义）；Request级=在整份HTTP报文上执行（eval语义）
    /// </summary>
    public enum ScriptScope
    {
        [Description("Payload级")] Payload = 0,
        [Description("报文级")] Request = 1
    }

    /// <summary>
    /// 统一脚本库脚本用途（config/rules/scripts/*.js 元数据 //@usage 的语义；持久化值固定，勿复用删除值）：
    /// Payload变换=编码链Encode块内payload变换（tamper语义）；报文变换=整份HTTP报文改写（eval语义）；
    /// 响应提取=动态值-从抓取响应报文提取；值生成=动态值-以主请求报文为输入生成（API签名等场景）
    /// </summary>
    public enum ScriptUsage
    {
        [Description("Payload变换")] PayloadTransform = 0,
        [Description("报文变换")] RequestTransform = 1,
        [Description("响应提取")] ResponseExtract = 2,
        [Description("值生成")] ValueGenerate = 3
    }

    /// <summary>ScriptUsage 与磁盘元数据字符串/旧格式（scope/kind）/内存模型（Scope/Kind）的映射</summary>
    public static class ScriptUsages
    {
        /// <summary>磁盘元数据值（//@usage）</summary>
        public static string ToMeta(ScriptUsage u) => u switch
        {
            ScriptUsage.RequestTransform => "request",
            ScriptUsage.ResponseExtract => "extract",
            ScriptUsage.ValueGenerate => "generate",
            _ => "payload"
        };

        /// <summary>解析统一 usage 元数据；无法识别时按 Payload变换 兜底</summary>
        public static ScriptUsage FromMeta(string? s) => (s ?? "").Trim().ToLowerInvariant() switch
        {
            "request" => ScriptUsage.RequestTransform,
            "extract" => ScriptUsage.ResponseExtract,
            "generate" => ScriptUsage.ValueGenerate,
            _ => ScriptUsage.PayloadTransform
        };

        /// <summary>旧格式推断：tampers 脚本的 //@scope（Payload/Request）</summary>
        public static ScriptUsage FromLegacyScope(string? scope) =>
            "request".Equals(scope, StringComparison.OrdinalIgnoreCase) || "Request".Equals(scope, StringComparison.OrdinalIgnoreCase)
                ? ScriptUsage.RequestTransform : ScriptUsage.PayloadTransform;

        /// <summary>旧格式推断：token-scripts 脚本的 //@kind（0=请求抓取 1=自主生成）</summary>
        public static ScriptUsage FromLegacyKind(int kind) =>
            kind == 1 ? ScriptUsage.ValueGenerate : ScriptUsage.ResponseExtract;

        /// <summary>内存模型映射：编码链 EncodeToolModel.Scope → usage</summary>
        public static ScriptUsage FromScope(ScriptScope scope) =>
            scope == ScriptScope.Request ? ScriptUsage.RequestTransform : ScriptUsage.PayloadTransform;

        /// <summary>内存模型映射：动态值脚本 ScriptTamperModel.Kind → usage</summary>
        public static ScriptUsage FromKind(int kind) => FromLegacyKind(kind);

        /// <summary>usage → 编码链 Scope（仅变换类用法有意义）</summary>
        public static ScriptScope ToScope(ScriptUsage u) =>
            u == ScriptUsage.RequestTransform ? ScriptScope.Request : ScriptScope.Payload;

        /// <summary>usage → 动态值脚本 Kind（仅动态值类用法有意义）</summary>
        public static int ToKind(ScriptUsage u) =>
            u == ScriptUsage.ValueGenerate ? 1 : 0;

        /// <summary>是否编码链变换类用法（payload/request）</summary>
        public static bool IsTransform(ScriptUsage u) => u is ScriptUsage.PayloadTransform or ScriptUsage.RequestTransform;

        /// <summary>用途显示名</summary>
        public static string Name(ScriptUsage u) => u switch
        {
            ScriptUsage.RequestTransform => "报文变换",
            ScriptUsage.ResponseExtract => "响应提取",
            ScriptUsage.ValueGenerate => "值生成",
            _ => "Payload变换"
        };
    }

    /// <summary>
    /// tamper脚本配置项：约定tamper(payload)函数变换目标文本（Payload级=Encode块内payload，报文级=整份HTTP报文）。
    /// JS脚本能力（运行时：QuickJS，NativeAOT兼容），磁盘 scripts/*.js 一脚本一文件。
    /// </summary>
    public partial class ScriptTamperModel : ViewModelBase, ITamperItem
    {
        /// <summary>统一执行视图：动态值脚本无注册表键，恒null（Code为空的兜底解析回落Name匹配EncodeToolRegistry）</summary>
        [JsonIgnore]
        string? ITamperItem.Key => null;

        [ObservableProperty]
        public partial string Name { get; set; } = "新tamper脚本";

        [ObservableProperty]
        public partial ScriptLang Lang { get; set; } = ScriptLang.JavaScript;

        /// <summary>脚本内容：function tamper(payload){...}</summary>
        [ObservableProperty]
        public partial string Code { get; set; } = "";

        [ObservableProperty]
        public partial bool Enable { get; set; } = true;

        /// <summary>TableView行勾选（工具栏"删除选中"批量操作目标；不参与序列化）</summary>
        [JsonIgnore]
        [ObservableProperty]
        public partial bool RowChecked { get; set; } = false;

        /// <summary>作用域：Payload级（默认，Encode块内）/报文级（整份HTTP报文，发送前执行）</summary>
        [ObservableProperty]
        public partial ScriptScope Scope { get; set; } = ScriptScope.Payload;

        /// <summary>动态值脚本类型：0=响应提取（输入=抓取请求返回的HTTP响应报文），1=值生成（输入=主请求报文，输出=动态值，API签名等场景）；仅动态值脚本使用，默认0兼容旧配置</summary>
        [ObservableProperty]
        public partial int Kind { get; set; } = 0;

        /// <summary>动态值脚本类型显示名（表格列绑定）</summary>
        [JsonIgnore]
        public string KindName => Kind == 1 ? "值生成" : "响应提取";

        partial void OnKindChanged(int value) => OnPropertyChanged(nameof(KindName));
    }
}
