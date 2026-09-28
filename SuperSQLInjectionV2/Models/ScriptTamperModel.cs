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
    /// tamper脚本配置项：约定tamper(payload)函数变换目标文本（Payload级=Encode块内payload，报文级=整份HTTP报文）。
    /// 自定义脚本能力（运行时：QuickJS，NativeAOT兼容）。
    /// Builtin=true时为内置C#实现（BuiltinTampers注册表按Name解析），Code为空、不可编辑。
    /// </summary>
    public partial class ScriptTamperModel : ViewModelBase, ITamperItem
    {
        /// <summary>统一执行视图：动态值脚本无内置注册表键，恒null（内置解析回落Name匹配EncodeToolRegistry）</summary>
        [JsonIgnore]
        string? ITamperItem.Key => null;

        [ObservableProperty]
        public partial string Name { get; set; } = "新tamper脚本";

        [ObservableProperty]
        public partial ScriptLang Lang { get; set; } = ScriptLang.JavaScript;

        /// <summary>脚本内容：function tamper(payload){...}；内置项为空</summary>
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

        /// <summary>内置C#实现标识（BuiltinTampers按Name解析，跳过QuickJS）</summary>
        [ObservableProperty]
        public partial bool Builtin { get; set; } = false;

        /// <summary>动态值脚本类型：0=请求抓取（输入=抓取请求返回的HTTP响应报文），1=自主生成（输入=主请求报文，输出=动态值，API签名等场景）；仅动态值脚本使用，默认0兼容旧配置</summary>
        [ObservableProperty]
        public partial int Kind { get; set; } = 0;

        /// <summary>动态值脚本类型显示名（表格列绑定）</summary>
        [JsonIgnore]
        public string KindName => Kind == 1 ? "自主生成" : "请求抓取";

        partial void OnKindChanged(int value) => OnPropertyChanged(nameof(KindName));

        [JsonIgnore]
        public List<ScriptLang> LangList { get; set; } = Enum.GetValues<ScriptLang>().ToList();

        [JsonIgnore]
        public List<ScriptScope> ScopeList { get; set; } = Enum.GetValues<ScriptScope>().ToList();

        /// <summary>类型展示文本（内置/JS），供表格列绑定</summary>
        [JsonIgnore]
        public string TypeText => Builtin ? "内置" : "JS";

        partial void OnBuiltinChanged(bool value) => OnPropertyChanged(nameof(TypeText));
    }
}
