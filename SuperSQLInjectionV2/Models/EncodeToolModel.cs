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
    /// 编码工具适用位置（Encode块内细分作用域；枚举值显式固定按数字持久化）：
    /// Any=所有块；QueryOnly=仅编码位（请求行query/URI段/urlencoded体——产出换行/控制符的工具依赖兜底URL编码才合法）；
    /// RawOnly=仅原文位（头/Cookie/JSON/XML/multipart体）
    /// </summary>
    public enum EncodePos
    {
        [Description("全部位置")] Any = 0,
        [Description("仅编码位")] QueryOnly = 1,
        [Description("仅原文位")] RawOnly = 2
    }

    /// <summary>
    /// 统一编码工具配置项（编码处理/tamper合并后的唯一变换链节点）：
    /// 内置项（Builtin=true）按Key从EncodeToolRegistry解析C#实现；自定义项（Builtin=false）为JS脚本（QuickJS执行，
    /// 约定 function tamper(payload){...}）。Scope=Payload级在Encode块内执行，Scope=报文级在整份HTTP报文发送前执行（--eval语义）。
    /// </summary>
    public partial class EncodeToolModel : ViewModelBase, ITamperItem
    {
        /// <summary>显示名</summary>
        [ObservableProperty]
        public partial string Name { get; set; } = "新编码工具";

        /// <summary>内置注册表键（EncodeToolRegistry.Key；自定义项为空）</summary>
        [ObservableProperty]
        public partial string Key { get; set; } = "";

        /// <summary>内置C#实现标识（true=按Key解析注册表，Code为空不可编辑）</summary>
        [ObservableProperty]
        public partial bool Builtin { get; set; } = false;

        /// <summary>自定义JS脚本内容（内置项为空）</summary>
        [ObservableProperty]
        public partial string Code { get; set; } = "";

        /// <summary>作用域：Payload级（默认，Encode块内）/报文级（整份HTTP报文，发送前执行）</summary>
        [ObservableProperty]
        public partial ScriptScope Scope { get; set; } = ScriptScope.Payload;

        /// <summary>适用位置（Payload级内细分）：全部/仅编码位（query/urlencoded体）/仅原文位（头/Cookie/JSON/XML体）；内置项由注册表固定不可改，自定义项可选</summary>
        [ObservableProperty]
        public partial EncodePos ApplyPos { get; set; } = EncodePos.Any;

        /// <summary>执行次数（同一变换连续执行N次，如双重编码场景）</summary>
        [ObservableProperty]
        public partial int DoCount { get; set; } = 1;

        [ObservableProperty]
        public partial bool Enable { get; set; } = true;

        /// <summary>类型展示文本（内置/自定义），供表格列绑定</summary>
        [JsonIgnore]
        public string TypeText => Builtin ? "内置" : "自定义";

        /// <summary>功能描述（内置项取注册表说明，自定义项取代码首行注释）</summary>
        [JsonIgnore]
        public string DescText
        {
            get
            {
                if (Builtin && EncodeToolRegistry.TryGet(Key, out EncodeTool tool))
                {
                    return tool.Description;
                }
                string first = (Code ?? "").TrimStart().Split('\n')[0].Trim();
                return first.StartsWith("//", StringComparison.Ordinal) ? first.TrimStart('/').Trim (): "";
            }
        }

        [JsonIgnore]
        public List<ScriptScope> ScopeList { get; set; } = Enum.GetValues<ScriptScope>().ToList();

        /// <summary>适用位置展示文本：内置项以注册表为准（模型字段对内置项不生效）</summary>
        [JsonIgnore]
        public string PosText
        {
            get
            {
                EncodePos pos = ApplyPos;
                if (Builtin && EncodeToolRegistry.TryGet(Key, out EncodeTool tool))
                {
                    pos = tool.Pos;
                }
                return pos switch
                {
                    EncodePos.QueryOnly => "仅编码位",
                    EncodePos.RawOnly => "仅原文位",
                    _ => "全部位置"
                };
            }
        }

        [JsonIgnore]
        public List<EncodePos> PosList { get; set; } = Enum.GetValues<EncodePos>().ToList();

        [JsonIgnore]
        public List<int> DoCountItems { get; set; } = new List<int> { 1, 2, 3 };

        partial void OnBuiltinChanged(bool value) { OnPropertyChanged(nameof(TypeText)); OnPropertyChanged(nameof(PosText)); }
        partial void OnKeyChanged(string value) { OnPropertyChanged(nameof(DescText)); OnPropertyChanged(nameof(PosText)); }
        partial void OnCodeChanged(string value) => OnPropertyChanged(nameof(DescText));
        partial void OnApplyPosChanged(EncodePos value) => OnPropertyChanged(nameof(PosText));
    }
}
