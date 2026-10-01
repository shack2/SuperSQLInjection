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
    /// 统一编码工具配置项（编码处理/tamper合并后的唯一变换链节点）：
    /// 所有项均为JS脚本（QuickJS执行，约定 function tamper(payload){...}），加载时从磁盘脚本文件物化代码到Code，
    /// 无内置/自定义区分；Key=脚本文件名主干（scripts/&lt;key&gt;.js，保存时保持文件名不变）。
    /// Scope=Payload级在Encode块内执行，Scope=报文级在整份HTTP报文发送前执行（--eval语义）。
    /// </summary>
    public partial class EncodeToolModel : ViewModelBase, ITamperItem
    {
        /// <summary>显示名</summary>
        [ObservableProperty]
        public partial string Name { get; set; } = "新编码工具";

        /// <summary>脚本文件名主干（scripts/&lt;key&gt;.js；注册表内置tamper与sqlmap同名；新建项保存时按名称生成并回填）</summary>
        [ObservableProperty]
        public partial string Key { get; set; } = "";

        /// <summary>JS脚本内容（加载时从磁盘脚本物化；执行时为空才回退注册表内嵌实现）</summary>
        [ObservableProperty]
        public partial string Code { get; set; } = "";

        /// <summary>作用域：Payload级（默认，Encode块内）/报文级（整份HTTP报文，发送前执行）</summary>
        [ObservableProperty]
        public partial ScriptScope Scope { get; set; } = ScriptScope.Payload;

        [ObservableProperty]
        public partial bool Enable { get; set; } = true;

        /// <summary>功能描述（磁盘脚本 //@description 元数据；保存时非空才写回文件头）</summary>
        [ObservableProperty]
        public partial string Description { get; set; } = "";

        /// <summary>执行顺序号（链内 1 起始位置，序号列展示=加载/执行顺序；集合增删移动时由 ByPassConfig 自动重编号）</summary>
        [JsonIgnore]
        [ObservableProperty]
        public partial int Seq { get; set; }

        /// <summary>功能描述展示（优先 //@description 元数据，空则取代码首行注释）</summary>
        [JsonIgnore]
        public string DescText
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(Description))
                {
                    return Description;
                }
                string first = (Code ?? "").TrimStart().Split('\n')[0].Trim();
                return first.StartsWith("//", StringComparison.Ordinal) ? first.TrimStart('/').Trim() : "";
            }
        }

        partial void OnDescriptionChanged(string value) => OnPropertyChanged(nameof(DescText));
        partial void OnCodeChanged(string value) => OnPropertyChanged(nameof(DescText));
    }
}
