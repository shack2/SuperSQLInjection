using AvaloniaEdit.Document;
using CommunityToolkit.Mvvm.ComponentModel;
using SuperSQLInjectionV2.Tools.Http;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Text.Json.Serialization;

namespace SuperSQLInjectionV2.Models
{
    /// <summary>
    /// 动态规则（动态值与二次注入统一模型，TableView规则管理）。
    /// 动态值（Kind=0）：主请求前从HTTP响应抓取或脚本生成动态值，回填主请求的&lt;DRule&gt;标记（CSRF/防重放/API签名），可同时启用多条；
    /// 二次注入（Kind=1）：主请求后追加请求回显页面，以其响应替代主响应取数，同时只能启用一条。
    /// 两方向共享同一套：启用开关、请求来源（报文/URL/脚本生成，脚本生成仅动态值）、提取规则（截取/脚本，动态值使用）。
    /// </summary>
    public partial class CompanionRequestConfig : ViewModelBase
    {
        /// <summary>规则类型：0=动态值，1=二次注入</summary>
        [ObservableProperty]
        public partial int Kind { get; set; } = 0;

        /// <summary>规则名称（TableView展示/管理用）</summary>
        [ObservableProperty]
        public partial string Name { get; set; } = "新规则";

        /// <summary>
        /// 标记名：请求报文中通过标记名关联本规则——动态值=&lt;DRule&gt;标记名:占位值&lt;DRule&gt;，二次注入=&lt;Sencond:标记名&gt;&lt;/Sencond&gt;。
        /// 为空时为默认规则（不带标记名的&lt;DRule&gt;&lt;DRule&gt;/未指定二次注入时生效）；同类型建议唯一。
        /// </summary>
        [ObservableProperty]
        public partial string TagName { get; set; } = "";

        /// <summary>启用规则（动态值可多条同时启用；二次注入同时只能启用一条，开启自动关闭其余）</summary>
        [ObservableProperty]
        public partial bool Enabled { get; set; } = false;

        /// <summary>TableView行勾选（工具栏"删除选中"批量操作目标；不参与序列化）</summary>
        [JsonIgnore]
        [ObservableProperty]
        public partial bool RowChecked { get; set; } = false;

        /// <summary>请求来源：0=直接粘贴请求报文，1=URL+请求方式，2=脚本生成（仅动态值：不发HTTP请求，脚本直接生成动态值，输入为主请求报文）</summary>
        [ObservableProperty]
        public partial int SourceMode { get; set; } = 0;

        /// <summary>抓取URL（SourceMode=1时生效）</summary>
        [ObservableProperty]
        public partial string Url { get; set; } = "";

        /// <summary>请求方式（GET/POST，SourceMode=1时生效）</summary>
        [ObservableProperty]
        public partial string Method { get; set; } = "GET";

        /// <summary>伴随请求报文文档（UI编辑器绑定；TxtRequest的编辑线程文档）</summary>
        [JsonIgnore]
        public TextDocument TxtRequest { get; set; } = new TextDocument();

        /// <summary>伴随请求报文文本（TxtRequest的同步镜像，序列化持久化以此为准）</summary>
        public string RequestTxt { get; set; } = "";

        //---- 提取规则（前置方向：从伴随响应中提取动态值回填主请求<DRule>标记）----

        /// <summary>true=用脚本从伴随响应提取，false=开始/结束字符截取</summary>
        [ObservableProperty]
        public partial bool UseScript { get; set; } = false;

        /// <summary>截取开始字符</summary>
        [ObservableProperty]
        public partial string SubStart { get; set; } = "";

        /// <summary>截取结束字符</summary>
        [ObservableProperty]
        public partial string SubEnd { get; set; } = "";

        /// <summary>当前选中的抓取脚本名（按Name匹配AppConfig.TokenScripts；为空时取第一个启用脚本）</summary>
        [ObservableProperty]
        public partial string ScriptName { get; set; } = "";

        //---- 显隐联动（不参与序列化）----

        /// <summary>URL抓取行显隐（SourceMode=1）</summary>
        [JsonIgnore]
        public bool UrlRowVisible => SourceMode == 1;

        /// <summary>报文编辑区显隐（SourceMode=0，URL模式下无需粘贴报文）</summary>
        [JsonIgnore]
        public bool PacketEditorVisible => SourceMode == 0;

        //---- TableView 列表展示列（不参与序列化）----

        /// <summary>类型显示名</summary>
        [JsonIgnore]
        public string KindName => Kind == 1 ? "二次注入" : "动态值";

        /// <summary>来源显示名</summary>
        [JsonIgnore]
        public string SourceName => SourceMode == 1 ? "URL请求" : SourceMode == 2 ? "脚本生成" : "请求报文";

        /// <summary>取值方式显示名（二次注入无需提取，整页响应替代）</summary>
        [JsonIgnore]
        public string ExtractName => Kind == 1 ? "—" : SourceMode == 2 ? "脚本生成" : (UseScript ? "脚本提取" : "字符串截取");

        /// <summary>右键规则菜单显示名</summary>
        [JsonIgnore]
        public string InsertMenuHeader => Kind == 1
            ? $"二次注入：{Name}（<Sencond:{TagName}>）"
            : $"动态值：{Name}（<DRule>{TagName}<DRule>）";

        /// <summary>规则摘要（URL、脚本名或报文首行截断）</summary>
        [JsonIgnore]
        public string Summary
        {
            get
            {
                if (SourceMode == 2)
                {
                    return "脚本：" + (string.IsNullOrWhiteSpace(ScriptName) ? "（默认第一个启用脚本）" : ScriptName);
                }
                string s = SourceMode == 1 ? Url : RequestTxt;
                s = (s ?? "").Replace("\r\n", " ").Replace("\n", " ").Trim();
                return s.Length > 60 ? s.Substring(0, 60) + "…" : s;
            }
        }

        /// <summary>规则是否已配置（按来源判定：URL模式看Url，报文模式看RequestTxt，脚本生成模式脚本运行时解析）</summary>
        [JsonIgnore]
        public bool IsConfigured => SourceMode == 2 || (SourceMode == 1 ? !string.IsNullOrWhiteSpace(Url) : !string.IsNullOrEmpty(RequestTxt));

        /// <summary>截取规则行显隐（报文/URL来源且非脚本提取方式）</summary>
        [JsonIgnore]
        public bool SubstrRowVisible => SourceMode != 2 && !UseScript;

        /// <summary>脚本选择行显隐（脚本提取方式 或 脚本生成来源）</summary>
        [JsonIgnore]
        public bool ScriptRowVisible => SourceMode == 2 || UseScript;

        /// <summary>"使用脚本提取"勾运行显隐（脚本生成来源时隐藏，脚本选择行直接显示）</summary>
        [JsonIgnore]
        public bool ExtractModeRowVisible => SourceMode != 2;

        partial void OnSourceModeChanged(int value)
        {
            OnPropertyChanged(nameof(UrlRowVisible));
            OnPropertyChanged(nameof(PacketEditorVisible));
            OnPropertyChanged(nameof(SourceName));
            OnPropertyChanged(nameof(Summary));
            OnPropertyChanged(nameof(SubstrRowVisible));
            OnPropertyChanged(nameof(ScriptRowVisible));
            OnPropertyChanged(nameof(ExtractModeRowVisible));
            OnPropertyChanged(nameof(ExtractName));
        }

        partial void OnKindChanged(int value)
        {
            OnPropertyChanged(nameof(KindName));
            OnPropertyChanged(nameof(ExtractName));
            OnPropertyChanged(nameof(InsertMenuHeader));
        }

        partial void OnNameChanged(string value) => OnPropertyChanged(nameof(InsertMenuHeader));

        partial void OnTagNameChanged(string value) => OnPropertyChanged(nameof(InsertMenuHeader));

        partial void OnUrlChanged(string value) => OnPropertyChanged(nameof(Summary));

        partial void OnScriptNameChanged(string value) => OnPropertyChanged(nameof(Summary));

        partial void OnUseScriptChanged(bool value)
        {
            OnPropertyChanged(nameof(SubstrRowVisible));
            OnPropertyChanged(nameof(ScriptRowVisible));
            OnPropertyChanged(nameof(ExtractName));
        }

        public CompanionRequestConfig()
        {
            TxtRequest.TextChanged += TxtRequest_TextChanged;
        }

        private void TxtRequest_TextChanged(object? sender, EventArgs e)
        {
            RequestTxt = ((sender as TextDocument)?.Text ?? "");
            OnPropertyChanged(nameof(Summary));
        }

        /// <summary>克隆一份独立副本（编辑弹窗取消语义：编辑副本，确认后才写回原规则）</summary>
        public CompanionRequestConfig Clone()
        {
            var copy = new CompanionRequestConfig();
            copy.CopyFrom(this);
            return copy;
        }

        /// <summary>把另一条规则的全部配置写入本规则（含报文文档同步）</summary>
        public void CopyFrom(CompanionRequestConfig src)
        {
            Kind = src.Kind;
            Name = src.Name;
            TagName = src.TagName;
            Enabled = src.Enabled;
            SourceMode = src.SourceMode;
            Url = src.Url;
            Method = src.Method;
            UseScript = src.UseScript;
            SubStart = src.SubStart;
            SubEnd = src.SubEnd;
            ScriptName = src.ScriptName;
            TxtRequest.Text = src.RequestTxt;
            RequestTxt = src.RequestTxt;
        }

        /// <summary>
        /// 按配置构造规则的HTTP请求（报文或URL+请求方式两种来源；脚本生成来源不发请求，不走本方法）。
        /// 供动态值（BypassPipeline抓取）与二次注入（HTTPTool）共用；配置无效时返回null并记录原因。
        /// </summary>
        public HttpRequest? BuildRequest(AppConfig config, string payloadTag)
        {
            string reqTxt;
            if (SourceMode == 1)
            {
                if (string.IsNullOrWhiteSpace(Url))
                {
                    Tools.Log.SysLog(payloadTag + "：未配置规则URL！");
                    return null;
                }
                reqTxt = RequestRewriter.BuildGetRequestFromUrl(Url);
                if (string.IsNullOrEmpty(reqTxt))
                {
                    Tools.Log.SysLog(payloadTag + "：规则URL无效，无法生成请求包：" + Url);
                    return null;
                }
                if ("POST".Equals(Method, StringComparison.OrdinalIgnoreCase))
                {
                    reqTxt = RequestRewriter.ChangeRequestFormat(reqTxt, RequestFormat.POST_FORM);
                }
            }
            else
            {
                reqTxt = RequestTxt;
                if (string.IsNullOrEmpty(reqTxt))
                {
                    Tools.Log.SysLog(payloadTag + "：未配置规则请求报文！");
                    return null;
                }
            }
            HttpRequest request = new HttpRequest(config, reqTxt)
            {
                Payload = payloadTag
            };
            return request;
        }
    }
}
