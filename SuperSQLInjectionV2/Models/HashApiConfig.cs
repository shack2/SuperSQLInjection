using CommunityToolkit.Mvvm.ComponentModel;
using SuperSQLInjectionV2.ViewModels;

namespace SuperSQLInjectionV2.Models
{
    /// <summary>
    /// Hash在线解密接口配置（cmd5类站点适配）：URL/POST数据中用 {hash} 占位待解密值，
    /// 响应用提取正则拿明文（命名组 (?&lt;result&gt;) 优先，否则取第1组/整段匹配）。
    /// 独立持久化到 config/rules/hashapis.json（RuleStore），不进 lastconfig.json。
    /// </summary>
    public partial class HashApiConfig : ViewModelBase
    {
        /// <summary>hash占位符（URL与POST数据中替换）</summary>
        public const string HashPlaceholder = "{hash}";

        /// <summary>令牌占位符（URL与POST数据中替换，值来自令牌预取正则）</summary>
        public const string TokenPlaceholder = "{token}";

        [ObservableProperty] public partial string Name { get; set; } = "";

        /// <summary>请求地址（含 {hash}/{token} 占位符，缺省scheme按http补全）</summary>
        [ObservableProperty] public partial string Url { get; set; } = "";

        /// <summary>GET 或 POST</summary>
        [ObservableProperty] public partial string Method { get; set; } = "GET";

        /// <summary>POST时的请求体（含 {hash}/{token} 占位符）</summary>
        [ObservableProperty] public partial string PostData { get; set; } = "";

        /// <summary>POST请求的Content-Type（表单urlencoded 或 application/json）</summary>
        [ObservableProperty] public partial string PostContentType { get; set; } = "application/x-www-form-urlencoded";

        /// <summary>令牌预取正则（可空）：配置后先对同URL发GET提取令牌替换 {token} 再正式查询（cmd5类VIEWSTATE站点）；空=单步查询</summary>
        [ObservableProperty] public partial string TokenRegex { get; set; } = "";

        /// <summary>明文提取正则：命名组 (?&lt;result&gt;) 优先，无则取第1组，再退整段匹配；空匹配视为未解密成功</summary>
        [ObservableProperty] public partial string Regex { get; set; } = "";

        [ObservableProperty] public partial bool Enable { get; set; } = true;

        /// <summary>表格勾选（界面态，不入盘）</summary>
        [ObservableProperty] public partial bool RowChecked { get; set; } = false;
    }
}
