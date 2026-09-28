using CommunityToolkit.Mvvm.ComponentModel;

namespace SuperSQLInjectionV2.Models
{
    /// <summary>
    /// UA池项：User-Agent串 + 系统类型标签（Windows / macOS / Linux / Android / iPhone / HarmonyOS / iPad / 其他）+ 是否参与随机抽取
    /// </summary>
    public partial class UaItem : ObservableObject
    {
        /// <summary>系统类型标签（界面可选，也可由InferType从UA串自动识别）</summary>
        [ObservableProperty] public partial string Type { get; set; } = "";
        /// <summary>完整User-Agent串</summary>
        [ObservableProperty] public partial string Ua { get; set; } = "";
        /// <summary>随机UA开启时是否参与随机抽取（默认选中）</summary>
        [ObservableProperty] public partial bool IsSelected { get; set; } = true;

        public UaItem (){ }

        public UaItem(string type, string ua)
        {
            Type = type;
            Ua = ua;
        }
        /// <summary>类型下拉项（系统名，可由InferType从UA串自动识别）</summary>
        public static readonly string[] TypeNames =
        {
            "Windows", "macOS", "Linux",
            "Android", "iPhone", "HarmonyOS", "iPad",
            "其他"
        };

        /// <summary>按UA串推断系统类型标签</summary>
        public static string InferType(string ua)
        {
            string s = ua ?? "";
            if (s.Contains("Harmony", StringComparison.Ordinal))
            {
                return "HarmonyOS";
            }
            if (s.Contains("iPad", StringComparison.Ordinal))
            {
                return "iPad";
            }
            if (s.Contains("iPhone", StringComparison.Ordinal))
            {
                return "iPhone";
            }
            if (s.Contains("Android", StringComparison.Ordinal))
            {
                return "Android";
            }
            if (s.Contains("Windows", StringComparison.Ordinal))
            {
                return "Windows";
            }
            if (s.Contains("Macintosh", StringComparison.Ordinal) || s.Contains("Mac OS", StringComparison.Ordinal))
            {
                return "macOS";
            }
            if (s.Contains("Linux", StringComparison.Ordinal) || s.Contains("X11", StringComparison.Ordinal))
            {
                return "Linux";
            }
            return "其他";
        }
    }
}
