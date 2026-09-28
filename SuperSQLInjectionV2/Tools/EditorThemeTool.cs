using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Styling;
using AvaloniaEdit;
using AvaloniaEdit.Highlighting;
using AvaloniaEdit.Highlighting.Xshd;
using System;
using System.Xml;

namespace SuperSQLInjectionV2.Tools
{
    /// <summary>
    /// HTTP报文编辑器主题：自定义 Http.xshd 语法高亮（浅色/深色两套），编辑器外观色取自 Dsg 设计令牌，
    /// 跟随应用 RequestedThemeVariant 切换。替代原 TextMate（LightPlus 写死且会把演示色刷到整个窗口）。
    /// </summary>
    public static class EditorThemeTool
    {
        private static bool _registered;

        /// <summary>注册浅/深色两套 HTTP 语法高亮（幂等）</summary>
        public static void RegisterHttpHighlightings()
        {
            if (_registered)
            {
                return;
            }
            _registered = true;
            Load("avares://SuperSQLInjectionV2/Assets/Http.xshd", "Http Light", ".http");
            Load("avares://SuperSQLInjectionV2/Assets/HttpDark.xshd", "Http Dark", ".httpdark");
            Load("avares://SuperSQLInjectionV2/Assets/HttpData.xshd", "HttpData Light", ".httpdata");
            Load("avares://SuperSQLInjectionV2/Assets/HttpDataDark.xshd", "HttpData Dark", ".httpdatadark");
        }

        private static void Load(string uri, string name, string ext)
        {
            try
            {
                using var stream = Avalonia.Platform.AssetLoader.Open(new Uri(uri));
                if (stream == null)
                {
                    return;
                }
                using var reader = new XmlTextReader(stream);
                var highlighting = HighlightingLoader.Load(reader, HighlightingManager.Instance);
                HighlightingManager.Instance.RegisterHighlighting(name, new[] { ext }, highlighting);
            }
            catch (Exception)
            {
                //高亮加载失败不阻断编辑器使用（退化为纯文本）
            }
        }

        /// <summary>当前是否为深色主题（Default 时跟随系统实际主题）</summary>
        public static bool IsDarkTheme
        {
            get
            {
                var app = Application.Current;
                if (app == null)
                {
                    return false;
                }
                ThemeVariant requested = app.RequestedThemeVariant ?? ThemeVariant.Default;
                if (requested == ThemeVariant.Default)
                {
                    return app.ActualThemeVariant == ThemeVariant.Dark;
                }
                return requested == ThemeVariant.Dark;
            }
        }

        /// <summary>按当前主题给编辑器应用 HTTP 高亮与外观色（背景/前景/行号/选中/当前行）</summary>
        public static void ApplyHttpEditorTheme(params TextEditor[] editors)
        {
            RegisterHttpHighlightings();
            bool dark = IsDarkTheme;
            ApplyTheme(HighlightingManager.Instance.GetDefinitionByExtension(dark ? ".httpdark" : ".http"), dark, editors);
        }

        /// <summary>按当前主题给响应区编辑器应用 HttpData 高亮与外观色（SQL报错指纹/HTML标签/hex段等响应特征）</summary>
        public static void ApplyHttpDataEditorTheme(params TextEditor[] editors)
        {
            RegisterHttpHighlightings();
            bool dark = IsDarkTheme;
            ApplyTheme(HighlightingManager.Instance.GetDefinitionByExtension(dark ? ".httpdatadark" : ".httpdata"), dark, editors);
        }

        /// <summary>给脚本编辑器应用 AvaloniaEdit 内置 JavaScript 高亮（报文钩子等JS脚本场景），外观色随主题</summary>
        public static void ApplyJsEditorTheme(params TextEditor[] editors)
        {
            ApplyTheme(HighlightingManager.Instance.GetDefinition("JavaScript"), IsDarkTheme, editors);
        }

        private static void ApplyTheme(IHighlightingDefinition? highlighting, bool dark, params TextEditor[] editors)
        {
            IBrush bg = GetDsgBrush("DsgCodeBg", dark ? "#13161D" : "#FCFDFE");
            IBrush fg = GetDsgBrush("DsgInk1", dark ? "#E6EAF2" : "#232936");
            IBrush lineNo = GetDsgBrush("DsgInk3", dark ? "#67707F" : "#939CAB");
            IBrush selection = GetDsgBrush("DsgPrimaryTint2", dark ? "#4522D3EE" : "#DBE8FE");
            IBrush currentLine = GetDsgBrush("DsgSurface2", dark ? "#1D222C" : "#F3F5F9");
            foreach (TextEditor editor in editors)
            {
                if (editor == null)
                {
                    continue;
                }
                editor.SyntaxHighlighting = highlighting;
                editor.Background = bg;
                editor.Foreground = fg;
                editor.LineNumbersForeground = lineNo;
                editor.TextArea.SelectionBrush = selection;
                editor.TextArea.TextView.CurrentLineBackground = currentLine;
                editor.TextArea.TextView.CurrentLineBorder = new Pen(Brushes.Transparent);
            }
        }

        /// <summary>跟随应用主题切换自动重刷编辑器主题（控件销毁时无需注销：随Application生命周期）</summary>
        public static void FollowAppTheme(params TextEditor[] editors)
        {
            FollowTheme(EditorKind.Http, editors);
        }

        /// <summary>响应区编辑器跟随主题切换自动重刷 HttpData 高亮</summary>
        public static void FollowAppThemeData(params TextEditor[] editors)
        {
            FollowTheme(EditorKind.HttpData, editors);
        }

        /// <summary>脚本编辑器跟随主题切换自动重刷 JavaScript 高亮</summary>
        public static void FollowAppThemeJs(params TextEditor[] editors)
        {
            FollowTheme(EditorKind.JavaScript, editors);
        }

        private enum EditorKind { Http, HttpData, JavaScript }

        private static void FollowTheme(EditorKind kind, TextEditor[] editors)
        {
            var app = Application.Current;
            if (app == null)
            {
                return;
            }
            app.PropertyChanged += (s, e) =>
            {
                if (e.Property == Application.RequestedThemeVariantProperty || e.Property == Application.ActualThemeVariantProperty)
                {
                    switch (kind)
                    {
                        case EditorKind.HttpData:
                            ApplyHttpDataEditorTheme(editors);
                            break;
                        case EditorKind.JavaScript:
                            ApplyJsEditorTheme(editors);
                            break;
                        default:
                            ApplyHttpEditorTheme(editors);
                            break;
                    }
                }
            };
        }

        private static IBrush GetDsgBrush(string key, string fallback)
        {
            var app = Application.Current;
            if (app != null && app.TryGetResource(key, app.ActualThemeVariant, out object? value) && value is IBrush brush)
            {
                return brush;
            }
            return new SolidColorBrush(Color.Parse(fallback));
        }
    }
}
