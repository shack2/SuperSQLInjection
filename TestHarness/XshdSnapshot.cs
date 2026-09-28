using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Headless;
using Avalonia.Markup.Xaml.Styling;
using Avalonia.Media;
using Avalonia.Styling;
using Avalonia.Themes.Fluent;
using AvaloniaEdit;
using AvaloniaEdit.Document;
using AvaloniaEdit.Highlighting;
using AvaloniaEdit.Highlighting.Xshd;
using System.Xml;

/// <summary>
/// xshd 高亮可视化快照自验：Avalonia 无头模式渲染真实 TextEditor 截图（请求区/响应区 × 浅色/深色），
/// 同时用 DocumentHighlighter 断言关键片段的染色规则名，避免改 xshd 后必须启动软件人工核对。
/// 产物输出到 TestHarness/snapshots/*.png。
/// </summary>
static class XshdSnapshot
{
    private static int _pass, _fail;
    private static bool _setupDone;

    private const string RequestSample =
        "GET /JVApp/mysql.jsp?id=1&name=$sql$ HTTP/1.1\n" +
        "Host: 127.0.0.1:8090\n" +
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\n" +
        "Content-Type: application/x-www-form-urlencoded\n" +
        "\n" +
        "id=1' %20 UNION ALL SELECT NULL,CONCAT(user,version)-- x\n" +
        "token=<Rand>\n" +
        "<Encode>1$sql$</Encode>";

    private const string ResponseSample =
        "HTTP/1.1 200 OK\n" +
        "Content-Type: text/html; charset=utf-8\n" +
        "Server: Apache-Coyote/1.1\n" +
        "\n" +
        "<html><body><div class=\"user\">admin</div>\n" +
        "<!-- debug info -->\n" +
        "You have an error in your SQL syntax near '' at line 1\n" +
        "{\"name\":\"admin\",\"id\":1} hash=0x4F8A2C1B\n" +
        "reflected:$sql$ see http://127.0.0.1:8090/api\n" +
        "</body></html>";

    private static readonly (string Sub, string Color)[] RequestAsserts =
    {
        ("GET", "HTTP.Method"),
        ("HTTP/1.1", "HTTP.Version"),
        ("Host", "HTTP.Header"),
        ("application/x-www-form-urlencoded", "HTTP.MIME"),
        ("?id=1", "HTTP.Param"),
        ("%20", "HTTP.Encode"),
        ("UNION", "HTTP.Sql"),
        ("$sql$", "HTTP.Point"),
        ("<Rand>", "HTTP.Encode"),
    };

    private static readonly (string Sub, string Color)[] ResponseAsserts =
    {
        ("HTTP/1.1", "Resp.Version"),
        ("200", "Resp.Status"),
        ("Content-Type", "Resp.Header"),
        ("text/html", "Resp.MIME"),
        ("<div", "Resp.HtmlTag"),
        ("class", "Resp.HtmlAttr"),
        ("<!-- debug info -->", "Resp.HtmlComment"),
        ("You have an error in your SQL syntax", "Resp.SqlError"),
        ("\"name\"", "Resp.JsonKey"),
        ("0x4F8A2C1B", "Resp.Hex"),
        ("$sql$", "Resp.Point"),
        ("http://127.0.0.1:8090/api", "Resp.Url"),
    };

    public static void Run()
    {
        SetupHeadless();
        string assetDir = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "SuperSQLInjectionV2", "Assets"));
        string outDir = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "TestHarness", "snapshots"));
        Directory.CreateDirectory(outDir);

        Case("Http.xshd", "request_light", false, RequestSample, RequestAsserts, assetDir, outDir);
        Case("HttpDark.xshd", "request_dark", true, RequestSample, RequestAsserts, assetDir, outDir);
        Case("HttpData.xshd", "response_light", false, ResponseSample, ResponseAsserts, assetDir, outDir);
        Case("HttpDataDark.xshd", "response_dark", true, ResponseSample, ResponseAsserts, assetDir, outDir);

        Console.WriteLine($"===== xshdsnap结果: PASS={_pass} FAIL={_fail} =====");
    }

    public static void SetupHeadless()
    {
        if (_setupDone) return;
        _setupDone = true;
        AppBuilder.Configure<Application>
            ().UseSkia
            ().UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
            .SetupWithoutStarting();
        var app = Application.Current!;
        app.Styles.Add(new FluentTheme());
        //TextEditor 控件模板与主程序 App.axaml 同源
        app.Styles.Add(new StyleInclude(new Uri("avares://AvaloniaEdit/", UriKind.Absolute))
        {
            Source = new Uri("avares://AvaloniaEdit/Themes/Fluent/AvaloniaEdit.xaml")
        });
    }

    private static void Case(string xshdFile, string snapName, bool dark, string sample,
        (string Sub, string Color)[] asserts, string assetDir, string outDir)
    {
        string path = Path.Combine(assetDir, xshdFile);
        IHighlightingDefinition def;
        try
        {
            using var stream = File.OpenRead(path);
            using var reader = new XmlTextReader(stream);
            def = HighlightingLoader.Load(reader, HighlightingManager.Instance);
        }
        catch (Exception e)
        {
            Console.WriteLine($"[{snapName}] xshd加载失败：{e}：FAIL");
            _fail++;
            return;
        }

        //1. 染色断言：关键片段必须落在期望的规则颜色上（与App内渲染共用同一套高亮引擎）
        var doc = new TextDocument(sample);
        var highlighter = new DocumentHighlighter(doc, def);
        if (Environment.GetEnvironmentVariable("XSHD_DUMP") == "1")
        {
            for (int ln = 1; ln <= doc.LineCount; ln++)
            {
                var dl = doc.GetLineByNumber(ln);
                var hl0 = highlighter.HighlightLine(ln);
                string text = doc.GetText(dl.Offset, dl.Length);
                Console.WriteLine($"  [dump] L{ln}: {text}");
                foreach (var s in hl0.Sections)
                    Console.WriteLine($"    [{s.Color?.Name ?? "-"}] '{doc.GetText(s.Offset, s.Length)}'");
            }
        }
        foreach (var (sub, color) in asserts)
        {
            int idx = sample.IndexOf(sub, StringComparison.Ordinal);
            if (idx < 0)
            {
                Console.WriteLine($"  [{snapName}][{sub}] 样例中不存在：FAIL");
                _fail++;
                continue;
            }
            var line = doc.GetLineByOffset(idx);
            var hl = highlighter.HighlightLine(line.LineNumber);
            //取包含目标位置的最内层（长度最小）分区：外层Span与嵌套Rule会同时出现在Sections里
            var section = hl.Sections.Where(s => idx >= s.Offset && idx < s.Offset + s.Length)
                .OrderBy(s => s.Length).FirstOrDefault();
            bool ok = section != null && section.Color != null && section.Color.Name == color;
            Console.WriteLine($"  [{snapName}][{sub}] 期望={color} 实际={(section?.Color?.Name ?? "无染色")}：{(ok ? "PASS" : "FAIL")}");
            if (ok) _pass++; else _fail++;
        }

        //2. 可视化快照：真实 TextEditor 无头渲染出图
        Application.Current!.RequestedThemeVariant = dark ? ThemeVariant.Dark : ThemeVariant.Light;
        var editor = new TextEditor
        {
            Text = sample,
            SyntaxHighlighting = def,
            ShowLineNumbers = true,
            IsReadOnly = true,
            Background = new SolidColorBrush(Color.Parse(dark ? "#13161D" : "#FCFDFE")),
            Foreground = new SolidColorBrush(Color.Parse(dark ? "#E6EAF2" : "#232936")),
        };
        var window = new Window
        {
            Width = 980,
            Height = 320,
            Content = editor,
            Background = editor.Background,
        };
        string png = Path.Combine(outDir, snapName + ".png");
        try
        {
            window.Show();
            using var frame = window.CaptureRenderedFrame();
            if (frame == null)
            {
                Console.WriteLine($"  [{snapName}] 截图为空：FAIL");
                _fail++;
                return;
            }
            frame.Save(png);
            //像素断言：排除纯背景/空白渲染（高亮生效时颜色数必然大于背景+前景+行号寥寥几种）
            int distinct = DistinctColors(frame);
            bool ok = distinct >= 8;
            Console.WriteLine($"  [{snapName}] 快照={png} 颜色数={distinct}：{(ok ? "PASS" : "FAIL")}");
            if (ok) _pass++; else _fail++;
        }
        catch (Exception e)
        {
            Console.WriteLine($"  [{snapName}] 渲染失败：{e}：FAIL");
            _fail++;
        }
        finally
        {
            window.Close();
        }
    }

    private static int DistinctColors(Avalonia.Media.Imaging.WriteableBitmap bmp)
    {
        var colors = new HashSet<int>();
        using var fb = bmp.Lock();
        unsafe
        {
            byte* basePtr = (byte*)fb.Address;
            int w = fb.Size.Width, h = fb.Size.Height, stride = fb.RowBytes;
            //抽样：每4像素取一个，足够判断"是否渲染出了多彩高亮"
            for (int y = 0; y < h; y += 4)
            {
                byte* row = basePtr + y * stride;
                for (int x = 0; x < w; x += 4)
                {
                    int px = *(int*)(row + x * 4);
                    colors.Add(px);
                    if (colors.Count > 64) return colors.Count;
                }
            }
        }
        return colors.Count;
    }
}
