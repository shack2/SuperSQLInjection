using AvaloniaEdit.Document;
using AvaloniaEdit.Highlighting;
using AvaloniaEdit.Highlighting.Xshd;
using System.Xml;

/// <summary>
/// xshd 正则探针：把候选正则逐一塞进最小 xshd 经真实 HighlightingLoader + DocumentHighlighter 跑一遍，
/// 用于定位 XshdRegexLexer 对 lookbehind/引号/空白等语法的实际支持情况。
/// </summary>
static class XshdProbe
{
    public static void Run()
    {
        var cases = new (string name, string pattern, string text)[]
        {
            ("status-lookbehind", @"(?<=HTTP\/\d(\.\d)? )\d{3}\b", "HTTP/1.1 200 OK"),
            ("status-lookbehind-nob", @"(?<=HTTP\/\d(\.\d)? )\d{3}", "HTTP/1.1 200 OK"),
            ("status-fixed-len", @"(?<=HTTP\/\d\.\d )\d{3}|(?<=HTTP\/\d )\d{3}", "HTTP/1.1 200 OK"),
            ("literal-space", @"foo bar", "x foo bar y"),
            ("escaped-space", @"foo\x20bar", "x foo bar y"),
            ("jsonkey-quote", @"""[^""\r\n]{1,60}""(?=\s*:)", "{\"name\":\"x\"}"),
            ("jsonkey-x22", @"\x22[^\x22\r\n]{1,60}\x22(?=\s*:)", "{\"name\":\"x\"}"),
            ("sqlerr-simple", @"(?i)You have an error in your SQL syntax", "You have an error in your SQL syntax near ''"),
            ("sqlerr-quantifier", @"(?i)SQL syntax.{0,40}MySQL", "SQL syntax; check the manual that corresponds to your MySQL server"),
            ("sqlerr-digit", @"ORA-\d{5}", "ORA-00933: SQL command"),
            ("sqlerr-brace", @"ERROR 1\d{3}", "ERROR 1064 (42000)"),
            ("lookahead", @"[A-Za-z\-]+(?==)", "class=\"x\""),
        };
        foreach (var (name, pattern, text) in cases)
        {
            string xml = "<?xml version=\"1.0\"?>\n<SyntaxDefinition name=\"probe\" xmlns=\"http://icsharpcode.net/sharpdevelop/syntaxdefinition/2008\" extensions=\".probe\">"
                + "<Color name=\"C\" foreground=\"Red\"/>"
                + "<RuleSet><Rule color=\"C\">" + SecurityEscape(pattern) + "</Rule></RuleSet></SyntaxDefinition>";
            try
            {
                IHighlightingDefinition def;
                using (var sr = new StringReader(xml))
                using (var reader = XmlTextReader.Create(sr, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }))
                    def = HighlightingLoader.Load(reader, HighlightingManager.Instance);
                var doc = new TextDocument(text);
                var hl = new DocumentHighlighter(doc, def);
                var line = hl.HighlightLine(1);
                string got = line.Sections.Count == 0
                    ? "无染色"
                    : string.Join(",", line.Sections.Select(s => "'" + doc.GetText(s.Offset, s.Length) + "'"));
                Console.WriteLine($"[probe][{name}] => {got}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[probe][{name}] 加载异常: {e.Message}");
            }
        }
        Console.WriteLine("===== probe完成 =====");
    }

    private static string SecurityEscape(string s)
    {
        return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");
    }
}
