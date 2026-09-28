using SuperSQLInjectionV2.Models.Detect;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace SuperSQLInjectionV2.Tools.Inject
{
    /// <summary>
    /// 加载检测用例库（config/injection/boundaries.xml 与 payloads/*.xml），带缓存
    /// </summary>
    public static class InjectPayloadLoader
    {
        private static List<PayloadBoundary>? _boundaries;
        private static List<PayloadTest>? _tests;
        private static List<PayloadTest>? _dnsTests;
        private static readonly object _lock = new object();

        private static string BaseDir => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config", "injection");

        /// <summary>用例库目录（payload管理器共用）</summary>
        public static string Dir => BaseDir;

        /// <summary>清空缓存（payload管理写盘后调用，下一次检测即使用新用例）</summary>
        public static void ResetCache()
        {
            lock (_lock)
            {
                _boundaries = null;
                _tests = null;
                _dnsTests = null;
            }
        }

        /// <summary>
        /// 检测用例库是否可用
        /// </summary>
        public static bool IsAvailable()
        {
            return File.Exists(Path.Combine(BaseDir, "boundaries.xml"))
                && File.Exists(Path.Combine(BaseDir, "boolean_blind.xml"));
        }

        public static List<PayloadBoundary> GetBoundaries()
        {
            EnsureLoaded();
            return _boundaries!;
        }

        /// <summary>
        /// 获取指定技术类型的检测用例（已按 level/risk 过滤）
        /// </summary>
        public static List<PayloadTest> GetTests(int stype, int level, int risk)
        {
            EnsureLoaded();
            return _tests!.Where(t => t.SType == stype && t.Level <= level && t.Risk <= risk).ToList();
        }

        /// <summary>
        /// 获取DNS外带探测用例（dns_blind.xml，stype=7；独立加载不混入主用例库，避免被常规技术循环误取）
        /// </summary>
        public static List<PayloadTest> GetDnsTests(int level, int risk)
        {
            EnsureDnsLoaded();
            return _dnsTests!.Where(t => t.Level <= level && t.Risk <= risk).ToList();
        }

        private static void EnsureDnsLoaded()
        {
            if (_dnsTests != null)
            {
                return;
            }
            lock (_lock)
            {
                _dnsTests ??= LoadTestsFromFile("dns_blind.xml");
            }
        }

        private static void EnsureLoaded()
        {
            if (_boundaries != null && _tests != null)
            {
                return;
            }
            lock (_lock)
            {
                if (_boundaries != null && _tests != null)
                {
                    return;
                }
                _boundaries = LoadBoundaries();
                _tests = LoadTests();
            }
        }

        private static List<int> ParseIntList(string text)
        {
            List<int> result = new List<int>();
            if (string.IsNullOrWhiteSpace(text))
            {
                return result;
            }
            foreach (string part in text.Split(','))
            {
                string p = part.Trim();
                //区间写法（如"1-8"）展开为连续整数，修复区间clause解析为空导致用例无匹配边界被静默跳过的问题
                Match m = Regex.Match(p, @"^(\d+)\s*-\s*(\d+)$");
                if (m.Success)
                {
                    int from = int.Parse(m.Groups[1].Value);
                    int to = int.Parse(m.Groups[2].Value);
                    for (int rv = Math.Min(from, to); rv <= Math.Max(from, to); rv++)
                    {
                        result.Add(rv);
                    }
                    continue;
                }
                if (int.TryParse(p, out int v))
                {
                    result.Add(v);
                }
            }
            return result;
        }

        private static string Text(XElement parent, string name)
        {
            return parent.Element(name)?.Value?.Trim ()?? "";
        }

        private static List<PayloadBoundary> LoadBoundaries()
        {
            List<PayloadBoundary> list = new List<PayloadBoundary>();
            string file = Path.Combine(BaseDir, "boundaries.xml");
            if (!File.Exists(file))
            {
                return list;
            }
            XDocument doc = XDocument.Load(file);
            foreach (XElement b in doc.Root!.Elements("boundary"))
            {
                list.Add(new PayloadBoundary
                {
                    Level = int.TryParse(Text(b, "level"), out int lv) ? lv : 1,
                    Clause = ParseIntList(Text(b, "clause")),
                    Where = ParseIntList(Text(b, "where")),
                    Ptype = int.TryParse(Text(b, "ptype"), out int pt) ? pt : 1,
                    //prefix/suffix 保留原始值（含前导空格），不能 Trim
                    Prefix = b.Element("prefix")?.Value ?? "",
                    Suffix = b.Element("suffix")?.Value ?? ""
                });
            }
            return list;
        }

        private static List<PayloadTest> LoadTests()
        {
            List<PayloadTest> list = new List<PayloadTest>();
            //官方六个文件保持与上游逐字节一致便于 diff；本工具自定义补充用例放 custom_*.xml（如 ClickHouse）
            string[] files = { "boolean_blind.xml", "error_based.xml", "inline_query.xml", "stacked_queries.xml", "time_blind.xml", "union_query.xml" };
            if (Directory.Exists(BaseDir))
            {
                files = files.Concat(Directory.GetFiles(BaseDir, "custom_*.xml").Select(f => Path.GetFileName(f)!)).ToArray();
            }
            foreach (string name in files)
            {
                list.AddRange(LoadTestsFromFile(name));
            }
            return list;
        }

        /// <summary>解析单个用例XML文件为PayloadTest列表（文件不存在返回空）</summary>
        private static List<PayloadTest> LoadTestsFromFile(string name)
        {
            List<PayloadTest> list = new List<PayloadTest>();
            string file = Path.Combine(BaseDir, name);
            if (!File.Exists(file))
            {
                return list;
            }
            XDocument doc = XDocument.Load(file);
            foreach (XElement t in doc.Root!.Elements("test"))
            {
                PayloadTest test = new PayloadTest
                {
                    FileName = name,
                    Title = Text(t, "title"),
                    SType = int.TryParse(Text(t, "stype"), out int st) ? st : 0,
                    Level = int.TryParse(Text(t, "level"), out int lv) ? lv : 1,
                    Risk = int.TryParse(Text(t, "risk"), out int rk) ? rk : 1,
                    Clause = ParseIntList(Text(t, "clause")),
                    Where = ParseIntList(Text(t, "where")),
                    Vector = t.Element("vector")?.Value ?? "",
                };
                XElement? req = t.Element("request");
                if (req != null)
                {
                    //payload 保留原始值（含前导空格），不能 Trim
                    test.RequestPayload = req.Element("payload")?.Value ?? "";
                    test.RequestComment = req.Element("comment")?.Value ?? "";
                    test.RequestChar = req.Element("char")?.Value ?? "";
                    test.RequestColumns = req.Element("columns")?.Value ?? "";
                }
                XElement? resp = t.Element("response");
                if (resp != null)
                {
                    test.ResponseComparison = resp.Element("comparison")?.Value ?? "";
                    test.ResponseGrep = resp.Element("grep")?.Value ?? "";
                    test.ResponseTime = resp.Element("time")?.Value ?? "";
                }
                XElement? details = t.Element("details");
                if (details != null)
                {
                    test.Dbms = Text(details, "dbms");
                    test.DbmsExclude = Text(details, "dbms_exclude");
                }
                list.Add(test);
            }
            return list;
        }
    }
}
