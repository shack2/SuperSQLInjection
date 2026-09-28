using SuperSQLInjectionV2.Models.Detect;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml.Linq;

namespace SuperSQLInjectionV2.Tools.Inject
{
    /// <summary>
    /// 检测payload管理：读取config/injection下全部用例（官方6文件 + custom_*.xml + dns_blind.xml），
    /// 支持新增/修改/删除并外科式写回XML（XDocument保留注释与未改动内容）。
    /// 每次写盘后调用 InjectPayloadLoader.ResetCache 使检测引擎立即使用新用例。
    /// 新增用例默认写入 custom_user.xml（不存在自动创建），避免污染官方文件便于上游diff。
    /// </summary>
    public static class InjectPayloadManager
    {
        private static readonly string[] s_dnsBlindFile = { "dns_blind.xml" };

        /// <summary>新增用例默认目标文件</summary>
        public const string UserFile = "custom_user.xml";

        /// <summary>全部payload文件（与加载器口径一致：官方6文件 + custom_*.xml + dns_blind.xml）</summary>
        public static List<string> ListFiles()
        {
            string[] files = { "boolean_blind.xml", "error_based.xml", "inline_query.xml", "stacked_queries.xml", "time_blind.xml", "union_query.xml" };
            string dir = InjectPayloadLoader.Dir;
            if (Directory.Exists(dir))
            {
                files = files.Concat(Directory.GetFiles(dir, "custom_*.xml").Select(f => Path.GetFileName(f)!))
                    .Concat(s_dnsBlindFile).Distinct().ToArray();
            }
            return files.Where(f => File.Exists(Path.Combine(dir, f))).ToList();
        }

        /// <summary>加载全部用例为可编辑项（FileName+Index定位）</summary>
        public static List<PayloadItem> LoadAll()
        {
            List<PayloadItem> list = new List<PayloadItem>();
            foreach (string name in ListFiles())
            {
                XDocument doc = XDocument.Load(Path.Combine(InjectPayloadLoader.Dir, name));
                int idx = 0;
                foreach (XElement t in doc.Root!.Elements("test"))
                {
                    list.Add(new PayloadItem
                    {
                        FileName = name,
                        Index = idx++,
                        Title = Text(t, "title"),
                        SType = Int(Text(t, "stype"), 1),
                        Level = Int(Text(t, "level"), 1),
                        Risk = Int(Text(t, "risk"), 1),
                        Clause = Text(t, "clause"),
                        Where = Text(t, "where"),
                        Vector = t.Element("vector")?.Value ?? "",
                        Payload = t.Element("request")?.Element("payload")?.Value ?? "",
                        Comment = t.Element("request")?.Element("comment")?.Value ?? "",
                        Dbms = Text(t.Element("details"), "dbms"),
                        DbmsExclude = Text(t.Element("details"), "dbms_exclude"),
                        HitCount = GetHitCount(name, Text(t, "title"))
                    });
                }
            }
            return list;
        }

        /// <summary>保存用例：Index>=0原位更新（序号漂移时按Title兜底定位），Index=-1追加到目标文件</summary>
        public static void Save(PayloadItem item)
        {
            string file = Path.Combine(InjectPayloadLoader.Dir, item.FileName);
            //PreserveWhitespace：保留原文件格式与注释，只改动目标test元素（官方文件仍可与上游diff）
            XDocument doc = File.Exists(file)
                ? XDocument.Load(file, LoadOptions.PreserveWhitespace)
                : new XDocument(new XElement("root"));
            List<XElement> tests = doc.Root!.Elements("test").ToList();
            XElement? target = null;
            if (item.Index >= 0 && item.Index < tests.Count)
            {
                target = tests[item.Index];
            }
            if (target == null && !string.IsNullOrEmpty(item.Title))
            {
                target = tests.FirstOrDefault(t => Text(t, "title") == item.Title);
            }
            if (target != null)
            {
                target.ReplaceWith(BuildElement(item));
            }
            else
            {
                //新增：payload/vector保留原始空白，用4空格缩进与官方文件风格一致
                doc.Root.Add(BuildElement(item));
                item.Index = tests.Count;
            }
            doc.Save(file);
            InjectPayloadLoader.ResetCache();
        }

        /// <summary>删除用例（按Index定位，Title校验防误删；漂移时按Title兜底）</summary>
        public static bool Delete(PayloadItem item)
        {
            string file = Path.Combine(InjectPayloadLoader.Dir, item.FileName);
            if (!File.Exists(file))
            {
                return false;
            }
            XDocument doc = XDocument.Load(file, LoadOptions.PreserveWhitespace);
            List<XElement> tests = doc.Root!.Elements("test").ToList();
            XElement? target = null;
            if (item.Index >= 0 && item.Index < tests.Count && Text(tests[item.Index], "title") == item.Title)
            {
                target = tests[item.Index];
            }
            target ??= tests.FirstOrDefault(t => Text(t, "title") == item.Title);
            if (target == null)
            {
                return false;
            }
            target.Remove();
            doc.Save(file);
            InjectPayloadLoader.ResetCache();
            return true;
        }

        /// <summary>按用例XML规范构造test元素（与加载器解析字段一一对应）</summary>
        private static XElement BuildElement(PayloadItem item)
        {
            return new XElement("test",
                new XElement("title", item.Title ?? ""),
                new XElement("stype", item.SType),
                new XElement("level", item.Level),
                new XElement("risk", item.Risk),
                new XElement("clause", item.Clause ?? ""),
                new XElement("where", item.Where ?? ""),
                new XElement("vector", item.Vector ?? ""),
                new XElement("request",
                    new XElement("payload", item.Payload ?? ""),
                    string.IsNullOrEmpty(item.Comment) ? null : new XElement("comment", item.Comment)),
                new XElement("response"),
                new XElement("details",
                    new XElement("dbms", item.Dbms ?? ""),
                    string.IsNullOrEmpty(item.DbmsExclude) ? null : new XElement("dbms_exclude", item.DbmsExclude)));
        }

        private static string Text(XElement? parent, string name)
        {
            return parent?.Element(name)?.Value?.Trim ()?? "";
        }

        #region 检测命中次数统计（持久化 config/injection/hit_count.json，键=文件名|标题）

        private static readonly Lock _hitLock = new Lock();
        private static Dictionary<string, int>? _hitCounts;

        private static string HitCountFile => Path.Combine(InjectPayloadLoader.Dir, "hit_count.json");

        private static Dictionary<string, int> HitCounts
        {
            get
            {
                lock (_hitLock)
                {
                    if (_hitCounts == null)
                    {
                        _hitCounts = new Dictionary<string, int>();
                        try
                        {
                            if (File.Exists(HitCountFile))
                            {
                                _hitCounts = System.Text.Json.JsonSerializer.Deserialize(
                                    File.ReadAllText(HitCountFile), Source.JsonCtx.CompactInfo<Dictionary<string, int>>())
                                    ?? new Dictionary<string, int>();
                            }
                        }
                        catch (Exception e)
                        {
                            Log.SysLog("加载用例命中次数失败：" + e.Message);
                        }
                    }
                    return _hitCounts;
                }
            }
        }

        /// <summary>检测引擎命中用例时计数+1并落盘（线程安全；命中低频，直接写盘）</summary>
        public static void RecordHit(PayloadTest test)
        {
            if (test == null || string.IsNullOrEmpty(test.Title))
            {
                return;
            }
            lock (_hitLock)
            {
                string key = (test.FileName ?? "") + "|" + test.Title;
                Dictionary<string, int> counts = HitCounts;
                counts[key] = counts.TryGetValue(key, out int c) ? c + 1 : 1;
                try
                {
                    File.WriteAllText(HitCountFile,
                        System.Text.Json.JsonSerializer.Serialize(counts, Source.JsonCtx.CompactInfo<Dictionary<string, int>>()));
                }
                catch (Exception e)
                {
                    Log.SysLog("保存用例命中次数失败：" + e.Message);
                }
            }
        }

        /// <summary>读取用例累计命中次数（键=文件名|标题）</summary>
        public static int GetHitCount(string fileName, string title)
        {
            if (string.IsNullOrEmpty(title))
            {
                return 0;
            }
            lock (_hitLock)
            {
                return HitCounts.TryGetValue((fileName ?? "") + "|" + title, out int c) ? c : 0;
            }
        }

        #endregion

        private static int Int(string text, int def)
        {
            return int.TryParse(text, out int v) ? v : def;
        }
    }
}
