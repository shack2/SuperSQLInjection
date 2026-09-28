using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace SuperSQLInjectionV2.Tools.Inject
{
    /// <summary>
    /// errors.xml 正则指纹引擎（config/injection/errors.xml，上游同步+本地增补的唯一事实源）。
    /// 支持 fork 库识别（MariaDB/TiDB/Doris/StarRocks/CockroachDB/OpenGauss 等），
    /// 指纹的增删改经 LoadRaw/SaveAll 管理（检测用例页-报错指纹选项卡）。
    /// </summary>
    public static class ErrorFingerprints
    {
        /// <summary>指纹条目：DBMS名（fork优先）+ 编译后的正则</summary>
        public sealed class Entry
        {
            public string Dbms = "";
            public Regex Pattern = null!;
        }

        private static List<Entry>? _patterns;
        private static readonly object _lock = new object();

        /// <summary>全部指纹（懒加载，按文件顺序）</summary>
        public static IReadOnlyList<Entry> Patterns
        {
            get
            {
                if (_patterns == null)
                {
                    lock (_lock)
                    {
                        _patterns ??= Load();
                    }
                }
                return _patterns;
            }
        }

        private static List<Entry> Load()
        {
            List<Entry> list = new List<Entry>();
            try
            {
                string file = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config", "injection", "errors.xml");
                if (!File.Exists(file))
                {
                    return list;
                }
                XDocument doc = XDocument.Load(file);
                foreach (XElement dbms in doc.Root!.Elements("dbms"))
                {
                    string dbmsName = dbms.Attribute("value")?.Value ?? "";
                    foreach (XElement err in dbms.Elements("error"))
                    {
                        string? regexp = err.Attribute("regexp")?.Value;
                        if (string.IsNullOrWhiteSpace(regexp))
                        {
                            continue;
                        }
                        //fork属性=更精确的衍生库名（如MariaDB/TiDB），优先作为识别结果
                        string name = err.Attribute("fork")?.Value ?? dbmsName;
                        //Python re 允许转义非字母字符（\_ 即字面_），.NET不允许，先规整
                        regexp = regexp.Replace("\\_", "_", StringComparison.Ordinal);
                        try
                        {
                            list.Add(new Entry
                            {
                                Dbms = name,
                                Pattern = new Regex(regexp, RegexOptions.IgnoreCase | RegexOptions.Singleline, TimeSpan.FromSeconds(1))
                            });
                        }
                        catch
                        {
                            //跳过上游个别非法正则，不影响整体
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Log.SysLog("加载错误指纹errors.xml失败：" + e.Message);
            }
            return list;
        }

        /// <summary>
        /// 正则指纹匹配响应体，返回命中的DBMS名（fork名优先），按指纹顺序去重
        /// </summary>
        public static List<string> MatchDbms(string body)
        {
            List<string> hits = new List<string>();
            if (string.IsNullOrEmpty(body))
            {
                return hits;
            }
            foreach (Entry e in Patterns)
            {
                try
                {
                    if (e.Pattern.IsMatch(body) && !hits.Contains(e.Dbms))
                    {
                        hits.Add(e.Dbms);
                    }
                }
                catch (RegexMatchTimeoutException)
                {
                    //异常响应体超时保护，跳过该条
                }
            }
            return hits;
        }

        /// <summary>响应体是否命中任一数据库错误指纹（用于错误页判定）</summary>
        public static bool IsErrorPage(string body)
        {
            if (string.IsNullOrEmpty(body))
            {
                return false;
            }
            foreach (Entry e in Patterns)
            {
                try
                {
                    if (e.Pattern.IsMatch(body))
                    {
                        return true;
                    }
                }
                catch (RegexMatchTimeoutException)
                {
                }
            }
            return false;
        }

        #region 指纹管理（检测用例页-报错指纹选项卡：增删改后整存 errors.xml）

        /// <summary>命中测试：返回命中的原始条目明细（管理页"命中测试"用，含具体 regexp）</summary>
        public static List<RawEntry> MatchDetails(string body)
        {
            List<RawEntry> hits = new List<RawEntry>();
            if (string.IsNullOrEmpty(body))
            {
                return hits;
            }
            foreach (RawEntry raw in LoadRaw())
            {
                try
                {
                    string rx = raw.Regexp.Replace("\\_", "_", StringComparison.Ordinal);
                    if (Regex.IsMatch(body, rx, RegexOptions.IgnoreCase | RegexOptions.Singleline, TimeSpan.FromSeconds(1)))
                    {
                        hits.Add(raw);
                    }
                }
                catch
                {
                    //非法正则/超时跳过
                }
            }
            return hits;
        }

        /// <summary>管理用原始条目（未编译，保留 fork/正则原文）</summary>
        public sealed class RawEntry
        {
            public string Dbms = "";
            public string Fork = "";
            public string Regexp = "";
        }

        private static string XmlFile => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config", "injection", "errors.xml");

        /// <summary>读取全部指纹原始条目（按文件顺序，含 fork 属性）</summary>
        public static List<RawEntry> LoadRaw()
        {
            List<RawEntry> list = new List<RawEntry>();
            if (!File.Exists(XmlFile))
            {
                return list;
            }
            XDocument doc = XDocument.Load(XmlFile);
            foreach (XElement dbms in doc.Root!.Elements("dbms"))
            {
                string dbmsName = dbms.Attribute("value")?.Value ?? "";
                foreach (XElement err in dbms.Elements("error"))
                {
                    string? regexp = err.Attribute("regexp")?.Value;
                    if (string.IsNullOrWhiteSpace(regexp))
                    {
                        continue;
                    }
                    list.Add(new RawEntry
                    {
                        Dbms = dbmsName,
                        Fork = err.Attribute("fork")?.Value ?? "",
                        Regexp = regexp
                    });
                }
            }
            return list;
        }

        /// <summary>整存 errors.xml（按 DBMS 分组、首见序；保存后检测缓存立即失效重建）</summary>
        public static void SaveAll(IEnumerable<RawEntry> items)
        {
            var root = new XElement("root");
            var groups = new Dictionary<string, XElement>(StringComparer.OrdinalIgnoreCase);
            foreach (RawEntry item in items)
            {
                if (string.IsNullOrWhiteSpace(item.Dbms) || string.IsNullOrWhiteSpace(item.Regexp))
                {
                    continue;
                }
                if (!groups.TryGetValue(item.Dbms.Trim(), out XElement? node))
                {
                    node = new XElement("dbms", new XAttribute("value", item.Dbms.Trim()));
                    groups[item.Dbms.Trim()] = node;
                    root.Add(node);
                }
                var err = new XElement("error", new XAttribute("regexp", item.Regexp));
                if (!string.IsNullOrWhiteSpace(item.Fork))
                {
                    err.SetAttributeValue("fork", item.Fork.Trim());
                }
                node.Add(err);
            }
            var doc = new XDocument(new XDeclaration("1.0", "UTF-8", null), root);
            doc.Save(XmlFile);
            Invalidate();
        }

        /// <summary>使编译缓存失效（指纹增删改后调用，下次匹配重建）</summary>
        public static void Invalidate()
        {
            lock (_lock)
            {
                _patterns = null;
            }
        }

        #endregion
    }
}
