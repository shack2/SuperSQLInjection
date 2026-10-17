using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using SuperSQLInjectionV2.Tools;

namespace SuperSQLInjectionV2.Models.Data
{
    /// <summary>
    /// 常见值字典预测（常见值预测机制）：
    /// 移植 common-outputs.txt 字典，按查询类型分区+DB标签裁剪。
    /// 扩展能力：跨会话学习（读过的值带命中计数持久化到predict_learned.json，候选按命中降序）、命名模式学习（wp_前缀变体）、
    /// 大小写变体（大小写敏感库）、检测期泄漏指纹入候选。
    /// Banners分区为前缀条目（"8.0."），走子串等值前缀延伸路径（GetBannerPrefixes）。
    /// </summary>
    public static class CommonOutputPredictor
    {
        /// <summary>参与整值等值预测的分区（Banners走前缀延伸，不在此列）</summary>
        private static readonly string[] PredictSections = { "Databases", "Users", "Tables", "Columns", "Passwords", "Privileges", "Roles" };

        /// <summary>字典条目：值+适用DB集合（null=通用）</summary>
        private class Entry
        {
            public string Value = "";
            public HashSet<DBType>? Dbs;
        }

        private static Dictionary<string, List<Entry>>? _sections;
        private static readonly object _loadLock = new object();

        /// <summary>会话学习条目：值+历史命中次数（跨会话持久化，候选排序按命中降序）</summary>
        private class LearnedItem
        {
            public string Value = "";
            public int Hits;
        }

        /// <summary>会话学习候选（分区→值，MRU在首；来源：成功读取值回写/检测期泄漏指纹），跨会话持久化到 config/sessions/predict_learned.json</summary>
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, List<LearnedItem>> _learned
            = new System.Collections.Concurrent.ConcurrentDictionary<string, List<LearnedItem>>(StringComparer.OrdinalIgnoreCase);
        private const int LearnedMaxPerSection = 64;
        private static string LearnedPath => "config/sessions/predict_learned.json";
        private static bool _learnedLoaded = false;
        private static int _learnedDirty = 0;
        private const int LearnedSaveEvery = 20;
        private static readonly object _learnedLock = new object();

        /// <summary>惰性加载历史学习值（命中降序排列，高命中排前优先探测），并挂进程退出兜底落盘</summary>
        private static void EnsureLearnedLoaded()
        {
            if (_learnedLoaded)
            {
                return;
            }
            lock (_learnedLock)
            {
                if (_learnedLoaded)
                {
                    return;
                }
                try
                {
                    if (File.Exists(LearnedPath))
                    {
                        var dic = System.Text.Json.JsonSerializer.Deserialize(
                            File.ReadAllText(LearnedPath), Source.JsonCtx.CompactInfo<Dictionary<string, Dictionary<string, int>>>());
                        if (dic != null)
                        {
                            foreach (var kv in dic)
                            {
                                var list = kv.Value
                                    .OrderByDescending(x => x.Value)
                                    .Take(LearnedMaxPerSection)
                                    .Select(x => new LearnedItem { Value = x.Key, Hits = x.Value })
                                    .ToList();
                                _learned[kv.Key] = list;
                            }
                            Log.SysLog("常见值预测学习库已加载：" + dic.Count + " 个分区（" + LearnedPath + "）");
                        }
                    }
                }
                catch (Exception ex) { Log.SysLog("常见值预测学习库加载异常：" + ex.Message); }
                _learnedLoaded = true;
                AppDomain.CurrentDomain.ProcessExit += (_, _) => SaveLearned();
            }
        }

        /// <summary>批量落盘学习库：攒够 LearnedSaveEvery 次新学习才写盘一次</summary>
        private static void SaveLearned()
        {
            if (System.Threading.Interlocked.Exchange(ref _learnedDirty, 0) == 0)
            {
                return;
            }
            try
            {
                lock (_learnedLock)
                {
                    var dic = new Dictionary<string, Dictionary<string, int>>();
                    foreach (var kv in _learned)
                    {
                        lock (kv.Value)
                        {
                            dic[kv.Key] = kv.Value.ToDictionary(x => x.Value, x => x.Hits, StringComparer.OrdinalIgnoreCase);
                        }
                    }
                    Directory.CreateDirectory(Path.GetDirectoryName(LearnedPath)!);
                    string tmp = LearnedPath + ".tmp";
                    File.WriteAllText(tmp, System.Text.Json.JsonSerializer.Serialize(dic, Source.JsonCtx.CompactInfo<Dictionary<string, Dictionary<string, int>>>()));
                    File.Copy(tmp, LearnedPath, true);
                    File.Delete(tmp);
                }
            }
            catch { }
        }

        private static Dictionary<string, List<Entry>> Sections
        {
            get
            {
                if (_sections == null)
                {
                    lock (_loadLock)
                    {
                        _sections ??= Load();
                    }
                }
                return _sections;
            }
        }

        /// <summary>字典注释标签→DBType集合（# MySQL >= 5.0 / # Microsoft SQL Server 等）</summary>
        private static HashSet<DBType>? TagToDbs(string comment)
        {
            string c = comment.ToLowerInvariant();
            if (c.Contains("mysql", StringComparison.Ordinal) || c.Contains("maria", StringComparison.Ordinal))
            {
                return new HashSet<DBType> { DBType.MySQL };
            }
            if (c.Contains("postgresql", StringComparison.Ordinal))
            {
                return new HashSet<DBType> { DBType.PostgreSQL, DBType.OpenGauss, DBType.Kingbase };
            }
            if (c.Contains("oracle", StringComparison.Ordinal))
            {
                return new HashSet<DBType> { DBType.Oracle, DBType.DM };
            }
            if (c.Contains("sql server", StringComparison.Ordinal) || c.Contains("mssql", StringComparison.Ordinal))
            {
                return new HashSet<DBType> { DBType.SQLServer };
            }
            if (c.Contains("sqlite", StringComparison.Ordinal))
            {
                return new HashSet<DBType> { DBType.SQLite };
            }
            if (c.Contains("db2", StringComparison.Ordinal))
            {
                return new HashSet<DBType> { DBType.DB2 };
            }
            if (c.Contains("clickhouse", StringComparison.Ordinal))
            {
                return new HashSet<DBType> { DBType.ClickHouse };
            }
            return null;   //未识别标签=通用
        }

        private static Dictionary<string, List<Entry>> Load()
        {
            var dic = new Dictionary<string, List<Entry>>(StringComparer.OrdinalIgnoreCase);
            try
            {
                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config", "dict", "common-outputs.txt");
                if (!File.Exists(path))
                {
                    return dic;
                }
                string? section = null;
                HashSet<DBType>? tagDbs = null;
                foreach (string raw in File.ReadLines(path))
                {
                    string line = raw.TrimEnd();
                    if (line.Length == 0)
                    {
                        continue;
                    }
                    if (line.StartsWith('['))
                    {
                        section = line.Trim('[', ']');
                        tagDbs = null;
                        continue;
                    }
                    if (line.StartsWith('#'))
                    {
                        //DB标签注释（# MySQL >= 5.0）：后续条目按库裁剪
                        tagDbs = TagToDbs(line.TrimStart('#', ' '));
                        continue;
                    }
                    if (section == null)
                    {
                        continue;
                    }
                    int hashIdx = line.IndexOf(" # ", StringComparison.Ordinal);
                    if (hashIdx > 0)
                    {
                        line = line.Substring(0, hashIdx).TrimEnd();
                    }
                    if (line.Length == 0 || line.Any(c => c >= 128))
                    {
                        continue;
                    }
                    if (!dic.TryGetValue(section, out List<Entry>? list))
                    {
                        list = new List<Entry>();
                        dic[section] = list;
                    }
                    if (!list.Any(x => x.Value == line))
                    {
                        list.Add(new Entry { Value = line, Dbs = tagDbs });
                    }
                }
            }
            catch
            {
                //字典损坏不影响取数主流程
            }
            return dic;
        }

        /// <summary>
        /// 按取值payload推断字典分区：列名→Columns、表名→Tables、版本/banner→Banners（前缀延伸路径）、
        /// 密码→Passwords、用户→Users、库/模式名→Databases；无法识别返回null不预测
        /// </summary>
        public static string? InferSection(string payload)
        {
            if (string.IsNullOrEmpty(payload))
            {
                return null;
            }
            string p = payload.ToLowerInvariant();
            if (p.Contains("column_name", StringComparison.Ordinal))
            {
                return "Columns";
            }
            if (p.Contains("table_name", StringComparison.Ordinal))
            {
                return "Tables";
            }
            if (p.Contains("version", StringComparison.Ordinal) || p.Contains("banner", StringComparison.Ordinal) || p.Contains("sqlite_source_id", StringComparison.Ordinal) || p.Contains("@@version", StringComparison.Ordinal))
            {
                return "Banners";
            }
            if (p.Contains("password", StringComparison.Ordinal) || p.Contains("passwd", StringComparison.Ordinal))
            {
                return "Passwords";
            }
            if (p.Contains("current_user", StringComparison.Ordinal) || p.Contains("session_user", StringComparison.Ordinal) || p.Contains("system_user", StringComparison.Ordinal)
                || p.Contains("user()", StringComparison.Ordinal) || p.Contains("user_name", StringComparison.Ordinal) || p.Contains("mysql.user", StringComparison.Ordinal) || p.Contains("pg_user", StringComparison.Ordinal))
            {
                return "Users";
            }
            if (p.Contains("priv", StringComparison.Ordinal))
            {
                return "Privileges";
            }
            if (p.Contains("role", StringComparison.Ordinal))
            {
                return "Roles";
            }
            if (p.Contains("schema_name", StringComparison.Ordinal) || p.Contains("database", StringComparison.Ordinal) || p.Contains("db_name", StringComparison.Ordinal)
                || p.Contains("current_schema", StringComparison.Ordinal) || p.Contains("datname", StringComparison.Ordinal) || p.Contains("owner", StringComparison.Ordinal))
            {
                return "Databases";
            }
            return null;
        }

        /// <summary>当前库等值比较是否大小写敏感（敏感库需生成大小写变体候选）</summary>
        private static bool CaseSensitive(DBType dbType)
        {
            return dbType is DBType.PostgreSQL or DBType.OpenGauss or DBType.Kingbase
                or DBType.SQLite or DBType.H2 or DBType.HSQLDB or DBType.ClickHouse or DBType.DB2;
        }

        /// <summary>会话学习：成功读取的值/检测期泄漏指纹回写对应分区（去重、命中计数+1、限量），批量落盘跨会话复用</summary>
        public static void Learn(string? section, string? value)
        {
            if (string.IsNullOrEmpty(section) || string.IsNullOrEmpty(value) || value.Length > 128 || value.Any(c => c >= 128))
            {
                return;
            }
            EnsureLearnedLoaded();
            var list = _learned.GetOrAdd(section, _ => new List<LearnedItem>());
            lock (list)
            {
                var item = list.FirstOrDefault(x => string.Equals(x.Value, value, StringComparison.OrdinalIgnoreCase));
                if (item != null)
                {
                    item.Hits++;
                }
                else
                {
                    list.Add(new LearnedItem { Value = value, Hits = 1 });
                    if (list.Count > LearnedMaxPerSection)
                    {
                        //淘汰命中最低的尾部条目（命中高者保留）
                        list.Sort((a, b) => b.Hits.CompareTo(a.Hits));
                        list.RemoveRange(LearnedMaxPerSection, list.Count - LearnedMaxPerSection);
                    }
                }
            }
            if (System.Threading.Interlocked.Increment(ref _learnedDirty) >= LearnedSaveEvery)
            {
                SaveLearned();
            }
        }

        /// <summary>学习到的表/列名公共前缀（如wp_）：用于生成字典候选的前缀变体（命名模式学习）</summary>
        private static string? LearnedPrefix(string section)
        {
            if (!_learned.TryGetValue(section, out List<LearnedItem>? list))
            {
                return null;
            }
            lock (list)
            {
                if (list.Count < 2)
                {
                    return null;
                }
                //取前几个高命中学习值的公共前缀，须以下划线/横线结尾才算命名模式（wp_、tbl_）
                string prefix = list.OrderByDescending(x => x.Hits).First().Value;
                foreach (var it in list.OrderByDescending(x => x.Hits).Skip(1).Take(5))
                {
                    string v = it.Value;
                    int i = 0;
                    while (i < prefix.Length && i < v.Length && char.ToLowerInvariant(prefix[i]) == char.ToLowerInvariant(v[i]))
                    {
                        i++;
                    }
                    prefix = prefix.Substring(0, i);
                }
                int sep = Math.Max(prefix.LastIndexOf('_'), prefix.LastIndexOf('-'));
                return sep >= 2 ? prefix.Substring(0, sep + 1) : null;
            }
        }

        /// <summary>
        /// 取整值等值预测候选：会话学习值优先，字典按库标签裁剪+长度过滤，大小写敏感库生成大小写变体，
        /// 命名模式前缀（wp_）生成变体；knownPrefix非空时按前缀再过滤（前缀混合预测）
        /// </summary>
        public static List<string> GetCandidates(string section, int valueLength, DBType dbType, int maxCount, string? knownPrefix = null)
        {
            EnsureLearnedLoaded();
            var result = new List<string>();
            if (section == null || valueLength <= 0 || !PredictSections.Contains(section, StringComparer.OrdinalIgnoreCase))
            {
                return result;
            }
            bool caseSens = CaseSensitive(dbType);
            void Add(string v)
            {
                if (v.Length != valueLength || result.Contains(v))
                {
                    return;
                }
                if (knownPrefix != null && !v.StartsWith(knownPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }
                result.Add(v);
            }
            //1.会话学习值（历史命中降序优先，跨会话持久化复用）
            if (_learned.TryGetValue(section, out List<LearnedItem>? learned))
            {
                lock (learned)
                {
                    foreach (var it in learned.OrderByDescending(x => x.Hits))
                    {
                        Add(it.Value);
                    }
                }
            }
            //2.字典值（库标签裁剪）
            if (Sections.TryGetValue(section, out List<Entry>? entries))
            {
                foreach (Entry e in entries)
                {
                    if (e.Dbs != null && !e.Dbs.Contains(dbType))
                    {
                        continue;
                    }
                    Add(e.Value);
                    //大小写敏感库：补小写/大写变体（字典多为大写条目，PG/SQLite实际存小写）
                    if (caseSens)
                    {
                        Add(e.Value.ToLowerInvariant());
                        Add(e.Value.ToUpperInvariant());
                    }
                    //命名模式学习：字典候选加学习前缀变体（wp_+USERS→wp_users）
                    if (section is "Tables" or "Columns")
                    {
                        string? prefix = LearnedPrefix(section);
                        if (prefix != null && !e.Value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        {
                            Add(prefix + e.Value.ToLowerInvariant());
                        }
                    }
                    if (result.Count >= maxCount * 2)
                    {
                        break;   //宽限收集再截断，避免变体挤掉全部字典条目
                    }
                }
            }
            return result.Take(maxCount).ToList();
        }

        /// <summary>Banners前缀条目（版本号前缀延伸预测用）：按库裁剪，含"8.0."式前缀与完整banner</summary>
        public static List<string> GetBannerEntries(DBType dbType)
        {
            EnsureLearnedLoaded();
            var result = new List<string>();
            if (Sections.TryGetValue("Banners", out List<Entry>? entries))
            {
                foreach (Entry e in entries)
                {
                    if (e.Dbs != null && !e.Dbs.Contains(dbType))
                    {
                        continue;
                    }
                    result.Add(e.Value);
                }
            }
            //会话学习的完整版本值（检测期泄漏指纹，命中降序）优先
            if (_learned.TryGetValue("Banners", out List<LearnedItem>? learned))
            {
                lock (learned)
                {
                    result.InsertRange(0, learned.OrderByDescending(x => x.Hits).Select(x => x.Value));
                }
            }
            return result;
        }
    }
}
