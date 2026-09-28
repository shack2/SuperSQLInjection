using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace SuperSQLInjectionV2.Models.Data
{
    /// <summary>
    /// n-gram 字符预测模型（离线训练，trigram/bigram 两级 backoff）：
    /// 语料为 config/dict 下常见值字典（common-outputs/common_tables/common_columns/access_*），
    /// 由 TestHarness/tools/build_char_ngram.py 离线生成 config/dict/char_ngram.json，运行时懒加载。
    /// 用途：盲注逐字符读取时按"当前值已读前缀"给出下一字符概率分布，
    /// 融入频率二分的权重计算（DataComm.GetBoolValueFreq），只影响分组顺序不影响候选全集。
    /// </summary>
    /// <summary>n-gram在线学习增量持久化DTO（NativeAOT源生成序列化需要命名类型，不能用匿名类型）</summary>
    public class NgramDeltaDto
    {
        [System.Text.Json.Serialization.JsonPropertyName("tri")]
        public Dictionary<string, Dictionary<string, int>> Tri { get; set; } = new Dictionary<string, Dictionary<string, int>>();

        [System.Text.Json.Serialization.JsonPropertyName("bi")]
        public Dictionary<string, Dictionary<string, int>> Bi { get; set; } = new Dictionary<string, Dictionary<string, int>>();
    }

    public static class NgramCharModel
    {
        /// <summary>trigram 表：2字符上下文 → (下一字符码值 → 概率)</summary>
        private static Dictionary<string, Dictionary<int, double>>? _tri;
        /// <summary>bigram 表：1字符上下文 → (下一字符码值 → 概率)</summary>
        private static Dictionary<string, Dictionary<int, double>>? _bi;
        private static bool _loaded;
        private static bool _available;
        private static readonly object _loadLock = new object();

        //---------------- 在线学习（会话级增量计数 + delta 持久化）----------------
        /// <summary>在线 trigram 计数：2字符上下文 → (下一字符码值 → 次数)</summary>
        private static readonly Dictionary<string, Dictionary<int, int>> _triOnline = new(StringComparer.Ordinal);
        /// <summary>在线 bigram 计数</summary>
        private static readonly Dictionary<string, Dictionary<int, int>> _biOnline = new(StringComparer.Ordinal);
        private static readonly object _onlineLock = new object();
        /// <summary>在线样本相对静态概率的合并权重（目标站点命名习惯比通用字典更贴）</summary>
        private const double OnlineWeight = 3.0;
        private static int _dirtyLearns;
        private static bool _exitHooked;

        /// <summary>delta 增量文件路径（不污染基座 char_ngram.json，删delta即恢复出厂分布）</summary>
        private static string DeltaPath
            => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config", "sessions", "char_ngram_delta.json");

        /// <summary>
        /// 在线学习：成功读取的值增量训练 trigram/bigram 计数。
        /// 门槛：2~64字符、纯ASCII可打印（防脏数据/行数据长文本污染）；小写折叠与基座一致
        /// </summary>
        public static void Learn(string? value)
        {
            if (string.IsNullOrEmpty(value) || value.Length < 2 || value.Length > 64)
            {
                return;
            }
            if (value.Any(c => c < 32 || c > 126))
            {
                return;
            }
            EnsureLoaded();
            string w = value.ToLowerInvariant();
            lock (_onlineLock)
            {
                for (int i = 1; i < w.Length; i++)
                {
                    AddCount(_biOnline, w.Substring(i - 1, 1), w[i]);
                    if (i >= 2)
                    {
                        AddCount(_triOnline, w.Substring(i - 2, 2), w[i]);
                    }
                }
                _dirtyLearns++;
                //每积累20次学习落盘一次（退出时也兜底保存）
                if (_dirtyLearns >= 20)
                {
                    SaveDelta();
                }
                if (!_exitHooked)
                {
                    _exitHooked = true;
                    AppDomain.CurrentDomain.ProcessExit += (_, _) => SaveDelta();
                }
            }
        }

        private static void AddCount(Dictionary<string, Dictionary<int, int>> table, string ctx, char next)
        {
            if (!table.TryGetValue(ctx, out Dictionary<int, int>? outcomes))
            {
                outcomes = new Dictionary<int, int>();
                table[ctx] = outcomes;
            }
            outcomes.TryGetValue(next, out int n);
            outcomes[next] = n + 1;
        }

        /// <summary>取在线计数（含总次数），无记录返回null</summary>
        private static Dictionary<int, int>? GetOnline(Dictionary<string, Dictionary<int, int>>? table, string? ctx, out int total)
        {
            total = 0;
            if (table == null || ctx == null)
            {
                return null;
            }
            lock (_onlineLock)
            {
                if (table.TryGetValue(ctx, out Dictionary<int, int>? outcomes))
                {
                    total = outcomes.Values.Sum();
                    return outcomes;
                }
            }
            return null;
        }

        /// <summary>持久化在线计数到delta文件（追加合并已有delta，防进程异常丢增量）</summary>
        private static void SaveDelta()
        {
            lock (_onlineLock)
            {
                if (_dirtyLearns == 0)
                {
                    return;
                }
                try
                {
                    string json = JsonSerializer.Serialize(new NgramDeltaDto
                    {
                        Tri = SerializeCounts(_triOnline),
                        Bi = SerializeCounts(_biOnline)
                    }, Source.JsonCtx.CompactInfo<NgramDeltaDto>());
                    string path = DeltaPath;
                    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                    File.WriteAllText(path, json);
                    _dirtyLearns = 0;
                }
                catch
                {
                    //delta写失败不影响取数（在线计数仍在内存中）
                }
            }
        }

        private static Dictionary<string, Dictionary<string, int>> SerializeCounts(Dictionary<string, Dictionary<int, int>> table)
        {
            return table.ToDictionary(kv => kv.Key,
                kv => kv.Value.ToDictionary(x => ((char)x.Key).ToString(), x => x.Value));
        }

        /// <summary>启动时加载delta增量到在线计数（跨会话复用学习成果）</summary>
        private static void LoadDelta()
        {
            try
            {
                string path = DeltaPath;
                if (!File.Exists(path))
                {
                    return;
                }
                using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(path));
                LoadCounts(doc.RootElement, "tri", _triOnline);
                LoadCounts(doc.RootElement, "bi", _biOnline);
                if (_triOnline.Count > 0 || _biOnline.Count > 0)
                {
                    Tools.Log.SysLog("n-gram 在线学习增量已加载：trigram上下文 " + _triOnline.Count
                        + " 个，bigram上下文 " + _biOnline.Count + " 个（" + path + "）");
                }
            }
            catch
            {
                //delta损坏忽略（在线学习从零开始）
            }
        }

        private static void LoadCounts(JsonElement root, string name, Dictionary<string, Dictionary<int, int>> table)
        {
            if (!root.TryGetProperty(name, out JsonElement el) || el.ValueKind != JsonValueKind.Object)
            {
                return;
            }
            foreach (JsonProperty ctx in el.EnumerateObject())
            {
                foreach (JsonProperty o in ctx.Value.EnumerateObject())
                {
                    if (o.Name.Length == 1 && o.Value.TryGetInt32(out int n) && n > 0)
                    {
                        AddCount(table, ctx.Name, o.Name[0]);
                        //AddCount只+1，直接覆盖为delta中的累计次数
                        table[ctx.Name][o.Name[0]] = n;
                    }
                }
            }
        }


        /// <summary>模型是否可用（基座文件存在且解析成功，或有在线学习增量）</summary>
        public static bool Available
        {
            get
            {
                EnsureLoaded();
                return _available;
            }
        }

        /// <summary>在线表是否有该上下文的计数</summary>
        private static bool HasOnline(Dictionary<string, Dictionary<int, int>> table, string ctx)
        {
            if (ctx == null)
            {
                return false;
            }
            lock (_onlineLock)
            {
                return table.ContainsKey(ctx);
            }
        }

        private static void EnsureLoaded()
        {
            if (_loaded)
            {
                return;
            }
            lock (_loadLock)
            {
                if (_loaded)
                {
                    return;
                }
                _loaded = true;
                LoadDelta();   //在线学习增量（跨会话复用）
                try
                {
                    string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config", "dict", "char_ngram.json");
                    if (File.Exists(path))
                    {
                        using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(path));
                        _tri = ParseTable(doc.RootElement, "tri");
                        _bi = ParseTable(doc.RootElement, "bi");
                        _available = _tri.Count > 0 || _bi.Count > 0;
                        if (_available)
                        {
                            Tools.Log.SysLog("n-gram 字符预测模型已加载（trigram上下文 " + _tri.Count + " 个，bigram上下文 " + _bi.Count + " 个）");
                        }
                    }
                }
                catch
                {
                    //模型文件损坏不影响取数主流程（回退纯静态频率/在线增量）
                    _tri = null;
                    _bi = null;
                }
                //基座缺失/损坏时，在线学习增量仍可独立成模型
                if (!_available)
                {
                    lock (_onlineLock)
                    {
                        _available = _triOnline.Count > 0 || _biOnline.Count > 0;
                    }
                }
            }
        }

        private static Dictionary<string, Dictionary<int, double>> ParseTable(JsonElement root, string name)
        {
            var table = new Dictionary<string, Dictionary<int, double>>(StringComparer.Ordinal);
            if (!root.TryGetProperty(name, out JsonElement el) || el.ValueKind != JsonValueKind.Object)
            {
                return table;
            }
            foreach (JsonProperty ctx in el.EnumerateObject())
            {
                var outcomes = new Dictionary<int, double>();
                foreach (JsonProperty o in ctx.Value.EnumerateObject())
                {
                    //内层键为单字符（训练脚本按字符存储）
                    if (o.Name.Length == 1 && o.Value.TryGetDouble(out double p) && p > 0)
                    {
                        outcomes[(int)o.Name[0]] = p;
                    }
                }
                if (outcomes.Count > 0)
                {
                    table[ctx.Name] = outcomes;
                }
            }
            return table;
        }

        /// <summary>
        /// 按已读前缀取下一字符概率分布：trigram（2字符上下文）优先，未命中 backoff 到 bigram（1字符）；
        /// 前缀小写折叠查询（训练语料已小写折叠）；在线学习计数按3倍权重合并进静态分布，
        /// 静态缺失的上下文在线计数可独立成分布；均无命中返回 false（调用方退静态频率）。
        /// useOnline=false（在线学习开关关闭）时只用基座静态分布，不读在线增量
        /// </summary>
        public static bool TryGetDist(string prefix, out Dictionary<int, double>? dist, bool useOnline = true)
        {
            dist = null;
            if (string.IsNullOrEmpty(prefix) || !Available)
            {
                return false;
            }
            string p = prefix.ToLowerInvariant();
            string? ctx2 = p.Length >= 2 ? p.Substring(p.Length - 2) : null;
            string ctx1 = p.Substring(p.Length - 1);
            //选上下文层级：trigram（静态或在线有记录）优先，否则 bigram
            bool useTri = ctx2 != null
                && ((_tri != null && _tri.ContainsKey(ctx2)) || (useOnline && HasOnline(_triOnline, ctx2)));
            string? ctx = useTri ? ctx2 : ctx1;
            Dictionary<int, double>? stat = null;
            if (useTri)
            {
                _tri?.TryGetValue(ctx!, out stat);
            }
            else
            {
                _bi?.TryGetValue(ctx!, out stat);
            }
            int total = 0;
            Dictionary<int, int>? online = useOnline
                ? GetOnline(useTri ? _triOnline : _biOnline, ctx, out total)
                : null;
            if (stat == null && online == null)
            {
                return false;
            }
            if (online == null)
            {
                dist = stat;
                return true;
            }
            //合并：静态概率 + 在线频次 × (OnlineWeight/总次数)
            double ow = OnlineWeight / total;
            var merged = new Dictionary<int, double>();
            if (stat != null)
            {
                foreach (KeyValuePair<int, double> kv in stat)
                {
                    merged[kv.Key] = kv.Value;
                }
            }
            foreach (KeyValuePair<int, int> kv in online)
            {
                merged[kv.Key] = (merged.TryGetValue(kv.Key, out double s) ? s : 0) + kv.Value * ow;
            }
            dist = merged;
            return true;
        }
    }
}
