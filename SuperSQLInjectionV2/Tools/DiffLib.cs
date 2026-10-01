using System;
using System.Collections.Generic;

namespace SuperSQLInjectionV2.Tools
{
    /// <summary>
    /// 对标Python difflib.SequenceMatcher的相似度算法（Ratcliff-Obershelp），
    /// 用于网页相似度对比（同款 ratio 判定）。
    ///
    /// 双模式设计：
    /// 1) 字符级模式（&lt;=32KB）：与difflib完全一致的 b2j 字符索引 + autojunk（高频字符剔除），
    ///    空间 O(n)，精度与业界同款算法相同；
    /// 2) 大块级模式（&gt;32KB）：按行（或定长块）切分为 token 后做加权 SequenceMatcher，
    ///    避免小字符集大页面下 autojunk 退化为 0 以及 O(n*m) 最坏耗时。
    /// </summary>
    public static class DiffLib
    {
        /// <summary>
        /// 超长页面截断保护（字符数），超过时只比较前缀部分，防止极端页面耗时过长
        /// </summary>
        private const int MaxCompareLength = 128 * 1024;

        /// <summary>
        /// 字符级模式的最大长度，超过则使用块级模式
        /// </summary>
        private const int CharLevelLimit = 32 * 1024;

        /// <summary>
        /// autojunk 仅对较长序列启用（difflib 为200，但小页面上1%阈值仅个位数出现次数，
        /// 会过度剔除导致失真；小页面 O(n*m) 最坏情况可承受，无需 autojunk）
        /// </summary>
        private const int AutoJunkMinLength = 2000;

        /// <summary>
        /// 块级模式下，行数不足时按该长度定长切块
        /// </summary>
        private const int ChunkSize = 512;

        /// <summary>
        /// 相似度结果全局缓存（sqlmap kb.cache.comparison同款思路）：
        /// 键=(a哈希,b哈希)，盲注取数/检测真假值重发的响应常聚簇到少数相同页面，命中即免全量比对。
        /// 哈希碰撞概率与sqlmap Python hash缓存同级，可接受；超上限整体清空防内存膨胀
        /// </summary>
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<(int, int), double> _ratioCache
            = new System.Collections.Concurrent.ConcurrentDictionary<(int, int), double>();
        private const int RatioCacheLimit = 20000;

        /// <summary>
        /// 计算两个字符串的相似度（近似 difflib.SequenceMatcher.ratio），范围 0.0-1.0，1.0 表示完全相同
        /// </summary>
        public static double Ratio(string? a, string? b)
        {
            if (ReferenceEquals(a, b))
            {
                return 1.0;
            }
            if (a == null) a = "";
            if (b == null) b = "";
            if (a.Length == 0 && b.Length == 0)
            {
                return 1.0;
            }
            if (a.Length == 0 || b.Length == 0)
            {
                return 0.0;
            }
            if (a.Equals(b, StringComparison.Ordinal))
            {
                return 1.0;
            }
            //全局缓存：命中直接返回（键为原文哈希，碰撞风险与sqlmap同款缓存一致）
            var cacheKey = (a.GetHashCode(), b.GetHashCode());
            if (_ratioCache.TryGetValue(cacheKey, out double cachedRatio))
            {
                return cachedRatio;
            }
            //截断保护
            if (a.Length > MaxCompareLength)
            {
                a = a.Substring(0, MaxCompareLength);
            }
            if (b.Length > MaxCompareLength)
            {
                b = b.Substring(0, MaxCompareLength);
            }

            double ratio;
            if (Math.Max(a.Length, b.Length) <= CharLevelLimit)
            {
                int matches = CountMatchingChars(a, b);
                ratio = 2.0 * matches / (a.Length + b.Length);
            }
            else
            {
                ratio = TokenRatio(a, b);
            }
            if (_ratioCache.Count >= RatioCacheLimit)
            {
                _ratioCache.Clear();
            }
            _ratioCache[cacheKey] = ratio;
            return ratio;
        }

        #region 字符级模式（difflib 一致）

        /// <summary>
        /// difflib get_matching_blocks 同款：返回 a 与 b 的匹配块列表（按位置升序，相邻连续块已合并）。
        /// 供动态内容标记（findDynamicContent移植）提取稳定锚点区块使用。
        /// </summary>
        public static List<(int APos, int BPos, int Size)> GetMatchingBlocks(string a, string b)
        {
            List<(int APos, int BPos, int Size)> result = new List<(int, int, int)>();
            if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b))
            {
                return result;
            }
            Dictionary<char, List<int>> b2j = BuildCharIndex(b);
            Queue<(int alo, int ahi, int blo, int bhi)> queue = new Queue<(int, int, int, int)>();
            queue.Enqueue((0, a.Length, 0, b.Length));
            while (queue.Count > 0)
            {
                (int alo, int ahi, int blo, int bhi) = queue.Dequeue();
                FindLongestMatch(a, alo, ahi, b, blo, bhi, b2j, out int ai, out int bi, out int size);
                if (size > 0)
                {
                    result.Add((ai, bi, size));
                    if (alo < ai && blo < bi)
                    {
                        queue.Enqueue((alo, ai, blo, bi));
                    }
                    if (ai + size < ahi && bi + size < bhi)
                    {
                        queue.Enqueue((ai + size, ahi, bi + size, bhi));
                    }
                }
            }
            //difflib语义：按位置升序排列，相邻连续块（前块终点=后块起点）合并为一块
            result.Sort((x, y) => x.APos != y.APos ? x.APos - y.APos : x.BPos - y.BPos);
            List<(int APos, int BPos, int Size)> merged = new List<(int, int, int)>();
            foreach (var block in result)
            {
                if (merged.Count > 0)
                {
                    var last = merged[merged.Count - 1];
                    if (last.APos + last.Size == block.APos && last.BPos + last.Size == block.BPos)
                    {
                        merged[merged.Count - 1] = (last.APos, last.BPos, last.Size + block.Size);
                        continue;
                    }
                }
                merged.Add(block);
            }
            return merged;
        }


        /// <summary>
        /// 构建 b 的字符到位置列表索引（difflib 的 b2j），
        /// 并按 difflib autojunk 规则剔除占比超过1%的高频字符
        /// </summary>
        private static Dictionary<char, List<int>> BuildCharIndex(string b)
        {
            Dictionary<char, List<int>> index = new Dictionary<char, List<int>>();
            for (int i = 0; i < b.Length; i++)
            {
                if (!index.TryGetValue(b[i], out List<int>? list))
                {
                    list = new List<int>();
                    index[b[i]] = list;
                }
                list.Add(i);
            }
            //autojunk：高频字符不参与匹配（difflib默认行为，沿用），阈值至少20次
            if (b.Length >= AutoJunkMinLength)
            {
                int junkThreshold = Math.Max(20, b.Length / 100);
                List<char> junkChars = new List<char>();
                foreach (KeyValuePair<char, List<int>> kv in index)
                {
                    if (kv.Value.Count > junkThreshold)
                    {
                        junkChars.Add(kv.Key);
                    }
                }
                foreach (char c in junkChars)
                {
                    index.Remove(c);
                }
            }
            return index;
        }

        /// <summary>
        /// 在 a[alo..ahi) 与 b[blo..bhi) 中查找最长匹配块（difflib 的 find_longest_match）
        /// </summary>
        private static void FindLongestMatch(string a, int alo, int ahi, string b, int blo, int bhi,
            Dictionary<char, List<int>> b2j, out int bestI, out int bestJ, out int bestSize)
        {
            bestI = alo;
            bestJ = blo;
            bestSize = 0;
            Dictionary<int, int> j2len = new Dictionary<int, int>();
            for (int i = alo; i < ahi; i++)
            {
                Dictionary<int, int> newJ2len = new Dictionary<int, int>();
                if (b2j.TryGetValue(a[i], out List<int>? indexes))
                {
                    foreach (int j in indexes)
                    {
                        if (j < blo)
                        {
                            continue;
                        }
                        if (j >= bhi)
                        {
                            break;
                        }
                        int k = (j2len.TryGetValue(j - 1, out int prev) ? prev : 0) + 1;
                        newJ2len[j] = k;
                        if (k > bestSize)
                        {
                            bestI = i - k + 1;
                            bestJ = j - k + 1;
                            bestSize = k;
                        }
                    }
                }
                j2len = newJ2len;
            }
        }

        /// <summary>
        /// 递归统计匹配字符总数（迭代队列实现，避免深递归栈溢出）
        /// </summary>
        private static int CountMatchingChars(string a, string b)
        {
            Dictionary<char, List<int>> b2j = BuildCharIndex(b);
            int total = 0;
            Queue<(int alo, int ahi, int blo, int bhi)> queue = new Queue<(int, int, int, int)>();
            queue.Enqueue((0, a.Length, 0, b.Length));
            while (queue.Count > 0)
            {
                (int alo, int ahi, int blo, int bhi) = queue.Dequeue();
                FindLongestMatch(a, alo, ahi, b, blo, bhi, b2j, out int ai, out int bi, out int size);
                if (size > 0)
                {
                    total += size;
                    if (alo < ai && blo < bi)
                    {
                        queue.Enqueue((alo, ai, blo, bi));
                    }
                    if (ai + size < ahi && bi + size < bhi)
                    {
                        queue.Enqueue((ai + size, ahi, bi + size, bhi));
                    }
                }
            }
            return total;
        }

        #endregion

        #region 块级模式（大页面）

        /// <summary>
        /// 将文本切分为 token：行数充足时按行切（保留换行符），否则按定长块切
        /// </summary>
        private static List<string> SplitTokens(string text)
        {
            List<string> tokens = new List<string>();
            int lineCount = 0;
            for (int i = 0; i < text.Length; i++)
            {
                if (text[i] == '\n')
                {
                    lineCount++;
                }
            }
            if (lineCount >= 8)
            {
                int start = 0;
                for (int i = 0; i < text.Length; i++)
                {
                    if (text[i] == '\n')
                    {
                        tokens.Add(text.Substring(start, i - start + 1));
                        start = i + 1;
                    }
                }
                if (start < text.Length)
                {
                    tokens.Add(text.Substring(start));
                }
            }
            else
            {
                for (int start = 0; start < text.Length; start += ChunkSize)
                {
                    tokens.Add(text.Substring(start, Math.Min(ChunkSize, text.Length - start)));
                }
            }
            return tokens;
        }

        private static int TotalWeight(List<string> tokens)
        {
            int sum = 0;
            foreach (string t in tokens)
            {
                sum += t.Length;
            }
            return sum;
        }

        private static Dictionary<string, List<int>> BuildTokenIndex(List<string> tokens)
        {
            Dictionary<string, List<int>> index = new Dictionary<string, List<int>>();
            for (int i = 0; i < tokens.Count; i++)
            {
                if (!index.TryGetValue(tokens[i], out List<int>? list))
                {
                    list = new List<int>();
                    index[tokens[i]] = list;
                }
                list.Add(i);
            }
            return index;
        }

        /// <summary>
        /// 块级加权相似度：对 token 序列做 SequenceMatcher，匹配块按 token 字符长度加权
        /// </summary>
        private static double TokenRatio(string a, string b)
        {
            List<string> ta = SplitTokens(a);
            List<string> tb = SplitTokens(b);
            int totalLength = TotalWeight(ta) + TotalWeight(tb);
            if (totalLength == 0)
            {
                return 1.0;
            }
            Dictionary<string, List<int>> b2j = BuildTokenIndex(tb);

            int matchedWeight = 0;
            Queue<(int alo, int ahi, int blo, int bhi)> queue = new Queue<(int, int, int, int)>();
            queue.Enqueue((0, ta.Count, 0, tb.Count));
            while (queue.Count > 0)
            {
                (int alo, int ahi, int blo, int bhi) = queue.Dequeue();

                //find_longest_match（token级）
                int bestI = alo, bestJ = blo, bestSize = 0;
                Dictionary<int, int> j2len = new Dictionary<int, int>();
                for (int i = alo; i < ahi; i++)
                {
                    Dictionary<int, int> newJ2len = new Dictionary<int, int>();
                    if (b2j.TryGetValue(ta[i], out List<int>? indexes))
                    {
                        foreach (int j in indexes)
                        {
                            if (j < blo)
                            {
                                continue;
                            }
                            if (j >= bhi)
                            {
                                break;
                            }
                            int k = (j2len.TryGetValue(j - 1, out int prev) ? prev : 0) + 1;
                            newJ2len[j] = k;
                            if (k > bestSize)
                            {
                                bestI = i - k + 1;
                                bestJ = j - k + 1;
                                bestSize = k;
                            }
                        }
                    }
                    j2len = newJ2len;
                }

                if (bestSize > 0)
                {
                    for (int t = bestI; t < bestI + bestSize; t++)
                    {
                        matchedWeight += ta[t].Length;
                    }
                    if (alo < bestI && blo < bestJ)
                    {
                        queue.Enqueue((alo, bestI, blo, bestJ));
                    }
                    if (bestI + bestSize < ahi && bestJ + bestSize < bhi)
                    {
                        queue.Enqueue((bestI + bestSize, ahi, bestJ + bestSize, bhi));
                    }
                }
            }
            return 2.0 * matchedWeight / totalLength;
        }

        #endregion
    }
}
