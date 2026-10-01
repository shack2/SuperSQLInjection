using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace SuperSQLInjectionV2.Tools
{
    /// <summary>
    /// 网页内容差异分析器（sqlmap findDynamicContent/removeDynamicContent 1:1移植）。
    /// 基于 difflib 匹配块提取「前缀/后缀锚点对」标记动态区块，比对前双边剥离动态内容。
    /// 另提供结构骨架（extractStructuralTokens移植）与 text-only（getFilteredPageContent移植）
    /// 两级降级投影：字节不稳定但结构/文本稳定的页面仍可可靠比对。
    /// </summary>
    public partial class WebPageDiffAnalyzer
    {
        /// <summary>动态特征正则编译缓存（Compiled一次编译复用）</summary>
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, Regex> _featureRegexCache
            = new System.Collections.Concurrent.ConcurrentDictionary<string, Regex>();

        private static Regex GetFeatureRegex(string pattern)
        {
            if (_featureRegexCache.Count > 64)
            {
                _featureRegexCache.Clear();
            }
            return _featureRegexCache.GetOrAdd(pattern, p => new Regex(p, RegexOptions.Compiled | RegexOptions.Singleline));
        }

        /// <summary>锚点边界长度（sqlmap DYNAMICITY_BOUNDARY_LENGTH）</summary>
        private const int BoundaryLength = 20;
        /// <summary>匹配块最小长度（sqlmap：剔除 ≤2*BoundaryLength 的过短匹配块，防锚定到重复短上下文）</summary>
        private const int MinBlockSize = 2 * BoundaryLength;
        /// <summary>标记提取的页面规模上限（字符级匹配块超出后耗时不可控；比对本身有截断保护不受影响）</summary>
        private const int MaxPageForMarkings = 256 * 1024;

        /// <summary>结构骨架标签正则（sqlmap STRUCTURAL_TAG_REGEX）</summary>
        [GeneratedRegex(@"<\s*([a-z][a-z0-9]*)((?:\s+[^<>]*)?)/?>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled)]
        private static partial Regex StructuralTagRegex();
        /// <summary>class属性正则（sqlmap STRUCTURAL_CLASS_REGEX）</summary>
        [GeneratedRegex(@"\bclass\s*=\s*(?:""([^""]*)""|'([^']*)'|([^\s""'<>]+))", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled)]
        private static partial Regex StructuralClassRegex();
        /// <summary>id属性正则（sqlmap STRUCTURAL_ID_REGEX）</summary>
        [GeneratedRegex(@"\bid\s*=\s*(?:""([^""]*)""|'([^']*)'|([^\s""'<>]+))", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled)]
        private static partial Regex StructuralIdRegex();
        /// <summary>script/style/注释剥离（骨架与text-only共用前置清洗）</summary>
        [GeneratedRegex(@"<script.+?</script>|<!--.+?-->|<style.+?</style>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled)]
        private static partial Regex ScriptStyleCommentRegex();
        /// <summary>text-only：标签/制表/换行折叠为空格（sqlmap getFilteredPageContent onlyText同款）</summary>
        [GeneratedRegex(@"<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\t|\n|\r", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled)]
        private static partial Regex TextOnlyStripRegex();
        /// <summary>text-only：连续空格折叠</summary>
        [GeneratedRegex(@" {2,}", RegexOptions.Compiled)]
        private static partial Regex MultiSpaceRegex();

        /// <summary>
        /// 对比三个网页提取动态特征：page1-page2 与 page1-page3 两对各自的动态标记合并去重（并集）。
        /// 三次采样都稳定的内容不会入标记；任一采样对出现差异即标记为动态（剥离方向保守，宁多勿漏）。
        /// </summary>
        public static List<ChangeFeature> AnalyzeThreePages(string page1, string page2, string page3)
        {
            if (string.IsNullOrEmpty(page1) || string.IsNullOrEmpty(page2) || string.IsNullOrEmpty(page3))
            {
                throw new ArgumentException("网页内容不能为空");
            }
            List<ChangeFeature> features = FindDynamicContent(page1, page2);
            FindDynamicContent(page1, page3, features);
            return features;
        }

        /// <summary>
        /// 动态特征增量学习（sqlmap findDynamicContent merge=True同款）：
        /// 把新页面与基准页面的差异区块并入既有动态特征表（按正则去重）。
        /// 仅用于"同一请求重发"的无注入页面——注入响应的差异学进特征会把真差异抹掉导致判定失真。
        /// </summary>
        public static List<ChangeFeature> MergeNewPage(List<ChangeFeature> existing, string basePage, string newPage)
        {
            if (string.IsNullOrEmpty(basePage) || string.IsNullOrEmpty(newPage))
            {
                return existing ?? new List<ChangeFeature>();
            }
            return FindDynamicContent(basePage, newPage, existing ?? new List<ChangeFeature>());
        }

        /// <summary>
        /// 清除动态文本（sqlmap removeDynamicContent同款）：按前缀/后缀锚点把动态区块整体替换回锚点，
        /// 保留锚点本身使剥离后页面长度/结构稳定，比对不受动态区长度变化影响
        /// </summary>
        public static string ClearDynamicText(List<ChangeFeature> changeFeatures, string srcPage)
        {
            if (string.IsNullOrEmpty(srcPage) || changeFeatures == null)
            {
                return srcPage ?? "";
            }
            foreach (ChangeFeature feature in changeFeatures)
            {
                if (string.IsNullOrEmpty(feature.RegexPattern))
                {
                    continue;
                }
                string replacement = feature.Replacement;
                //MatchEvaluator返回字面替换串，规避$在替换串中的分组语义
                srcPage = GetFeatureRegex(feature.RegexPattern).Replace(srcPage, m => replacement);
            }
            return srcPage;
        }

        /// <summary>兼容旧签名：先提取三页特征再剥离</summary>
        public static string ClearDynamicText(string page1, string page2, string page3, string srcPage)
        {
            return ClearDynamicText(AnalyzeThreePages(page1, page2, page3), srcPage);
        }

        /// <summary>
        /// 动态内容标记提取（sqlmap findDynamicContent 1:1移植）：
        /// difflib匹配块→剔除过短块→相邻匹配块间隙即为动态区→取20字符前后缀锚点，
        /// 动态区两端贴字母数字时按trimAlphaNum修剪锚点（避免锚点吃进动态值）。
        /// mergeInto非空时按正则去重追加（merge=True语义）
        /// </summary>
        public static List<ChangeFeature> FindDynamicContent(string firstPage, string secondPage, List<ChangeFeature>? mergeInto = null)
        {
            List<ChangeFeature> markings = mergeInto ?? new List<ChangeFeature>();
            if (string.IsNullOrEmpty(firstPage) || string.IsNullOrEmpty(secondPage)
                || firstPage.Equals(secondPage, StringComparison.Ordinal)
                || Math.Max(firstPage.Length, secondPage.Length) > MaxPageForMarkings)
            {
                return markings;
            }

            List<(int APos, int BPos, int Size)> blocks = DiffLib.GetMatchingBlocks(firstPage, secondPage);
            blocks.RemoveAll(b => b.Size <= MinBlockSize);
            if (blocks.Count == 0)
            {
                return markings;
            }

            var seen = new HashSet<string>(markings.Select(m => m.RegexPattern), StringComparer.Ordinal);
            //sqlmap：blocks首尾各插None后按相邻对遍历——(None,块0)…(块N-1,None)
            int n = blocks.Count;
            for (int i = -1; i < n; i++)
            {
                (int APos, int BPos, int Size)? prev = i >= 0 ? blocks[i] : null;
                (int APos, int BPos, int Size)? next = i + 1 < n ? blocks[i + 1] : null;

                string? prefix = prev.HasValue ? firstPage.Substring(prev.Value.APos, prev.Value.Size) : null;
                string? suffix = next.HasValue ? firstPage.Substring(next.Value.APos, next.Value.Size) : null;

                //首块起于页面开头：其前无动态区；末块止于页面末尾：其后无动态区
                if (prefix == null && next!.Value.APos == 0)
                {
                    continue;
                }
                if (suffix == null && prev!.Value.APos + prev.Value.Size >= firstPage.Length)
                {
                    continue;
                }

                if (prefix != null && suffix != null)
                {
                    prefix = prefix.Length > BoundaryLength ? prefix.Substring(prefix.Length - BoundaryLength) : prefix;
                    suffix = suffix.Length > BoundaryLength ? suffix.Substring(0, BoundaryLength) : suffix;

                    //锚点贴字母数字时修剪（sqlmap：infix首/尾为alnum则trimAlphaNum锚点，防锚点吃进动态值一部分）
                    string? infix = FindInfix(firstPage, prefix, suffix) ?? FindInfix(secondPage, prefix, suffix);
                    if (!string.IsNullOrEmpty(infix))
                    {
                        if (char.IsLetterOrDigit(infix[0]))
                        {
                            prefix = TrimAlphaNum(prefix);
                        }
                        if (char.IsLetterOrDigit(infix[infix.Length - 1]))
                        {
                            suffix = TrimAlphaNum(suffix);
                        }
                    }
                }

                ChangeFeature? feature = MakeMarking(prefix, suffix);
                if (feature != null && seen.Add(feature.RegexPattern))
                {
                    markings.Add(feature);
                }
            }
            return markings;
        }

        /// <summary>sqlmap trimAlphaNum：剔除字符串两端的字母数字</summary>
        public static string TrimAlphaNum(string value)
        {
            int start = 0, end = value.Length;
            while (end > start && char.IsLetterOrDigit(value[end - 1]))
            {
                end--;
            }
            while (start < end && char.IsLetterOrDigit(value[start]))
            {
                start++;
            }
            return value.Substring(start, end - start);
        }

        /// <summary>在page中查找prefix(.+?)suffix的动态区内容（用于锚点修剪判定）</summary>
        private static string? FindInfix(string page, string prefix, string suffix)
        {
            if (prefix.Length == 0 || suffix.Length == 0)
            {
                return null;
            }
            int pi = page.IndexOf(prefix, StringComparison.Ordinal);
            if (pi < 0)
            {
                return null;
            }
            int si = page.IndexOf(suffix, pi + prefix.Length, StringComparison.Ordinal);
            if (si < 0)
            {
                return null;
            }
            return page.Substring(pi + prefix.Length, si - pi - prefix.Length);
        }

        /// <summary>由前后缀锚点生成移除正则与替换串（sqlmap removeDynamicContent三种形态）</summary>
        private static ChangeFeature? MakeMarking(string? prefix, string? suffix)
        {
            if (string.IsNullOrEmpty(prefix))
            {
                prefix = null;
            }
            if (string.IsNullOrEmpty(suffix))
            {
                suffix = null;
            }
            if (prefix == null && suffix == null)
            {
                return null;
            }
            string pattern;
            string replacement;
            if (prefix == null)
            {
                //页面开头动态区：^.+?suffix
                pattern = "\\A.+?" + Regex.Escape(suffix!);
                replacement = suffix!;
            }
            else if (suffix == null)
            {
                //页面结尾动态区：prefix.+$
                pattern = Regex.Escape(prefix) + ".+\\z";
                replacement = prefix;
            }
            else
            {
                pattern = Regex.Escape(prefix) + ".+?" + Regex.Escape(suffix);
                replacement = prefix + suffix;
            }
            return new ChangeFeature
            {
                Prefix = prefix,
                Suffix = suffix,
                RegexPattern = pattern,
                Replacement = replacement,
                FeatureDescription = "动态区块（锚点剥离）"
            };
        }

        /// <summary>
        /// 提取页面结构骨架（sqlmap extractStructuralTokens移植）：
        /// 值无关的标签名/class/id令牌集合，排序后拼接——字节不稳定但结构稳定的页面按骨架比对，
        /// 动态文本（结果行/广告位）不再干扰相似度，而结构变化（结果表出现/消失）仍能体现。
        /// 返回null表示页面无可提取结构（无HTML标签），调用方应降级到其他比对方式
        /// </summary>
        public static string? ExtractStructuralTokens(string? page)
        {
            if (string.IsNullOrEmpty(page))
            {
                return null;
            }
            string cleaned = ScriptStyleCommentRegex().Replace(page, " ");
            var tokens = new SortedSet<string>(StringComparer.Ordinal);
            foreach (Match m in StructuralTagRegex().Matches(cleaned))
            {
                string tag = m.Groups[1].Value.ToLowerInvariant();
                string attrs = m.Groups[2].Value;
                tokens.Add("tag:" + tag);
                foreach (Match cm in StructuralClassRegex().Matches(attrs))
                {
                    string cls = cm.Groups[1].Success ? cm.Groups[1].Value : cm.Groups[2].Success ? cm.Groups[2].Value : cm.Groups[3].Value;
                    foreach (string v in cls.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
                    {
                        tokens.Add("cls:" + tag + "." + v);
                    }
                }
                foreach (Match im in StructuralIdRegex().Matches(attrs))
                {
                    string id = (im.Groups[1].Success ? im.Groups[1].Value : im.Groups[2].Success ? im.Groups[2].Value : im.Groups[3].Value).Trim();
                    if (id.Length > 0)
                    {
                        tokens.Add("id:" + tag + "#" + id);
                    }
                }
            }
            if (tokens.Count == 0)
            {
                return null;
            }
            StringBuilder sb = new StringBuilder();
            foreach (string t in tokens)
            {
                sb.Append(t).Append('\n');
            }
            return sb.ToString();
        }

        /// <summary>
        /// text-only投影（sqlmap getFilteredPageContent(page, onlyText=True)移植）：
        /// 剥script/style/注释/全部标签/制表换行，折叠空格——结构也不稳定时的终极兜底比对形态
        /// </summary>
        public static string GetFilteredPageContent(string? page)
        {
            if (string.IsNullOrEmpty(page))
            {
                return "";
            }
            string text = TextOnlyStripRegex().Replace(page, " ");
            text = MultiSpaceRegex().Replace(text, " ");
            return System.Net.WebUtility.HtmlDecode(text.Trim());
        }
    }

    /// <summary>
    /// 变化特征模型：前缀/后缀锚点对 + 移除正则与替换串（sqlmap dynamicMarkings项等价物）
    /// </summary>
    public class ChangeFeature
    {
        /// <summary>前锚点（动态区之前的稳定文本，null=动态区直达页面开头）</summary>
        public string? Prefix { get; set; }
        /// <summary>后锚点（动态区之后的稳定文本，null=动态区直达页面末尾）</summary>
        public string? Suffix { get; set; }
        /// <summary>动态区移除正则（含锚点，Singleline）</summary>
        public string RegexPattern { get; set; } = "";
        /// <summary>替换串（保留锚点本身）</summary>
        public string Replacement { get; set; } = "";
        /// <summary>特征描述（日志用）</summary>
        public string FeatureDescription { get; set; } = "";

        public override string ToString()
        {
            return $"【动态标记】前缀：[{Prefix ?? "<页首>"}] 后缀：[{Suffix ?? "<页尾>"}]";
        }
    }
}
