using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using DiffPlex;
using DiffPlex.DiffBuilder;
using DiffPlex.DiffBuilder.Model;

namespace SuperSQLInjectionV2.Tools
{
    /// <summary>
    /// 网页内容差异分析器（基于DiffPlex）
    /// 对比多版本网页，提取变化特征并生成适配不同长度的正则表达式
    /// </summary>
    public partial class WebPageDiffAnalyzer
    {
        /// <summary>动态特征正则编译缓存（特征由页面diff动态生成无法源生成；检测期每页比对都要跑，Compiled一次编译复用）</summary>
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, Regex> _featureRegexCache
            = new System.Collections.Concurrent.ConcurrentDictionary<string, Regex>();

        private static Regex GetFeatureRegex(string pattern)
        {
            if (_featureRegexCache.Count > 64)
            {
                _featureRegexCache.Clear();
            }
            return _featureRegexCache.GetOrAdd(pattern, p => new Regex(p, RegexOptions.Compiled));
        }

        /// <summary>UUID形态判定（常量模式源生成）</summary>
        [GeneratedRegex(@"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")]
        private static partial Regex UuidRegex();

        /// <summary>时间戳形态判定</summary>
        [GeneratedRegex(@"^\d{10,13}$")]
        private static partial Regex TimestampRegex();

        // 差异分析器实例
        private static ISideBySideDiffBuilder _diffBuilder =new SideBySideDiffBuilder(new Differ());

        // 最小变化片段长度（过滤极短噪声，如单个字符的偶然差异）
        private const int MinChangeLength = 1; // 放宽到1，保留短字符识别
        // 上下文截取长度（特征前后各取N个字符作为正则上下文）
        private const int ContextLength = 8; // 增加上下文长度，提升匹配精准度
        // 动态内容长度范围（适配常见动态内容长度）
        private const int MinDynamicLength = 1;
        private const int MaxDynamicLength = 100;

      
        /// <summary>
        /// 对比三个网页内容，提取变化特征并生成适配不同长度的正则
        /// </summary>
        /// <param name="page1">基准网页内容</param>
        /// <param name="page2">对比网页1</param>
        /// <param name="page3">对比网页2</param>
        /// <returns>变化特征列表（含正则、位置、特征描述）</returns>
        public static List<ChangeFeature> AnalyzeThreePages(string page1, string page2, string page3)
        {
            if (string.IsNullOrEmpty(page1) || string.IsNullOrEmpty(page2) || string.IsNullOrEmpty(page3))
                throw new ArgumentException("网页内容不能为空");

            // 1. 分别对比page1-page2、page1-page3的差异
            var diff1_2 = _diffBuilder.BuildDiffModel(page1, page2);
            var diff1_3 = _diffBuilder.BuildDiffModel(page1, page3);

            //2. 提取两个对比结果中共同的变化区域（以page1的位置为基准）
            var commonChangeBlocks = GetCommonChangeBlocks(diff1_2.OldText.Lines, diff1_3.OldText.Lines);

            // 3. 分析每个变化区块的特征，生成适配不同长度的正则
            var changeFeatures = new List<ChangeFeature>();
            foreach (var block in commonChangeBlocks)
            {
                var feature = AnalyzeChangeBlock(page1, block.StartIndex, block.Length);
                if (feature != null && !string.IsNullOrEmpty(feature.RegexPattern))
                {
                    changeFeatures.Add(feature);
                }
            }

            return changeFeatures;
        }

        /// <summary>
        /// 清除动态文本
        /// </summary>
        /// <param name="page1"></param>
        /// <param name="page2"></param>
        /// <param name="page3"></param>
        /// <param name="srcPage">要清除动态特征的原始文本</param>
        /// <returns></returns>
        public static string ClearDynamicText(string page1, string page2, string page3,string srcPage)
        {
            // 分析三个网页的变化特征
            var changeFeatures = AnalyzeThreePages(page1, page2, page3);

            foreach (var feature in changeFeatures)
            {
                srcPage = GetFeatureRegex(feature.RegexPattern).Replace(srcPage, "");
            }

            return srcPage;
        }


        /// <summary>
        /// 清除动态文本
        /// </summary>
        /// <param name="page1"></param>
        /// <param name="page2"></param>
        /// <param name="page3"></param>
        /// <param name="srcPage">要清除动态特征的原始文本</param>
        /// <returns></returns>
        public static string ClearDynamicText(List<ChangeFeature> changeFeatures,string srcPage)
        {

            foreach (var feature in changeFeatures)
            {
                srcPage = GetFeatureRegex(feature.RegexPattern).Replace(srcPage, "");
            }

            return srcPage;
        }

        /// <summary>
        /// 提取两个差异结果中共同的变化区块（基于基准文本的位置）
        /// </summary>
        private static List<ChangeBlock> GetCommonChangeBlocks(List<DiffPiece> diffLines1, List<DiffPiece> diffLines2)
        {
            // 第一步：从diffLines中提取所有变化的位置和长度
            var changeBlocks1 = ExtractChangeBlocks(diffLines1);
            var changeBlocks2 = ExtractChangeBlocks(diffLines2);
            changeBlocks1.AddRange(changeBlocks2); // 合并两个列表，后续通过位置重叠来筛选共同变化
           
            //// 第二步：找两个集合中重叠的变化区块（共同变化的部分）

            //            // 过滤过短的噪声（保留MinChangeLength及以上）
            //            if (length >= MinChangeLength)
            //            {
            //                commonBlocks.Add(new ChangeBlock(start, length));
            //            }
            //        }
            //    }
            //}

            //// 去重（合并重叠的区块）
            return MergeOverlappingBlocks(changeBlocks1);
        }

        /// <summary>
        /// 从DiffPlex的差异行中提取变化区块
        /// </summary>
        private static List<ChangeBlock> ExtractChangeBlocks(List<DiffPiece> diffLines)
        {
            var changeBlocks = new List<ChangeBlock>();
            int currentPosition = 0;

            foreach (var line in diffLines)
            {
                if (line.Type == ChangeType.Deleted || line.Type == ChangeType.Modified)
                {
                    // 只处理基准文本中被修改/删除的部分（变化的核心）
                    int lineLength = line.Text?.Length ?? 0;
                    if (lineLength >= MinChangeLength)
                    {
                        changeBlocks.Add(new ChangeBlock(currentPosition, lineLength));
                    }
                }
                // 更新当前位置（无论是否变化，都累加长度，包含换行符）
                currentPosition += line.Text?.Length ?? 0;
                currentPosition += Environment.NewLine.Length;
            }

            return changeBlocks;
        }

        /// <summary>
        /// 合并重叠/相邻的变化区块
        /// </summary>
        private static List<ChangeBlock> MergeOverlappingBlocks(List<ChangeBlock> blocks)
        {
            if (blocks.Count == 0) return new List<ChangeBlock>();

            // 按起始位置排序
            var sortedBlocks = blocks.OrderBy(b => b.StartIndex).ToList();
            var merged = new List<ChangeBlock> { sortedBlocks[0] };

            foreach (var block in sortedBlocks.Skip(1))
            {
                var last = merged.Last();
                // 检查是否重叠或相邻（包含相邻区块，避免拆分连续变化）
                if (block.StartIndex <= last.StartIndex + last.Length + 1)
                {
                    // 合并区块
                    int newStart = last.StartIndex;
                    int newEnd = Math.Max(last.StartIndex + last.Length, block.StartIndex + block.Length);
                    merged.Remove(last);
                    merged.Add(new ChangeBlock(newStart, newEnd - newStart));
                }
                else
                {
                    merged.Add(block);
                }
            }

            return merged;
        }

        /// <summary>
        /// 分析单个变化区块，提取特征并生成适配不同长度的正则表达式
        /// </summary>
        private static ChangeFeature? AnalyzeChangeBlock(string baseText, int startIndex, int length)
        {
            // 边界检查
            if (startIndex < 0 || startIndex + length > baseText.Length)
                return null;

            // 1. 提取变化区域的文本和上下文（扩大上下文提升匹配稳定性）
            string changeText = baseText.Substring(startIndex, length);
            int contextStart = Math.Max(0, startIndex - ContextLength);
            int contextEnd = Math.Min(baseText.Length, startIndex + length + ContextLength);
            string leftContext = baseText.Substring(contextStart, startIndex - contextStart);
            string rightContext = baseText.Substring(startIndex + length, contextEnd - (startIndex + length));

            // 2. 分析变化文本的特征
            var feature = new ChangeFeature
            {
                StartIndex = startIndex,
                EndIndex = startIndex + length - 1,
                OriginalText = changeText,
                LeftContext = leftContext,
                RightContext = rightContext
            };

            // 3. 生成适配不同长度的正则表达式
            string regexPattern = GenerateFlexibleRegexPattern(leftContext, changeText, rightContext);
            feature.RegexPattern = regexPattern;
            feature.FeatureDescription = GetFeatureDescription(changeText);

            return feature;
        }

        /// <summary>
        /// 生成适配不同长度的正则表达式（核心优化点）
        /// </summary>
        private static string GenerateFlexibleRegexPattern(string leftContext, string changeText, string rightContext)
        {
            // 转义上下文的特殊字符（避免正则语法冲突）
            string escapedLeft = Regex.Escape(leftContext);
            string escapedRight = Regex.Escape(rightContext);

            // 根据变化文本的特征生成**动态长度**的匹配模式
            string changePattern = GetFlexibleChangePattern(changeText);

            // 拼接完整正则（上下文 + 动态长度变化模式），添加边界约束
            return $"(?<={escapedLeft}){changePattern}(?={escapedRight})";
        }

        /// <summary>
        /// 根据变化文本的特征生成动态长度的匹配模式（取消固定长度限制）
        /// </summary>
        private static string GetFlexibleChangePattern(string changeText)
        {
            // 判断字符类型，生成适配不同长度的正则
            bool isAllDigit = changeText.All(char.IsDigit);
            bool isAllLetter = changeText.All(char.IsLetter);
            bool isAllLetterOrDigit = changeText.All(char.IsLetterOrDigit);
            bool isUUID = UuidRegex().IsMatch(changeText);
            bool isTimestamp = TimestampRegex().IsMatch(changeText);

            if (isUUID)
            {
                // UUID格式固定，保留精准匹配
                return @"[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}";
            }
            else if (isTimestamp)
            {
                // 时间戳匹配10-13位数字（适配常见的秒/毫秒级时间戳）
                return @"\d{10,13}";
            }
            else if (isAllDigit)
            {
                // 纯数字：匹配1-100位数字（适配任意长度数字）
                return $@"\d{{{MinDynamicLength},{MaxDynamicLength}}}";
            }
            else if (isAllLetter)
            {
                // 纯字母：匹配1-100位字母（大小写不敏感）
                return $@"[a-zA-Z]{{{MinDynamicLength},{MaxDynamicLength}}}";
            }
            else if (isAllLetterOrDigit)
            {
                // 字母数字混合：匹配1-100位字母数字
                return $@"[a-zA-Z0-9]{{{MinDynamicLength},{MaxDynamicLength}}}";
            }
            else
            {
                // 混合字符：匹配1-100位非空字符（排除换行符）
                return $@".{{{MinDynamicLength},{MaxDynamicLength}}}";
            }
        }

        /// <summary>
        /// 生成变化特征的描述信息（包含长度适配说明）
        /// </summary>
        private static string GetFeatureDescription(string changeText)
        {
            if (UuidRegex().IsMatch(changeText))
            {
                return "UUID格式字符串（固定格式）";
            }
            else if (TimestampRegex().IsMatch(changeText))
            {
                return "时间戳（10-13位数字）";
            }
            else if (changeText.All(char.IsDigit))
            {
                return $"数字序列（适配长度：{MinDynamicLength}-{MaxDynamicLength}位）";
            }
            else if (changeText.All(char.IsLetter))
            {
                return $"字母序列（适配长度：{MinDynamicLength}-{MaxDynamicLength}位）";
            }
            else if (changeText.All(char.IsLetterOrDigit))
            {
                return $"字母数字混合序列（适配长度：{MinDynamicLength}-{MaxDynamicLength}位）";
            }
            else
            {
                return $"混合字符序列（适配长度：{MinDynamicLength}-{MaxDynamicLength}位）";
            }
        }
    }

    /// <summary>
    /// 变化区块模型（记录位置和长度）
    /// </summary>
    public  class ChangeBlock
    {
        public int StartIndex { get; }
        public int Length { get; }

        public ChangeBlock(int startIndex, int length)
        {
            StartIndex = startIndex;
            Length = length;
        }
    }

    /// <summary>
    /// 变化特征模型（含适配不同长度的正则、位置、描述）
    /// </summary>
    public class ChangeFeature
    {
        // 位置信息
        public int StartIndex { get; set; }
        public int EndIndex { get; set; }
        // 文本内容
        public string OriginalText { get; set; } = "";
        public string LeftContext { get; set; } = "";
        public string RightContext { get; set; } = "";
        // 特征信息
        public string RegexPattern { get; set; } = "";
        public string FeatureDescription { get; set; } = "";

        /// <summary>
        /// 格式化输出特征信息（包含长度适配说明）
        /// </summary>
        public override string ToString()
        {
            return $"【变化特征】\n" +
                   $"位置：{StartIndex}-{EndIndex}\n" +
                   $"原始文本：{OriginalText}\n" +
                   $"上下文：{LeftContext}[{OriginalText}]{RightContext}\n" +
                   $"特征描述：{FeatureDescription}\n" +
                   $"适配不同长度的正则：{RegexPattern}\n" +
                   "------------------------";
        }
    }

}
