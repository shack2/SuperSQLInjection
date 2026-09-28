using System;

namespace SuperSQLInjectionV2.Tools
{

    public class PageLikeTool
    {
        /// <summary>
        /// 计算两个字符串的相似度（等价Python difflib.SequenceMatcher.ratio），
        /// 范围 0.0-1.0，1.0 表示完全相同。
        /// 内部使用内存安全的 b2j 索引算法，可安全用于大网页。
        /// </summary>
        /// <param name="a">第一个字符串</param>
        /// <param name="b">第二个字符串</param>
        /// <returns>相似度，范围0-1，1表示完全相同</returns>
        public static double CalculateSimilarity(string? a, string? b)
        {
            return DiffLib.Ratio(a, b);
        }

        /// <summary>
        /// 检查两个页面是否相似
        /// </summary>
        /// <param name="originalContent">原始页面内容</param>
        /// <param name="testContent">测试页面内容</param>
        /// <param name="threshold">相似度阈值，默认0.98（与UPPER_RATIO_BOUND一致）</param>
        /// <returns>是否相似</returns>
        public static bool IsSimilar(string originalContent, string testContent, double threshold = 0.98)
        {
            double similarity = CalculateSimilarity(originalContent, testContent);
            return similarity >= threshold;
        }
    }
}
