namespace SuperSQLInjectionV2.Tools.Inject
{
    /// <summary>
    /// 检测判定阈值统一收拢：相似度/差值/WAF状态码/Union阈值/技术遍历顺序等判定口径在此声明，
    /// 检测引擎统一引用，调参只改一处。
    /// </summary>
    internal static class DetectTuning
    {
        /// <summary>默认相似度阈值：真值页>=0.98视为与模板一致</summary>
        public const double UpperBound = 0.98;

        /// <summary>真假页相似度差值>=0.02视为可区分</summary>
        public const double MinDelta = 0.02;

        /// <summary>相似度下界（sqlmap LOWER_RATIO_BOUND同款）：低于此值视为与模板完全不同</summary>
        public const double LowerBound = 0.02;

        /// <summary>matchRatio锚点容差（sqlmap DIFF_TOLERANCE同款）：真值页ratio需高出锚点此值才视为与模板一致</summary>
        public const double DiffTolerance = 0.05;

        /// <summary>相似度灰区半宽：ratio与判定阈值的距离小于此值视为不可判定（取数链路灰区重发，sqlmap comparison返回None同款语义）</summary>
        public const double SimGrayZone = 0.01;

        /// <summary>WAF拦截状态码（401未授权/403禁止/406不接受/429限流/501不支持）：Send拦截统计与布尔WAF假象否决共用</summary>
        public static readonly int[] WafBlockCodes = { 401, 403, 406, 429, 501 };

        /// <summary>Union列数探测的相似度阈值</summary>
        public const double UnionBound = 0.95;

        /// <summary>检测技术遍历顺序：布尔→报错→Union→堆叠→时间→内联（确认即停）</summary>
        public static readonly int[] TechniqueOrder = { 1, 2, 6, 4, 5, 3 };
    }
}
