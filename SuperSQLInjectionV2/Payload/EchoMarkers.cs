using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Tools;

namespace SuperSQLInjectionV2.Payload
{
    /// <summary>
    /// 回显标记会话持有者：Union/报错通道取数结果的包裹标记（起始/结束/分隔）。
    /// 模板提供默认值（data_/_data/_s_p_），检测命中后为每个注入点生成随机标记并随注入记录持久化，
    /// 避免固定短串与目标页面自然内容冲突导致取数解析误切。
    /// 消费方（TemplateDialect.ConcatData / DataComm解析 / DataTools拆列）统一从这里取，保证拼接与解析同源。
    /// </summary>
    public static class EchoMarkers
    {
        /// <summary>数据起始标记</summary>
        public static string Start { get; private set; } = "data_";
        /// <summary>数据结束标记</summary>
        public static string End { get; private set; } = "_data";
        /// <summary>多列分隔标记</summary>
        public static string Split { get; private set; } = "_s_p_";

        /// <summary>按模板默认值初始化（数据库类型切换/无记录的人工标记场景）</summary>
        public static void Init(BasePayload bp)
        {
            if (bp == null)
            {
                return;
            }
            Start = bp.DataStartStr;
            End = bp.DataEndStr;
            Split = bp.DataSplitStr;
        }

        /// <summary>应用注入记录携带的标记；记录无标记（旧记录）时回退模板默认值</summary>
        public static void Use(InjectRecord record, BasePayload bp)
        {
            if (record != null && !string.IsNullOrEmpty(record.StartMark)
                && !string.IsNullOrEmpty(record.EndMark) && !string.IsNullOrEmpty(record.SplitMark))
            {
                Start = record.StartMark;
                End = record.EndMark;
                Split = record.SplitMark;
                return;
            }
            Init(bp);
        }

        /// <summary>生成一组随机标记（字母数字下划线，正则/SQL字面量安全，三段互不相同）</summary>
        public static (string start, string end, string split) Generate()
        {
            string start = MyTools.RandStr(5).ToLowerInvariant ()+ "_";
            string end = "_" + MyTools.RandStr(5).ToLowerInvariant();
            string split = "_" + MyTools.RandStr(4).ToLowerInvariant ()+ "_";
            return (start, end, split);
        }
    }
}
