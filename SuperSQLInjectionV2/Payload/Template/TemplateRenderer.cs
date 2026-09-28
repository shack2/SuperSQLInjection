using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace SuperSQLInjectionV2.Payload
{
    /// <summary>
    /// 命名占位符模板渲染引擎：把模板中的 {expr}/{db}/{table}/{rowIndex}/{cols} 等命名槽位替换为实参。
    /// 取代原 string.Format 位置占位符（{0}~{6}），模板槽位含义自解释、各库可只引用需要的槽位
    /// （如 SQLite/Access 模板无 {db} 槽位），方言差异收敛到模板本身。
    /// 未知名称保留原样（容错用户自定义模板）。
    /// 命名词汇表：
    ///   expr=表达式 start/len=截子串位置 value=布尔比较值 cond/sleep/alias=时间盲注条件/秒数/别名
    ///   cols=列串或数据表达式 db=库名 table=表名 rowIndex=行索引(0基，top/rownumber系由方言+1)
    ///   where=where片段 batchSize=批量行数 fill=Union外层填充列串 index=枚举序号
    ///   split/startMark/endMark=数据分隔/起始/结束标记字面量
    /// </summary>
    public static partial class TemplateRenderer
    {
        [GeneratedRegex(@"\{([a-zA-Z][a-zA-Z0-9_]*)\}")]
        private static partial Regex TokenRegex();

        public static string Render(string? template, IReadOnlyDictionary<string, object?> args)
        {
            if (string.IsNullOrEmpty(template) || args == null || args.Count == 0)
            {
                return template ?? "";
            }
            return TokenRegex().Replace(template, m =>
                args.TryGetValue(m.Groups[1].Value, out object? v) ? v?.ToString() ?? "" : m.Value);
        }

        public static string Render(string? template, params (string Name, object? Value)[] args)
        {
            if (string.IsNullOrEmpty(template) || args == null || args.Length == 0)
            {
                return template ?? "";
            }
            Dictionary<string, object?> dict = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            foreach ((string name, object? value) in args)
            {
                dict[name] = value;
            }
            return Render(template, dict);
        }
    }
}
