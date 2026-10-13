using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;
using System.Text.Json.Serialization;

namespace SuperSQLInjectionV2.Models;


[JsonConverter(typeof(JsonStringEnumConverter<BoolInjectType>))]
public enum BoolInjectType
{
    [Description("关键字判断")] KeyWord,
    [Description("关键字正则判断")] RegexWord,
    [Description("状态码判断")] Code,
    [Description("时间")] Time,
    [Description("响应长度")] BodyLength,
    [Description("长度大于")] MaxLength,
    [Description("响应长度")] MinLength,
    /// <summary>页面相似度判断（sqlmap同款取数oracle）：高动态页面离散判断依据（关键字/状态码/长度）均不可靠时，
    /// 以检测期三档兜底确定的比对基准（清动态模板/结构骨架/纯文本）+阈值判定真假</summary>
    [Description("页面相似度判断")] Similarity,
}