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
}