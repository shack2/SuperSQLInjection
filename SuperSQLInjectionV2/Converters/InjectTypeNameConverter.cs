using System;
using System.Globalization;
using Avalonia.Data.Converters;
using SuperSQLInjectionV2.Models;

namespace SuperSQLInjectionV2.Converters;

/// <summary>
/// 枚举的界面显示名转换器（AOT 安全：全部编译期映射，不用反射读 Description 特性）：
/// InjectType 用内置中文映射（Blind=Bool盲注、Time=时间盲注、Dns=DNS盲注等）；
/// 其余枚举（BoolInjectType/DBType/EncodePos/ScriptScope/ParamPlace/ErrorInjectType）
/// 按各自 Description 特性的文案逐一映射，未覆盖的枚举回退枚举名。
/// </summary>
public class InjectTypeNameConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value switch
        {
            InjectType it => it switch
            {
                InjectType.Blind => "Bool盲注",
                InjectType.Time => "时间盲注",
                InjectType.Dns => "DNS盲注",
                InjectType.Stacked => "堆叠",
                InjectType.Union => "Union",
                InjectType.Error => "Error",
                _ => "UnKnow"
            },
            BoolInjectType b => b switch
            {
                BoolInjectType.KeyWord => "关键字判断",
                BoolInjectType.RegexWord => "关键字正则判断",
                BoolInjectType.Code => "状态码判断",
                BoolInjectType.Time => "时间",
                BoolInjectType.BodyLength => "响应长度",
                BoolInjectType.MaxLength => "长度大于",
                BoolInjectType.MinLength => "响应长度",
                _ => b.ToString()
            },
            DBType d => d switch
            {
                DBType.UnKnow => "未知",
                DBType.Access => "Access",
                DBType.MySQL => "MySQL",
                DBType.SQLServer => "SQLServer",
                DBType.Oracle => "Oracle",
                DBType.PostgreSQL => "PostgreSQL",
                DBType.DB2 => "DB2",
                DBType.SQLite => "SQLite",
                DBType.Informix => "Informix",
                DBType.DM => "达梦DM",
                DBType.Kingbase => "人大金仓KingbaseES",
                DBType.OpenGauss => "openGauss",
                DBType.H2 => "H2",
                DBType.HSQLDB => "HSQLDB",
                DBType.ClickHouse => "ClickHouse",
                _ => d.ToString()
            },
            EncodePos ep => ep switch
            {
                EncodePos.Any => "全部位置",
                EncodePos.QueryOnly => "仅编码位",
                EncodePos.RawOnly => "仅原文位",
                _ => ep.ToString()
            },
            ScriptScope ss => ss switch
            {
                ScriptScope.Payload => "Payload级",
                ScriptScope.Request => "报文级",
                _ => ss.ToString()
            },
            ParamPlace pp => pp switch
            {
                ParamPlace.Query => "GET参数",
                ParamPlace.BodyForm => "POST表单",
                ParamPlace.BodyJson => "JSON请求体",
                ParamPlace.BodyXml => "XML/SOAP体",
                ParamPlace.BodyMultipart => "Multipart表单",
                ParamPlace.Cookie => "Cookie",
                ParamPlace.Header => "HTTP头",
                ParamPlace.Uri => "URI路径段",
                _ => pp.ToString()
            },
            ErrorInjectType ei => ei switch
            {
                ErrorInjectType.FloorRand => "FloorRand",
                ErrorInjectType.RawToHex => "RawToHex",
                _ => ei.ToString()
            },
            Enum e => e.ToString(),
            _ => value?.ToString() ?? ""
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}
