using System;
using System.ComponentModel;
using System.Globalization;
using System.Reflection;
using Avalonia.Data.Converters;
using SuperSQLInjectionV2.Models;

namespace SuperSQLInjectionV2.Converters;

/// <summary>
/// 注入类型/盲注判断方式的界面显示名转换器：
/// InjectType 用内置中文映射（Blind=Bool盲注、Time=时间盲注、Dns=DNS盲注等）；
/// BoolInjectType 优先读枚举的 Description 特性（关键字判断/状态码判断等），无特性回退枚举名
/// </summary>
public class InjectTypeNameConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is InjectType it)
        {
            return it switch
            {
                InjectType.Blind => "Bool盲注",
                InjectType.Time => "时间盲注",
                InjectType.Dns => "DNS盲注",
                InjectType.Stacked => "堆叠",
                InjectType.Union => "Union",
                InjectType.Error => "Error",
                _ => "UnKnow"
            };
        }
        if (value is Enum e)
        {
            FieldInfo? f = e.GetType().GetField(e.ToString());
            var attr = f?.GetCustomAttribute<DescriptionAttribute>();
            return attr?.Description ?? e.ToString();
        }
        return value?.ToString ()?? "";
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}
