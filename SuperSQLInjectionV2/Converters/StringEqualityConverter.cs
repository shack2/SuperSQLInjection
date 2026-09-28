using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace SuperSQLInjectionV2.Converters;

/// <summary>
/// 字符串相等转换器：value 与 ConverterParameter 相等时返回 true。
/// 用于标签按钮组的选中态高亮（value=当前选中项，parameter=本项）。
/// </summary>
public class StringEqualityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return string.Equals(value as string, parameter as string, StringComparison.Ordinal);
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
