using System;
using System.Collections;
using System.Globalization;
using Avalonia.Data.Converters;

namespace SuperSQLInjectionV2.Converters;

/// <summary>
/// 集合为空转换器：值为 null、Count==0 或空集合时返回 true。
/// 用于表格空态水印的 IsVisible 绑定（空数据时显示"暂无数据"提示）。
/// </summary>
public class EmptyToBoolConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value switch
        {
            null => true,
            int n => n == 0,
            ICollection c => c.Count == 0,
            _ => false
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
