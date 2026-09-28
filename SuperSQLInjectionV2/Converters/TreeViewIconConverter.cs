using Avalonia;
using Avalonia.Data.Converters;
using Avalonia.Metadata;
using SuperSQLInjectionV2.Models.Data;
using System;
using System.Collections.Generic;
using System.Globalization;

namespace SuperSQLInjectionV2.Converters;

public class TreeViewIconConverter : IMultiValueConverter
{
    [Content] public IDictionary<string, object?> Items { get; } = new Dictionary<string, object?>();

    public object? Convert(IList<object?> values, Type targetType, object? parameter, CultureInfo culture)
    {

        if (values[0] is DBStructType Type && values[1] is bool IsExpanded)
        {
            if (values[0] is DBStructType.DBName)
            {
                return Items["IconDataBase"];
            }
            else if (values[0] is DBStructType.TableName)
            {
                return Items["IconTable"];
            }

            else if (values[0] is DBStructType.ColumnName)
            {
                return Items["IconTable"];
            }
        }

       
        return AvaloniaProperty.UnsetValue;
    }
}