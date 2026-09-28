using System;
using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Data.Converters;
using Avalonia.Media;
using Avalonia.Styling;
using SuperSQLInjectionV2.Models;

namespace SuperSQLInjectionV2.Converters;

/// <summary>
/// 注入类型徽章配色转换器：ConverterParameter="bg" 返回底色，"fg" 返回文字色。
/// Union=绿（快通道）、Error=橙、Bool/时间/DNS盲注=主色蓝、堆叠=红、未知=灰。
/// 颜色取自 Dsg 主题令牌，随浅/暗主题自动切换。
/// </summary>
public class InjectTypeBadgeConverter : IValueConverter
{
    private static IBrush Res(string key, string fallback)
    {
        Application? app = Application.Current;
        if (app != null)
        {
            //手写解析必须显式带主题变体：无参 TryFindResource 以 Default 变体查找，
            //命中不了 ThemeDictionaries 的 Light/Dark 字典（应用跟随系统主题时 RequestedThemeVariant=Default，
            //需用 ActualThemeVariant 取系统实际明暗），否则暗色主题下落到浅色兜底色
            ThemeVariant? theme = app.RequestedThemeVariant;
            if (theme == null || theme == ThemeVariant.Default)
            {
                theme = app.ActualThemeVariant ?? ThemeVariant.Light;
            }
            if (app.TryFindResource(key, theme, out var v) && v is IBrush b)
            {
                return b;
            }
        }
        return new SolidColorBrush(Color.Parse(fallback));
    }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool bg = "bg".Equals(parameter as string, StringComparison.OrdinalIgnoreCase);
        InjectType t = value is InjectType it ? it : InjectType.UnKnow;
        return t switch
        {
            InjectType.Union => bg ? Res("DsgSuccessTint", "#E7F6EC") : Res("DsgSuccess", "#15A34A"),
            InjectType.Error => bg ? Res("DsgWarningTint", "#FBF2DD") : Res("DsgWarning", "#C77A08"),
            InjectType.Stacked => bg ? Res("DsgErrorTint", "#FDECEC") : Res("DsgError", "#DC2626"),
            InjectType.Blind or InjectType.Time or InjectType.Dns => bg ? Res("DsgPrimaryTint", "#EAF1FE") : Res("DsgPrimary", "#2563EB"),
            _ => bg ? Res("DsgSurface3", "#EAEEF4") : Res("DsgInk2", "#5B6372"),
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}
