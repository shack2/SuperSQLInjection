using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using Avalonia.Styling;

namespace SuperSQLInjectionV2.Views;

public partial class TitleBarRightContent : UserControl
{
    /// <summary>GitHub 代码仓库地址</summary>
    private static readonly Uri RepoUri = new Uri("https://github.com/shack2/SuperSQLInjectionV2");

    public TitleBarRightContent()
    {
        InitializeComponent();
        // 构造时控件尚未挂到逻辑树，资源查找不可靠；挂树后再设置初始图标
        AttachedToVisualTree += (_, _) => UpdateThemeIcon();
    }

    /// <summary>跳转 GitHub 代码仓库（系统默认浏览器，跨平台 Launcher）</summary>
    private async void OpenRepo_Click(object? sender, RoutedEventArgs e)
    {
        TopLevel? top = TopLevel.GetTopLevel(this);
        if (top != null)
        {
            await top.Launcher.LaunchUriAsync(RepoUri);
        }
    }

    /// <summary>主题单击直接浅色/深色互换；跟随系统时按实际生效主题判定当前档位</summary>
    private void ToggleTheme_Click(object? sender, RoutedEventArgs e)
    {
        if (Application.Current is not App app) return;
        bool isDark = app.RequestedThemeVariant == ThemeVariant.Dark ||
                      (app.RequestedThemeVariant == ThemeVariant.Default &&
                       app.ActualThemeVariant == ThemeVariant.Dark);
        app.RequestedThemeVariant = isDark ? ThemeVariant.Light : ThemeVariant.Dark;
        UpdateThemeIcon();
    }

    /// <summary>图标与目标动作一致：当前深色显示太阳（点击切浅色），当前浅色显示月亮（点击切深色）</summary>
    private void UpdateThemeIcon()
    {
        if (Application.Current is not App app) return;
        bool isDark = app.RequestedThemeVariant == ThemeVariant.Dark ||
                      (app.RequestedThemeVariant == ThemeVariant.Default &&
                       app.ActualThemeVariant == ThemeVariant.Dark);
        string key = isDark ? "LgSun" : "LgMoon";
        if (Application.Current != null && Application.Current.TryFindResource(key, out object? geo) && geo is StreamGeometry g)
            ThemeIconPath.Data = g;
    }
}
