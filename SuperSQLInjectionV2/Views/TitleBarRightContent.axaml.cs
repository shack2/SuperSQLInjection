using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;

namespace SuperSQLInjectionV2.Views;

public partial class TitleBarRightContent : UserControl
{
    /// <summary>GitHub 代码仓库地址</summary>
    private static readonly Uri RepoUri = new Uri("https://github.com/shack2/SuperSQLInjectionV2");

    public TitleBarRightContent()
    {
        InitializeComponent();
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
}
