using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Irihi.Avalonia.Shared.Contracts;
using SuperSQLInjectionV2.Models;
using System;
using System.Collections.Generic;

namespace SuperSQLInjectionV2.Dialogs;

/// <summary>
/// 代理编辑弹窗：主机/端口/类型/账号/密码/启用状态，保存前校验主机与端口
/// </summary>
public partial class ProxyEditViewModel : ObservableObject, IDialogContext
{
    [ObservableProperty] private string _host = "";
    [ObservableProperty] private int _port = 80;
    [ObservableProperty] private string _proxyType = "Socks5";
    [ObservableProperty] private string _username = "";
    [ObservableProperty] private string _password = "";
    [ObservableProperty] private bool _isEnabled;
    [ObservableProperty] private string _status = "";

    public List<string> TypeItems { get; } = new() { "Socks5", "HTTP" };

    /// <summary>弹窗结果：true=保存，false=取消/关闭</summary>
    public bool Confirmed { get; private set; }

    public static ProxyEditViewModel FromItem(Proxy proxy)
    {
        return new ProxyEditViewModel
        {
            Host = proxy.Host,
            Port = proxy.Port,
            ProxyType = string.IsNullOrWhiteSpace(proxy.proxyType) ? "Socks5" : proxy.proxyType,
            Username = proxy.username,
            Password = proxy.password,
            IsEnabled = proxy.IsEnabled
        };
    }

    public void ApplyTo(Proxy proxy)
    {
        proxy.Host = Host?.Trim() ?? "";
        proxy.Port = Port;
        proxy.proxyType = ProxyType;
        proxy.username = Username?.Trim() ?? "";
        proxy.password = Password ?? "";
        proxy.IsEnabled = IsEnabled;
        //代理信息变更后原有验证结论作废
        proxy.IsOk = false;
        proxy.CheckTime = "";
        proxy.UseTime = 0;
    }

    [RelayCommand]
    private void Confirm()
    {
        if (string.IsNullOrWhiteSpace(Host))
        {
            Status = "主机不能为空！";
            return;
        }
        if (Port < 1 || Port > 65535)
        {
            Status = "端口必须在 1-65535 之间！";
            return;
        }
        Confirmed = true;
        Close();
    }

    [RelayCommand]
    private void Cancel()
    {
        Confirmed = false;
        Close();
    }

    public void Close()
    {
        RequestClose?.Invoke(this, null);
    }

    public event EventHandler<object?>? RequestClose;
}
