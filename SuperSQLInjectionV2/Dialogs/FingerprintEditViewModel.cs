using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Irihi.Avalonia.Shared.Contracts;
using SuperSQLInjectionV2.Models.Detect;
using System;

namespace SuperSQLInjectionV2.Dialogs;

/// <summary>
/// 报错指纹查看/编辑/新增弹窗：DBMS + fork + 正则，保存前校验正则可编译
/// </summary>
public partial class FingerprintEditViewModel : ObservableObject, IDialogContext
{
    [ObservableProperty] private string _dbms = "";
    [ObservableProperty] private string _fork = "";
    [ObservableProperty] private string _regexp = "";
    [ObservableProperty] private string _status = "";

    /// <summary>弹窗结果：true=保存，false=取消/关闭</summary>
    public bool Confirmed { get; private set; }

    public static FingerprintEditViewModel FromItem(FingerprintItem? item)
    {
        var vm = new FingerprintEditViewModel();
        if (item != null)
        {
            vm.Dbms = item.Dbms;
            vm.Fork = item.Fork;
            vm.Regexp = item.Regexp;
        }
        return vm;
    }

    public void ApplyTo(FingerprintItem item)
    {
        item.Dbms = Dbms?.Trim ()?? "";
        item.Fork = Fork?.Trim ()?? "";
        item.Regexp = Regexp?.Trim ()?? "";
    }

    [RelayCommand]
    private void Confirm()
    {
        if (string.IsNullOrWhiteSpace(Dbms) || string.IsNullOrWhiteSpace(Regexp))
        {
            Status = "DBMS 和正则不能为空！";
            return;
        }
        try
        {
            _ = new System.Text.RegularExpressions.Regex(Regexp, System.Text.RegularExpressions.RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
        }
        catch (Exception e)
        {
            Status = "正则无法编译：" + e.Message;
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
