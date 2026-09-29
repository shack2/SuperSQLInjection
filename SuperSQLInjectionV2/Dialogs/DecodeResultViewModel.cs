using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Irihi.Avalonia.Shared.Contracts;
using System;

namespace SuperSQLInjectionV2.Dialogs;

/// <summary>
/// 解码结果弹窗：展示解码方式/原文/解码结果（请求日志payload与请求包/响应包右键解码菜单共用）
/// </summary>
public partial class DecodeResultViewModel : ObservableObject, IDialogContext
{
    /// <summary>解码方式名（如 URL解码/Base64）</summary>
    [ObservableProperty] private string _methodName = "";

    /// <summary>解码原文（选区或全文）</summary>
    [ObservableProperty] private string _sourceText = "";

    /// <summary>解码结果</summary>
    [ObservableProperty] private string _resultText = "";

    public DecodeResultViewModel(string methodName, string sourceText, string resultText)
    {
        MethodName = methodName;
        SourceText = sourceText;
        ResultText = resultText;
    }

    [RelayCommand]
    public void Close() => RequestClose?.Invoke(this, null);

    public event EventHandler<object?>? RequestClose;
}
