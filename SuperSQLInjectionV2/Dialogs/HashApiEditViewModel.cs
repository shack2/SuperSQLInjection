using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Irihi.Avalonia.Shared.Contracts;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Tools;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Dialogs;

/// <summary>
/// Hash在线解密接口编辑弹窗：名称/URL（{hash}占位）/方法/POST数据/提取正则/启用，
/// 内置"测试"区：输入测试hash真实发一包验证接口与正则是否还有效。
/// </summary>
public partial class HashApiEditViewModel : ObservableObject, IDialogContext
{
    [ObservableProperty] private string _name = "";
    [ObservableProperty] private string _url = "";
    [ObservableProperty] private int _methodIndex = 0;
    [ObservableProperty] private bool _postVisible = false;
    [ObservableProperty] private string _postData = "";
    [ObservableProperty] private int _contentTypeIndex = 0;
    [ObservableProperty] private string _tokenRegex = "";
    [ObservableProperty] private string _regex = "";
    [ObservableProperty] private bool _enable = true;
    [ObservableProperty] private string _status = "";

    [ObservableProperty] private string _testHash = "";
    [ObservableProperty] private string _testResult = "";
    [ObservableProperty] private bool _testing = false;

    public List<string> MethodItems { get; } = new() { "GET", "POST" };

    /// <summary>POST Content-Type 选项（索引与 ToItem/FromItem 互转一致）</summary>
    public List<string> ContentTypeItems { get; } = new() { "application/x-www-form-urlencoded", "application/json" };

    /// <summary>弹窗结果：true=保存，false=取消/关闭</summary>
    public bool Confirmed { get; private set; }

    private readonly AppConfig _config;

    partial void OnMethodIndexChanged(int value)
    {
        PostVisible = value == 1;
    }

    public HashApiEditViewModel(AppConfig config)
    {
        _config = config;
    }

    public static HashApiEditViewModel FromItem(AppConfig config, HashApiConfig? item)
    {
        var vm = new HashApiEditViewModel(config);
        if (item != null)
        {
            vm.Name = item.Name;
            vm.Url = item.Url;
            vm.MethodIndex = "POST".Equals(item.Method, StringComparison.OrdinalIgnoreCase) ? 1 : 0;
            vm.PostData = item.PostData;
            vm.ContentTypeIndex = item.PostContentType.Contains("json", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
            vm.TokenRegex = item.TokenRegex;
            vm.Regex = item.Regex;
            vm.Enable = item.Enable;
        }
        return vm;
    }

    /// <summary>草稿对象（测试与保存共用）</summary>
    public HashApiConfig ToItem()
    {
        return new HashApiConfig
        {
            Name = Name?.Trim() ?? "",
            Url = Url?.Trim() ?? "",
            Method = MethodIndex == 1 ? "POST" : "GET",
            PostData = PostData ?? "",
            PostContentType = ContentTypeIndex == 1 ? "application/json" : "application/x-www-form-urlencoded",
            TokenRegex = TokenRegex?.Trim() ?? "",
            Regex = Regex?.Trim() ?? "",
            Enable = Enable
        };
    }

    public void ApplyTo(HashApiConfig item)
    {
        HashApiConfig draft = ToItem();
        item.Name = draft.Name;
        item.Url = draft.Url;
        item.Method = draft.Method;
        item.PostData = draft.PostData;
        item.PostContentType = draft.PostContentType;
        item.TokenRegex = draft.TokenRegex;
        item.Regex = draft.Regex;
        item.Enable = draft.Enable;
    }

    [RelayCommand]
    private async Task TestAsync()
    {
        if (Testing)
        {
            return;
        }
        if (string.IsNullOrWhiteSpace(TestHash))
        {
            TestResult = "请输入测试hash！";
            return;
        }
        string? err = Validate(out _);
        if (err != null)
        {
            TestResult = err;
            return;
        }
        Testing = true;
        TestResult = "请求中…";
        try
        {
            HashCrackTool.CrackReply reply = await HashCrackTool.QueryOneAsync(_config, ToItem(), TestHash.Trim());
            TestResult = reply.Found
                ? "解密成功：" + reply.Text + "（" + reply.CostMs + "ms）"
                : "未解密成功：" + reply.Error + "（" + reply.CostMs + "ms）";
        }
        finally
        {
            Testing = false;
        }
    }

    private string? Validate(out HashApiConfig draft)
    {
        draft = ToItem();
        if (draft.Name.Length == 0)
        {
            return "名称不能为空！";
        }
        if (!draft.Url.Contains(HashApiConfig.HashPlaceholder, StringComparison.Ordinal)
            && !(draft.Method == "POST" && draft.PostData.Contains(HashApiConfig.HashPlaceholder, StringComparison.Ordinal)))
        {
            return "URL或POST数据中必须包含 " + HashApiConfig.HashPlaceholder + " 占位符！";
        }
        if (draft.Regex.Length == 0)
        {
            return "提取正则不能为空！";
        }
        try
        {
            _ = new System.Text.RegularExpressions.Regex(draft.Regex);
            if (draft.TokenRegex.Length > 0)
            {
                _ = new System.Text.RegularExpressions.Regex(draft.TokenRegex);
            }
        }
        catch (Exception e)
        {
            return "正则无效：" + e.Message;
        }
        return null;
    }

    [RelayCommand]
    private void Confirm()
    {
        string? err = Validate(out _);
        if (err != null)
        {
            Status = err;
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
