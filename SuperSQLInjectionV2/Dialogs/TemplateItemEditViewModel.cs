using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Irihi.Avalonia.Shared.Contracts;
using SuperSQLInjectionV2.Models;
using System;

namespace SuperSQLInjectionV2.Dialogs;

/// <summary>
/// 取数模板项编辑弹窗：Key/Value编辑，用途描述随Key自动刷新（来自BasePayload.KeyDescriptions）
/// </summary>
public partial class TemplateItemEditViewModel : ObservableObject, IDialogContext
{
    [ObservableProperty] private string _key = "";

    [ObservableProperty] private string _value = "";

    [ObservableProperty] private string _desc = "";

    [ObservableProperty] private string _status = "";

    /// <summary>弹窗结果：true=保存，false=取消/关闭</summary>
    public bool Confirmed { get; private set; }

    /// <summary>从已有模型创建（编辑），为空则新建</summary>
    public static TemplateItemEditViewModel FromModel(PayloadTemplateItem? item)
    {
        var vm = new TemplateItemEditViewModel();
        if (item != null)
        {
            vm.Key = item.Key;
            vm.Value = item.Value;
            vm.Desc = item.Desc;
        }
        return vm;
    }

    partial void OnKeyChanged(string value)
    {
        Desc = Payload.BasePayload.GetKeyDescription(value);
    }

    /// <summary>把编辑内容写回模型</summary>
    public void ApplyTo(PayloadTemplateItem item)
    {
        item.Key = Key?.Trim ()?? "";
        item.Value = Value ?? "";
    }

    /// <summary>生成新模型</summary>
    public PayloadTemplateItem ToModel()
    {
        var item = new PayloadTemplateItem();
        ApplyTo(item);
        return item;
    }

    [RelayCommand]
    private void Confirm()
    {
        if (string.IsNullOrWhiteSpace(Key))
        {
            Status = "模板Key不能为空！";
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
