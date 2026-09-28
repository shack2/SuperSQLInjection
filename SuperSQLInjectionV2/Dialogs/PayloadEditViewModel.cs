using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Irihi.Avalonia.Shared.Contracts;
using SuperSQLInjectionV2.Models.Detect;
using System;
using System.Collections.Generic;

namespace SuperSQLInjectionV2.Dialogs;

/// <summary>
/// 检测用例查看/编辑/新增弹窗：字段与用例XML规范一一对应，保存时校验标题+payload非空
/// </summary>
public partial class PayloadEditViewModel : ObservableObject, IDialogContext
{
    [ObservableProperty] private string _title = "";
    [ObservableProperty] private string _sTypeName = "布尔盲注";
    [ObservableProperty] private int _level = 1;
    [ObservableProperty] private int _risk = 1;
    [ObservableProperty] private string _clause = "1,2,3,8,9";
    [ObservableProperty] private string _where = "1";
    [ObservableProperty] private string _vector = "";
    [ObservableProperty] private string _payload = "";
    [ObservableProperty] private string _comment = "";
    [ObservableProperty] private string _dbms = "";
    [ObservableProperty] private string _dbmsExclude = "";
    /// <summary>目标文件显示（新增固定custom_user.xml，编辑为原文件，只读展示）</summary>
    [ObservableProperty] private string _fileName = "";
    [ObservableProperty] private string _status = "";

    public List<string> STypeNames => PayloadItem.STypeNames;

    /// <summary>弹窗结果：true=保存，false=取消/关闭</summary>
    public bool Confirmed { get; private set; }

    /// <summary>从已有用例创建（查看/编辑），为空则新增（默认custom_user.xml）</summary>
    public static PayloadEditViewModel FromItem(PayloadItem? item)
    {
        var vm = new PayloadEditViewModel();
        if (item != null)
        {
            vm.Title = item.Title;
            vm.STypeName = item.STypeName;
            vm.Level = item.Level;
            vm.Risk = item.Risk;
            vm.Clause = item.Clause;
            vm.Where = item.Where;
            vm.Vector = item.Vector;
            vm.Payload = item.Payload;
            vm.Comment = item.Comment;
            vm.Dbms = item.Dbms;
            vm.DbmsExclude = item.DbmsExclude;
            vm.FileName = item.FileName;
        }
        else
        {
            vm.Title = "自定义用例" + DateTime.Now.ToString("HHmmss");
            vm.FileName = Tools.Inject.InjectPayloadManager.UserFile;
        }
        return vm;
    }

    /// <summary>把编辑内容写回用例项</summary>
    public void ApplyTo(PayloadItem item)
    {
        item.Title = Title?.Trim ()?? "";
        item.STypeName = STypeName;
        item.Level = Level;
        item.Risk = Risk;
        item.Clause = Clause ?? "";
        item.Where = Where ?? "";
        item.Vector = Vector ?? "";
        item.Payload = Payload ?? "";
        item.Comment = Comment ?? "";
        item.Dbms = Dbms ?? "";
        item.DbmsExclude = DbmsExclude ?? "";
    }

    [RelayCommand]
    private void Confirm()
    {
        if (string.IsNullOrWhiteSpace(Title) || string.IsNullOrWhiteSpace(Payload))
        {
            Status = "标题和payload不能为空！";
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
