using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Irihi.Avalonia.Shared.Contracts;
using SuperSQLInjectionV2.Models;
using System;
using System.Text;

namespace SuperSQLInjectionV2.Dialogs;

/// <summary>
/// 注入记录详情弹窗（只读）：结构化展示记录的全部上下文字段，便于核对注入点配置
/// </summary>
public partial class InjectRecordDetailViewModel : ObservableObject, IDialogContext
{
    [ObservableProperty] private string _detailsText = "";

    public InjectRecordDetailViewModel(InjectRecord record)
    {
        DetailsText = Build(record);
    }

    private static string Build(InjectRecord r)
    {
        var sb = new StringBuilder();
        void Line(string name, string? value)
        {
            sb.Append(name.PadRight(14)).Append('：').AppendLine(string.IsNullOrEmpty(value) ? "-" : value);
        }
        Line("发现时间", r.Time.ToString("yyyy-MM-dd HH:mm:ss"));
        Line("目标", r.Target);
        Line("注入参数", r.PName);
        Line("注入位置", r.PlaceDesc);
        Line("数据库类型", r.DBType.ToString());
        Line("Fork库", string.IsNullOrEmpty(r.ForkName) ? "-（宿主库）" : r.ForkName);
        Line("注入类型", r.InjectTypeDesc);
        Line("盲注判断值", r.CheckValue);
        Line("判断取反", r.Revers ? "是" : "否");
        Line("注入上下文", r.BoundaryDesc);
        Line("Clause上下文", r.Clause);
        Line("Where语义", r.Where switch { 1 => "1=原值后追加", 2 => "2=负值替换", 3 => "3=参数整体替换", _ => r.Where.ToString() });
        Line("Union列数", r.InjectType == InjectType.Union ? r.SumColumnCount.ToString() : "-");
        Line("Union显示位", r.InjectType == InjectType.Union ? r.ShowColumnIndex.ToString() : "-");
        Line("Union起始payload", r.UnionStartPayLoad);
        Line("检测payload", r.TestPayload);
        Line("boundary前缀", r.Prefix);
        Line("boundary后缀", r.Suffix);
        Line("参数原始值", r.OrigValue);
        Line("vector模板", r.VectorTemplate);
        Line("自动tamper", r.AutoTamper);
        Line("真值状态码", r.TrueCode == 0 ? "-" : r.TrueCode.ToString());
        Line("假值状态码", r.FalseCode == 0 ? "-" : r.FalseCode.ToString());
        Line("报错净容量", r.ErrorChunkLen > 0 ? r.ErrorChunkLen + " 字符（实测）" : "-");
        Line("回显标记", string.IsNullOrEmpty(r.StartMark) ? "-" : r.StartMark + " … " + r.EndMark + "（分隔 " + r.SplitMark + "）");
        sb.AppendLine();
        sb.AppendLine("── 注入标记报文 ──");
        sb.AppendLine(string.IsNullOrEmpty(r.RequestTxt) ? "-" : r.RequestTxt);
        return sb.ToString();
    }

    [RelayCommand]
    public void Close() => RequestClose?.Invoke(this, null);

    public event EventHandler<object?>? RequestClose;
}
