using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Irihi.Avalonia.Shared.Contracts;
using SuperSQLInjectionV2.Bypass;
using SuperSQLInjectionV2.Models;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using Ursa.Controls;

namespace SuperSQLInjectionV2.Dialogs;

/// <summary>
/// 伴随请求规则编辑弹窗：新增/编辑一条前置（动态值抓取/生成回填&lt;DRule&gt;）或后置（二次注入取数）规则。
/// 编辑对象为规则副本（Clone），确认后由调用方 CopyFrom 写回原规则，取消不落任何改动。
/// 前置规则支持"测试抓取"：按当前编辑内容实际发伴随请求并提取随机值（与管道同一实现 BypassPipeline.FetchTokenAsync）。
/// </summary>
public partial class CompanionRuleEditViewModel : ObservableObject, IDialogContext
{
    private readonly AppConfig _config;

    /// <summary>编辑中的规则副本（UI直接绑定其属性）</summary>
    public CompanionRequestConfig Rule { get; }

    /// <summary>弹窗结果：true=保存，false=取消/关闭</summary>
    public bool Confirmed { get; private set; }

    /// <summary>规则类型选项</summary>
    public string[] KindNames { get; } = ["动态值（抓取/生成动态值回填<DRule>标记）", "二次注入（响应替代主响应取数）"];

    /// <summary>请求来源选项：动态值=报文/URL/脚本生成；二次注入=报文/URL</summary>
    public List<string> SourceModes => IsBefore ? _beforeSourceModes : _config.TokenFetchModes;
    private readonly List<string> _beforeSourceModes;

    /// <summary>请求方式选项（与主配置共用）</summary>
    public List<string> Methods => _config.TokenMethods;

    /// <summary>抓取脚本候选（防护绕过-随机值脚本页管理）</summary>
    public ObservableCollection<ScriptTamperModel> TokenScripts => _config.TokenScripts;

    /// <summary>是否为前置规则（提取规则区/测试抓取仅前置显示）</summary>
    public bool IsBefore => Rule.Kind == 0;

    [ObservableProperty] private bool _isTesting;

    [ObservableProperty] private string _testStatus = "";

    [ObservableProperty] private string _testResult = "";

    /// <summary>existing为null=新建（默认动态值、启用），否则编辑其副本</summary>
    public CompanionRuleEditViewModel(AppConfig config, CompanionRequestConfig? existing)
    {
        _config = config;
        _beforeSourceModes = new List<string>(config.TokenFetchModes) { "脚本生成" };
        Rule = existing?.Clone() ?? new CompanionRequestConfig
        {
            Kind = 0,
            Name = "新规则",
            Enabled = true
        };
        Rule.PropertyChanged += Rule_PropertyChanged;
    }

    /// <summary>脚本候选（防护绕过-动态值脚本页管理）：脚本生成来源=自主生成类型，脚本提取=请求抓取类型；对应类型为空时兜底显示全部</summary>
    public List<ScriptTamperModel> ScriptItems
    {
        get
        {
            int kind = Rule.SourceMode == 2 ? 1 : 0;
            var filtered = _config.TokenScripts.Where(s => s.Kind == kind).ToList();
            return filtered.Count > 0 ? filtered : _config.TokenScripts.ToList();
        }
    }

    /// <summary>
    /// 脚本下拉选中项（SelectedItem 编译绑定，与 Rule.ScriptName 按名称双向映射；替代 SelectedValueBinding 反射绑定）。
    /// setter 忽略 null：ItemsSource 刷新（来源切换）时 ComboBox 会先回写 null，不能因此误清用户已选脚本
    /// </summary>
    public ScriptTamperModel? SelectedScript
    {
        get => ScriptItems.FirstOrDefault(s => s.Name == Rule.ScriptName);
        set
        {
            if (value != null && Rule.ScriptName != value.Name)
            {
                Rule.ScriptName = value.Name;
                OnPropertyChanged();
            }
        }
    }

    private void Rule_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(CompanionRequestConfig.Kind))
        {
            //切到二次注入时，脚本生成来源不可用，回落为报文来源
            if (Rule.Kind == 1 && Rule.SourceMode == 2)
            {
                Rule.SourceMode = 0;
            }
            OnPropertyChanged(nameof(IsBefore));
            OnPropertyChanged(nameof(SourceModes));
        }
        if (e.PropertyName == nameof(CompanionRequestConfig.SourceMode))
        {
            OnPropertyChanged(nameof(ScriptItems));
            OnPropertyChanged(nameof(SelectedScript));
        }
    }

    /// <summary>添加脚本：按当前来源预设脚本类型（脚本生成→自主生成，其余→请求抓取），保存后加入脚本库并选中</summary>
    [RelayCommand]
    private async Task AddScript()
    {
        var vm = TokenScriptEditViewModel.FromModel(null, Rule.SourceMode == 2 ? 1 : 0);
        var options = new OverlayDialogOptions
        {
            FullScreen = false,
            HorizontalAnchor = HorizontalPosition.Center,
            VerticalAnchor = VerticalPosition.Center,
            HorizontalOffset = 0,
            VerticalOffset = 0,
            Mode = DialogMode.None,
            Buttons = DialogButton.None,
            Title = "添加动态值脚本",
            CanLightDismiss = true,
            CanDragMove = true,
            IsCloseButtonVisible = true,
            CanResize = true,
        };
        await OverlayDialog.ShowStandardAsync<TokenScriptEditView, TokenScriptEditViewModel>(vm, options: options);
        if (vm.Confirmed)
        {
            ScriptTamperModel item = vm.ToModel();
            _config.TokenScripts.Add(item);
            OnPropertyChanged(nameof(ScriptItems));
            Rule.ScriptName = item.Name;
            OnPropertyChanged(nameof(SelectedScript));
        }
    }

    /// <summary>测试获取（仅动态值）：按当前编辑内容实际抓取/生成动态值</summary>
    [RelayCommand]
    private async Task TestFetch()
    {
        if (IsTesting || Rule.Kind != 0)
        {
            return;
        }
        IsTesting = true;
        TestStatus = Rule.SourceMode == 2 ? "脚本执行中……" : "抓取中……";
        TestResult = "";
        try
        {
            //计时反馈抓取/脚本执行耗时（毫秒）
            var sw = System.Diagnostics.Stopwatch.StartNew();
            (string token, string? error) = await BypassPipeline.FetchTokenAsync(_config, Rule, "测试获取动态值");
            sw.Stop();
            if (error != null)
            {
                TestStatus = "失败：" + error;
            }
            else if (string.IsNullOrEmpty(token))
            {
                TestStatus = "执行成功但未获取到动态值，请检查截取规则/脚本，或查看HTTP发包记录确认响应内容。";
            }
            else
            {
                TestStatus = $"获取成功（耗时 {sw.ElapsedMilliseconds} 毫秒）";
                TestResult = token;
            }
        }
        finally
        {
            IsTesting = false;
        }
    }

    [RelayCommand]
    private void Confirm()
    {
        if (string.IsNullOrWhiteSpace(Rule.Name))
        {
            TestStatus = "规则名称不能为空！";
            return;
        }
        //标记名留空时按类型补默认值（空标记名也可作为默认规则工作，补上后可通过命名标记显式关联）
        if (string.IsNullOrWhiteSpace(Rule.TagName))
        {
            Rule.TagName = Rule.Kind == 1 ? "sencond" : "token";
        }
        if (Rule.TagName.Any(char.IsWhiteSpace))
        {
            TestStatus = "标记名不能包含空格！";
            return;
        }
        if (Rule.SourceMode == 1 && string.IsNullOrWhiteSpace(Rule.Url))
        {
            TestStatus = "URL来源模式下请填写请求URL！";
            return;
        }
        if (Rule.SourceMode == 0 && string.IsNullOrWhiteSpace(Rule.RequestTxt))
        {
            TestStatus = "报文来源模式下请粘贴规则请求报文！";
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
