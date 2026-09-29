using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Notifications;
using Avalonia.Input.Platform;
using Avalonia.Media;
using Avalonia.Styling;
using Avalonia.Threading;
using AvaloniaEdit;
using AvaloniaEdit.Editing;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Semi.Avalonia;
using SuperSQLInjectionV2.Dialogs;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Models.Data;
using SuperSQLInjectionV2.Models.Detect;
using SuperSQLInjectionV2.Bypass;
using SuperSQLInjectionV2.Payload;
using SuperSQLInjectionV2.Source;
using SuperSQLInjectionV2.Tools;
using SuperSQLInjectionV2.Tools.Http;
using SuperSQLInjectionV2.Tools.Update;
using UpdateManager = SuperSQLInjectionV2.Tools.Update.UpdateManager;
using UpdateManagerOptions = SuperSQLInjectionV2.Tools.Update.UpdateManagerOptions;
using UpdateManifest = SuperSQLInjectionV2.Tools.Update.UpdateManifest;
using UpdateProgress = SuperSQLInjectionV2.Tools.Update.UpdateProgress;
using SuperSQLInjectionV2.ViewModels.Tools;
using SuperSQLInjectionV2.Views;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using Ursa.Controls;

namespace SuperSQLInjectionV2.ViewModels;

public partial class MainViewViewModel : ViewModelBase
{
        private static readonly string[] s_allFilterOption = { "全部" };


    [ObservableProperty] private bool _isRuning = true;

    public DataDumpViewModel? DataDumpViewModel { set; get; }


    public Ursa.Controls.WindowNotificationManager? NotificationManager { get; set; }
    public MainView? MainView { get; set; }

    public IClipboard?  Clipboard { get; set; }

    [ObservableProperty] private AppConfig _appConfig=new AppConfig();

    /// <summary>
    /// 编码转换工具
    /// </summary>
    public EncodeToolsViewModel EncodeTools { get; } = new EncodeToolsViewModel();

    private Task? RunTask;


    [RelayCommand]
    private void StartGetVersInfo()
    {
        AppConfig.ResetStop();
        if (!EnsureDataOpReady(AppConfig))
        {
            return;
        }
        RunTask = GetVersInfo();
        IsRuning = true;
        WorkRunner.OnCompletedSurfaced(RunTask,  ()=>
        {
            IsRuning = false;
            if (AppConfig.StopSignal)
            {
                NotificationManager?.Show("已停止获取环境变量！");
            }
            else
            {
                NotificationManager?.Show("获取环境变量完成！");
            }
        });
    }

    /// <summary>
    /// 停止所有正在运行的线程任务
    /// </summary>
    [RelayCommand]
    private void StopAll()
    {
        //置停止信号+取消令牌：取消所有未派发迭代，在飞socket读取立即中断
        AppConfig.SignalStop();
        IsRuning = false;
        AppConfig.IsRuning = false;
        Log.Show("已发出停止线程信号！");
    }



    [RelayCommand]
    private void ClearLogs()
    {
        AppConfig.RequestLog.Items.Clear();
    }

    [RelayCommand]
    private void CopyPayload()
    {
        if (AppConfig.RequestLog.SelectItem != null&&Clipboard!=null) {

            Clipboard.SetTextAsync((string)AppConfig.RequestLog.SelectItem.Payload);
        }
    }

    private async Task GetVersInfo()
    {
        try
        {
            if (AppConfig.DataConfig.SelectedDBType.Equals(DBType.UnKnow))
            {
                Log.Warning("未识别数据库类型，无法确定取数模板！请执行注入检测自动识别，或在数据操作页手动选择数据库类型。");
                return;
            }
            await InjectChannelRouter.DispatchAsync(AppConfig, "读取环境变量",
                async  ()=> await VersTools.GetVersByBool(AppConfig),
                 ()=> { VersTools.GetVersByEcho(AppConfig); return Task.CompletedTask; });
        }
        catch (OperationCanceledException)
        {
            Log.Show("已停止获取环境变量！");
        }
    }


    [RelayCommand]
    private void SelectVersAll()
    {
        foreach (var x in AppConfig.DataConfig.VersItems) { x.IsChecked = true; }
    }

    //---- Hash读取（与环境变量同机制，条目来自取数模板中Hash/DBA/sysadmin类分流）----

    [RelayCommand]
    private void StartGetHashInfo()
    {
        AppConfig.ResetStop();
        if (!EnsureDataOpReady(AppConfig))
        {
            return;
        }
        RunTask = GetHashInfo();
        IsRuning = true;
        WorkRunner.OnCompletedSurfaced(RunTask,  ()=>
        {
            IsRuning = false;
            if (AppConfig.StopSignal)
            {
                NotificationManager?.Show("已停止Hash读取！");
            }
            else
            {
                NotificationManager?.Show("Hash读取完成！");
            }
        });
    }

    private async Task GetHashInfo()
    {
        try
        {
            if (AppConfig.DataConfig.SelectedDBType.Equals(DBType.UnKnow))
            {
                Log.Warning("未识别数据库类型，无法确定取数模板！请执行注入检测自动识别，或在数据操作页手动选择数据库类型。");
                return;
            }
            var items = AppConfig.DataConfig.HashItems;
            await InjectChannelRouter.DispatchAsync(AppConfig, "Hash读取",
                //Hash类值有明确上界（MD5=32/MySQL口令41/SQLServer pwdhash hex≈140），maxLen收窄256省长度探测
                async  ()=> await VersTools.GetVersByBool(AppConfig, items, 256),
                 ()=> { VersTools.GetVersByEcho(AppConfig, items); return Task.CompletedTask; });
        }
        catch (OperationCanceledException)
        {
            Log.Show("已停止Hash读取！");
        }
    }

    [RelayCommand]
    private void SelectHashAll()
    {
        foreach (var x in AppConfig.DataConfig.HashItems) { x.IsChecked = true; }
    }

    [RelayCommand]
    private void ReverseSelectHash()
    {
        foreach (var item in AppConfig.DataConfig.HashItems)
        {
            item.IsChecked = !item.IsChecked;
        }
    }

    //---- 权限角色枚举（与Hash读取同机制，条目来自取数模板中权限/角色类分流，对标业界同类工具 --privileges/--roles）----

    [RelayCommand]
    private void StartGetPrivInfo()
    {
        AppConfig.ResetStop();
        if (!EnsureDataOpReady(AppConfig))
        {
            return;
        }
        RunTask = GetPrivInfo();
        IsRuning = true;
        WorkRunner.OnCompletedSurfaced(RunTask,  ()=>
        {
            IsRuning = false;
            if (AppConfig.StopSignal)
            {
                NotificationManager?.Show("已停止权限角色读取！");
            }
            else
            {
                NotificationManager?.Show("权限角色读取完成！");
            }
        });
    }

    private async Task GetPrivInfo()
    {
        try
        {
            if (AppConfig.DataConfig.SelectedDBType.Equals(DBType.UnKnow))
            {
                Log.Warning("未识别数据库类型，无法确定取数模板！请执行注入检测自动识别，或在数据操作页手动选择数据库类型。");
                return;
            }
            var items = AppConfig.DataConfig.PrivItems;
            if (!items.Any())
            {
                Log.Warning("当前数据库无权限/角色枚举模板（SQLite/Access/Informix不支持）！");
                return;
            }
            await InjectChannelRouter.DispatchAsync(AppConfig, "权限角色读取",
                async  ()=> await VersTools.GetVersByBool(AppConfig, items),
                 ()=> { VersTools.GetVersByEcho(AppConfig, items); return Task.CompletedTask; });
        }
        catch (OperationCanceledException)
        {
            Log.Show("已停止权限角色读取！");
        }
    }

    [RelayCommand]
    private void SelectPrivAll()
    {
        foreach (var x in AppConfig.DataConfig.PrivItems) { x.IsChecked = true; }
    }

    [RelayCommand]
    private void ReverseSelectPriv()
    {
        foreach (var item in AppConfig.DataConfig.PrivItems)
        {
            item.IsChecked = !item.IsChecked;
        }
    }


    [RelayCommand]
    private void AddRepaceModel()
    {
        if (string.IsNullOrEmpty(AppConfig.ByPassConfig.AddReplaceItem.Src)) //源字符为空时规则无意义（执行计划层也会跳过），直接拦截
        {
            NotificationManager?.Show("源字符不能为空！");
            return;
        }
        AppConfig.ByPassConfig.AddReplaceItem.Index = AppConfig.ByPassConfig.ReplaceItems.Count+1;
        AppConfig.ByPassConfig.ReplaceItems.Add(AppConfig.ByPassConfig.AddReplaceItem);
        AppConfig.ByPassConfig.AddReplaceItem = new();
        NotificationManager?.Show("添加成功！");
    }

    [RelayCommand]
    private void ReverseSelectVers()
    {
        ObservableCollection<VersModel>? versItems = AppConfig.DataConfig.VersItems;
        if (versItems!=null&& versItems.Count > 0) {
            foreach (var item in versItems)
            {
                if (item.IsChecked)
                {
                    item.IsChecked = false;
                }
                else
                {
                    item.IsChecked = true;
                }
            }
        }
    }

    [RelayCommand]
    private async Task StartCheckInject()
    {
        AppConfig.ResetStop();
        //新一轮检测：复位上一注入记录的vector取数模式，命中新记录时会重新写入
        AppConfig.DataConfig.ResetVectorMode();
        if (AppConfig.TxtDetectRequest.Text.Contains(ConstData.GetInjectPoint(), StringComparison.Ordinal))
        {
            Log.Show("检测报文中含注入标记，已自动剥离标记后检测！" );
        }

        HttpRequest request = new HttpRequest(AppConfig, AppConfig.DetectRequestTxt);
        if (request.Params.Count < 1)
        {

            Log.Show("未发现参数！");
            return;

        }
        //获取原始的页面信息
        HttpResponse coserver = await HTTPTool.SendRequestRetryAsync(request);


        //判断是否有编码设置
        if (!AppConfig.AutoEncode)
        {
            //自定义
            if (!AppConfig.PageEncoding.Equals(coserver.PageEncoding, StringComparison.Ordinal))
            {
                var result = await OverlayMessageBox.ShowAsync("自动识别发现网页编码为" + coserver.PageEncoding + "，而你选择的编码是" + AppConfig.PageEncoding + "，是否采用自定义编码？", "信息", button: MessageBoxButton.YesNo);

                if (MessageBoxResult.Yes.Equals(result))
                {
                    coserver.PageEncoding = AppConfig.PageEncoding;
                }
            }
        }

       await CheckInject();


    }

   

    [RelayCommand]
    private void AddProxy()
    {
        if (!string.IsNullOrEmpty((string?)(AppConfig.ProxyConfig?.AddProxy?.Host.ToString()))&& AppConfig.ProxyConfig.AddProxy.Port>0)
        {
           
            AppConfig.ProxyConfig.ProxyItems.Add(AppConfig.ProxyConfig.AddProxy);
            AppConfig.ProxyConfig.AddProxy=new();
            NotificationManager?.Show("添加成功！");
        }
    }

    /// <summary>编码工具编辑弹窗（添加/编辑共用）</summary>
    private async Task<bool> ShowScriptTamperEditDialog(ScriptTamperEditViewModel vm, string title)
    {
        var options = new OverlayDialogOptions
        {
            FullScreen = false,
            HorizontalAnchor = HorizontalPosition.Center,
            VerticalAnchor = VerticalPosition.Center,
            HorizontalOffset = 0,
            VerticalOffset = 0,
            Mode = DialogMode.None,
            Buttons = DialogButton.None,
            Title = title,
            CanLightDismiss = true,
            CanDragMove = true,
            IsCloseButtonVisible = true,
            CanResize = true,
        };
        await OverlayDialog.ShowStandardAsync<ScriptTamperEditView, ScriptTamperEditViewModel>(vm, options: options);
        return vm.Confirmed;
    }

    [RelayCommand]
    private async Task AddCustomEncodeTool()
    {
        var vm = ScriptTamperEditViewModel.FromModel(null);
        if (await ShowScriptTamperEditDialog(vm, "添加自定义编码工具"))
        {
            AppConfig.ByPassConfig.EncodeTools.Add(vm.ToModel());
            NotificationManager?.Show("添加成功！");
        }
    }

    [RelayCommand]
    private async Task EditEncodeTool(EncodeToolModel item)
    {
        if (item == null || item.Builtin) //内置规则不可编辑（操作列按钮已禁用，此处命令层防御）
        {
            return;
        }
        var vm = ScriptTamperEditViewModel.FromModel(item);
        if (await ShowScriptTamperEditDialog(vm, "编辑编码工具"))
        {
            vm.ApplyTo(item);
            NotificationManager?.Show("保存成功！");
        }
    }

    [RelayCommand]
    private void RemoveEncodeTool(EncodeToolModel item)
    {
        if (item != null && !item.Builtin && AppConfig.ByPassConfig.EncodeTools.Contains(item)) //内置规则不可删除（命令层防御）
        {
            AppConfig.ByPassConfig.EncodeTools.Remove(item);
        }
    }

    /// <summary>编码处理页 TableView 当前选中行（上移/下移按钮与行拖拽排序的操作目标）</summary>
    [ObservableProperty] private EncodeToolModel? _selectedEncodeTool;

    /// <summary>编码工具移动到指定序号位置（上移/下移按钮与行拖拽共用；越界自动收敛，移动后保持选中）</summary>
    public void MoveEncodeTool(EncodeToolModel? item, int newIndex)
    {
        var col = AppConfig.ByPassConfig.EncodeTools;
        if (item == null)
        {
            return;
        }
        int old = col.IndexOf(item);
        if (old < 0)
        {
            return;
        }
        newIndex = Math.Clamp(newIndex, 0, col.Count - 1);
        if (old != newIndex)
        {
            col.Move(old, newIndex);
        }
        SelectedEncodeTool = item;
    }

    [RelayCommand]
    private void MoveEncodeToolUp()
    {
        if (SelectedEncodeTool == null)
        {
            NotificationManager?.Show("请先选中要上移的行！");
            return;
        }
        MoveEncodeTool(SelectedEncodeTool, AppConfig.ByPassConfig.EncodeTools.IndexOf(SelectedEncodeTool) - 1);
    }

    [RelayCommand]
    private void MoveEncodeToolDown()
    {
        if (SelectedEncodeTool == null)
        {
            NotificationManager?.Show("请先选中要下移的行！");
            return;
        }
        MoveEncodeTool(SelectedEncodeTool, AppConfig.ByPassConfig.EncodeTools.IndexOf(SelectedEncodeTool) + 1);
    }

    #region 动态值脚本管理（防护绕过-动态规则页脚本管理选项卡；请求抓取=输入抓取响应报文，自主生成=输入主请求报文，输出动态值）

    /// <summary>防护绕过页选项卡索引（"管理脚本"入口跳转定位用）</summary>
    [ObservableProperty] private int _bypassTabIndex;

    /// <summary>动态规则页内嵌选项卡索引（0=动态规则，1=脚本管理）</summary>
    [ObservableProperty] private int _dynRuleTabIndex;

    private async Task<bool> ShowTokenScriptEditDialog(TokenScriptEditViewModel vm, string title)
    {
        var options = new OverlayDialogOptions
        {
            FullScreen = false,
            HorizontalAnchor = HorizontalPosition.Center,
            VerticalAnchor = VerticalPosition.Center,
            HorizontalOffset = 0,
            VerticalOffset = 0,
            Mode = DialogMode.None,
            Buttons = DialogButton.None,
            Title = title,
            CanLightDismiss = true,
            CanDragMove = true,
            IsCloseButtonVisible = true,
            CanResize = true,
        };
        await OverlayDialog.ShowStandardAsync<TokenScriptEditView, TokenScriptEditViewModel>(vm, options: options);
        return vm.Confirmed;
    }

    [RelayCommand]
    private async Task AddTokenScript()
    {
        var vm = TokenScriptEditViewModel.FromModel(null);
        if (await ShowTokenScriptEditDialog(vm, "添加动态值脚本"))
        {
            ScriptTamperModel item = vm.ToModel();
            AppConfig.TokenScripts.Add(item);
            RefreshTokenScriptFilter();
            //新脚本自动设为当前生效前置规则的抓取脚本
            if (AppConfig.ActiveCompanionBefore != null)
            {
                AppConfig.ActiveCompanionBefore.ScriptName = item.Name;
            }
            NotificationManager?.Show("添加成功！");
        }
    }

    [RelayCommand]
    private async Task EditTokenScript(ScriptTamperModel? item)
    {
        //优先选中行，无选中行时回落到第一条勾选行（勾选框点击不触发行选中）
        item ??= SelectedTokenScript ?? AppConfig.TokenScripts.FirstOrDefault(s => s.RowChecked);
        if (item == null)
        {
            NotificationManager?.Show("请先选择或勾选要编辑的脚本！");
            return;
        }
        string oldName = item.Name;
        var vm = TokenScriptEditViewModel.FromModel(item);
        if (await ShowTokenScriptEditDialog(vm, "编辑动态值脚本"))
        {
            vm.ApplyTo(item);
            //改名时同步所有引用该脚本的伴随规则（按Name解析）
            foreach (Models.CompanionRequestConfig rule in AppConfig.CompanionRules)
            {
                if (rule.ScriptName == oldName)
                {
                    rule.ScriptName = item.Name;
                }
            }
            RefreshTokenScriptFilter();
            NotificationManager?.Show("保存成功！");
        }
    }

    [RelayCommand]
    private void RemoveTokenScript(ScriptTamperModel? item)
    {
        if (item != null && AppConfig.TokenScripts.Contains(item))
        {
            foreach (Models.CompanionRequestConfig rule in AppConfig.CompanionRules)
            {
                if (rule.ScriptName == item.Name)
                {
                    rule.ScriptName = "";
                }
            }
            AppConfig.TokenScripts.Remove(item);
            RefreshTokenScriptFilter();
        }
    }

    /// <summary>数据管理页"管理脚本"入口：跳转防护绕过页并定位到随机值脚本选项卡（第4个，索引3）</summary>
    [RelayCommand]
    private void ManageTokenScripts()
    {
        SelectedNavIndex = 6;
        BypassTabIndex = 3;
        DynRuleTabIndex = 1;
    }

    #endregion

    #region 动态规则管理（防护绕过-动态规则：TableView规则列表 + 新增/编辑弹窗）

    /// <summary>动态规则列表当前选中项</summary>
    [ObservableProperty] private Models.CompanionRequestConfig? _selectedCompanionRule;

    /// <summary>脚本管理列表当前选中项</summary>
    [ObservableProperty] private ScriptTamperModel? _selectedTokenScript;

    /// <summary>动态规则搜索关键字（名称/标记名/类型/来源/摘要模糊匹配，空=全部）</summary>
    [ObservableProperty] private string _dynRuleSearchKeyword = "";

    /// <summary>脚本管理搜索关键字（名称/类型模糊匹配，空=全部）</summary>
    [ObservableProperty] private string _tokenScriptSearchKeyword = "";

    /// <summary>动态规则过滤视图（TableView绑定源；搜索筛选后的AppConfig.CompanionRules子集，对象引用同源）</summary>
    public ObservableCollection<Models.CompanionRequestConfig> FilteredCompanionRules { get; } = new();

    /// <summary>动态值脚本过滤视图（TableView绑定源）</summary>
    public ObservableCollection<ScriptTamperModel> FilteredTokenScripts { get; } = new();

    partial void OnDynRuleSearchKeywordChanged(string value) => RefreshDynRuleFilter();

    partial void OnTokenScriptSearchKeywordChanged(string value) => RefreshTokenScriptFilter();

    /// <summary>配置整体替换（导入/启动加载）后同步两个过滤视图</summary>
    partial void OnAppConfigChanged(AppConfig value)
    {
        RefreshDynRuleFilter();
        RefreshTokenScriptFilter();
    }

    private static bool DynRuleHit(Models.CompanionRequestConfig r, string kw)
    {
        return string.IsNullOrWhiteSpace(kw)
            || (r.Name?.Contains(kw, StringComparison.OrdinalIgnoreCase) == true)
            || (r.TagName?.Contains(kw, StringComparison.OrdinalIgnoreCase) == true)
            || r.KindName.Contains(kw, StringComparison.OrdinalIgnoreCase)
            || r.SourceName.Contains(kw, StringComparison.OrdinalIgnoreCase)
            || (r.Summary?.Contains(kw, StringComparison.OrdinalIgnoreCase) == true);
    }

    /// <summary>按搜索关键字重建动态规则过滤视图（增删改/配置替换/关键字变化后调用）</summary>
    public void RefreshDynRuleFilter()
    {
        string kw = DynRuleSearchKeyword ?? "";
        FilteredCompanionRules.Clear();
        foreach (var rule in AppConfig.CompanionRules)
        {
            if (DynRuleHit(rule, kw))
            {
                FilteredCompanionRules.Add(rule);
            }
        }
    }

    /// <summary>按搜索关键字重建脚本过滤视图</summary>
    public void RefreshTokenScriptFilter()
    {
        string kw = TokenScriptSearchKeyword ?? "";
        FilteredTokenScripts.Clear();
        foreach (var s in AppConfig.TokenScripts)
        {
            if (string.IsNullOrWhiteSpace(kw)
                || (s.Name?.Contains(kw, StringComparison.OrdinalIgnoreCase) == true)
                || s.KindName.Contains(kw, StringComparison.OrdinalIgnoreCase))
            {
                FilteredTokenScripts.Add(s);
            }
        }
    }

    /// <summary>工具栏"删除选中"：弹窗确认后批量删除勾选行的动态规则</summary>
    [RelayCommand]
    private async Task RemoveCheckedCompanionRules()
    {
        var checkedRules = AppConfig.CompanionRules.Where(r => r.RowChecked).ToList();
        if (checkedRules.Count == 0)
        {
            NotificationManager?.Show("请先勾选要删除的规则！");
            return;
        }
        var result = await OverlayMessageBox.ShowAsync(
            "确认删除勾选的 " + checkedRules.Count + " 条动态规则？",
            "删除确认", button: MessageBoxButton.YesNo);
        if (!MessageBoxResult.Yes.Equals(result))
        {
            return;
        }
        foreach (var rule in checkedRules)
        {
            AppConfig.CompanionRules.Remove(rule);
        }
        RefreshDynRuleFilter();
        Log.Success("已删除 " + checkedRules.Count + " 条动态规则");
    }

    /// <summary>工具栏"删除选中"：弹窗确认后批量删除勾选行的动态值脚本（同步清理规则引用）</summary>
    [RelayCommand]
    private async Task RemoveCheckedTokenScripts()
    {
        var checkedItems = AppConfig.TokenScripts.Where(s => s.RowChecked).ToList();
        if (checkedItems.Count == 0)
        {
            NotificationManager?.Show("请先勾选要删除的脚本！");
            return;
        }
        var result = await OverlayMessageBox.ShowAsync(
            "确认删除勾选的 " + checkedItems.Count + " 个动态值脚本？引用这些脚本的规则将清空脚本设置。",
            "删除确认", button: MessageBoxButton.YesNo);
        if (!MessageBoxResult.Yes.Equals(result))
        {
            return;
        }
        foreach (var item in checkedItems)
        {
            foreach (Models.CompanionRequestConfig rule in AppConfig.CompanionRules)
            {
                if (rule.ScriptName == item.Name)
                {
                    rule.ScriptName = "";
                }
            }
            AppConfig.TokenScripts.Remove(item);
        }
        RefreshTokenScriptFilter();
        Log.Success("已删除 " + checkedItems.Count + " 个动态值脚本");
    }

    private async Task<bool> ShowCompanionRuleEditDialog(CompanionRuleEditViewModel vm, string title)
    {
        var options = new OverlayDialogOptions
        {
            FullScreen = false,
            HorizontalAnchor = HorizontalPosition.Center,
            VerticalAnchor = VerticalPosition.Center,
            HorizontalOffset = 0,
            VerticalOffset = 0,
            Mode = DialogMode.None,
            Buttons = DialogButton.None,
            Title = title,
            CanLightDismiss = true,
            CanDragMove = true,
            IsCloseButtonVisible = true,
            CanResize = true,
        };
        await OverlayDialog.ShowStandardAsync<CompanionRuleEditView, CompanionRuleEditViewModel>(vm, options: options);
        return vm.Confirmed;
    }

    /// <summary>新增动态规则（弹窗配置，确认后加入规则集合）</summary>
    [RelayCommand]
    private async Task AddCompanionRule()
    {
        var vm = new CompanionRuleEditViewModel(AppConfig, null);
        if (await ShowCompanionRuleEditDialog(vm, "新增动态规则"))
        {
            AppConfig.CompanionRules.Add(vm.Rule);
            SelectedCompanionRule = vm.Rule;
            RefreshDynRuleFilter();
            NotificationManager?.Show("添加成功！");
        }
    }

    /// <summary>编辑动态规则（编辑副本，确认后写回原规则，取消不落地；无选中行时回落到第一条勾选行）</summary>
    [RelayCommand]
    private async Task EditCompanionRule(Models.CompanionRequestConfig? item)
    {
        item ??= SelectedCompanionRule ?? AppConfig.CompanionRules.FirstOrDefault(r => r.RowChecked);
        if (item == null)
        {
            NotificationManager?.Show("请先选择或勾选要编辑的规则！");
            return;
        }
        var vm = new CompanionRuleEditViewModel(AppConfig, item);
        if (await ShowCompanionRuleEditDialog(vm, "编辑动态规则"))
        {
            item.CopyFrom(vm.Rule);
            RefreshDynRuleFilter();
            NotificationManager?.Show("保存成功！");
        }
    }

    /// <summary>删除动态规则</summary>
    [RelayCommand]
    private void RemoveCompanionRule(Models.CompanionRequestConfig? item)
    {
        item ??= SelectedCompanionRule;
        if (item != null && AppConfig.CompanionRules.Contains(item))
        {
            AppConfig.CompanionRules.Remove(item);
            if (SelectedCompanionRule == item)
            {
                SelectedCompanionRule = null;
            }
            RefreshDynRuleFilter();
        }
    }

    #endregion

    #region 取数模板管理（可视化编辑config/payload模板，保存后热生效）

    /// <summary>支持模板管理的数据库类型</summary>
    public List<DBType> TemplateDbList { get; } = new List<DBType>
    {
        DBType.MySQL, DBType.SQLServer, DBType.PostgreSQL, DBType.Oracle, DBType.DB2,
        DBType.Informix, DBType.SQLite, DBType.Access, DBType.DM, DBType.Kingbase,
        DBType.OpenGauss, DBType.H2, DBType.HSQLDB, DBType.ClickHouse
    };

    [ObservableProperty] private DBType _selectedTemplateDb = DBType.MySQL;

    [ObservableProperty] private ObservableCollection<PayloadTemplateItem> _templateItems = new();

    [ObservableProperty] private PayloadTemplateItem? _selectedTemplateItem;

    partial void OnSelectedTemplateDbChanged(DBType value)
    {
        LoadTemplate();
    }

    private static string GetTemplateFileFullPath(DBType db)
    {
        return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, BasePayload.GetTemplateRelativePath(db));
    }

    /// <summary>
    /// 从模板文件加载（按首个冒号分割key:value，保持文件原始行序与key大小写）
    /// </summary>
    [RelayCommand]
    private void LoadTemplate()
    {
        TemplateItems.Clear();
        string path = GetTemplateFileFullPath(SelectedTemplateDb);
        if (!File.Exists(path))
        {
            NotificationManager?.Show("模板文件不存在：" + path);
            return;
        }
        try
        {
            foreach (string line in File.ReadAllLines(path))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                int idx = line.IndexOf(':', StringComparison.Ordinal);
                if (idx > 0)
                {
                    TemplateItems.Add(new PayloadTemplateItem(line.Substring(0, idx), line.Substring(idx + 1)));
                }
            }
        }
        catch (Exception ex)
        {
            NotificationManager?.Show("读取模板失败：" + ex.Message);
        }
    }

    /// <summary>
    /// 保存模板：写回运行时模板文件（并尽力同步源码目录副本），随后热生效
    /// </summary>
    [RelayCommand]
    private void SaveTemplate()
    {
        var validItems = TemplateItems.Where(i => !string.IsNullOrWhiteSpace(i.Key)).ToList();
        if (validItems.Count == 0)
        {
            NotificationManager?.Show("模板为空，无法保存！");
            return;
        }
        //key重复校验
        var dup = validItems.GroupBy(i => i.Key.Trim(), StringComparer.OrdinalIgnoreCase)
                            .Where(g => g.Count ()> 1).Select(g => g.Key).ToList();
        if (dup.Count > 0)
        {
            NotificationManager?.Show("存在重复key：" + string.Join("、", dup) + "，请先处理再保存！");
            return;
        }
        StringBuilder sb = new StringBuilder();
        foreach (var item in validItems)
        {
            sb.Append(item.Key.Trim()).Append(':').AppendLine(item.Value ?? "");
        }
        string content = sb.ToString();
        string path = GetTemplateFileFullPath(SelectedTemplateDb);
        try
        {
            File.WriteAllText(path, content);
            //尽力同步源码目录副本，避免下次构建被旧模板覆盖
            TrySyncSourceTemplate(content);
        }
        catch (Exception ex)
        {
            NotificationManager?.Show("保存模板失败：" + ex.Message);
            return;
        }
        //必需key校验（仅警告，允许保存——用户可能有意裁剪）
        var keys = new HashSet<string>(validItems.Select(i => i.Key.Trim()), StringComparer.OrdinalIgnoreCase);
        var missing = BasePayload.RequiredKeys.Where(k => !keys.Contains(k)).ToList();
        //热生效：仅当编辑的是当前取数配置的数据库时重建PayloadFactory，避免劫持其他库的取数
        bool hotLoaded = false;
        if (SelectedTemplateDb == AppConfig.DataConfig.SelectedDBType)
        {
            try
            {
                PayloadFactory.Init(SelectedTemplateDb);
                hotLoaded = true;
            }
            catch (Exception ex)
            {
                NotificationManager?.Show("模板已保存，但热加载失败：" + ex.Message);
                return;
            }
        }
        string msg = "模板已保存" + (hotLoaded ? "并热生效！" : "（切换到该库取数时自动生效）");
        if (missing.Count > 0)
        {
            msg += " 警告：缺少必需key：" + string.Join("、", missing) + "，取数可能异常！";
        }
        NotificationManager?.Show(msg);
        Log.Show("[取数模板] " + SelectedTemplateDb + " 模板已更新保存。" + (missing.Count > 0 ? " 缺少必需key：" + string.Join(",", missing) : ""));
    }

    /// <summary>
    /// 尽力把模板内容同步到源码目录的config/payload副本（定位含csproj的项目目录），保持下次构建一致
    /// </summary>
    private void TrySyncSourceTemplate(string content)
    {
        try
        {
            string fileName = Path.GetFileName(BasePayload.GetTemplateRelativePath(SelectedTemplateDb));
            DirectoryInfo? dir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
            for (int i = 0; i < 8 && dir != null; i++)
            {
                string candidate = Path.Combine(dir.FullName, "SuperSQLInjectionV2", "config", "payload", fileName);
                if (File.Exists(candidate))
                {
                    File.WriteAllText(candidate, content);
                    return;
                }
                //也兼容当前目录本身就是主项目目录的情况
                string candidate2 = Path.Combine(dir.FullName, "config", "payload", fileName);
                if (File.Exists(candidate2) && File.Exists(Path.Combine(dir.FullName, "SuperSQLInjectionV2.csproj")))
                {
                    File.WriteAllText(candidate2, content);
                    return;
                }
                dir = dir.Parent;
            }
        }
        catch
        {
            //同步源码副本失败不影响运行时生效，忽略
        }
    }

    [RelayCommand]
    private void AddTemplateItem()
    {
        TemplateItems.Add(new PayloadTemplateItem("NewKey", ""));
        SelectedTemplateItem = TemplateItems.LastOrDefault();
    }

    /// <summary>取数模板项编辑弹窗（操作列入口，弹窗修改Key/Value，用途描述随Key联动）</summary>
    [RelayCommand]
    private async Task EditTemplateItem(PayloadTemplateItem item)
    {
        if (item == null)
        {
            return;
        }
        var vm = TemplateItemEditViewModel.FromModel(item);
        var options = new OverlayDialogOptions
        {
            FullScreen = false,
            HorizontalAnchor = HorizontalPosition.Center,
            VerticalAnchor = VerticalPosition.Center,
            Mode = DialogMode.None,
            Buttons = DialogButton.None,
            Title = "编辑取数模板项",
            CanLightDismiss = true,
            CanDragMove = true,
            IsCloseButtonVisible = true,
            CanResize = true,
        };
        await OverlayDialog.ShowStandardAsync<TemplateItemEditView, TemplateItemEditViewModel>(vm, options: options);
        if (vm.Confirmed)
        {
            vm.ApplyTo(item);
            NotificationManager?.Show("保存成功！");
        }
    }


    #endregion

    #region 检测用例管理（P10：管理config/injection下检测用例，弹窗查看/新增，删除需确认，保存即热生效）

    /// <summary>检测用例列表（搜索筛选后的视图）</summary>
    [ObservableProperty] private ObservableCollection<PayloadItem> _payloadItems = new ObservableCollection<PayloadItem>();

    /// <summary>搜索筛选：关键字（标题/payload模糊）、技术类型、级别、风险、DBMS、文件</summary>
    [ObservableProperty] private string _payloadSearchKeyword = "";
    [ObservableProperty] private string _payloadFilterSType = "全部";
    [ObservableProperty] private string _payloadFilterLevel = "全部";
    [ObservableProperty] private string _payloadFilterRisk = "全部";
    [ObservableProperty] private string _payloadFilterDbms = "全部";
    [ObservableProperty] private string _selectedPayloadFileFilter = "全部";
    /// <summary>文件筛选项（全部+各XML文件名）</summary>
    [ObservableProperty] private ObservableCollection<string> _payloadFileFilters = new ObservableCollection<string>();
    /// <summary>DBMS筛选项（全部+用例库中出现的DBMS去重）</summary>
    [ObservableProperty] private ObservableCollection<string> _payloadDbmsFilters = new ObservableCollection<string>();

    /// <summary>技术类型筛选项（全部+7种技术）</summary>
    public List<string> PayloadSTypeFilters { get; } = new List<string> { "全部" }.Concat(PayloadItem.STypeNames).ToList();
    public List<string> PayloadLevelFilters { get; } = new List<string> { "全部", "1", "2", "3", "4", "5" };
    public List<string> PayloadRiskFilters { get; } = new List<string> { "全部", "1", "2", "3" };

    private List<PayloadItem> _allPayloads = new List<PayloadItem>();

    /// <summary>过滤后的全量结果（分页数据源）</summary>
    private List<PayloadItem> _filteredPayloads = new List<PayloadItem>();
    /// <summary>每页条数</summary>
    public const int PayloadPageSize = 20;
    /// <summary>当前页（1基）</summary>
    [ObservableProperty] private int _payloadPageIndex = 1;
    [ObservableProperty] private int _payloadPageCount = 1;
    [ObservableProperty] private string _payloadPageInfo = "第 1/1 页 · 共 0 条";

    partial void OnPayloadSearchKeywordChanged(string value) => ApplyPayloadFilter();
    partial void OnPayloadFilterSTypeChanged(string value) => ApplyPayloadFilter();
    partial void OnPayloadFilterLevelChanged(string value) => ApplyPayloadFilter();
    partial void OnPayloadFilterRiskChanged(string value) => ApplyPayloadFilter();
    partial void OnPayloadFilterDbmsChanged(string value) => ApplyPayloadFilter();
    partial void OnSelectedPayloadFileFilterChanged(string value) => ApplyPayloadFilter();

    private static bool IsAllFilter(string? v) => string.IsNullOrEmpty(v) || v == "全部";

    private void ApplyPayloadFilter()
    {
        IEnumerable<PayloadItem> q = _allPayloads;
        string kw = (PayloadSearchKeyword ?? "").Trim();
        if (kw.Length > 0)
        {
            q = q.Where(p => (p.Title ?? "").Contains(kw, StringComparison.OrdinalIgnoreCase)
                || (p.Payload ?? "").Contains(kw, StringComparison.OrdinalIgnoreCase));
        }
        if (!IsAllFilter(PayloadFilterSType))
        {
            q = q.Where(p => p.STypeName == PayloadFilterSType);
        }
        if (!IsAllFilter(PayloadFilterLevel) && int.TryParse(PayloadFilterLevel, out int lv))
        {
            q = q.Where(p => p.Level == lv);
        }
        if (!IsAllFilter(PayloadFilterRisk) && int.TryParse(PayloadFilterRisk, out int rk))
        {
            q = q.Where(p => p.Risk == rk);
        }
        if (!IsAllFilter(PayloadFilterDbms))
        {
            q = q.Where(p => string.Equals(p.Dbms, PayloadFilterDbms, StringComparison.OrdinalIgnoreCase));
        }
        if (!IsAllFilter(SelectedPayloadFileFilter))
        {
            q = q.Where(p => p.FileName == SelectedPayloadFileFilter);
        }
        _filteredPayloads = q.ToList();
        PayloadPageIndex = 1;
        UpdatePayloadPage();
    }

    /// <summary>按当前页刷新表格视图与页信息</summary>
    private void UpdatePayloadPage()
    {
        int total = _filteredPayloads.Count;
        int pageCount = Math.Max(1, (int)Math.Ceiling(total / (double)PayloadPageSize));
        PayloadPageCount = pageCount;
        if (PayloadPageIndex > pageCount)
        {
            PayloadPageIndex = pageCount;
        }
        if (PayloadPageIndex < 1)
        {
            PayloadPageIndex = 1;
        }
        PayloadItems = new ObservableCollection<PayloadItem>(
            _filteredPayloads.Skip((PayloadPageIndex - 1) * PayloadPageSize).Take(PayloadPageSize));
        PayloadPageInfo = "第 " + PayloadPageIndex + "/" + pageCount + " 页 · 共 " + total + " 条";
    }

    [RelayCommand]
    private void PayloadFirstPage()
    {
        if (PayloadPageIndex != 1)
        {
            PayloadPageIndex = 1;
            UpdatePayloadPage();
        }
    }

    [RelayCommand]
    private void PayloadPrevPage()
    {
        if (PayloadPageIndex > 1)
        {
            PayloadPageIndex--;
            UpdatePayloadPage();
        }
    }

    [RelayCommand]
    private void PayloadNextPage()
    {
        if (PayloadPageIndex < PayloadPageCount)
        {
            PayloadPageIndex++;
            UpdatePayloadPage();
        }
    }

    [RelayCommand]
    private void PayloadLastPage()
    {
        if (PayloadPageIndex != PayloadPageCount)
        {
            PayloadPageIndex = PayloadPageCount;
            UpdatePayloadPage();
        }
    }

    /// <summary>重新加载用例列表（进入页面/写盘后刷新）</summary>
    [RelayCommand]
    private void ReloadPayloads()
    {
        try
        {
            _allPayloads = SuperSQLInjectionV2.Tools.Inject.InjectPayloadManager.LoadAll();
            List<string> files = SuperSQLInjectionV2.Tools.Inject.InjectPayloadManager.ListFiles();
            PayloadFileFilters = new ObservableCollection<string>(s_allFilterOption.Concat(files));
            PayloadDbmsFilters = new ObservableCollection<string>(s_allFilterOption.Concat(
                _allPayloads.Select(p => p.Dbms ?? "").Where(d => d.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(d => d)));
            //ItemsSource替换后ComboBox内部选中态丢失，但绑定值相等不再触发通知导致显示空白；
            //UI空闲时先置null再恢复，强制一次变更通知让ComboBox重新选中
            Dispatcher.UIThread.Post( ()=>
            {
                string dbms = !string.IsNullOrEmpty(PayloadFilterDbms) && PayloadDbmsFilters.Contains(PayloadFilterDbms) ? PayloadFilterDbms : "全部";
                string file = !string.IsNullOrEmpty(SelectedPayloadFileFilter) && PayloadFileFilters.Contains(SelectedPayloadFileFilter) ? SelectedPayloadFileFilter : "全部";
                SelectedPayloadFileFilter = null!;
                PayloadFilterDbms = null!;
                SelectedPayloadFileFilter = file;
                PayloadFilterDbms = dbms;
            }, DispatcherPriority.Background);
            ApplyPayloadFilter();
            Log.Show("已加载检测用例 " + _allPayloads.Count + " 条（" + files.Count + "个文件）！");
        }
        catch (Exception e)
        {
            Log.Error("加载检测用例失败：" + e.Message);
        }
    }

    /// <summary>用例查看/编辑/新增弹窗（共用PayloadEditView）</summary>
    private async Task<bool> ShowPayloadEditDialog(PayloadEditViewModel vm, string title)
    {
        var options = new OverlayDialogOptions
        {
            FullScreen = false,
            HorizontalAnchor = HorizontalPosition.Center,
            VerticalAnchor = VerticalPosition.Center,
            Mode = DialogMode.None,
            Buttons = DialogButton.None,
            Title = title,
            CanLightDismiss = true,
            CanDragMove = true,
            IsCloseButtonVisible = true,
            CanResize = true,
        };
        await OverlayDialog.ShowStandardAsync<PayloadEditView, PayloadEditViewModel>(vm, options: options);
        return vm.Confirmed;
    }

    /// <summary>查看/编辑用例（操作列"查看"）：确认后写回原XML文件</summary>
    [RelayCommand]
    private async Task ViewPayload(PayloadItem item)
    {
        if (item == null)
        {
            return;
        }
        var vm = PayloadEditViewModel.FromItem(item);
        if (!await ShowPayloadEditDialog(vm, "查看/编辑检测用例"))
        {
            return;
        }
        try
        {
            vm.ApplyTo(item);
            SuperSQLInjectionV2.Tools.Inject.InjectPayloadManager.Save(item);
            NotificationManager?.Show("已保存用例「" + item.Title + "」，检测引擎立即生效！");
            ReloadPayloads();
        }
        catch (Exception e)
        {
            Log.Error("保存用例失败：" + e.Message);
        }
    }

    /// <summary>新增用例（弹窗编辑，目标文件custom_user.xml，不污染官方文件）</summary>
    [RelayCommand]
    private async Task AddPayload()
    {
        var vm = PayloadEditViewModel.FromItem(null);
        if (!await ShowPayloadEditDialog(vm, "新增检测用例"))
        {
            return;
        }
        try
        {
            PayloadItem item = new PayloadItem
            {
                FileName = SuperSQLInjectionV2.Tools.Inject.InjectPayloadManager.UserFile,
                Index = -1
            };
            vm.ApplyTo(item);
            SuperSQLInjectionV2.Tools.Inject.InjectPayloadManager.Save(item);
            NotificationManager?.Show("已新增用例「" + item.Title + "」到 " + item.FileName + "！");
            ReloadPayloads();
        }
        catch (Exception e)
        {
            Log.Error("新增用例失败：" + e.Message);
        }
    }

    /// <summary>删除用例（操作列"删除"，弹窗确认后从XML移除并刷新）</summary>
    [RelayCommand]
    private async Task DeletePayload(PayloadItem item)
    {
        if (item == null)
        {
            return;
        }
        var result = await OverlayMessageBox.ShowAsync(
            "确认删除用例「" + item.Title + "」（" + item.FileName + "）？删除后检测不再使用该payload。",
            "删除确认", button: MessageBoxButton.YesNo);
        if (!MessageBoxResult.Yes.Equals(result))
        {
            return;
        }
        try
        {
            SuperSQLInjectionV2.Tools.Inject.InjectPayloadManager.Delete(item);
            ReloadPayloads();
            Log.Success("已删除用例「" + item.Title + "」！");
        }
        catch (Exception e)
        {
            Log.Error("删除用例失败：" + e.Message);
        }
    }

    #endregion

    #region 报错指纹管理（检测用例页-报错指纹选项卡，唯一事实源 config/injection/errors.xml）

    [ObservableProperty] private ObservableCollection<FingerprintItem> _fingerprintItems = new();
    [ObservableProperty] private string _fingerprintSearchKeyword = "";
    [ObservableProperty] private string _fingerprintFilterDbms = "全部";
    [ObservableProperty] private ObservableCollection<string> _fingerprintDbmsFilters = new (){ "全部" };
    [ObservableProperty] private string _fingerprintCountInfo = "";
    [ObservableProperty] private string _fingerprintTestText = "";
    [ObservableProperty] private string _fingerprintTestResult = "";

    /// <summary>指纹分页（每页 20 条）</summary>
    public const int FingerprintPageSize = 20;
    [ObservableProperty] private int _fingerprintPageIndex = 1;
    [ObservableProperty] private int _fingerprintPageCount = 1;
    [ObservableProperty] private string _fingerprintPageInfo = "第 1/1 页 · 共 0 条";

    private List<FingerprintItem> _allFingerprints = new List<FingerprintItem>();
    private List<FingerprintItem> _filteredFingerprints = new List<FingerprintItem>();

    partial void OnFingerprintSearchKeywordChanged(string value) => ApplyFingerprintFilter();
    partial void OnFingerprintFilterDbmsChanged(string value) => ApplyFingerprintFilter();

    private void ApplyFingerprintFilter()
    {
        IEnumerable<FingerprintItem> q = _allFingerprints;
        string kw = (FingerprintSearchKeyword ?? "").Trim();
        if (kw.Length > 0)
        {
            q = q.Where(f => f.Regexp.Contains(kw, StringComparison.OrdinalIgnoreCase)
                          || f.Dbms.Contains(kw, StringComparison.OrdinalIgnoreCase)
                          || f.Fork.Contains(kw, StringComparison.OrdinalIgnoreCase));
        }
        if (!string.IsNullOrEmpty(FingerprintFilterDbms) && FingerprintFilterDbms != "全部")
        {
            q = q.Where(f => string.Equals(f.Dbms, FingerprintFilterDbms, StringComparison.OrdinalIgnoreCase));
        }
        _filteredFingerprints = q.ToList();
        FingerprintCountInfo = $"共 {_allFingerprints.Count} 条 · 筛选后 {_filteredFingerprints.Count} 条";
        FingerprintPageIndex = 1;
        UpdateFingerprintPage();
    }

    private void UpdateFingerprintPage()
    {
        int total = _filteredFingerprints.Count;
        int pageCount = Math.Max(1, (int)Math.Ceiling(total / (double)FingerprintPageSize));
        FingerprintPageCount = pageCount;
        if (FingerprintPageIndex > pageCount)
        {
            FingerprintPageIndex = pageCount;
        }
        if (FingerprintPageIndex < 1)
        {
            FingerprintPageIndex = 1;
        }
        FingerprintItems = new ObservableCollection<FingerprintItem>(
            _filteredFingerprints.Skip((FingerprintPageIndex - 1) * FingerprintPageSize).Take(FingerprintPageSize));
        FingerprintPageInfo = "第 " + FingerprintPageIndex + "/" + pageCount + " 页 · 共 " + total + " 条";
    }

    [RelayCommand]
    private void FingerprintFirstPage()
    {
        if (FingerprintPageIndex != 1)
        {
            FingerprintPageIndex = 1;
            UpdateFingerprintPage();
        }
    }

    [RelayCommand]
    private void FingerprintPrevPage()
    {
        if (FingerprintPageIndex > 1)
        {
            FingerprintPageIndex--;
            UpdateFingerprintPage();
        }
    }

    [RelayCommand]
    private void FingerprintNextPage()
    {
        if (FingerprintPageIndex < FingerprintPageCount)
        {
            FingerprintPageIndex++;
            UpdateFingerprintPage();
        }
    }

    [RelayCommand]
    private void FingerprintLastPage()
    {
        if (FingerprintPageIndex != FingerprintPageCount)
        {
            FingerprintPageIndex = FingerprintPageCount;
            UpdateFingerprintPage();
        }
    }

    /// <summary>重新加载指纹列表（进入页面/写盘后刷新）</summary>
    [RelayCommand]
    private void ReloadFingerprints()
    {
        try
        {
            _allFingerprints = SuperSQLInjectionV2.Tools.Inject.ErrorFingerprints.LoadRaw()
                .Select(r => new FingerprintItem { Dbms = r.Dbms, Fork = r.Fork, Regexp = r.Regexp }).ToList();
            FingerprintDbmsFilters = new ObservableCollection<string>(s_allFilterOption.Concat(
                _allFingerprints.Select(f => f.Dbms).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(d => d)));
            ApplyFingerprintFilter();
        }
        catch (Exception e)
        {
            Log.Error("加载报错指纹失败：" + e.Message);
        }
    }

    /// <summary>把当前全量列表整存回 errors.xml（保持现有筛选之外条目不丢失）</summary>
    private void SaveAllFingerprints()
    {
        SuperSQLInjectionV2.Tools.Inject.ErrorFingerprints.SaveAll(
            _allFingerprints.Select(f => new SuperSQLInjectionV2.Tools.Inject.ErrorFingerprints.RawEntry
            {
                Dbms = f.Dbms,
                Fork = f.Fork,
                Regexp = f.Regexp
            }));
    }

    private async Task<bool> ShowFingerprintEditDialog(FingerprintEditViewModel vm, string title)
    {
        var options = new OverlayDialogOptions
        {
            FullScreen = false,
            HorizontalAnchor = HorizontalPosition.Center,
            VerticalAnchor = VerticalPosition.Center,
            Mode = DialogMode.None,
            Buttons = DialogButton.None,
            Title = title,
            CanLightDismiss = true,
            CanDragMove = true,
            IsCloseButtonVisible = true,
            CanResize = true,
        };
        await OverlayDialog.ShowStandardAsync<FingerprintEditView, FingerprintEditViewModel>(vm, options: options);
        return vm.Confirmed;
    }

    /// <summary>新增指纹（弹窗编辑，写入 errors.xml）</summary>
    [RelayCommand]
    private async Task AddFingerprint()
    {
        var vm = FingerprintEditViewModel.FromItem(null);
        if (!await ShowFingerprintEditDialog(vm, "新增报错指纹"))
        {
            return;
        }
        try
        {
            var item = new FingerprintItem();
            vm.ApplyTo(item);
            //防重复：同 DBMS + 同正则（忽略大小写）视为重复
            if (_allFingerprints.Any(f => string.Equals(f.Dbms, item.Dbms, StringComparison.OrdinalIgnoreCase)
                                       && string.Equals(f.Regexp, item.Regexp, StringComparison.OrdinalIgnoreCase)))
            {
                NotificationManager?.Show("相同 DBMS 下已存在相同正则的指纹，未重复添加！");
                return;
            }
            _allFingerprints.Add(item);
            SaveAllFingerprints();
            NotificationManager?.Show("已新增指纹（" + item.Dbms + "），检测立即生效！");
            ReloadFingerprints();
        }
        catch (Exception e)
        {
            Log.Error("新增指纹失败：" + e.Message);
        }
    }

    /// <summary>查看/编辑指纹（操作列"查看"）</summary>
    [RelayCommand]
    private async Task EditFingerprint(FingerprintItem item)
    {
        if (item == null)
        {
            return;
        }
        var vm = FingerprintEditViewModel.FromItem(item);
        if (!await ShowFingerprintEditDialog(vm, "查看/编辑报错指纹"))
        {
            return;
        }
        try
        {
            vm.ApplyTo(item);
            SaveAllFingerprints();
            NotificationManager?.Show("指纹已保存，检测立即生效！");
            ReloadFingerprints();
        }
        catch (Exception e)
        {
            Log.Error("保存指纹失败：" + e.Message);
        }
    }

    /// <summary>删除指纹（操作列"删除"，弹窗确认）</summary>
    [RelayCommand]
    private async Task DeleteFingerprint(FingerprintItem item)
    {
        if (item == null)
        {
            return;
        }
        var result = await OverlayMessageBox.ShowAsync(
            "确认删除该指纹？\n\nDBMS：" + item.Dbms + (string.IsNullOrEmpty(item.Fork) ? "" : "（fork：" + item.Fork + "）") + "\n正则：" + item.Regexp,
            "删除确认", button: MessageBoxButton.YesNo);
        if (!MessageBoxResult.Yes.Equals(result))
        {
            return;
        }
        try
        {
            _allFingerprints.Remove(item);
            SaveAllFingerprints();
            ReloadFingerprints();
            Log.Success("已删除指纹（" + item.Dbms + "）！");
        }
        catch (Exception e)
        {
            Log.Error("删除指纹失败：" + e.Message);
        }
    }

    /// <summary>命中测试：粘贴响应文本，实时显示命中的指纹明细</summary>
    [RelayCommand]
    private void TestFingerprintHit()
    {
        string body = FingerprintTestText ?? "";
        if (string.IsNullOrWhiteSpace(body))
        {
            FingerprintTestResult = "请先粘贴响应文本";
            return;
        }
        var hits = SuperSQLInjectionV2.Tools.Inject.ErrorFingerprints.MatchDetails(body);
        FingerprintTestResult = hits.Count == 0
            ? "未命中任何指纹"
            : "命中 " + hits.Count + " 条：" + string.Join("；", hits.Take(8).Select(h =>
                (string.IsNullOrEmpty(h.Fork) ? h.Dbms : h.Fork) + "[" + (h.Regexp.Length > 40 ? h.Regexp[..40] + "…" : h.Regexp) + "]"))
              + (hits.Count > 8 ? " …" : "");
    }

    #endregion

    private async Task CheckInject()
    {
        IsRuning = true;
        try
        {
            //剥离人工/自动标记（$sql$/<Encode>/<DRule>），避免标记字面量混入参数值污染检测探针；
            //检测页报文为独立文档，始终只有用户原始报文，标记只随命中进入注入记录
            string cleanRequestTxt = RequestRewriter.StripRequestMarks(AppConfig.DetectRequestTxt);
            if (cleanRequestTxt.Length != AppConfig.DetectRequestTxt.Length)
            {
                Log.Show("检测到报文含注入/编码标记，已自动剥离后进行检测……");
            }
            //新一轮检测=新目标：把干净报文同步到取数页文档，覆盖旧目标残留的标记报文（取数页与检测页文档已分离，互不污染）
            //覆盖保护：取数页报文含注入标记（$sql$）时说明用户正在利用已标记注入点，跳过覆盖避免丢失人工/记录恢复的标记配置
            if (AppConfig.TxtRequest.Text.Contains(ConstData.InjectStr, StringComparison.Ordinal))
            {
                Log.Show("取数页报文含注入标记（$sql$），本次检测不同步覆盖取数页，标记配置保持不变……");
            }
            else if (!AppConfig.TxtRequest.Text.Equals(cleanRequestTxt, StringComparison.Ordinal))
            {
                AppConfig.TxtRequest.Text = cleanRequestTxt;
            }
            HttpRequest request = new HttpRequest(AppConfig, cleanRequestTxt);
           
            //获取原始的页面信息
            HttpResponse coserver = await HTTPTool.SendRequestRetryAsync(request);
        
            //拆分参数,存放到集合，方便后面从新拼接组合参数
            Log.Show("报告大侠，发现" + request.Params.Count + "个参数，请稍候正在对每一个参数进行注入测试！");

            bool wafChecked = false;
            _detectHitFound = false;
            _detectHitCount = 0;
            _lastHitRequestTxt = null;

            foreach (KeyValuePair<string, string> paramNameAndData in request.Params)
            {
                string paramName = paramNameAndData.Key;
                if (ConstData.JumpkeyList.ContainsKey(paramName))
                {
                    Log.Show("跳过Token参数检测！" + paramName);
                    continue;
                }
                string paramData = paramNameAndData.Value;

                //首个参数检测前，先做一次WAF启发式探测（WAF启发式探测）
                if (!wafChecked)
                {
                    wafChecked = true;
                    await InjectTools.CheckWaf(AppConfig, cleanRequestTxt, paramName, paramData);
                }


                string requestTxt = cleanRequestTxt;
                if (SuperSQLInjectionV2.Tools.Inject.InjectPayloadLoader.IsAvailable())
                {
                    //多技术检测引擎：覆盖B/E/U/S/T/Q全技术类型，支持level/risk/boundary矩阵过滤，命中后继续检测其余类型
                    Log.Show("报告大侠，正在使用多技术检测引擎对参数" + paramName + "进行注入测试（Level=" + AppConfig.DataConfig.DetectLevel + "，Risk=" + AppConfig.DataConfig.DetectRisk + "）！");
                    List<InjectPoint> inpList = await SuperSQLInjectionV2.Tools.Inject.InjectDetectEngine.DetectParam(AppConfig, requestTxt, paramName, paramData);
                    //按利用价值升序应用：所有命中都会写入注入记录，最优注入点最后生效为当前配置
                    foreach (InjectPoint inp_sq in inpList)
                    {
                        UpdateData(inp_sq);
                    }
                    if (inpList.Count > 1)
                    {
                        Log.Show("该参数共发现" + inpList.Count + "种注入类型，已全部记录到注入记录列表，可在注入记录中切换利用！");
                    }
                    continue;
                }

                //旧回退检测链路已移除：检测唯一走多技术引擎，引擎缺失时直接报错终止
                Log.Error("未找到检测用例库（config/injection/），注入检测无法继续！请重新安装或恢复该目录！");
                break;

            }


            //扩展注入位置（level 扩展行为）：JSON请求体任意level；level>=2测Cookie键值；level>=3测User-Agent/Referer头
            if (SuperSQLInjectionV2.Tools.Inject.InjectPayloadLoader.IsAvailable())
            {
                await CheckExtendedPlaces(request, cleanRequestTxt);
            }
            //检测命中后主动确认DBMS banner（指纹识别阶段），坐实库型与版本
            if (_detectHitFound)
            {
                _detectHitFound = false;
                await ConfirmDbBanner();
            }
            //取数引导：标记报文只存注入记录不回写编辑器，明确指引下一步操作
            if (_detectHitCount > 0)
            {
                Log.Success("检测完成：共发现 " + _detectHitCount + " 个注入点，已全部记录到注入记录列表——请到注入记录选择注入点加载标记报文后开始取数！");
            }
            //检测正常跑完（未中途停止/未异常）：标记当前目标已出结论，状态栏据此显示"未检测到注入"
            _detectFinishedTarget = AppConfig.Host + ":" + AppConfig.Port;
        }
        catch (OperationCanceledException)
        {
            Log.Show("已停止注入检测！");
        }
        catch (Exception e)
        {
            Log.Show("识别注入发生异常！" + e.Message);
        }
        finally
        {
            IsRuning = false;
        }

    }

    /// <summary>
    /// 扩展注入位置检测（level 行为）：JSON请求体任意level；level>=2测Cookie键值对；level>=3测User-Agent/Referer头。
    /// 命中同样走UpdateData进入注入记录，可恢复利用（标记已嵌入请求文本对应位置）。
    /// </summary>
    private async Task CheckExtendedPlaces(HttpRequest request, string requestTxt)
    {
        int level = Math.Max(1, Math.Min(5, AppConfig.DataConfig.DetectLevel));
        //扩展位置目标枚举与 CLI 共用（ParamTargetDiscovery），保证两端参数发现面一致
        var targets = SuperSQLInjectionV2.Tools.ParamTargetDiscovery.DiscoverExtended(request, requestTxt, level)
            .Select(x => (name: x.Name, value: x.Value, place: x.Place, header: x.Header, desc: x.Desc, uriIdx: x.UriIdx))
            .ToList();

        if (AppConfig.DataConfig.DetectParamParallel && targets.Count > 1)
        {
            //多参数并行：参数间检测上下文（页面模板/相似度基线/DB候选）各自独立，可安全并发；
            //并发度取线程数配置（上限10），命中统一回到本线程UpdateData应用，避免UI绑定并发写
            int maxPar = Math.Max(1, Math.Min(AppConfig.ThreadSize, 10));
            Log.Show("报告大侠，发现" + targets.Count + "个参数，多参数并行检测已开启（并发=" + maxPar + "），正在同时对所有参数进行注入测试（Level=" + level + "）！");
            using SemaphoreSlim gate = new SemaphoreSlim(maxPar);
            var tasks = targets.Select(async t =>
            {
                await gate.WaitAsync().ConfigureAwait(false);
                try
                {
                    return await SuperSQLInjectionV2.Tools.Inject.InjectDetectEngine.DetectParam(AppConfig, requestTxt, t.name, t.value, t.place, t.header, t.uriIdx).ConfigureAwait(false);
                }
                finally
                {
                    gate.Release();
                }
            }).ToList();
            List<InjectPoint>[] allHits = await Task.WhenAll(tasks).ConfigureAwait(false);
            foreach (List<InjectPoint> hits in allHits)
            {
                foreach (InjectPoint inp in hits)
                {
                    UpdateData(inp);
                }
            }
            return;
        }
        foreach (var t in targets)
        {
            Log.Show("报告大侠，正在对" + t.desc + "参数 " + t.name + " 进行注入测试（Level=" + level + "）！");
            List<InjectPoint> hits = await SuperSQLInjectionV2.Tools.Inject.InjectDetectEngine.DetectParam(AppConfig, requestTxt, t.name, t.value, t.place, t.header, t.uriIdx);
            foreach (InjectPoint inp in hits)
            {
                UpdateData(inp);
            }
        }
    }

    /// <summary>
    /// 时间通道命中/恢复注入记录时，把检测出的延时秒数同步到通道配置的时间盲注参数（SleepInjectMaxTime），
    /// 选择记录后数据管理页通道配置的时间盲注组自动带出对应值
    /// </summary>
    private void SyncTimeSleepFromCheckValue()
    {
        if (AppConfig.DataConfig.IsTimeChannel || AppConfig.DataConfig.SelectedInjectType == InjectType.Stacked)
        {
            int sec = MyTools.ConvertToInt(AppConfig.DataConfig.CheckValue);
            if (sec > 0 && sec <= 60 && AppConfig.SleepInjectMaxTime != sec)
            {
                AppConfig.SleepInjectMaxTime = sec;
            }
        }
    }

    private void UpdateData(InjectPoint inp)
    {
        if (inp.IsInject) {
            _detectHitFound = true;
            _detectHitCount++;

            //旧模型兼容：Bool盲注+时间判定 的命中升级为独立的时间盲注类型（判定经EffectiveBoolType强制走时间）
            if (inp.InjectType == InjectType.Blind && inp.BoolInjectType == BoolInjectType.Time)
            {
                inp.InjectType = InjectType.Time;
            }
            AppConfig.DataConfig.SelectedInjectType = inp.InjectType;
            //检测概览"注入参数"实时联动
            AppConfig.DataConfig.InjectParamName = inp.PName ?? "";
            if (inp.InjectType.Equals(InjectType.Blind) || inp.InjectType.Equals(InjectType.Stacked) || inp.InjectType.Equals(InjectType.Time)) {
                //堆叠命中同样携带时间盲注oracle（BoolInjectType.Time + CheckValue=延时秒数），取数回退依赖
                //时间盲注类型的判定由EffectiveBoolType强制为时间，SelectBoolInject不跟随（避免选中已下线的"时间"判断方式）
                if (!inp.InjectType.Equals(InjectType.Time))
                {
                    AppConfig.DataConfig.SelectBoolInject = inp.BoolInjectType;
                }
                AppConfig.DataConfig.CheckValue = inp.CheckValue;
                //反取标志联动（概览"反取"标记 + 盲注取数链路消费）
                AppConfig.DataConfig.Reverse = inp.Revers;
                //时间盲注延时秒数带出到通道配置时间盲注组
                SyncTimeSleepFromCheckValue();
            }
            if (!inp.DBType.Equals(DBType.UnKnow)) {
                AppConfig.DataConfig.SelectedDBType = inp.DBType;
            }
            if (inp.InjectType.Equals(InjectType.Union))
            {
                AppConfig.DataConfig.ShowColumnIndex = inp.ShowColumnIndex;
                AppConfig.DataConfig.SumColumnCount = inp.SumColumnCount;
            }
            if (inp.InjectType.Equals(InjectType.Error))
            {
                //报错方式联动：从命中的报错payload反推对应变体（须在SelectedDBType之后，变体表已随库切换就绪；
                //后台线程时Post派发，保证晚于OnSelectedDBTypeChanged里"复位为默认"的Post执行，不被覆盖）
                string? method = InferErrorMethod(inp.TestPayload);
                if (method != null)
                {
                    if (Avalonia.Application.Current == null || Dispatcher.UIThread.CheckAccess())
                    {
                        AppConfig.DataConfig.SelectedErrorMethod = method;
                    }
                    else
                    {
                        Dispatcher.UIThread.Post( ()=> AppConfig.DataConfig.SelectedErrorMethod = method);
                    }
                }
            }
            //标记报文不回写编辑器：检测页报文保持干净，利用标记只随注入点存入注入记录，
            //取数时在注入记录中选择对应注入点（恢复记录）才加载带标记的报文
            _lastHitRequestTxt = inp.RequestTxt;
            AddInjectRecord(inp);
        }
    }

    /// <summary>本轮检测是否有命中（UpdateData置位，驱动检测完成后的banner主动确认）</summary>
    private bool _detectHitFound;

    /// <summary>本轮检测命中点总数（UpdateData累加，驱动检测完成后的取数引导提示）</summary>
    private int _detectHitCount;

    /// <summary>已正常跑完检测的目标（Host:Port）：状态栏据此区分"待检测"与"未检测到注入"，切换目标后自动回到待检测</summary>
    private string _detectFinishedTarget = "";

    /// <summary>最后一个命中点的标记报文（编辑器不回写后，banner主动确认等检测后动作据此构造请求）</summary>
    private string? _lastHitRequestTxt;

    /// <summary>
    /// 检测命中后主动确认DBMS banner（指纹识别阶段）：
    /// 用当前命中的Union/报错通道查询版本表达式，坐实库型与版本；失败不影响检测结论
    /// </summary>
    private async Task ConfirmDbBanner()
    {
        try
        {
            DBType db = AppConfig.DataConfig.SelectedDBType;
            InjectType type = AppConfig.DataConfig.SelectedInjectType;
            if (db == DBType.UnKnow || (type != InjectType.Union && type != InjectType.Error))
            {
                return;
            }
            ObservableCollection<VersModel> vers = new ObservableCollection<VersModel>();
            VersTools.ReadVersByDBType(db, vers);
            VersModel? item = vers.FirstOrDefault(v => v.Name.Contains("版本", StringComparison.Ordinal));
            if (item == null || string.IsNullOrWhiteSpace(item.VerPayload))
            {
                return;
            }
            string payload = type == InjectType.Union
                ? PayloadFactory.BPTool.UnionAll(item.VerPayload, AppConfig.DataConfig.SumColumnCount, AppConfig.DataConfig.ShowColumnIndex)
                : PayloadFactory.BPTool.ErrorData(item.VerPayload);
            //编辑器不回写标记报文后，用最后一个命中点的标记报文构造请求
            if (string.IsNullOrEmpty(_lastHitRequestTxt))
            {
                return;
            }
            HttpRequest hr = new HttpRequest(AppConfig, _lastHitRequestTxt);
            hr.Payload = payload;
            HttpResponse resp = await HTTPTool.SendRequestRetryAsync(hr).ConfigureAwait(false);
            string banner = DataComm.ParseUnionOrErrorData(resp, payload);
            //长banner（如PG/MSSQL版本串）被截断时兜底抢救部分数据（一次性确认不做分片，拿到部分banner即可）
            if (string.IsNullOrWhiteSpace(banner) && DataComm.IsTruncatedMarker(resp, payload))
            {
                banner = DataComm.ParseTrimmed(resp, payload);
            }
            if (!string.IsNullOrWhiteSpace(banner))
            {
                Log.Success("DBMS banner主动确认：" + db + " → " + banner);
            }
        }
        catch (Exception e)
        {
            //banner确认失败不影响检测结论
            Log.SysLog("DBMS banner确认失败：" + e.Message);
        }
    }

    /// <summary>报错payload特征→报错方式变体名映射（变体名与函数名不一致时兜底，如FloorRand/GtidSubset）</summary>
    private static readonly (string Token, string Method)[] ErrorPayloadMethodHints =
    [
        ("floor(rand", "FloorRand"),
        ("gtid_subset(", "GtidSubset"),
    ];

    /// <summary>
    /// 根据命中的报错payload反推当前库模板中的报错方式变体名：
    /// 先按变体名（不区分大小写）包含匹配（UpdateXml/ExtractValue等变体名与函数名一致），
    /// 再按已知函数特征映射兜底；无匹配返回null（保持当前选择不变）
    /// </summary>
    private static string? InferErrorMethod(string? payload)
    {
        if (string.IsNullOrEmpty(payload))
        {
            return null;
        }
        var variants = PayloadFactory.BasePayload?.ErrorDataVariants;
        if (variants == null || variants.Count == 0)
        {
            return null;
        }
        string lower = payload.ToLowerInvariant();
        foreach (string name in variants.Keys)
        {
            if (lower.Contains(name.ToLowerInvariant(), StringComparison.Ordinal))
            {
                return name;
            }
        }
        foreach ((string token, string method) in ErrorPayloadMethodHints)
        {
            if (lower.Contains(token, StringComparison.Ordinal) && variants.ContainsKey(method))
            {
                return method;
            }
        }
        return null;
    }

    #region 注入记录

    /// <summary>
    /// 当前注入上下文（检测/记录/手工产生的利用结论，数据读取等链路消费）
    /// </summary>
    public InjectionContext CurrentContext { get; } = new InjectionContext();

    /// <summary>上下文摘要显示文本（P4页头展示）</summary>
    [ObservableProperty] private string _contextSummaryText = "未建立注入上下文";

    /// <summary>上下文来源显示文本</summary>
    [ObservableProperty] private string _contextSourceText = "";

    /// <summary>检测概览：已检出（支持）的注入类型标签集合</summary>
    public ObservableCollection<string> InjectTypeTags { get; } = new ObservableCollection<string>();

    /// <summary>检测概览：数据库类型显示，未检出时显示"待检测"，检出后展示记录中的数据库类型</summary>
    [ObservableProperty] private string _overviewDBType = "待检测";

    /// <summary>检测概览：当前目标（Host:Port）已检出的注入点数量</summary>
    [ObservableProperty] private int _overviewRecordCount = 0;

    /// <summary>检测概览：端口+协议显示（如 5099 · HTTP）</summary>
    [ObservableProperty] private string _overviewPortText = "";

    /// <summary>检测概览：当前目标记录的注入位置（GET参数/POST表单/JSON体/Cookie/HTTP头，去重）</summary>
    [ObservableProperty] private string _overviewPlaceText = "待检测";

    /// <summary>检测概览：当前目标最新命中记录的测试payload</summary>
    [ObservableProperty] private string _overviewPayloadText = "待检测";

    /// <summary>检测概览：当前目标最近一次命中时间</summary>
    [ObservableProperty] private string _overviewLastTimeText = "-";

    /// <summary>刷新注入上下文摘要显示（由1秒定时器驱动）</summary>
    private void RefreshContextSummary()
    {
        if (CurrentContext.Source == InjectContextSource.None)
        {
            ContextSummaryText = "未建立注入上下文";
            ContextSourceText = "";
            return;
        }
        ContextSummaryText = $"{RequestMethod} {CurrentContext.ParamName} · {CurrentContext.InjectType} · {CurrentContext.DbType} · {CurrentContext.DbEncoding}";
        ContextSourceText = string.IsNullOrEmpty(CurrentContext.SourceDetail)
            ? CurrentContext.SourceText
            : $"{CurrentContext.SourceText} · {CurrentContext.SourceDetail}";
    }

    /// <summary>
    /// 手工指定/覆盖注入上下文：写入共享配置使取数链路生效，标记来源为手工指定
    /// </summary>
    [RelayCommand]
    private void ApplyContextOverride()
    {
        AppConfig.DataConfig.SelectedInjectType = CurrentContext.InjectType;
        AppConfig.DataConfig.SelectedDBType = CurrentContext.DbType;
        //编码已改为直接绑定全局配置（AppConfig.DataConfig.DbEncoding），此处仅同步回上下文用于摘要显示
        CurrentContext.DbEncoding = AppConfig.DataConfig.DbEncoding;
        AppConfig.DataConfig.SumColumnCount = CurrentContext.SumColumnCount;
        AppConfig.DataConfig.ShowColumnIndex = CurrentContext.ShowColumnIndex;
        //手工指定上下文与注入记录无关，复位vector取数模式防止残留记录状态污染
        AppConfig.DataConfig.ResetVectorMode();
        CurrentContext.Source = InjectContextSource.Manual;
        CurrentContext.SourceDetail = "手动覆盖";
        Log.Success($"已手工指定注入上下文：{CurrentContext.InjectType} · {CurrentContext.DbType} · {CurrentContext.DbEncoding}（Union {CurrentContext.SumColumnCount} 列，显示列 {CurrentContext.ShowColumnIndex}），取数等利用将按此执行");
    }

    /// <summary>
    /// 注入记录列表（检测命中自动记录，可恢复利用）
    /// </summary>
    public ObservableCollection<InjectRecord> InjectRecords { get; } = new ObservableCollection<InjectRecord>();

    /// <summary>注入记录页表格绑定源（筛选后的视图）</summary>
    [ObservableProperty] private ObservableCollection<InjectRecord> _filteredInjectRecords = new();
    [ObservableProperty] private string _injectRecordSearchKeyword = "";
    [ObservableProperty] private string _injectRecordFilterDb = "全部";
    [ObservableProperty] private string _injectRecordFilterType = "全部";
    [ObservableProperty] private ObservableCollection<string> _injectRecordDbFilters = new ObservableCollection<string> { "全部" };
    [ObservableProperty] private ObservableCollection<string> _injectRecordTypeFilters = new ObservableCollection<string> { "全部" };
    [ObservableProperty] private string _injectRecordCountInfo = "";

    partial void OnInjectRecordSearchKeywordChanged(string value) => ApplyInjectRecordFilter();
    partial void OnInjectRecordFilterDbChanged(string value) => ApplyInjectRecordFilter();
    partial void OnInjectRecordFilterTypeChanged(string value) => ApplyInjectRecordFilter();

    /// <summary>按关键字（目标/参数/Payload）+ 数据库 + 注入类型筛选注入记录</summary>
    private void ApplyInjectRecordFilter()
    {
        IEnumerable<InjectRecord> q = InjectRecords;
        string kw = (InjectRecordSearchKeyword ?? "").Trim();
        if (kw.Length > 0)
        {
            q = q.Where(r => (r.Target ?? "").Contains(kw, StringComparison.OrdinalIgnoreCase)
                          || (r.PName ?? "").Contains(kw, StringComparison.OrdinalIgnoreCase)
                          || (r.TestPayload ?? "").Contains(kw, StringComparison.OrdinalIgnoreCase));
        }
        if (!string.IsNullOrEmpty(InjectRecordFilterDb) && InjectRecordFilterDb != "全部")
        {
            q = q.Where(r => string.Equals(r.DBType.ToString(), InjectRecordFilterDb, StringComparison.OrdinalIgnoreCase));
        }
        if (!string.IsNullOrEmpty(InjectRecordFilterType) && InjectRecordFilterType != "全部")
        {
            q = q.Where(r => string.Equals(r.InjectTypeDesc, InjectRecordFilterType, StringComparison.OrdinalIgnoreCase));
        }
        var list = q.ToList();
        FilteredInjectRecords = new ObservableCollection<InjectRecord>(list);
        InjectRecordCountInfo = $"共 {InjectRecords.Count} 条 · 筛选后 {list.Count} 条";
    }

    /// <summary>刷新数据库/注入类型筛选项（随记录增删自动更新）</summary>
    private void RefreshInjectRecordFilters()
    {
        InjectRecordDbFilters = new ObservableCollection<string>(s_allFilterOption.Concat(
            InjectRecords.Select(r => r.DBType.ToString()).Distinct().OrderBy(x => x)));
        InjectRecordTypeFilters = new ObservableCollection<string>(s_allFilterOption.Concat(
            InjectRecords.Select(r => r.InjectTypeDesc).Distinct().OrderBy(x => x)));
        ApplyInjectRecordFilter();
    }

    [ObservableProperty] private InjectRecord? _selectedInjectRecord;

    /// <summary>数据操作合并页顶部快速选择的注入记录（选中即自动恢复配置）</summary>
    [ObservableProperty] private InjectRecord? _quickSelectRecord;

    partial void OnQuickSelectRecordChanged(InjectRecord? value)
    {
        if (value == null)
        {
            return;
        }
        SelectedInjectRecord = value;
        RestoreInjectRecord(value);
    }

    private static string InjectRecordPath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config", "inject_records.json");

    /// <summary>
    /// 检测命中后记录注入点（同参数同类型去重更新）
    /// </summary>
    private void AddInjectRecord(InjectPoint inp)
    {
        InjectRecord record = new InjectRecord
        {
            Time = DateTime.Now,
            Target = AppConfig.Host + ":" + AppConfig.Port,
            PName = inp.PName ?? "",
            DBType = inp.DBType,
            InjectType = inp.InjectType,
            BoolInjectType = inp.BoolInjectType,
            CheckValue = inp.CheckValue ?? "",
            Revers = inp.Revers,
            SumColumnCount = inp.SumColumnCount,
            ShowColumnIndex = inp.ShowColumnIndex,
            UnionStartPayLoad = inp.UnionStartPayLoad ?? "",
            TestPayload = inp.TestPayload ?? "",
            RequestTxt = inp.RequestTxt ?? "",
            PValue = inp.PValue ?? "",
            Place = inp.Place,
            HeaderName = inp.HeaderName ?? "",
            Where = inp.Where,
            VectorTemplate = inp.VectorTemplate ?? "",
            OrigValue = inp.OrigValue ?? "",
            AutoTamper = inp.AutoTamper ?? "",
            TrueCode = inp.TrueCode,
            FalseCode = inp.FalseCode,
            Prefix = inp.Prefix ?? "",
            Suffix = inp.Suffix ?? "",
            UriIndex = inp.UriIndex,
            Clause = inp.Clause ?? ""
        };
        //每注入点生成随机回显标记（防固定短串与页面内容冲突），随记录持久化并立即生效
        (record.StartMark, record.EndMark, record.SplitMark) = Payload.EchoMarkers.Generate();
        Payload.EchoMarkers.Use(record, Payload.PayloadFactory.BasePayload);
        InjectRecord? exist = InjectRecords.FirstOrDefault(r =>
            r.PName == record.PName && r.InjectType == record.InjectType && r.BoolInjectType == record.BoolInjectType
            && r.Target == record.Target && r.RequestTxt == record.RequestTxt);
        if (exist != null)
        {
            int index = InjectRecords.IndexOf(exist);
            InjectRecords[index] = record;
        }
        else
        {
            InjectRecords.Insert(0, record);
        }
        SaveInjectRecords();
        //登记通道注册表：取数自动通道升级用（盲注/时间取数前探测同参数Union/Error）
        InjectChannelRegistry.Register(AppConfig.Host, AppConfig.Port, record);
        Log.Success("已记录注入点到注入记录列表：" + record.PName + "（" + record.InjectTypeDesc + "，" + record.DBType + "）");

        //检测命中 → 建立注入上下文（来源：自动检测）
        CurrentContext.Source = InjectContextSource.AutoDetect;
        CurrentContext.SourceDetail = record.Target;
        CurrentContext.ParamName = record.PName;
        CurrentContext.InjectType = record.InjectType;
        CurrentContext.DbType = record.DBType;
        CurrentContext.DbEncoding = AppConfig.DataConfig.DbEncoding;
        //列数/显示位仅Union命中时有意义，非Union保留默认值（4/2）
        if (record.InjectType == InjectType.Union)
        {
            CurrentContext.SumColumnCount = Math.Max(1, record.SumColumnCount);
            CurrentContext.ShowColumnIndex = Math.Max(1, record.ShowColumnIndex);
        }
    }

    /// <summary>
    /// 将选中的注入记录恢复到当前配置（请求标记/注入类型/数据库类型/判断值/列位等），随后即可进行取数等利用
    /// </summary>
    [RelayCommand]
    private void RestoreInjectRecord()
    {
        InjectRecord? record = SelectedInjectRecord;
        if (record == null)
        {
            Log.Warning("大侠，请先在注入记录列表中选择一条记录！");
            return;
        }
        RestoreInjectRecord(record);
    }

    /// <summary>
    /// 右键"进入数据操作"：恢复选中注入记录并跳转到数据操作页
    /// </summary>
    [RelayCommand]
    private void EnterDataOp()
    {
        //优先选中行，无选中行时回落到第一条勾选行（勾选框点击不触发行选中）
        InjectRecord? record = SelectedInjectRecord ?? InjectRecords.FirstOrDefault(r => r.RowChecked);
        if (record == null)
        {
            Log.Warning("大侠，请先在注入记录列表中选择或勾选一条记录！");
            return;
        }
        RestoreInjectRecord(record);
        SelectNav("4.7");
    }

    /// <summary>
    /// 恢复指定注入记录到当前配置（请求标记/注入类型/数据库类型/判断值/列位等），并建立注入上下文
    /// </summary>
    /// <summary>记录恢复重入保护：RestoreInjectRecord内联动QuickSelectRecord会经OnQuickSelectRecordChanged回调本方法</summary>
    private bool _restoringRecord;

    private void RestoreInjectRecord(InjectRecord record)
    {
        if (_restoringRecord)
        {
            return;
        }
        _restoringRecord = true;
        try
        {
            RestoreInjectRecordCore(record);
        }
        finally
        {
            _restoringRecord = false;
        }
    }

    private void RestoreInjectRecordCore(InjectRecord record)
    {
        //方案C：恢复时不信任存储的烘焙快照，按结构化字段（Prefix/Suffix/Where/VectorTemplate/OrigValue/Place）重烘焙标记报文，
        //保证标记形态与当前编码/取数链路一致；定位失败时RebakeRecordRequest内部回退存储报文
        AppConfig.TxtRequest.Text = RequestRewriter.RebakeRecordRequest(AppConfig, record);
        //回显标记随记录恢复（记录无标记的旧数据回退模板默认值）
        Payload.EchoMarkers.Use(record, Payload.PayloadFactory.BasePayload);
        SyncUrlFromRecord(record);
        //旧记录迁移：Bool盲注+时间判定 升级为独立的时间盲注类型
        if (record.InjectType == InjectType.Blind && record.BoolInjectType == BoolInjectType.Time)
        {
            record.InjectType = InjectType.Time;
        }
        AppConfig.DataConfig.InjectParamName = record.PName;
        AppConfig.DataConfig.SelectedDBType = record.DBType;
        AppConfig.DataConfig.SelectedInjectType = record.InjectType;
        //where=3参数替换点的vector取数模式随记录恢复（旧记录无此字段时自动为1/空=胶水模式）
        AppConfig.DataConfig.Where = record.Where;
        AppConfig.DataConfig.VectorTemplate = record.VectorTemplate ?? "";
        AppConfig.DataConfig.OrigValue = record.OrigValue ?? "";
        //实测报错回显容量随记录恢复（>0时报错分片直接用实测步长，免重复探测；SelectedDBType切换时已清零）
        AppConfig.DataConfig.MeasuredErrorChunkLen = record.ErrorChunkLen;
        //防脏数据校验基线随记录恢复（0=旧记录未记录，取数不做意外码校验）
        AppConfig.DataConfig.TrueCode = record.TrueCode;
        AppConfig.DataConfig.FalseCode = record.FalseCode;
        AppConfig.DataConfig.SawUnexpectedCode = false;
        //检测期自动适配的编码工具随记录恢复：自动启用对应工具（内置注册表解析）
        if (!string.IsNullOrEmpty(record.AutoTamper))
        {
            try
            {
                EncodeToolModel? item = AppConfig.ByPassConfig.EncodeTools.FirstOrDefault(s =>
                    string.Equals(s.Key, record.AutoTamper, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(s.Name, record.AutoTamper, StringComparison.OrdinalIgnoreCase));
                if (item == null)
                {
                    //解析统一编码工具注册表（EncodeToolRegistry，C#内置实现）
                    var found = Bypass.ScriptTamperEngine.FindBuiltinScript(record.AutoTamper);
                    if (found != null)
                    {
                        item = new EncodeToolModel { Name = found.Name, Key = found.Key, Scope = ScriptScope.Payload, Builtin = true, Enable = false };
                        AppConfig.ByPassConfig.EncodeTools.Add(item);
                    }
                }
                if (item != null && !item.Enable)
                {
                    item.Enable = true;
                    Log.Show("已按注入记录自动启用编码工具：" + record.AutoTamper + "（检测时验证可绕过 '>' 过滤）");
                }
            }
            catch (Exception ex)
            {
                Log.SysLog("恢复AutoTamper失败：" + ex.Message);
            }
        }
        if (record.InjectType == InjectType.Blind || record.InjectType == InjectType.Stacked || record.InjectType == InjectType.Time)
        {
            //堆叠记录同样携带时间盲注oracle（CheckValue=延时秒数），取数回退时需要
            //时间盲注类型判定由EffectiveBoolType强制为时间，SelectBoolInject不跟随
            if (record.InjectType != InjectType.Time)
            {
                AppConfig.DataConfig.SelectBoolInject = record.BoolInjectType;
            }
            AppConfig.DataConfig.CheckValue = record.CheckValue;
            AppConfig.DataConfig.Reverse = record.Revers;
            //时间盲注延时秒数随记录带出到通道配置时间盲注组
            SyncTimeSleepFromCheckValue();
        }
        if (record.InjectType == InjectType.Union)
        {
            AppConfig.DataConfig.SumColumnCount = record.SumColumnCount;
            AppConfig.DataConfig.ShowColumnIndex = record.ShowColumnIndex;
        }
        //非WHERE子句上下文告警：GROUP BY/ORDER BY/LIMIT/INSERT/UPDATE等位置检出时，取数"and"胶水可能不适用
        if (!string.IsNullOrWhiteSpace(record.Clause))
        {
            var nonWhere = record.Clause.Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(s => int.TryParse(s.Trim(), out int c) ? c : 0)
                .Where(c => c != 0 && c != 1).Distinct().ToList();
            if (nonWhere.Count > 0)
            {
                string[] names = { "", "", "GROUP BY", "ORDER BY", "LIMIT", "OFFSET", "INSERT", "UPDATE" };
                string ctxNames = string.Join("/", nonWhere.Select(c => c >= 2 && c <= 7 ? names[c] : "clause" + c));
                Log.Warning("该注入点位于 " + ctxNames + " 子句上下文：取数默认使用\"and\"胶水拼接，可能出现语法错误；若取数失败请手工调整注入标记的胶水（如逗号/直接替换）。");
            }
        }
        Log.Show("已恢复注入记录到当前配置：参数" + record.PName + "（" + record.InjectTypeDesc + "，" + record.DBType + "），可以直接进行取数等利用操作！");

        //联动数据操作页"检测记录"下拉：恢复即选中对应记录
        //（同引用时SetProperty不触发变更，不会经OnQuickSelectRecordChanged递归回调本方法）
        if (!ReferenceEquals(QuickSelectRecord, record) && InjectRecords.Contains(record))
        {
            QuickSelectRecord = record;
        }

        //恢复记录 → 建立注入上下文（来源：注入记录）
        CurrentContext.Source = InjectContextSource.InjectRecord;
        CurrentContext.SourceDetail = record.Target;
        CurrentContext.ParamName = record.PName;
        CurrentContext.InjectType = record.InjectType;
        CurrentContext.DbType = record.DBType;
        CurrentContext.DbEncoding = AppConfig.DataConfig.DbEncoding;
        //列数/显示位仅Union记录有意义，非Union记录保留当前值，避免被无意义的1或0覆盖
        if (record.InjectType == InjectType.Union)
        {
            CurrentContext.SumColumnCount = Math.Max(1, record.SumColumnCount);
            CurrentContext.ShowColumnIndex = Math.Max(1, record.ShowColumnIndex);
        }
    }

    /// <summary>
    /// 从注入记录还原顶部URL/主机/端口/方法显示：剥离报文中的注入/编码/随机值标记，重建干净URL
    /// </summary>
    private void SyncUrlFromRecord(InjectRecord record)
    {
        try
        {
            if (string.IsNullOrEmpty(record.RequestTxt))
            {
                return;
            }
            string[] reqLines = record.RequestTxt.Split('\n');
            //先整行剥除编码标记块再按空格切分：标记内payload可能含空格（如" and $sql$#"），
            //若先按空格切，闭合标签会被切掉导致<Encode>前缀残留在URL中
            string firstLine = reqLines[0].Trim();
            firstLine = Regex.Replace(firstLine, "<Encode>.*?</Encode>", "");
            //兜底：剥除未闭合的标记残余（含标记本身到行尾）
            firstLine = Regex.Replace(firstLine, "<Encode>.*$", "");
            string[] firstParts = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (firstParts.Length >= 2)
            {
                string cleanPath = firstParts[1];
                //裸$sql$替换为原始参数值：PValue本身含编码块，须先剥除再作为替换值
                string cleanPValue = Regex.Replace(record.PValue ?? "", "<Encode>.*?</Encode>", "");
                cleanPath = cleanPath.Replace(ConstData.InjectStr, cleanPValue, StringComparison.Ordinal);
                cleanPath = Regex.Replace(cleanPath, @"<DRule>[^:<>\s]*(?::([.\s\S]*?))?<DRule>", "$1");
                if (cleanPath.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                    cleanPath.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    AppConfig.Url = cleanPath;
                }
                else
                {
                    string hostHeader = reqLines.FirstOrDefault(l => l.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))?
                        .Substring(5).Trim()?? "";
                    if (!string.IsNullOrEmpty(hostHeader))
                    {
                        AppConfig.Url = (AppConfig.IsSSL ? "https://" : "http://") + hostHeader
                            + (cleanPath.StartsWith('/') ? cleanPath : "/" + cleanPath);
                    }
                }
            }
            //同步主机/端口到公共配置与检测概览
            if (!string.IsNullOrEmpty(record.Target))
            {
                string[] hp = record.Target.Split(':');
                AppConfig.Host = hp[0];
                if (hp.Length > 1 && int.TryParse(hp[1], out int port))
                {
                    AppConfig.Port = port;
                }
            }
        }
        catch
        {
            //URL同步失败不影响记录恢复主流程
        }
    }

    /// <summary>
    /// 删除选中的注入记录
    /// </summary>
    [RelayCommand]
    private void RemoveInjectRecord()
    {
        InjectRecord? record = SelectedInjectRecord;
        if (record == null)
        {
            Log.Warning("大侠，请先选择要删除的注入记录！");
            return;
        }
        InjectRecords.Remove(record);
        SaveInjectRecords();
    }

    /// <summary>操作列"查看"/工具栏"查看详情"：弹窗展示注入记录全部上下文字段（只读）；无参数时取当前选中行</summary>
    [RelayCommand]
    private async Task ViewInjectRecord(InjectRecord? record)
    {
        record ??= SelectedInjectRecord;
        if (record == null)
        {
            Log.Warning("大侠，请先在注入记录列表中选择一条记录！");
            return;
        }
        var options = new OverlayDialogOptions
        {
            FullScreen = false,
            HorizontalAnchor = HorizontalPosition.Center,
            VerticalAnchor = VerticalPosition.Center,
            Mode = DialogMode.None,
            Buttons = DialogButton.None,
            Title = "注入记录详情 · " + record.Target + " · " + record.PName,
            CanLightDismiss = true,
            CanDragMove = true,
            IsCloseButtonVisible = true,
            CanResize = true,
        };
        await OverlayDialog.ShowStandardAsync<InjectRecordDetailView, InjectRecordDetailViewModel>(
            new InjectRecordDetailViewModel(record), options: options);
    }

    /// <summary>操作列"删除"：弹窗确认后删除该条注入记录</summary>
    [RelayCommand]
    private async Task DeleteInjectRecord(InjectRecord record)
    {
        if (record == null)
        {
            return;
        }
        var result = await OverlayMessageBox.ShowAsync(
            "确认删除注入记录「" + record.Target + " · " + record.PName + " · " + record.InjectTypeDesc + "」？",
            "删除确认", button: MessageBoxButton.YesNo);
        if (!MessageBoxResult.Yes.Equals(result))
        {
            return;
        }
        InjectRecords.Remove(record);
        SaveInjectRecords();
        Log.Success("已删除注入记录：" + record.Target + " · " + record.PName);
    }

    /// <summary>操作列"取数"：恢复该注入记录并跳转到数据操作页</summary>
    [RelayCommand]
    private void EnterDataOpWithRecord(InjectRecord record)
    {
        if (record == null)
        {
            return;
        }
        RestoreInjectRecord(record);
        SelectNav("4.7");
    }

    /// <summary>工具栏"删除选中"：弹窗确认后批量删除勾选行的注入记录</summary>
    [RelayCommand]
    private async Task RemoveCheckedInjectRecords()
    {
        var checkedRecords = InjectRecords.Where(r => r.RowChecked).ToList();
        if (checkedRecords.Count == 0)
        {
            NotificationManager?.Show("请先勾选要删除的注入记录！");
            return;
        }
        var result = await OverlayMessageBox.ShowAsync(
            "确认删除勾选的 " + checkedRecords.Count + " 条注入记录？",
            "删除确认", button: MessageBoxButton.YesNo);
        if (!MessageBoxResult.Yes.Equals(result))
        {
            return;
        }
        foreach (var record in checkedRecords)
        {
            InjectRecords.Remove(record);
        }
        SaveInjectRecords();
        Log.Success("已删除 " + checkedRecords.Count + " 条注入记录");
    }

    /// <summary>
    /// 清空全部注入记录
    /// </summary>
    [RelayCommand]
    private async Task ClearInjectRecords()
    {
        if (InjectRecords.Count == 0)
        {
            return;
        }
        var result = await OverlayMessageBox.ShowAsync(
            "确认清空全部 " + InjectRecords.Count + " 条注入记录？该操作不可恢复！", "清空确认", button: MessageBoxButton.YesNo);
        if (!MessageBoxResult.Yes.Equals(result))
        {
            return;
        }
        InjectRecords.Clear();
        SaveInjectRecords();
        Log.Success("已清空全部注入记录！");
    }

    private void LoadInjectRecords()
    {
        try
        {
            if (File.Exists(InjectRecordPath))
            {
                List<InjectRecord>? list = JsonSerializer.Deserialize(File.ReadAllText(InjectRecordPath), Source.JsonCtx.CompactInfo<List<InjectRecord>>());
                if (list != null)
                {
                    foreach (InjectRecord record in list)
                    {
                        InjectRecords.Add(record);
                        //登记通道注册表：供取数自动通道升级查询同参数Union/Error记录
                        InjectChannelRegistry.Register(record.Target?.Split(':')[0],
                            int.TryParse(record.Target?.Split(':').Skip(1).FirstOrDefault(), out int p) ? p : 0, record);
                    }
                }
            }
        }
        catch (Exception e)
        {
            Log.SysLog("加载注入记录失败：" + e.Message);
        }
        RefreshInjectRecordFilters();
    }

    private void SaveInjectRecords()
    {
        try
        {
            string dir = Path.GetDirectoryName(InjectRecordPath)!;
            if (!Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }
            File.WriteAllText(InjectRecordPath, JsonSerializer.Serialize(InjectRecords.ToList(), Source.JsonCtx.CompactInfo<List<InjectRecord>>()));
            RefreshInjectRecordFilters();
        }
        catch (Exception e)
        {
            Log.SysLog("保存注入记录失败：" + e.Message);
        }
    }

    #endregion

    /// <summary>
    /// 取数/文件/命令/自定义SQL操作前的统一配置检查：任一不符合弹窗提示并阻断后续操作。
    /// 检查项：注入标记存在且唯一、数据库类型已识别、注入类型已选择、
    /// 盲注类通道（Blind/Stacked/Dns）判断值已配置、DNS通道DNSLog域名已配置。
    /// </summary>
    public static bool EnsureDataOpReady(AppConfig config)
    {
        //1 注入标记必须存在（否则payload无处插入，所有请求打到干净页面导致误判/空数据）
        //读RequestTxt纯字符串镜像（TxtRequest是AvaloniaEdit文档有线程亲和，工作线程读Text会抛异常）
        string txt = config.RequestTxt ?? "";
        if (txt.IndexOf(ConstData.InjectStr, StringComparison.Ordinal) < 0)
        {
            return DataOpBlock("请求报文中没有注入标记（$sql$），payload将无处插入！\n请在请求报文中标记注入点，或在注入记录中选择对应注入点加载标记报文。");
        }
        //2 注入标记必须唯一（StringReplace会全位置替换payload）
        int markCount = (txt.Length - txt.Replace(ConstData.InjectStr, "", StringComparison.Ordinal).Length) / ConstData.InjectStr.Length;
        if (markCount > 1)
        {
            return DataOpBlock("请求报文含 " + markCount + " 个注入标记（$sql$），payload将同时替换所有位置！\n请只保留一个注入标记后再操作。");
        }
        //2.5 注入标记必须位于<Encode>块内（裸$sql$会让payload原文进入请求行，含空格即畸形请求/500）
        if (!InjectMarkInEncodeBlock(txt))
        {
            return DataOpBlock("注入标记（$sql$）未包裹在编码标记（<Encode>…</Encode>）内！\n裸标记的payload将原文进入请求行（含空格/引号即畸形请求），请用编码标记包裹注入点，或恢复注入记录自动加载规范报文。");
        }
        //3 数据库类型已识别（决定取数模板）
        if (config.DataConfig.SelectedDBType == DBType.UnKnow)
        {
            return DataOpBlock("未识别数据库类型，无法确定取数模板！\n请执行注入检测自动识别，或手动选择数据库类型。");
        }
        //4 注入类型已选择（决定取数通道）
        InjectType type = config.DataConfig.SelectedInjectType;
        if (type == InjectType.UnKnow)
        {
            return DataOpBlock("未选择注入类型，无法确定取数通道！\n请执行注入检测自动标注，或手动选择注入类型。");
        }
        //5 盲注类通道需要判断值作为oracle（Bool盲注逐字符/时间盲注延时秒数/Stacked时间回退/Dns传输携带）
        if ((type == InjectType.Blind || type == InjectType.Time || type == InjectType.Stacked || type == InjectType.Dns)
            && string.IsNullOrWhiteSpace(config.DataConfig.CheckValue))
        {
            return DataOpBlock("盲注判断值未配置！\nBool盲注/时间盲注/堆叠/DNS通道需要判断值作为判定依据，请配置判断值（或用\"查找判断值\"自动探测），或恢复对应注入记录。");
        }
        //6 DNS通道需要DNSLog域名
        if (type == InjectType.Dns && string.IsNullOrWhiteSpace(config.DataConfig.DnsLogDomain))
        {
            return DataOpBlock("DNS盲注需要先配置DNSLog域名！\n请在网络设置中配置DNSLog域名（如 abc.ceye.io）。");
        }
        return true;
    }

    /// <summary>配置检查不通过：红色日志 + 弹窗提示（无UI环境只记日志），并阻断后续操作</summary>
    private static bool DataOpBlock(string message)
    {
        Log.Error(message);
        if (!LogTools.Headless && Avalonia.Application.Current != null)
        {
            _ = Ursa.Controls.OverlayMessageBox.ShowAsync(message, "取数配置检查", button: Ursa.Controls.MessageBoxButton.OK);
        }
        return false;
    }

    /// <summary>Encode块匹配（与StringReplace.EncodeBlockRegex同款：命名组捕获块类型与块体，配对闭合）</summary>
    private static readonly System.Text.RegularExpressions.Regex EncodeBlockRegex = new System.Text.RegularExpressions.Regex(
        "\\<(?<t>Encode)\\>(?<body>[.\\s\\S]*?)\\<\\/\\k<t>\\>",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>判断注入标记$sql$是否位于某个Encode块体内</summary>
    private static bool InjectMarkInEncodeBlock(string txt)
    {
        foreach (System.Text.RegularExpressions.Match m in EncodeBlockRegex.Matches(txt))
        {
            if (m.Groups["body"].Value.Contains(ConstData.InjectStr, StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }

    [RelayCommand]
    public async Task AutoFindKey()
    {
        try
        {
            if (!AppConfig.TxtRequest.Text.Contains(ConstData.InjectStr, StringComparison.Ordinal))
            {

                Log.Warning("大侠，请标记注入后，程序才能自动查找判断值！");
                return;
            }
            if (!AppConfig.TxtRequest.Text.Contains(ConstData.StartPoint, StringComparison.Ordinal))
            {

                Log.Warning("大侠，请将注入标记范围内参数标记编码，程序才能对标记编码范围内的数据进行URL编码，否则有错误！");
                return;
            }

            HttpRequest hr = new HttpRequest(AppConfig);
            hr.Payload=ConstData.TruePayload;
            HttpResponse trueServer = await HTTPTool.SendRequestRetryAsync(hr);
            HttpRequest hr1 = new HttpRequest(AppConfig);
            hr1.Payload = ConstData.FalsePayload;
            HttpResponse falseServer = await HTTPTool.SendRequestRetryAsync(hr1);

            InjectPoint inp= InjectTools.CheckTheKey(AppConfig,trueServer, falseServer, trueServer);
            if (inp.IsInject) {
                AppConfig.DataConfig.SelectBoolInject = inp.BoolInjectType;
                AppConfig.DataConfig.Reverse = inp.Revers;
                AppConfig.DataConfig.CheckValue = inp.CheckValue;
                //查找到时间判断时同步延时秒数到通道配置时间盲注组
                SyncTimeSleepFromCheckValue();
            }
            Log.Show("自动查找判断值完成！");

        }
        catch (Exception ep)
        {
            Log.Show("自动查找判断值发生异常！" + ep.Message);
        }
    }

    /// <summary>
    /// 验证当前设置的判断值是否正确（真条件应命中，假条件不应命中）
    /// </summary>
    [RelayCommand]
    public async Task CheckKey()
    {
        if (!AppConfig.TxtRequest.Text.Contains(ConstData.InjectStr, StringComparison.Ordinal))
        {
            Log.Warning("大侠，请先标记注入点，程序才能验证判断值！");
            return;
        }
        if (string.IsNullOrEmpty(AppConfig.DataConfig.CheckValue))
        {
            Log.Warning("大侠，请先设置判断值！");
            return;
        }
        AppConfig.ResetStop();
        IsRuning = true;
        bool isok = false;
        try
        {
            HttpRequest hr = new HttpRequest(AppConfig);
            hr.Payload = ConstData.TruePayload;
            HttpResponse trueServer = await HTTPTool.SendRequestRetryAsync(hr);
            HttpRequest hr1 = new HttpRequest(AppConfig);
            hr1.Payload = ConstData.FalsePayload;
            HttpResponse falseServer = await HTTPTool.SendRequestRetryAsync(hr1);

            bool truep = TruthOracle.IsTrue(trueServer, AppConfig.DataConfig.CheckValue, AppConfig.DataConfig.Reverse, AppConfig.DataConfig.EffectiveBoolType);
            bool falsep = TruthOracle.IsTrue(falseServer, AppConfig.DataConfig.CheckValue, AppConfig.DataConfig.Reverse, AppConfig.DataConfig.EffectiveBoolType);
            isok = truep && !falsep;
        }
        catch (Exception ep)
        {
            Log.Show("验证判断值发生异常！" + ep.Message);
            IsRuning = false;
            return;
        }
        IsRuning = false;
        if (isok)
        {
            await OverlayMessageBox.ShowAsync("判断值设置正确！", "信息", button: MessageBoxButton.OK);
        }
        else
        {
            await OverlayMessageBox.ShowAsync("此判断值设置错误，无法通过此判断值获取数据！请查看HTTP发包记录是否存在乱码，检查编码设置是否正确；可能此判断值同时在真假条件上出现，请更换判断值！", "信息", button: MessageBoxButton.OK);
        }
    }



    [RelayCommand]
    public void CopyMouseCommand(TextArea textArea)
    {
        ApplicationCommands.Copy.Execute(null, textArea);
    }


    [RelayCommand]
    private async Task SendRequest(string? source)
    {
        var options = new OverlayDialogOptions
        {
            FullScreen = false,
            HorizontalAnchor = HorizontalPosition.Center,
            VerticalAnchor = VerticalPosition.Center,
            HorizontalOffset = 0,
            VerticalOffset = 0,
            Mode = DialogMode.None,
            Buttons = DialogButton.None,
            Title = "数据发送结果",
            CanLightDismiss = true,
            CanDragMove = true,
            IsCloseButtonVisible = true,
            CanResize = false,
            
        };
        OverlayDialogOptions dialogOptions = new OverlayDialogOptions();

        //检测页与取数页报文已分离：按调用来源选择对应报文发送（detect=检测页干净报文，其余=取数页报文）
        string? reqTxt = string.Equals(source, "detect", StringComparison.OrdinalIgnoreCase) ? AppConfig.DetectRequestTxt : null;
        await OverlayDialog.ShowStandardAsync<RequestView, RequestViewViewModel>(new RequestViewViewModel(AppConfig, reqTxt), options: options);
    }
    private DispatcherTimer timer;

    #region 新UI外壳状态（左侧导航/目标栏/概览/日志过滤/主题切换）

    /// <summary>当前选中的左侧导航页索引：0注入检测 3注入记录 4数据操作 9取数模版 5网络设置 6防护绕过 7编码工具 8请求日志（1请求报文/2注入操作已删除合并，兜底跳0）</summary>
    [ObservableProperty] private int _selectedNavIndex = 0;
    /// <summary>面包屑当前页名（页面区顶部“首页 › xxx”位置标识）</summary>
    [ObservableProperty] private string _navCurrentPageName = "注入检测";
    [ObservableProperty] private bool _navPage0Visible = true;
    [ObservableProperty] private bool _navPage3Visible = false;
    [ObservableProperty] private bool _navPage4Visible = false;
    [ObservableProperty] private bool _navPage5Visible = false;
    [ObservableProperty] private bool _navPage6Visible = false;
    [ObservableProperty] private bool _navPage7Visible = false;
    [ObservableProperty] private bool _navPage8Visible = false;
    [ObservableProperty] private bool _navPage9Visible = false;
    [ObservableProperty] private bool _navPage10Visible = false;
    [ObservableProperty] private bool _navPage11Visible = false;

    /// <summary>顶部命令栏（URL卡片+公共配置）是否显示：仅注入检测页与数据操作页显示</summary>
    [ObservableProperty] private bool _topBarVisible = true;

    /// <summary>当前页是否允许显示日志面板（网络设置/防护绕过/编码工具/请求日志/取数模版页不显示）</summary>
    [ObservableProperty] private bool _logPageAllowed = true;

    /// <summary>状态栏库/表/字段/数据行统计是否显示：仅注入检测/注入记录/数据操作页（设置类页面与数据无关不显示）</summary>
    [ObservableProperty] private bool _dataStatsVisible = true;

    /// <summary>检测概览右列是否收起（收起后只留30px展开条，报文编辑区让出宽度）</summary>
    [ObservableProperty] private bool _overviewCollapsed = false;

    /// <summary>检测概览面板宽度：展开288/收起30</summary>
    public double OverviewPanelWidth => OverviewCollapsed ? 30 : 338;

    partial void OnOverviewCollapsedChanged(bool value)
    {
        OnPropertyChanged(nameof(OverviewPanelWidth));
    }

    /// <summary>收起/展开检测概览右列</summary>
    [RelayCommand]
    private void ToggleOverview()
    {
        OverviewCollapsed = !OverviewCollapsed;
    }

    /// <summary>用户手动收起日志面板（日志标题栏"收起"按钮/状态栏"日志"按钮切换，跨页面保持）</summary>
    [ObservableProperty] private bool _logCollapsed = false;

    /// <summary>日志面板最终可见性 = 当前页允许显示 且 未被手动收起</summary>
    public bool LogPanelVisible => LogPageAllowed && !LogCollapsed;

    partial void OnLogPageAllowedChanged(bool value)
    {
        OnPropertyChanged(nameof(LogPanelVisible));
    }

    partial void OnLogCollapsedChanged(bool value)
    {
        OnPropertyChanged(nameof(LogPanelVisible));
    }

    /// <summary>收起/展开运行日志面板</summary>
    [RelayCommand]
    private void ToggleLogPanel()
    {
        LogCollapsed = !LogCollapsed;
    }

    /// <summary>左侧导航折叠状态（true=仅图标窄栏）</summary>
    [ObservableProperty] private bool _isNavCollapsed;

    /// <summary>侧边栏宽度：展开240 / 折叠58</summary>
    public double NavSidebarWidth => IsNavCollapsed ? 58 : 240;

    partial void OnIsNavCollapsedChanged(bool value)
    {
        OnPropertyChanged(nameof(NavSidebarWidth));
    }

    /// <summary>折叠/展开左侧导航菜单</summary>
    [RelayCommand]
    private void ToggleNavCollapse()
    {
        IsNavCollapsed = !IsNavCollapsed;
    }

    partial void OnSelectedNavIndexChanged(int value)
    {
        NavPage0Visible = value == 0;
        NavPage3Visible = value == 3;
        NavPage4Visible = value == 4;
        NavPage5Visible = value == 5;
        NavPage6Visible = value == 6;
        NavPage7Visible = value == 7;
        NavPage8Visible = value == 8;
        NavPage9Visible = value == 9;
        NavPage10Visible = value == 10;
        NavPage11Visible = value == 11;
        NavCurrentPageName = value switch
        {
            0 => "注入检测",
            10 => "检测用例",
            3 => "注入记录",
            4 => "数据管理",
            9 => "取数模版",
            5 => "网络设置",
            6 => "防护绕过",
            7 => "编码工具",
            8 => "请求日志",
            11 => "关于",
            _ => ""
        };
        TopBarVisible = value == 0 || value == 4;
        LogPageAllowed = value != 5 && value != 6 && value != 7 && value != 8 && value != 9 && value != 10 && value != 11;
        DataStatsVisible = value == 0 || value == 3 || value == 4;
        if (value == 5)
        {
            ReloadDictWords(); //进入网络设置页时刷新字典管理列表（文件可能被外部改过）
        }
        if (value == 10)
        {
            ReloadPayloads(); //进入检测用例页时刷新用例列表（文件可能被外部改过）
            ReloadFingerprints(); //同步刷新报错指纹列表
        }
    }

    /// <summary>数据管理页选项卡：0请求配置 1环境变量 2Hash读取 3权限角色 4文件操作 5命令执行 6自定义SQL 7数据操作</summary>
    [ObservableProperty] private int _dataOpTabIndex = 0;

    /// <summary>导航切换，参数格式："页索引" 或 "页索引.子页索引"（2.x 映射到数据操作页的同级选项卡：2.0环境变量 2.1文件操作 2.2命令执行）</summary>
    [RelayCommand]
    private void SelectNav(string index)
    {
        if (string.IsNullOrEmpty(index))
        {
            return;
        }
        string[] parts = index.Split('.');
        if (int.TryParse(parts[0], out int page))
        {
            if (page == 1)
            {
                page = 0; //1=已删除的请求报文页，兜底回扫描注入
            }
            if (page == 2)
            {
                //注入操作功能已并入数据管理页（P4）：2.x直达同级选项卡（2.0环境变量→1 2.1文件操作→4 2.2命令执行→5）
                page = 4;
                DataOpTabIndex = 1;
                if (parts.Length > 1 && int.TryParse(parts[1], out int sub))
                {
                    DataOpTabIndex = sub switch { 0 => 1, 1 => 4, 2 => 5, _ => 1 };
                }
            }
            else if (page == 4)
            {
                //数据管理页默认选中“请求配置”选项卡；带子索引（如4.7）时直达对应选项卡
                DataOpTabIndex = 0;
                if (parts.Length > 1 && int.TryParse(parts[1], out int tab) && tab >= 0 && tab <= 7)
                {
                    DataOpTabIndex = tab;
                }
            }
            //跳过参数子页（索引3）仅注入检测页提供：切到数据管理页时若停留在3，回退到请求报文避免请求区空白
            if (page == 4 && RequestSubTabIndex == 3)
            {
                RequestSubTabIndex = 0;
            }
            //伴随请求（1，原随机值规则/二次注入已合并）仅数据管理页提供：切到注入检测页时若停留在1/2，回退到请求报文避免请求区空白
            if (page == 0 && (RequestSubTabIndex == 1 || RequestSubTabIndex == 2))
            {
                RequestSubTabIndex = 0;
            }
            SelectedNavIndex = page;
        }
    }

    /// <summary>主编辑面板子页：0请求报文 1伴随请求（前置随机值抓取+后置二次注入）3跳过参数（2已并入1）</summary>
    [ObservableProperty] private int _requestSubTabIndex = 0;
    [ObservableProperty] private bool _requestSubTab0Visible = true;
    [ObservableProperty] private bool _requestSubTab1Visible = false;
    [ObservableProperty] private bool _requestSubTab2Visible = false;
    [ObservableProperty] private bool _requestSubTab3Visible = false;

    partial void OnRequestSubTabIndexChanged(int value)
    {
        RequestSubTab0Visible = value == 0;
        RequestSubTab1Visible = value == 1;
        RequestSubTab2Visible = value == 2;
        RequestSubTab3Visible = value == 3;
    }

    [RelayCommand]
    private void SelectRequestSubTab(string index)
    {
        if (int.TryParse(index, out int i))
        {
            RequestSubTabIndex = i;
        }
    }

    /// <summary>日志级别过滤：0全部 1信息 2成功 3警告/错误</summary>
    [ObservableProperty] private int _logFilterIndex = 0;
    [ObservableProperty] private bool _logFilter0On = true;
    [ObservableProperty] private bool _logFilter1On = false;
    [ObservableProperty] private bool _logFilter2On = false;
    [ObservableProperty] private bool _logFilter3On = false;

    partial void OnLogFilterIndexChanged(int value)
    {
        LogFilter0On = value == 0;
        LogFilter1On = value == 1;
        LogFilter2On = value == 2;
        LogFilter3On = value == 3;
        Log.SetFilter(value);
    }

    [RelayCommand]
    private void SelectLogFilter(string index)
    {
        if (int.TryParse(index, out int i))
        {
            LogFilterIndex = i;
        }
    }

    //状态卡片/目标栏/状态栏用的实时显示状态（由1秒定时器刷新）
    [ObservableProperty] private string _requestMethod = "GET";
    [ObservableProperty] private string _elapsedTime = "00:00";
    [ObservableProperty] private string _detectStatusText = "就绪";
    [ObservableProperty] private IBrush _detectStatusBrush = IdleBrush;
    [ObservableProperty] private string _targetCardMeta = "未检测";
    [ObservableProperty] private string _proxyModeText = "直连模式";
    /// <summary>状态栏302跟随指示（开关在网络设置-请求设置，与FollowRedirect联动）</summary>
    [ObservableProperty] private string _redirectModeText = "302不跟随";
    [ObservableProperty] private bool _hasInjectRecords = false;
    [ObservableProperty] private string _requestFootText = "0 处注入点标记 · 0 行";
    [ObservableProperty] private IBrush _requestFootBrush = WarnBrush;
    [ObservableProperty] private string _dumpPathText = "未选择表";
    [ObservableProperty] private string _dumpColsText = "0 列";
    [ObservableProperty] private string _dumpRowsText = "0 行";

    private DateTime? _runStartTime;

    /// <summary>运行中文本色取 DsgPrimary 主题令牌（浅色=蓝、暗色=青自动适配），解析失败回落蓝；
    /// 手写解析需显式带主题变体（跟随系统时 RequestedThemeVariant=Default，要用 ActualThemeVariant 兜底）</summary>
    private static IBrush RunBrush
    {
        get
        {
            Application? app = Application.Current;
            if (app != null)
            {
                ThemeVariant? theme = app.RequestedThemeVariant;
                if (theme == null || theme == ThemeVariant.Default)
                {
                    theme = app.ActualThemeVariant ?? ThemeVariant.Light;
                }
                if (app.TryFindResource("DsgPrimary", theme, out var v) && v is IBrush b)
                {
                    return b;
                }
            }
            return new SolidColorBrush(Color.Parse("#2563EB"));
        }
    }
    private static readonly IBrush OkBrush = new SolidColorBrush(Color.Parse("#15A34A"));
    private static readonly IBrush IdleBrush = new SolidColorBrush(Color.Parse("#939CAB"));
    private static readonly IBrush WarnBrush = new SolidColorBrush(Color.Parse("#C77A08"));
    private static readonly IBrush ErrorBrush = new SolidColorBrush(Color.Parse("#DC2626"));


    /// <summary>刷新外壳实时状态（请求方法徽章/耗时/检测状态/目标卡片/报文统计），由1秒定时器驱动</summary>
    private void RefreshShellState()
    {
        //请求方法徽章：取请求首行第一个token
        string firstLine = AppConfig.RequestTxt?.Split('\n')[0]?.Trim() ?? "";
        string method = firstLine.Length > 0 ? firstLine.Split(' ')[0].ToUpperInvariant (): "GET";
        if (method.Length > 10)
        {
            method = method[..10];
        }
        RequestMethod = string.IsNullOrEmpty(method) ? "GET" : method;

        //耗时：运行期间累计，停止归零
        if (AppConfig.IsRuning)
        {
            _runStartTime ??= DateTime.Now;
            TimeSpan span = DateTime.Now - _runStartTime.Value;
            ElapsedTime = span.ToString(span.TotalHours >= 1 ? @"hh\:mm\:ss" : @"mm\:ss");
        }
        else
        {
            _runStartTime = null;
            ElapsedTime = "00:00";
        }

        //检测概览只统计当前目标（Host:Port）的注入记录：切换URL后概览随当前检测情况刷新，
        //历史其他目标的记录不再混入（记录列表本身仍全量保留供恢复）
        string curTarget = AppConfig.Host + ":" + AppConfig.Port;
        var curRecords = InjectRecords.Where(r => string.Equals(r.Target, curTarget, StringComparison.OrdinalIgnoreCase)).ToList();
        OverviewRecordCount = curRecords.Count;

        //检测状态：待检测 → 检测中 → 存在注入 / 未检测到注入（结论只对正常跑完的目标生效，切换目标自动回到待检测）
        if (AppConfig.IsRuning)
        {
            DetectStatusText = "检测中";
            DetectStatusBrush = RunBrush;
        }
        else if (curRecords.Count > 0)
        {
            DetectStatusText = "存在注入";
            DetectStatusBrush = OkBrush;
        }
        else if (string.Equals(_detectFinishedTarget, curTarget, StringComparison.OrdinalIgnoreCase))
        {
            DetectStatusText = "未检测到注入";
            DetectStatusBrush = IdleBrush;
        }
        else
        {
            DetectStatusText = "待检测";
            DetectStatusBrush = IdleBrush;
        }

        HasInjectRecords = curRecords.Count > 0;
        ProxyModeText = AppConfig.ProxyConfig.ProxyEnable ? "代理模式" : "直连模式";

        string param = string.IsNullOrEmpty(AppConfig.DataConfig.InjectParamName) ? "-" : AppConfig.DataConfig.InjectParamName;
        TargetCardMeta = $"{RequestMethod} · 参数 {param} · {(curRecords.Count > 0 ? "可注入" : "未标注")}";

        //报文面板底部统计：注入点标记数与行数（多标记红色警示：payload将全位置替换）
        string reqTxt = AppConfig.RequestTxt ?? "";
        int markCount = string.IsNullOrEmpty(reqTxt)
            ? 0
            : (reqTxt.Length - reqTxt.Replace(ConstData.InjectStr, "", StringComparison.Ordinal).Length) / ConstData.InjectStr.Length;
        int lineCount = string.IsNullOrEmpty(reqTxt) ? 0 : reqTxt.Split('\n').Length;
        if (markCount > 1)
        {
            RequestFootText = $"⚠ {markCount} 处注入点标记（payload将全位置替换）· {lineCount} 行";
            RequestFootBrush = ErrorBrush;
        }
        else
        {
            RequestFootText = $"{markCount} 处注入点标记 · {lineCount} 行";
            RequestFootBrush = WarnBrush;
        }

        //注入上下文摘要（P4页头）
        RefreshContextSummary();

        //检测概览：支持注入类型标签（按当前目标注入记录去重，仅在变化时重建避免闪烁）
        var tags = curRecords.Select(r => r.InjectTypeDesc).Where(t => !string.IsNullOrEmpty(t)).Distinct().ToList();
        if (!tags.SequenceEqual(InjectTypeTags))
        {
            InjectTypeTags.Clear();
            foreach (string t in tags)
            {
                InjectTypeTags.Add(t);
            }
        }

        //检测概览：数据库类型，未检出显示"待检测"，检出后展示当前目标记录中的数据库类型（去重）
        string dbTypes = string.Join("/", curRecords.Select(r => r.DBType.ToString()).Where(t => !string.IsNullOrEmpty(t)).Distinct());
        OverviewDBType = string.IsNullOrEmpty(dbTypes) ? "待检测" : dbTypes;

        //检测概览：端口+协议 / 注入位置 / 最新命中payload与时间（注入记录头插，首条即最新；
        //payload取最新一条非空记录——Union命中不写TestPayload，跳过避免显示"待检测"）
        OverviewPortText = AppConfig.Port + " · " + (AppConfig.IsSSL ? "HTTPS" : "HTTP");
        OverviewPlaceText = curRecords.Count == 0
            ? "待检测"
            : string.Join("/", curRecords.Select(r => r.PlaceDesc).Where(t => !string.IsNullOrEmpty(t)).Distinct());
        InjectRecord? latestHit = curRecords.FirstOrDefault(r => !string.IsNullOrEmpty(r.TestPayload)) ?? curRecords.FirstOrDefault();
        OverviewPayloadText = latestHit == null || string.IsNullOrEmpty(latestHit.TestPayload) ? "待检测" : latestHit.TestPayload;
        OverviewLastTimeText = curRecords.Count == 0 ? "-" : curRecords[0].TimeStr;

        //数据读取页头部实时统计：当前表路径 / 列数 / 已读行数
        var dump = AppConfig.DataDump;
        DumpPathText = string.IsNullOrEmpty(dump.TableName) ? "未选择表" : dump.TableName;
        DumpColsText = $"{dump.Columns.Count} 列";
        DumpRowsText = $"{dump.Rows.Count} 行";
    }

    #endregion


    private void TimerEventProcessor(object? sender, EventArgs e)
    {
        AppConfig.RuningInfo.RunThreadCount=WorkRunner.ActiveCount;
        AppConfig.RuningInfo.MaxThreaadCount=AppConfig.ThreadSize;
        RefreshShellState();
    }

    public void SavaConfig()
    {

        try {

            //string result = JsonSerializer.Serialize(AppConfig, SourceGenerationContext.Default.AppConfig);

            string result = JsonSerializer.Serialize(AppConfig, Source.JsonCtx.CompactInfo<AppConfig>());

            File.WriteAllText(AppDomain.CurrentDomain.BaseDirectory+"/config/lastconfig.json", result);
            //五类规则独立落 config/rules/（RuleStore），便于人工编辑与 CLI 共用
            Bypass.RuleStore.SaveAll(AppConfig);

        } catch(Exception e) {
            //配置保存失败（占用/权限/序列化异常）：不阻断退出，但记录日志
            Log.SysLog("保存配置到lastconfig.json失败：" + e.Message);
        }
       

      
    }

  
    public AppConfig ReadConfig()
    {

       
        try
        {
            FileStream fs=new FileStream(AppDomain.CurrentDomain.BaseDirectory + "/config/lastconfig.json", FileMode.Open, FileAccess.Read);
            AppConfig? config = JsonSerializer.Deserialize(fs, Source.JsonCtx.CompactInfo<AppConfig>());

            if (config != null)
            {
                return config;
            }
                
        }
        catch (Exception e)
        {
            //配置读取失败（文件不存在/损坏）：回落默认配置，记录日志便于排查
            Log.SysLog("读取lastconfig.json失败（将使用默认配置）：" + e.Message);
        }
        return new AppConfig();


    }


    // ---------------- 重发关键词 / 代理验证 / 绕过模板 / 配置导入导出 ----------------

    /// <summary>
    /// 保存文件选择回调，由View注入
    /// </summary>
    public Func<Task<string?>>? SaveFilePicker { get; set; }

    /// <summary>
    /// 打开文件选择回调，由View注入
    /// </summary>
    public Func<Task<string?>>? OpenFilePicker { get; set; }

    [ObservableProperty] private string _newRetryKey = "";

    /// <summary>UA池-新增UA文本</summary>
    [ObservableProperty] private string _newUa = "";

    /// <summary>UA池-新增UA类型（"自动识别"时按UA串推断）</summary>
    [ObservableProperty] private string _newUaType = "自动识别";

    /// <summary>UA类型下拉项（自动识别+8种平台类型）</summary>
    public List<string> UaTypeNames { get; } = new List<string> { "自动识别" }.Concat(UaItem.TypeNames).ToList();

    /// <summary>UA池：添加自定义UA（随机UA开启时每请求从池内轮换；池为空用内置UA池）</summary>
    [RelayCommand]
    private void AddUa()
    {
        if (string.IsNullOrWhiteSpace(NewUa))
        {
            Log.Warning("大侠，请输入User-Agent串！");
            return;
        }
        string ua = NewUa.Trim();
        if (AppConfig.ByPassConfig.UaItemList.Any(x => string.Equals(x.Ua, ua, StringComparison.OrdinalIgnoreCase)))
        {
            Log.Warning("该UA已经在UA池中！");
            return;
        }
        string type = NewUaType == "自动识别" || string.IsNullOrWhiteSpace(NewUaType) ? UaItem.InferType(ua) : NewUaType;
        AppConfig.ByPassConfig.UaItemList.Add(new UaItem(type, ua));
        NewUa = "";
        Log.Show("添加UA成功（类型：" + type + "）！");
    }

    /// <summary>UA池：一键导入内置UA池（已存在的跳过，类型自动识别）</summary>
    [RelayCommand]
    private void ImportBuiltinUa()
    {
        int added = 0;
        foreach (string ua in Bypass.BypassPipeline.BuiltinUaPool)
        {
            if (!AppConfig.ByPassConfig.UaItemList.Any(x => string.Equals(x.Ua, ua, StringComparison.OrdinalIgnoreCase)))
            {
                AppConfig.ByPassConfig.UaItemList.Add(new UaItem(UaItem.InferType(ua), ua));
                added++;
            }
        }
        Log.Show(added > 0 ? "已导入内置UA " + added + " 条！" : "内置UA已全部在池中，无需导入！");
    }

    /// <summary>内置编码工具列表（编码处理页"添加内置"下拉数据源，统一注册表可见项）</summary>
    public System.Collections.Generic.IReadOnlyList<Bypass.EncodeTool> BuiltinEncodeTools => Bypass.EncodeToolRegistry.VisibleTools;

    /// <summary>编码处理页：添加选中的内置工具到链路（同名/同键去重，默认启用）</summary>
    [RelayCommand]
    private void AddBuiltinEncodeTool()
    {
        Bypass.EncodeTool? tool = AppConfig.ByPassConfig.AddBuiltinTool;
        if (tool == null)
        {
            NotificationManager?.Show("请先选择要添加的内置工具！");
            return;
        }
        if (AppConfig.ByPassConfig.EncodeTools.Any(s => string.Equals(s.Key, tool.Key, StringComparison.OrdinalIgnoreCase)))
        {
            NotificationManager?.Show("该内置工具已在列表中！");
            return;
        }
        AppConfig.ByPassConfig.EncodeTools.Add(new EncodeToolModel
        {
            Name = tool.Name,
            Key = tool.Key,
            Scope = ScriptScope.Payload,
            Builtin = true,
            Enable = true
        });
        NotificationManager?.Show("添加成功！");
    }

    #region 字典管理（网络设置·字典管理页：字典猜解词表的查看/增删，去重忽略大小写）

    /// <summary>当前编辑的字典：0 Access表名 1 Access字段 2 通用表名（其他库） 3 通用字段（其他库）</summary>
    [ObservableProperty] private int _dictEditIndex = 0;

    /// <summary>新增词条输入</summary>
    [ObservableProperty] private string _newDictWord = "";

    /// <summary>当前字典信息提示（名称·条目数·文件路径）</summary>
    [ObservableProperty] private string _dictEditHint = "";

    /// <summary>当前编辑字典的词条集合（过滤后的展示列表）</summary>
    public ObservableCollection<string> DictWordItems { get; } = new ObservableCollection<string>();

    /// <summary>词条过滤关键字（忽略大小写包含匹配，空=全部）</summary>
    [ObservableProperty] private string _dictWordFilter = "";

    /// <summary>当前字典全量词条（过滤前的完整列表，保存文件以此为准）</summary>
    private List<string> _dictAllWords = new List<string>();

    private static readonly string[] DictBuiltInFiles = { "access_tables.txt", "access_columns.txt", "common_tables.txt", "common_columns.txt" };
    private static readonly string[] DictNames = { "Access表名字典", "Access字段字典", "通用表名字典", "通用字段字典" };

    partial void OnDictEditIndexChanged(int value)
    {
        DictWordFilter = "";
        ReloadDictWords();
    }

    partial void OnDictWordFilterChanged(string value)
    {
        ApplyDictFilter();
    }

    /// <summary>解析当前编辑字典的磁盘路径：Access表/字段优先用配置的外部txt，否则用内置config/dict/文件</summary>
    private string ResolveDictPath()
    {
        string? custom = DictEditIndex == 0 ? AppConfig.DataConfig.AccessTableDictPath
            : DictEditIndex == 1 ? AppConfig.DataConfig.AccessColumnDictPath : null;
        if (!string.IsNullOrWhiteSpace(custom))
        {
            return custom!;
        }
        return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config", "dict", DictBuiltInFiles[Math.Clamp(DictEditIndex, 0, 3)]);
    }

    /// <summary>重新加载当前选中字典到列表（去空白/注释/重复，忽略大小写；进入网络设置页或切换字典时触发）</summary>
    public void ReloadDictWords()
    {
        if (AppConfig?.DataConfig == null)
        {
            return;
        }
        _dictAllWords = new List<string>();
        string path = ResolveDictPath();
        try
        {
            if (File.Exists(path))
            {
                _dictAllWords = File.ReadAllLines(path, Encoding.UTF8)
                    .Select(w => w.Trim())
                    .Where(w => w.Length > 0 && !w.StartsWith('#'))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }
        }
        catch (Exception ex)
        {
            Log.Error($"字典读取失败：{path}，{ex.Message}");
        }
        ApplyDictFilter();
    }

    /// <summary>按过滤关键字刷新展示列表（忽略大小写包含匹配），并更新底部统计提示</summary>
    private void ApplyDictFilter()
    {
        string f = (DictWordFilter ?? "").Trim();
        DictWordItems.Clear();
        foreach (string w in _dictAllWords)
        {
            if (f.Length == 0 || w.Contains(f, StringComparison.OrdinalIgnoreCase))
            {
                DictWordItems.Add(w);
            }
        }
        UpdateDictHint();
    }

    /// <summary>更新字典信息提示：名称 · 条目数（过滤时显示 匹配/总数） · 文件路径</summary>
    private void UpdateDictHint()
    {
        string name = DictNames[Math.Clamp(DictEditIndex, 0, 3)];
        string path = ResolveDictPath();
        DictEditHint = DictWordItems.Count == _dictAllWords.Count
            ? $"{name} · {DictWordItems.Count} 项 · {path}"
            : $"{name} · 匹配 {DictWordItems.Count} / 共 {_dictAllWords.Count} 项 · {path}";
    }

    /// <summary>保存当前字典全量列表回磁盘（每行一词，UTF8，无BOM）</summary>
    private void SaveDictWords()
    {
        string path = ResolveDictPath();
        try
        {
            string? dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }
            File.WriteAllLines(path, _dictAllWords, new UTF8Encoding(false));
            UpdateDictHint();
        }
        catch (Exception ex)
        {
            Log.Error($"字典保存失败：{path}，{ex.Message}");
        }
    }

    /// <summary>添加词条并保存（自动去重，忽略大小写）</summary>
    [RelayCommand]
    private void AddDictWord()
    {
        string w = (NewDictWord ?? "").Trim();
        if (w.Length == 0 || w.StartsWith('#'))
        {
            Log.Warning("大侠，请输入有效词条（空白或以#开头的注释行不会收录）！");
            return;
        }
        if (_dictAllWords.Any(x => x.Equals(w, StringComparison.OrdinalIgnoreCase)))
        {
            Log.Warning($"词条已存在（忽略大小写），未重复添加：{w}");
            return;
        }
        _dictAllWords.Add(w);
        NewDictWord = "";
        SaveDictWords();
        ApplyDictFilter();
        Log.Success($"已加入{DictNames[Math.Clamp(DictEditIndex, 0, 3)]}：{w}（当前 {_dictAllWords.Count} 项）");
    }

    /// <summary>删除选中词条并保存（供列表右键菜单调用）</summary>
    public void RemoveDictWords(IEnumerable<string> selected)
    {
        var list = selected.ToList();
        if (list.Count == 0)
        {
            return;
        }
        foreach (string w in list)
        {
            _dictAllWords.Remove(w);
        }
        SaveDictWords();
        ApplyDictFilter();
        Log.Show($"已从{DictNames[Math.Clamp(DictEditIndex, 0, 3)]}删除 {list.Count} 个词条：{string.Join(",", list)}");
    }

    #endregion

    [RelayCommand]
    private void AddRetryKey()
    {
        if (string.IsNullOrWhiteSpace(NewRetryKey))
        {
            Log.Warning("大侠，请输入关键词！");
            return;
        }
        if (AppConfig.RetryKeyItems.Contains(NewRetryKey))
        {
            Log.Warning("关键词已经在列表中！");
            return;
        }
        AppConfig.RetryKeyItems.Add(NewRetryKey);
        NewRetryKey = "";
        Log.Show("添加重发关键词成功！");
    }


    // ---------------- 跳过参数（jumpkey.txt）管理 ----------------

    /// <summary>跳过参数列表：注入检测时命中参数名（不区分大小写）直接跳过，对应 config/injection/jumpkey.txt</summary>
    public ObservableCollection<string> JumpkeyItems { get; } = new ObservableCollection<string>();

    /// <summary>跳过参数-新增参数名文本</summary>
    [ObservableProperty] private string _newJumpkey = "";

    /// <summary>启动时加载 jumpkey.txt 到界面列表与检测用字典（此前文件存在但从未加载，JumpkeyList 恒空）</summary>
    private void LoadJumpkeys()
    {
        try
        {
            foreach (string key in JumpkeyTool.Load())
            {
                JumpkeyItems.Add(key);
            }
            SyncJumpkeyDict();
        }
        catch (Exception e)
        {
            Log.Error("加载跳过参数jumpkey.txt失败：" + e.Message);
        }
    }

    /// <summary>把界面列表同步到检测字典（不区分大小写）</summary>
    private void SyncJumpkeyDict()
    {
        ConstData.JumpkeyList = JumpkeyTool.ToDict(JumpkeyItems);
    }

    /// <summary>保存界面列表回 jumpkey.txt 并刷新检测字典</summary>
    private void SaveJumpkeys()
    {
        try
        {
            JumpkeyTool.Save(JumpkeyItems);
            SyncJumpkeyDict();
        }
        catch (Exception e)
        {
            Log.Error("保存跳过参数jumpkey.txt失败：" + e.Message);
        }
    }

    /// <summary>跳过参数：添加参数名（不区分大小写去重，即时生效并落盘）</summary>
    [RelayCommand]
    private void AddJumpkey()
    {
        string key = (NewJumpkey ?? "").Trim();
        if (key.Length == 0)
        {
            Log.Warning("大侠，请输入要跳过的参数名！");
            return;
        }
        if (JumpkeyItems.Contains(key, StringComparer.OrdinalIgnoreCase))
        {
            Log.Warning("参数名已经在跳过列表中！");
            return;
        }
        JumpkeyItems.Add(key);
        NewJumpkey = "";
        SaveJumpkeys();
        Log.Show("添加跳过参数成功，注入检测将跳过该参数：" + key);
    }

    /// <summary>跳过参数：批量删除选中项（由View右键菜单调用），即时生效并落盘</summary>
    public void RemoveJumpkeys(IEnumerable<string> keys)
    {
        int count = 0;
        foreach (string key in keys.ToList())
        {
            if (JumpkeyItems.Remove(key))
            {
                count++;
            }
        }
        if (count > 0)
        {
            SaveJumpkeys();
            Log.Show("删除跳过参数成功，共 " + count + " 项！");
        }
    }

    [RelayCommand]
    private async Task CheckProxy(Proxy? proxy)
    {
        if (proxy == null)
        {
            return;
        }
        Log.Show("开始验证代理：" + proxy.Host + ":" + proxy.Port);
        bool isok = await HTTPTool.CheckProxyAsync(AppConfig, proxy);
        proxy.IsOk = isok;
        proxy.CheckTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        if (isok)
        {
            Log.Show("代理：" + proxy.Host + ":" + proxy.Port + "验证成功，耗时：" + proxy.UseTime + "毫秒！");
        }
        else
        {
            Log.Warning("代理：" + proxy.Host + ":" + proxy.Port + "验证失败，无法使用！");
        }
    }

    [RelayCommand]
    private async Task CheckAllProxy()
    {
        if (AppConfig.ProxyConfig.ProxyItems.Count == 0)
        {
            Log.Warning("大侠，代理列表为空，请先添加代理！");
            return;
        }
        Log.Show("开始验证所有代理，共：" + AppConfig.ProxyConfig.ProxyItems.Count + "个！");
        List<Proxy> items = AppConfig.ProxyConfig.ProxyItems.ToList();
        //全异步并行验证（网络等待不占线程），逐个回写UI状态
        await Task.WhenAll(items.Select(async proxy =>
        {
            bool isok = await HTTPTool.CheckProxyAsync(AppConfig, proxy);
            Dispatcher.UIThread.Post( ()=>
            {
                proxy.IsOk = isok;
                proxy.CheckTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            });
        }));
        int okCount = items.Count(p => p.IsOk);
        Log.Show("所有代理验证完成，可用代理：" + okCount + "个，不可用代理：" + (items.Count - okCount) + "个！");
    }

    [RelayCommand]
    private async Task ExportProxy()
    {
        if (SaveFilePicker == null)
        {
            return;
        }
        string? path = await SaveFilePicker();
        if (string.IsNullOrEmpty(path))
        {
            return;
        }
        try
        {
            Dictionary<string, Proxy> dict = AppConfig.ProxyConfig.ProxyItems
                .GroupBy(p => p.Host + ":" + p.Port)
                .ToDictionary(g => g.Key, g => g.First());
            FileTool.SaveProxyList(path, dict.Values);
            Log.Show("导出代理成功：" + path);
        }
        catch (Exception e)
        {
            Log.Warning("导出代理发生异常！" + e.Message);
        }
    }

    [RelayCommand]
    private async Task ImportProxy()
    {
        if (OpenFilePicker == null)
        {
            return;
        }
        string? path = await OpenFilePicker();
        if (string.IsNullOrEmpty(path))
        {
            return;
        }
        try
        {
            Dictionary<string, Proxy> dict = FileTool.ReadProxyList(path);
            int addCount = 0;
            foreach (Proxy proxy in dict.Values)
            {
                if (!AppConfig.ProxyConfig.ProxyItems.Any(p => p.Host == proxy.Host && p.Port == proxy.Port))
                {
                    AppConfig.ProxyConfig.ProxyItems.Add(proxy);
                    addCount++;
                }
            }
            Log.Show("导入代理成功，新增代理：" + addCount + "个！");
        }
        catch (Exception e)
        {
            Log.Warning("导入代理发生异常！" + e.Message);
        }
    }


    public MainViewViewModel()
    {

        AppConfig =ReadConfig();
        //规则与状态分离：lastconfig.json 只含界面状态与基础配置，五类规则从 config/rules/ 独立加载
        Bypass.RuleStore.LoadAll(AppConfig);
        //LoadAll 回填规则发生在 AppConfig 赋值（OnAppConfigChanged 刷新过滤视图）之后，此处补刷新，否则动态规则/脚本页显示空快照
        RefreshDynRuleFilter();
        RefreshTokenScriptFilter();
        AppConfig.TxtRequest.Text = AppConfig.RequestTxt;
        //检测页独立文档：优先载入持久化的检测报文；旧配置无此字段时用剥离标记后的取数报文兜底
        AppConfig.TxtDetectRequest.Text = string.IsNullOrWhiteSpace(AppConfig.DetectRequestTxt)
            ? RequestRewriter.StripRequestMarks(AppConfig.RequestTxt)
            : AppConfig.DetectRequestTxt;

        //自愈：清理历史AOT源生成序列化丢失属性产生的空壳条目（{}反序列化出的默认实例）
        try
        {
            var shellTools = AppConfig.ByPassConfig.EncodeTools.Where(s => string.IsNullOrWhiteSpace(s.Code) && !s.Builtin).ToList();
            foreach (var s in shellTools)
            {
                AppConfig.ByPassConfig.EncodeTools.Remove(s);
            }
            if (shellTools.Count > 0)
            {
                Log.SysLog($"已清理{shellTools.Count}条空壳编码工具条目（历史序列化缺陷残留）。");
            }
            var shellUas = AppConfig.ByPassConfig.UaItemList.Where(u => string.IsNullOrWhiteSpace(u.Ua)).ToList();
            foreach (var u in shellUas)
            {
                AppConfig.ByPassConfig.UaItemList.Remove(u);
            }
        }
        catch (Exception ex) { Log.SysLog("UA池空壳清理异常：" + ex.Message); }

        //应用连接池配置（读配置后OnPoolSizeChanged不一定触发，显式同步一次）
        SuperSQLInjectionV2.Tools.Http.HttpConnectionPool.MaxPerKey = Math.Max(1, Math.Min(10, AppConfig.PoolSize));

        //内置DNS接收服务：启动时按持久化配置恢复运行状态（P2-8本机形态）
        SuperSQLInjectionV2.Models.Data.DnsServerManager.EnsureState(AppConfig);

        //代理开关联动：状态栏"直连/代理模式"即时刷新 + 日志提示（开关唯一入口在网络设置页）
        AppConfig.ProxyConfig.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ProxyConfig.ProxyEnable))
            {
                bool enable = AppConfig.ProxyConfig.ProxyEnable;
                ProxyModeText = enable ? "代理模式" : "直连模式";
                if (enable)
                {
                    string mode = AppConfig.ProxyConfig.SelectProxyType == ProxyType.Rand ? "代理池轮换" : "固定代理";
                    Log.Show($"已开启代理模式（{mode}），当前代理：{AppConfig.ProxyConfig.CurrentProxyText}");
                }
                else
                {
                    Log.Show("已切换为直连模式，所有请求不再经过代理！");
                }
            }
        };

        //302跟随联动：状态栏徽章即时刷新（开关唯一入口在网络设置-请求设置）
        RedirectModeText = AppConfig.FollowRedirect ? "302跟随" : "302不跟随";
        AppConfig.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(AppConfig.FollowRedirect))
            {
                RedirectModeText = AppConfig.FollowRedirect ? "302跟随" : "302不跟随";
            }
        };

        //AppConfig.TxtRequest.TextChanged += OnTextDocumentChanged;
        AppConfig.DataConfig.SelectedInjectType = InjectType.UnKnow;
        AppConfig.DataConfig.SelectedDBType = DBType.UnKnow;
        //数据操作页的"数据库"下拉绑定在CurrentContext上，切换时同步过滤注入类型选项（隐藏无报错通道库的"报错注入"）
        //并联动刷新文件操作/命令执行方式列表（无需先点"应用"）
        CurrentContext.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(InjectionContext.DbType))
            {
                AppConfig.DataConfig.RefreshInjectTypes(CurrentContext.DbType);
                if (LogTools.Headless || Avalonia.Application.Current == null || Dispatcher.UIThread.CheckAccess())
                {
                    AppConfig.FileCmd?.RefreshFileMethods(CurrentContext.DbType);
                }
                else
                {
                    Dispatcher.UIThread.Post( ()=> AppConfig.FileCmd?.RefreshFileMethods(CurrentContext.DbType));
                }
            }
        };
        LoadInjectRecords();
        //报错回显容量探测结果写回注入记录（第二次取数免探测）；仅更新条目属性不动集合，后台线程直改安全
        DataComm.OnErrorChunkLenProbed = (cfg, len) =>
        {
            try
            {
                string target = cfg.Host + ":" + cfg.Port;
                InjectRecord? rec = InjectRecords.FirstOrDefault(r =>
                    r.Target == target && r.PName == cfg.DataConfig.InjectParamName
                    && r.DBType == cfg.DataConfig.SelectedDBType && r.InjectType == InjectType.Error);
                if (rec != null && rec.ErrorChunkLen != len)
                {
                    rec.ErrorChunkLen = len;
                    SaveInjectRecords();
                }
            }
            catch (Exception ex) { Log.SysLog("报错容量回写注入记录异常：" + ex.Message); }
        };
        //加载跳过参数列表（jumpkey.txt），检测阶段按参数名跳过
        LoadJumpkeys();
        //初始加载默认库的取数模板，供模板管理页展示
        LoadTemplate();

        timer = new DispatcherTimer();
        timer.Interval = TimeSpan.FromSeconds(1); // 设置间隔时间为1秒
        timer.Tick += TimerEventProcessor;
        timer.Start();
    }

    public void InitLogTools(Ursa.Controls.WindowNotificationManager? notificationManager, AvaloniaEdit.TextEditor TxtLog)
    {
        NotificationManager = notificationManager;
        //初始化日志工具并注入全局日志门面（逻辑层经 Log.* 输出，不再反向引用本ViewModel）
        var logTools = new LogTools { NotificationManager = notificationManager, AppConfig = AppConfig, TxtLog = TxtLog };
        Log.Sink = logTools;
        //只读兜底：axaml已设IsReadOnly，代码再固定一次防止被覆盖（日志追加走Document级Insert，不受只读影响）
        TxtLog.IsReadOnly = true;
        //挂载行级着色器：按日志级别逐行着色（Info默认/Success绿/Warn琥珀/Error红/Highlight蓝）
        if (!TxtLog.TextArea.TextView.LineTransformers.Contains(logTools.Colorizer))
        {
            TxtLog.TextArea.TextView.LineTransformers.Add(logTools.Colorizer);
        }

        //启动自动检测更新（视图就绪后触发，弹窗/通知可用；后台执行不阻塞UI；需开启自动检测且config/update.ini配置了服务地址）
        if (AppConfig.UpdateCheckEnable && !string.IsNullOrWhiteSpace(UpdateSettings.ServerUrl))
        {
            _ = RunUpdateCheck(false);
        }
    }

    #region 软件更新（SoftUpdate 自托管更新服务，接口见 SoftUpdate/docs/API.md）

    /// <summary>当前版本显示（菜单标题徽章/软件更新页）</summary>
    public string AppVersionText => "v" + ConstData.AppVersion;

    /// <summary>更新状态文本（软件更新页显示最近一次检测/下载结果）</summary>
    [ObservableProperty] private string _updateStatusText = "";

    /// <summary>手动检查更新（软件更新页按钮，结果必提示）</summary>
    [RelayCommand]
    private async Task CheckUpdateNow()
    {
        await RunUpdateCheck(true);
    }

    private bool _updateChecking;

    /// <summary>
    /// 检测更新：manual=手动（结果必提示）；自动模式发现新版本且未标记"不再提示"时弹窗询问。
    /// 确认后更新 zip 包下载到软件运行目录（SHA256 校验），解压安装由用户关闭软件后自行完成。
    /// </summary>
    private async Task RunUpdateCheck(bool manual)
    {
        if (_updateChecking)
        {
            return;
        }
        if (string.IsNullOrWhiteSpace(UpdateSettings.ServerUrl))
        {
            if (manual)
            {
                UpdateStatusText = "未配置服务地址";
                Log.Warning("config/update.ini 未配置更新服务地址！");
            }
            return;
        }
        _updateChecking = true;
        try
        {
            UpdateStatusText = "正在检测更新…";
            using var manager = new UpdateManager(new UpdateManagerOptions
            {
                ServerUrl = UpdateSettings.ServerUrl,
                AppId = UpdateSettings.AppId,
                Channel = UpdateSettings.Channel,
                ClientAuthKey = UpdateSettings.AuthKey,
                InstallDir = AppDomain.CurrentDomain.BaseDirectory
            });
            var check = await manager.CheckForUpdatesAsync(ConstData.AppVersion);
            if (!check.HasUpdate || check.Manifest == null)
            {
                UpdateStatusText = "已是最新版本";
                if (manual)
                {
                    NotificationManager?.Show(string.IsNullOrWhiteSpace(check.Message)
                        ? $"当前 v{ConstData.AppVersion} 已是最新版本！"
                        : check.Message!);
                }
                return;
            }
            UpdateManifest manifest = check.Manifest;
            UpdateStatusText = $"发现新版本 {manifest.Version}";
            //自动模式：该版本已被用户标记"不再提示"则跳过（手动检测不受影响）
            if (!manual && string.Equals(AppConfig.UpdateSkipVersion, manifest.Version, StringComparison.OrdinalIgnoreCase))
            {
                Log.Show($"检测到新版本 {manifest.Version}，已按你的选择跳过提示（可在软件更新页手动检查）。");
                return;
            }
            string notes = string.IsNullOrWhiteSpace(manifest.Notes) ? "（无更新说明）" : manifest.Notes.Trim();
            var result = await OverlayMessageBox.ShowAsync(
                $"发现新版本 {manifest.Version}（当前 {ConstData.AppVersion}）{((check.Mandatory || manifest.Mandatory) ? "，本次为强制更新" : "")}\r\n\r\n更新说明：\r\n{notes}\r\n\r\n[是] 下载更新包（zip）到软件运行目录\r\n[否] 本次跳过\r\n[取消] 不再提示该版本",
                "发现新版本", button: MessageBoxButton.YesNoCancel);
            if (MessageBoxResult.Cancel.Equals(result))
            {
                AppConfig.UpdateSkipVersion = manifest.Version;
                SavaConfig();
                UpdateStatusText = $"已跳过 {manifest.Version}";
                return;
            }
            if (!MessageBoxResult.Yes.Equals(result))
            {
                return;
            }
            await DownloadUpdatePackage(manifest);
        }
        catch (Exception e)
        {
            UpdateStatusText = "检测失败";
            Log.Warning("检测更新失败：" + e.Message + "（不影响正常使用，服务地址在 config/update.ini 中配置）");
            if (manual)
            {
                NotificationManager?.Show("检测更新失败：" + e.Message);
            }
        }
        finally
        {
            _updateChecking = false;
        }
    }

    /// <summary>下载更新 zip 包到软件运行目录（SHA256 校验），进度写入运行日志</summary>
    private async Task DownloadUpdatePackage(UpdateManifest manifest)
    {
        string installDir = AppDomain.CurrentDomain.BaseDirectory;
        try
        {
            UpdateStatusText = $"正在下载 {manifest.Version}…";
            Log.Show($"开始下载更新包 {manifest.Version} 到软件运行目录：{installDir}");
            using var manager = new UpdateManager(new UpdateManagerOptions
            {
                ServerUrl = UpdateSettings.ServerUrl,
                AppId = UpdateSettings.AppId,
                Channel = UpdateSettings.Channel,
                ClientAuthKey = UpdateSettings.AuthKey,
                InstallDir = installDir
            });
            int lastPct = -1;
            var progress = new Progress<UpdateProgress>(p =>
            {
                int pct = (int)p.Percent;
                if (pct != lastPct && (pct % 10 == 0 || pct == 100))
                {
                    lastPct = pct;
                    Log.Show($"更新包下载中 {pct}%（{p.TransferredBytes / 1024}KB/{p.TotalBytes / 1024}KB）");
                }
            });
            string packagePath = await manager.DownloadUpdateAsync(manifest, progress);
            UpdateStatusText = $"{manifest.Version} 下载完成";
            Log.Success($"更新包 {manifest.Version} 下载完成（SHA256校验通过）：{packagePath}——关闭软件后解压该 zip 替换旧文件即可完成升级！");
            NotificationManager?.Show($"更新包 {manifest.Version} 下载完成，已保存到软件运行目录：{Path.GetFileName(packagePath)}");
        }
        catch (Exception e)
        {
            UpdateStatusText = "下载失败";
            Log.Error("下载更新包失败：" + e.Message);
            NotificationManager?.Show("下载更新包失败：" + e.Message);
        }
    }

    #region 问题反馈（关于页，POST /api/client/feedback 提交到更新服务）

    /// <summary>反馈内容（关于页输入）</summary>
    [ObservableProperty] private string _feedbackContent = "";

    /// <summary>联系方式（可空）</summary>
    [ObservableProperty] private string _feedbackContact = "";

    /// <summary>反馈提交状态文本</summary>
    [ObservableProperty] private string _feedbackStatusText = "";

    private bool _feedbackSubmitting;

    /// <summary>提交问题反馈到更新服务</summary>
    [RelayCommand]
    private async Task SubmitFeedback()
    {
        if (_feedbackSubmitting)
        {
            return;
        }
        if (string.IsNullOrWhiteSpace(FeedbackContent))
        {
            NotificationManager?.Show("请先填写反馈内容！");
            return;
        }
        if (string.IsNullOrWhiteSpace(UpdateSettings.ServerUrl))
        {
            FeedbackStatusText = "未配置服务地址";
            Log.Warning("config/update.ini 未配置更新服务地址，无法提交反馈！");
            NotificationManager?.Show("未配置更新服务地址，无法提交反馈！");
            return;
        }
        _feedbackSubmitting = true;
        try
        {
            FeedbackStatusText = "正在提交…";
            using var manager = new UpdateManager(new UpdateManagerOptions
            {
                ServerUrl = UpdateSettings.ServerUrl,
                AppId = UpdateSettings.AppId,
                Channel = UpdateSettings.Channel,
                ClientAuthKey = UpdateSettings.AuthKey,
                InstallDir = AppDomain.CurrentDomain.BaseDirectory
            });
            await manager.SubmitFeedbackAsync(FeedbackContent, FeedbackContact, ConstData.AppVersion);
            FeedbackStatusText = "提交成功";
            Log.Success("问题反馈已提交，感谢你的反馈！");
            NotificationManager?.Show("反馈提交成功，感谢你的反馈！");
            FeedbackContent = "";
        }
        catch (Exception e)
        {
            FeedbackStatusText = "提交失败";
            Log.Warning("反馈提交失败：" + e.Message);
            NotificationManager?.Show("反馈提交失败：" + e.Message);
        }
        finally
        {
            _feedbackSubmitting = false;
        }
    }

    #endregion

    #endregion

}