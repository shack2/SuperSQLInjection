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
using System.Threading;
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

    /// <summary>请求日志：导出全部记录为CSV（含完整请求/响应报文，UTF-8 BOM头Excel可直接打开）</summary>
    [RelayCommand]
    private async Task ExportRequestLogs()
    {
        if (AppConfig.RequestLog.Items.Count == 0)
        {
            NotificationManager?.Show("请求日志为空，无数据可导出！");
            return;
        }
        if (RequestLogSaveFilePicker == null)
        {
            return;
        }
        string? path = await RequestLogSaveFilePicker();
        if (string.IsNullOrEmpty(path))
        {
            return;
        }
        try
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("序号,时间,Payload,主机,端口,代理,状态码,用时(ms),响应长度,请求包,响应包");
            foreach (RequestLog item in AppConfig.RequestLog.Items)
            {
                sb.Append(item.index).Append(',')
                    .Append(item.Time).Append(',')
                    .Append(CsvCell(item.Payload)).Append(',')
                    .Append(item.Request?.Host).Append(',')
                    .Append(item.Request?.Port ?? 0).Append(',')
                    .Append(CsvCell(item.Proxy)).Append(',')
                    .Append(item.Response?.StatusCode ?? 0).Append(',')
                    .Append(item.UseTime).Append(',')
                    .Append(item.Response?.BodyLength ?? 0).Append(',')
                    .Append(CsvCell(TruncCell(item.Request?.HeaderAndBody))).Append(',')
                    .Append(CsvCell(TruncCell(item.Response?.HeaderAndBody))).AppendLine();
            }
            //不用ConfigureAwait(false)：后续NotificationManager.Show必须回到UI线程，否则Dispatcher.VerifyAccess崩
            await File.WriteAllTextAsync(path, sb.ToString(), new UTF8Encoding(true));
            Log.Show("请求日志已导出：" + path + "（共" + AppConfig.RequestLog.Items.Count + "条记录）");
            NotificationManager?.Show("请求日志已导出：" + path);
        }
        catch (Exception ex)
        {
            Log.Error("请求日志导出异常：" + ex.Message);
        }
    }

    /// <summary>CSV单元格：引号包裹+内部引号双写（报文含逗号/换行/引号，必须转义）</summary>
    private static string CsvCell(string? v)
    {
        if (string.IsNullOrEmpty(v))
        {
            return "";
        }
        return "\"" + v.Replace("\"", "\"\"") + "\"";
    }

    /// <summary>Excel单元格上限32767字符，超长报文截断防导入失败</summary>
    private static string TruncCell(string? v)
    {
        if (v != null && v.Length > 32000)
        {
            return v.Substring(0, 32000) + "……[超长截断]";
        }
        return v ?? "";
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
        HttpResponse coserver;
        try
        {
            coserver = await HTTPTool.SendRequestRetryAsync(request);
        }
        catch (SuperSQLInjectionV2.Tools.Http.TargetUnreachableException tue)
        {
            //目标不可达：检测尚未开始，直接终止，不再进入后续阶段空跑
            Log.Error("目标主机无法连接，注入检测未开始！" + tue.Message + "请确认目标服务/代理可用后重试。");
            return;
        }
        catch (OperationCanceledException)
        {
            Log.Show("已停止注入检测！");
            return;
        }


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

    /// <summary>
    /// 批量检测：弹窗导入一批URL多线程检测（检测配置与当前界面一致），
    /// 命中点经AddBatchInjectRecord写入注入记录（不切换当前注入上下文）
    /// </summary>
    [RelayCommand]
    private async Task OpenBatchDetect()
    {
        if (AppConfig.IsRuning)
        {
            Log.Warning("大侠，单目标检测进行中，请先停止或等待完成后再批量检测！");
            return;
        }
        var vm = new Dialogs.BatchDetectViewModel(AppConfig, AddBatchInjectRecord, OpenFilePicker);
        var options = new OverlayDialogOptions
        {
            FullScreen = false,
            HorizontalAnchor = HorizontalPosition.Center,
            VerticalAnchor = VerticalPosition.Center,
            HorizontalOffset = 0,
            VerticalOffset = 0,
            Mode = DialogMode.None,
            Buttons = DialogButton.None,
            Title = "批量注入检测",
            CanLightDismiss = false,
            CanDragMove = true,
            IsCloseButtonVisible = true,
            CanResize = true,
        };
        await OverlayDialog.ShowStandardAsync<Dialogs.BatchDetectView, Dialogs.BatchDetectViewModel>(vm, options: options);
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

    /// <summary>脚本库页 TableView 当前选中行（编辑/上移/下移按钮与行拖拽排序的操作目标）</summary>
    [ObservableProperty] private Models.ScriptLibRow? _selectedScriptRow;

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
        //集合Move触发脚本库视图重建（行实例换新），按底层模型重新选中
        SelectedScriptRow = FilteredScriptLib.FirstOrDefault(r => r.Tool == item);
    }

    [RelayCommand]
    private void MoveEncodeToolUp()
    {
        if (SelectedScriptRow == null)
        {
            NotificationManager?.Show("请先选中要上移的行！");
            return;
        }
        if (!SelectedScriptRow.IsTransform)
        {
            NotificationManager?.Show("动态值脚本不参与编码链排序！");
            return;
        }
        MoveEncodeTool(SelectedScriptRow.Tool, AppConfig.ByPassConfig.EncodeTools.IndexOf(SelectedScriptRow.Tool!) - 1);
    }

    [RelayCommand]
    private void MoveEncodeToolDown()
    {
        if (SelectedScriptRow == null)
        {
            NotificationManager?.Show("请先选中要下移的行！");
            return;
        }
        if (!SelectedScriptRow.IsTransform)
        {
            NotificationManager?.Show("动态值脚本不参与编码链排序！");
            return;
        }
        MoveEncodeTool(SelectedScriptRow.Tool, AppConfig.ByPassConfig.EncodeTools.IndexOf(SelectedScriptRow.Tool!) + 1);
    }

    #region 脚本库管理（防护绕过-脚本库页：内置/自定义编码链脚本 + 动态值脚本统一管理）

    /// <summary>防护绕过页选项卡索引（"管理脚本"入口跳转定位用）</summary>
    [ObservableProperty] private int _bypassTabIndex;

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

    /// <summary>脚本库统一添加：4种用途可选；payload/request保存为编码链自定义节点（默认不启用，需开启启用开关入链），extract/generate保存为动态值脚本</summary>
    [RelayCommand]
    private async Task AddTokenScript()
    {
        var vm = TokenScriptEditViewModel.FromUsage(null);
        if (await ShowTokenScriptEditDialog(vm, "添加脚本"))
        {
            if (vm.IsTransformUsage)
            {
                AppConfig.ByPassConfig.EncodeTools.Add(vm.ToEncodeTool());
            }
            else
            {
                ScriptTamperModel item = vm.ToModel();
                AppConfig.TokenScripts.Add(item);
                //新脚本自动设为当前生效前置规则的抓取脚本
                if (AppConfig.ActiveCompanionBefore != null)
                {
                    AppConfig.ActiveCompanionBefore.ScriptName = item.Name;
                }
            }
            RefreshScriptLibFilter();
            NotificationManager?.Show("添加成功！");
        }
    }

    [RelayCommand]
    private async Task EditTokenScript(Models.ScriptLibRow? row)
    {
        //优先选中行，无选中行时回落到第一条勾选行（勾选框点击不触发行选中）
        row ??= SelectedScriptRow ?? FilteredScriptLib.FirstOrDefault(s => s.RowChecked);
        if (row == null)
        {
            NotificationManager?.Show("请先选择或勾选要编辑的脚本！");
            return;
        }
        //全部脚本走统一编辑弹窗（4种用途）：内置项限定变换类用途、代码保存写磁盘脚本文件；
        //自定义项保存时按所选用途在编码链/动态值集合间迁移
        var vm = row.IsTransform
            ? TokenScriptEditViewModel.FromEncodeTool(row.Tool!)
            : TokenScriptEditViewModel.FromUsage(row.Token);
        if (!await ShowTokenScriptEditDialog(vm, "编辑脚本"))
        {
            return;
        }
        string oldName = row.Name;
        if (vm.IsTransformUsage)
        {
            if (row.IsTransform)
            {
                //变换→变换：原地更新（内置项代码写磁盘脚本文件）
                vm.ApplyToEncodeTool(row.Tool!);
            }
            else
            {
                //动态值→变换：从动态值集合移除（清空伴随规则引用），加入编码链（默认停用）
                ClearTokenScriptRefs(oldName);
                AppConfig.TokenScripts.Remove(row.Token!);
                AppConfig.ByPassConfig.EncodeTools.Add(vm.ToEncodeTool());
            }
        }
        else
        {
            if (row.IsTransform)
            {
                //变换→动态值：从编码链移除，加入动态值脚本集合
                AppConfig.ByPassConfig.EncodeTools.Remove(row.Tool!);
                AppConfig.TokenScripts.Add(vm.ToModel());
            }
            else
            {
                //动态值→动态值：原地更新，改名时同步所有引用该脚本的伴随规则（按Name解析）
                vm.ApplyTo(row.Token!);
                foreach (Models.CompanionRequestConfig rule in AppConfig.CompanionRules)
                {
                    if (rule.ScriptName == oldName)
                    {
                        rule.ScriptName = row.Token!.Name;
                    }
                }
            }
        }
        RefreshScriptLibFilter();
        NotificationManager?.Show("保存成功！");
    }

    /// <summary>清空引用指定动态值脚本的伴随规则（脚本删除/迁移出动态值集合时调用）</summary>
    private void ClearTokenScriptRefs(string scriptName)
    {
        foreach (Models.CompanionRequestConfig rule in AppConfig.CompanionRules)
        {
            if (rule.ScriptName == scriptName)
            {
                rule.ScriptName = "";
            }
        }
    }

    [RelayCommand]
    private void RemoveTokenScript(Models.ScriptLibRow? row)
    {
        if (row == null)
        {
            return;
        }
        if (row.IsTransform)
        {
            if (row.Tool != null && AppConfig.ByPassConfig.EncodeTools.Contains(row.Tool))
            {
                AppConfig.ByPassConfig.EncodeTools.Remove(row.Tool);
            }
            return;
        }
        if (row.Token != null && AppConfig.TokenScripts.Contains(row.Token))
        {
            foreach (Models.CompanionRequestConfig rule in AppConfig.CompanionRules)
            {
                if (rule.ScriptName == row.Token.Name)
                {
                    rule.ScriptName = "";
                }
            }
            AppConfig.TokenScripts.Remove(row.Token);
        }
    }

    /// <summary>数据管理页/动态规则页"管理脚本"入口：跳转防护绕过页并定位到脚本库选项卡（第3个，索引2）</summary>
    [RelayCommand]
    private void ManageTokenScripts()
    {
        SelectedNavIndex = 6;
        BypassTabIndex = 2;
    }

    #endregion

    #region 动态规则管理（防护绕过-动态规则：TableView规则列表 + 新增/编辑弹窗）

    /// <summary>动态规则列表当前选中项</summary>
    [ObservableProperty] private Models.CompanionRequestConfig? _selectedCompanionRule;

    /// <summary>动态规则搜索关键字（名称/标记名/类型/来源/摘要模糊匹配，空=全部）</summary>
    [ObservableProperty] private string _dynRuleSearchKeyword = "";

    /// <summary>脚本库搜索关键字（名称/用途模糊匹配，空=全部）</summary>
    [ObservableProperty] private string _scriptLibSearchKeyword = "";

    /// <summary>动态规则过滤视图（TableView绑定源；搜索筛选后的AppConfig.CompanionRules子集，对象引用同源）</summary>
    public ObservableCollection<Models.CompanionRequestConfig> FilteredCompanionRules { get; } = new();

    /// <summary>脚本库过滤视图（TableView绑定源：内置/自定义编码链脚本 + 动态值脚本统一展示，按用途区分）</summary>
    public ObservableCollection<Models.ScriptLibRow> FilteredScriptLib { get; } = new();

    partial void OnDynRuleSearchKeywordChanged(string value) => RefreshDynRuleFilter();

    partial void OnScriptLibSearchKeywordChanged(string value) => RefreshScriptLibFilter();

    /// <summary>配置整体替换（导入/启动加载）后同步两个过滤视图</summary>
    partial void OnAppConfigChanged(AppConfig value)
    {
        RefreshDynRuleFilter();
        RefreshScriptLibFilter();
    }

    /// <summary>配置替换时退订旧集合并订阅新集合：编码链/动态值脚本集合增删后脚本库视图同步刷新</summary>
    partial void OnAppConfigChanged(AppConfig? oldValue, AppConfig newValue)
    {
        if (oldValue != null)
        {
            oldValue.TokenScripts.CollectionChanged -= ScriptSourcesChanged;
            oldValue.ByPassConfig.EncodeTools.CollectionChanged -= ScriptSourcesChanged;
        }
        newValue.TokenScripts.CollectionChanged += ScriptSourcesChanged;
        newValue.ByPassConfig.EncodeTools.CollectionChanged += ScriptSourcesChanged;
    }

    private void ScriptSourcesChanged(object? sender, System.Collections.Specialized.NotifyCollectionChangedEventArgs e)
    {
        RefreshScriptLibFilter();
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

    private static bool ScriptLibHit(Models.ScriptLibRow row, string kw)
    {
        return string.IsNullOrWhiteSpace(kw)
            || row.Name.Contains(kw, StringComparison.OrdinalIgnoreCase)
            || row.UsageName.Contains(kw, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>按搜索关键字重建脚本库过滤视图（编码链脚本含内置项按链序在前，动态值脚本在后；重建时保留勾选与选中状态）</summary>
    public void RefreshScriptLibFilter()
    {
        string kw = ScriptLibSearchKeyword ?? "";
        var checkedKeys = FilteredScriptLib.Where(r => r.RowChecked).Select(r => (r.IsTransform, r.Name)).ToHashSet();
        var selectedKey = SelectedScriptRow != null ? (SelectedScriptRow.IsTransform, SelectedScriptRow.Name) : ((bool, string)?)null;
        FilteredScriptLib.Clear();
        foreach (var t in AppConfig.ByPassConfig.EncodeTools)
        {
            var row = Models.ScriptLibRow.FromTool(t);
            if (ScriptLibHit(row, kw))
            {
                row.RowChecked = checkedKeys.Contains((true, row.Name));
                FilteredScriptLib.Add(row);
            }
        }
        int tokenBase = AppConfig.ByPassConfig.EncodeTools.Count; //动态值脚本序号接续编码链（全库连续编号，搜索过滤时序号稳定）
        for (int si = 0; si < AppConfig.TokenScripts.Count; si++)
        {
            var row = Models.ScriptLibRow.FromToken(AppConfig.TokenScripts[si]);
            row.TokenSeq = tokenBase + si + 1;
            if (ScriptLibHit(row, kw))
            {
                row.RowChecked = checkedKeys.Contains((false, row.Name));
                FilteredScriptLib.Add(row);
            }
        }
        if (selectedKey != null)
        {
            SelectedScriptRow = FilteredScriptLib.FirstOrDefault(r => (r.IsTransform, r.Name) == selectedKey);
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

    /// <summary>工具栏"删除选中"：弹窗确认后批量删除勾选行的脚本（动态值类同步清理规则引用，变换类从编码链移除）</summary>
    [RelayCommand]
    private async Task RemoveCheckedTokenScripts()
    {
        var checkedRows = FilteredScriptLib.Where(s => s.RowChecked).ToList();
        if (checkedRows.Count == 0)
        {
            NotificationManager?.Show("请先勾选要删除的脚本！");
            return;
        }
        var result = await OverlayMessageBox.ShowAsync(
            "确认删除勾选的 " + checkedRows.Count + " 个脚本？引用这些脚本的规则将清空脚本设置。",
            "删除确认", button: MessageBoxButton.YesNo);
        if (!MessageBoxResult.Yes.Equals(result))
        {
            return;
        }
        foreach (var row in checkedRows)
        {
            if (row.IsTransform)
            {
                if (row.Tool != null)
                {
                    AppConfig.ByPassConfig.EncodeTools.Remove(row.Tool);
                }
            }
            else if (row.Token != null)
            {
                foreach (Models.CompanionRequestConfig rule in AppConfig.CompanionRules)
                {
                    if (rule.ScriptName == row.Token.Name)
                    {
                        rule.ScriptName = "";
                    }
                }
                AppConfig.TokenScripts.Remove(row.Token);
            }
        }
        RefreshScriptLibFilter();
        Log.Success("已删除 " + checkedRows.Count + " 个脚本");
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

    /// <summary>支持模板管理的数据库类型（按语法族聚类排序；fork化变体库的差异模板为fork_*.txt，不在此列）</summary>
    public List<DBType> TemplateDbList { get; } = new List<DBType>
    {
        DBType.MySQL, DBType.SQLServer, DBType.Oracle,
        DBType.PostgreSQL,
        DBType.Access, DBType.DB2, DBType.SQLite, DBType.Informix,
        DBType.H2, DBType.HSQLDB, DBType.ClickHouse
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
        //必需key校验（仅警告，允许保存——用户可能有意裁剪）；
        //overlay模板（声明了Base继承）的必需key由族基准提供，跳过缺失警告
        var keys = new HashSet<string>(validItems.Select(i => i.Key.Trim()), StringComparer.OrdinalIgnoreCase);
        bool isOverlay = keys.Contains(BasePayload.BaseKey);
        var missing = isOverlay ? new List<string>() : BasePayload.RequiredKeys.Where(k => !keys.Contains(k)).ToList();
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

    /// <summary>URL/方式⇄报文联动防循环标志（程序内改写报文/URL时置位，另一方向跳过）</summary>
    private bool _requestSyncGuard;

    /// <summary>上一条由URL自动生成的报文（判断当前报文是否被人工定制的基准）</summary>
    private string _lastAutoRequest = "";

    /// <summary>上一条由URL自动生成的取数页报文（数据管理页联动基准，与检测页互不影响）</summary>
    private string _lastAutoDataRequest = "";

    /// <summary>URL归一化：缺scheme时按http://补齐，保证Uri.TryCreate/重建可用（不回写输入框，避免打断键入）</summary>
    private static string NormalizeInputUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url) || url.Contains("://", StringComparison.Ordinal))
        {
            return url;
        }
        return "http://" + url;
    }

    /// <summary>
    /// URL/请求方式 → 检测报文：空报文/上一条自动生成时按URL重新生成；
    /// URL变更且报文与URL语义不一致时一律按新URL构造默认请求（注入标记/定制请求头不保留）；
    /// 报文与URL语义一致（记录加载/报文回同步的回声）不重建，避免冲掉刚加载的标记报文；
    /// 切换请求方式且报文被人工定制时，用ChangeRequestFormat原地转换（参数迁移、请求头与标记保留）
    /// </summary>
    private void RegenerateDetectRequest(bool methodSwitched)
    {
        if (_requestSyncGuard)
        {
            return;
        }
        string targetUrl = NormalizeInputUrl(AppConfig.DetectUrl);
        string current = AppConfig.TxtDetectRequest.Text;
        bool isAutoOrEmpty = current.Length == 0 || current == _lastAutoRequest;
        if (!isAutoOrEmpty && methodSwitched)
        {
            //定制报文原地转换请求方式（参数迁移、请求头保留），与右键"转换数据报文"同一实现
            string converted = RequestRewriter.ChangeRequestFormat(current,
                string.Equals(AppConfig.DetectMethod, "POST", StringComparison.OrdinalIgnoreCase)
                    ? RequestFormat.POST_FORM : RequestFormat.GET);
            if (!string.IsNullOrEmpty(converted) && converted != current)
            {
                _requestSyncGuard = true;
                try
                {
                    AppConfig.TxtDetectRequest.Text = converted;
                    _lastAutoRequest = "";
                }
                finally
                {
                    _requestSyncGuard = false;
                }
            }
            return;
        }
        if (!isAutoOrEmpty)
        {
            //报文与URL语义一致（注入记录加载/报文回同步的回声）无需变动——避免记录加载时URL回写冲掉刚加载的标记报文；
            //不一致说明用户切换了目标：一律按新URL构造默认请求（注入标记/定制请求头不保留）
            string clean = RequestRewriter.StripRequestMarks(current);
            (_, string? curUrl) = RequestRewriter.ExtractMethodAndUrlLenient(clean, AppConfig.IsSSL);
            if (RequestRewriter.SameUrl(curUrl, targetUrl))
            {
                return;
            }
        }
        string req = RequestRewriter.BuildRequestFromUrl(targetUrl, AppConfig.DetectMethod);
        if (string.IsNullOrEmpty(req))
        {
            return;
        }
        _requestSyncGuard = true;
        try
        {
            AppConfig.TxtDetectRequest.Text = req;
            _lastAutoRequest = req;
        }
        finally
        {
            _requestSyncGuard = false;
        }
    }

    /// <summary>检测报文 → 请求方式/检测URL：解析请求行与Host头回同步（报文不完整或程序内改写时跳过）</summary>
    private void SyncUrlFromDetectRequest()
    {
        if (_requestSyncGuard)
        {
            return;
        }
        (string? method, string? url) = RequestRewriter.ExtractMethodAndUrl(AppConfig.TxtDetectRequest.Text, AppConfig.IsSSL);
        _requestSyncGuard = true;
        try
        {
            if ((method == "GET" || method == "POST") && method != AppConfig.DetectMethod)
            {
                AppConfig.DetectMethod = method;
            }
            if (url != null && !RequestRewriter.SameUrl(url, AppConfig.DetectUrl))
            {
                AppConfig.DetectUrl = url;
            }
        }
        finally
        {
            _requestSyncGuard = false;
        }
    }

    /// <summary>
    /// URL/请求方式 → 取数页报文（数据管理页联动，语义与检测页RegenerateDetectRequest一致）：
    /// 空报文/上一条自动生成时按URL+DataMethod重建；URL变更且报文与URL语义不一致时一律按新URL构造默认请求
    /// （注入标记/定制请求头不保留）；报文与URL语义一致（记录加载/回同步回声）不重建；
    /// 方式切换时定制报文用ChangeRequestFormat原地转换（参数迁移、请求头与标记保留）
    /// </summary>
    private void RegenerateDataRequest(bool methodSwitched)
    {
        if (_requestSyncGuard)
        {
            return;
        }
        string targetUrl = NormalizeInputUrl(AppConfig.Url);
        string current = AppConfig.TxtRequest.Text;
        bool isAutoOrEmpty = current.Length == 0 || current == _lastAutoDataRequest;
        if (!isAutoOrEmpty && methodSwitched)
        {
            //定制报文原地转换请求方式（参数迁移、请求头保留），与右键"转换数据报文"同一实现
            string converted = RequestRewriter.ChangeRequestFormat(current,
                string.Equals(AppConfig.DataMethod, "POST", StringComparison.OrdinalIgnoreCase)
                    ? RequestFormat.POST_FORM : RequestFormat.GET);
            if (!string.IsNullOrEmpty(converted) && converted != current)
            {
                _requestSyncGuard = true;
                try
                {
                    AppConfig.TxtRequest.Text = converted;
                    _lastAutoDataRequest = "";
                }
                finally
                {
                    _requestSyncGuard = false;
                }
            }
            return;
        }
        //URL变更（非方式切换）：报文与URL语义一致（注入记录加载/报文回同步的回声）无需变动——
        //避免记录加载时URL回写冲掉刚加载的标记报文；不一致说明用户切换了目标：
        //一律按新URL构造默认请求（注入标记/定制请求头不保留）
        if (!isAutoOrEmpty)
        {
            string clean = RequestRewriter.StripRequestMarks(current);
            (_, string? curUrl) = RequestRewriter.ExtractMethodAndUrlLenient(clean, AppConfig.IsSSL);
            if (RequestRewriter.SameUrl(curUrl, targetUrl))
            {
                return;
            }
        }
        string req = RequestRewriter.BuildRequestFromUrl(targetUrl, AppConfig.DataMethod);
        if (string.IsNullOrEmpty(req))
        {
            return;
        }
        _requestSyncGuard = true;
        try
        {
            AppConfig.TxtRequest.Text = req;
            _lastAutoDataRequest = req;
        }
        finally
        {
            _requestSyncGuard = false;
        }
    }

    /// <summary>取数页报文 → URL/请求方式：剥离标记后解析请求行与Host头回同步（报文不完整或程序内改写时跳过）</summary>
    private void SyncUrlFromDataRequest()
    {
        if (_requestSyncGuard)
        {
            return;
        }
        //标记报文请求行可能含<Encode>等字面量与未编码空格的payload，先剥离再用宽松版提取URL
        string clean = RequestRewriter.StripRequestMarks(AppConfig.TxtRequest.Text);
        (string? method, string? url) = RequestRewriter.ExtractMethodAndUrlLenient(clean, AppConfig.IsSSL);
        _requestSyncGuard = true;
        try
        {
            if ((method == "GET" || method == "POST") && method != AppConfig.DataMethod)
            {
                AppConfig.DataMethod = method;
            }
            if (url != null && !RequestRewriter.SameUrl(url, AppConfig.Url))
            {
                AppConfig.Url = url;
            }
        }
        finally
        {
            _requestSyncGuard = false;
        }
    }

    private async Task CheckInject()
    {
        IsRuning = true;
        //检测日志全程带目标URL前缀（多次/批量检测日志归属一目了然；keepChannel保持原日志通道与颜色，finally释放）
        IDisposable logScope = Log.PushScope(new PrefixLogSink("[" + AppConfig.DetectUrl + "] ", Log.Sink, keepChannel: true));
        try
        {
            //剥离人工/自动标记（$sql$/<Encode>/<DRule>），避免标记字面量混入参数值污染检测探针；
            //检测页报文为独立文档，始终只有用户原始报文，标记只随命中进入注入记录
            string cleanRequestTxt = RequestRewriter.StripRequestMarks(AppConfig.DetectRequestTxt);
            if (cleanRequestTxt.Length != AppConfig.DetectRequestTxt.Length)
            {
                Log.Show("检测到报文含注入/编码标记，已自动剥离后进行检测……");
            }
            //取数页报文与检测流程完全隔离：只能由注入记录加载或手工配置改变，检测不再覆盖
            HttpRequest request = new HttpRequest(AppConfig, cleanRequestTxt);

            //日志标注本次检测目标URL（批量/多次检测时可据此区分日志归属）
            Log.Highlight("本次检测目标URL：" + AppConfig.DetectUrl);

            //获取原始的页面信息
            HttpResponse coserver = await HTTPTool.SendRequestRetryAsync(request);

            //拆分参数,存放到集合，方便后面从新拼接组合参数
            Log.Show("报告大侠，发现" + request.Params.Count + "个参数，请稍候正在对每一个参数进行注入测试！");

            bool wafChecked = false;
            _detectHitFound = false;
            _detectHitCount = 0;
            _appliedHitPriority = -1;
            _lastHitRequestTxt = null;
            //检出即停标记：某参数命中后停止其余参数与扩展位置检测
            bool stopTesting = false;

            //跨参数信号共享会话：参数间共享命中boundary/命中库（优先排序非限定），贯穿主参数与扩展位置检测
            SuperSQLInjectionV2.Tools.Inject.DetectSessionState detectSession = new SuperSQLInjectionV2.Tools.Inject.DetectSessionState();

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
                    List<InjectPoint> inpList = await SuperSQLInjectionV2.Tools.Inject.InjectDetectEngine.DetectParam(AppConfig, requestTxt, paramName, paramData, session: detectSession, onHit: ApplyHitImmediate);
                    //命中已即时写入注入记录（onHit回调），这里只按命中数量做提示与检出即停判断
                    if (inpList.Count > 1)
                    {
                        Log.Show("该参数共发现" + inpList.Count + "种注入类型，已全部记录到注入记录列表，可在注入记录中切换利用！");
                    }
                    //检出即停（sqlmap「keep testing the others」默认N同款）：已检出注入，停止其余参数检测
                    if (inpList.Count > 0 && AppConfig.DataConfig.DetectStopOnHit)
                    {
                        Log.Show("已检出注入点，按「检出即停」设置停止对其余参数/扩展位置的检测（需完整画像请关闭该开关）！");
                        stopTesting = true;
                        break;
                    }
                    continue;
                }

                //旧回退检测链路已移除：检测唯一走多技术引擎，引擎缺失时直接报错终止
                Log.Error("未找到检测用例库（config/injection/），注入检测无法继续！请重新安装或恢复该目录！");
                break;

            }


            //扩展注入位置（level 扩展行为）：JSON请求体任意level；level>=2测Cookie键值；level>=3测User-Agent/Referer头
            if (!stopTesting && SuperSQLInjectionV2.Tools.Inject.InjectPayloadLoader.IsAvailable())
            {
                await CheckExtendedPlaces(request, cleanRequestTxt, detectSession);
            }
            //检测命中后先精确识别族内变体（金仓/openGauss/达梦），再主动确认DBMS banner坐实库型与版本
            if (_detectHitFound)
            {
                _detectHitFound = false;
                await ConfirmDbVariantAsync();
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
        catch (SuperSQLInjectionV2.Tools.Http.TargetUnreachableException)
        {
            //引擎内已记Error日志，这里只补一条结果提示，不再重复堆异常详情
            Log.Show("目标主机无法连接，本次注入检测已终止！请确认目标服务/代理可用后重试。");
        }
        catch (Exception e)
        {
            Log.Show("识别注入发生异常！" + e.Message);
        }
        finally
        {
            logScope.Dispose();
            IsRuning = false;
        }

    }

    /// <summary>
    /// 扩展注入位置检测（level 行为）：JSON请求体任意level；level>=2测Cookie键值对；level>=3测User-Agent/Referer头。
    /// 命中同样走UpdateData进入注入记录，可恢复利用（标记已嵌入请求文本对应位置）。
    /// </summary>
    private async Task CheckExtendedPlaces(HttpRequest request, string requestTxt, SuperSQLInjectionV2.Tools.Inject.DetectSessionState detectSession)
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
            //检出即停（并行模式）：命中置位后，尚未启动的参数检测直接跳过；在飞参数自然跑完（语义近似sqlmap默认N）
            int parHitFound = 0;
            var tasks = targets.Select(async t =>
            {
                await gate.WaitAsync().ConfigureAwait(false);
                try
                {
                    if (AppConfig.DataConfig.DetectStopOnHit && Volatile.Read(ref parHitFound) == 1)
                    {
                        return new List<InjectPoint>();
                    }
                    List<InjectPoint> hits = await SuperSQLInjectionV2.Tools.Inject.InjectDetectEngine.DetectParam(AppConfig, requestTxt, t.name, t.value, t.place, t.header, t.uriIdx, detectSession, ApplyHitImmediate).ConfigureAwait(false);
                    if (hits.Count > 0)
                    {
                        Volatile.Write(ref parHitFound, 1);
                    }
                    return hits;
                }
                finally
                {
                    gate.Release();
                }
            }).ToList();
            //命中已通过onHit即时写入注入记录（回调内封送UI线程），这里只需等待全部参数检测完成
            await Task.WhenAll(tasks).ConfigureAwait(false);
            return;
        }
        foreach (var t in targets)
        {
            Log.Show("报告大侠，正在对" + t.desc + "参数 " + t.name + " 进行注入测试（Level=" + level + "）！");
            List<InjectPoint> hits = await SuperSQLInjectionV2.Tools.Inject.InjectDetectEngine.DetectParam(AppConfig, requestTxt, t.name, t.value, t.place, t.header, t.uriIdx, detectSession, ApplyHitImmediate);
            //命中已即时写入注入记录（onHit回调），这里只做检出即停判断
            //检出即停：已检出注入，停止其余扩展位置参数检测
            if (hits.Count > 0 && AppConfig.DataConfig.DetectStopOnHit)
            {
                Log.Show("已检出注入点，按「检出即停」设置停止对其余扩展位置参数的检测（需完整画像请关闭该开关）！");
                return;
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
        if (!inp.IsInject) {
            return;
        }
        _detectHitFound = true;
        _detectHitCount++;

        //旧模型兼容：Bool盲注+时间判定 的命中升级为独立的时间盲注类型（判定经EffectiveBoolType强制走时间）
        if (inp.InjectType == InjectType.Blind && inp.BoolInjectType == BoolInjectType.Time)
        {
            inp.InjectType = InjectType.Time;
        }
        //fork化归一：变体库（金仓/openGauss/达梦）归一到族宿主+Fork名，取数=族模板+fork overlay
        //（记录落库与配置应用共用规范化结果，须先于AddInjectRecord执行）
        if (!inp.DBType.Equals(DBType.UnKnow))
        {
            var (fam, fork) = SuperSQLInjectionV2.Payload.DbProfile.ToFamilyFork(inp.DBType);
            inp.DBType = fam;
            if (!string.IsNullOrEmpty(fork))
            {
                inp.ForkName = fork;
            }
        }
        //命中记录始终落库（按发现顺序全量记录，与通道价值无关，可在注入记录中任意切换利用）
        AddInjectRecord(inp);

        //配置应用按利用价值收敛：onHit按检测顺序（技术遍历序：布尔→…→时间→内联）回调，
        //后到命中可能是更慢通道——只应用不劣于当前已应用的命中，保证最优通道成为生效配置
        int prio = SuperSQLInjectionV2.Tools.Inject.InjectDetectEngine.ExploitPriority(inp);
        if (prio < _appliedHitPriority)
        {
            return;
        }
        _appliedHitPriority = prio;

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
            //相似度oracle基准联动（高动态三档兜底命中时取数依赖）
            AppConfig.DataConfig.SimilarTemplate = inp.SimilarTemplate ?? "";
            AppConfig.DataConfig.SimilarMode = inp.SimilarMode ?? "";
            AppConfig.DataConfig.SimilarCutoff = inp.SimilarCutoff;
            AppConfig.DataConfig.SimilarFeatures = inp.DynamicFeatures;
            //时间盲注延时秒数带出到通道配置时间盲注组
            SyncTimeSleepFromCheckValue();
        }
        if (!inp.DBType.Equals(DBType.UnKnow)) {
            AppConfig.DataConfig.SelectedDBType = inp.DBType;
            if (!string.IsNullOrEmpty(inp.ForkName))
            {
                AppConfig.DataConfig.SelectedForkName = inp.ForkName;
            }
        }
        if (inp.InjectType.Equals(InjectType.Union))
        {
            AppConfig.DataConfig.ShowColumnIndex = inp.ShowColumnIndex;
            AppConfig.DataConfig.SumColumnCount = inp.SumColumnCount;
            //检测成功的填充字符同步到通道配置（空=ORDER BY路径未定，取数回退模板UnionFillStr）
            AppConfig.DataConfig.UnionFill = inp.UnionFill ?? "";
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
                    AppConfig.DataConfig.AutoSelectErrorMethod(method);
                }
                else
                {
                    Dispatcher.UIThread.Post( ()=> AppConfig.DataConfig.AutoSelectErrorMethod(method));
                }
            }
        }
        //vector原文复用上下文联动（报错[QUERY]/where=3[INFERENCE]）：利用标记报文只留$sql$胶水，
        //发送期按VectorTemplate装配触发函数/包装结构（ConfirmDbBanner与取数链路依赖）；
        //非vector命中写入1/空，同时清掉上一注入点的残留vector状态
        AppConfig.DataConfig.Where = inp.Where;
        AppConfig.DataConfig.VectorTemplate = inp.VectorTemplate ?? "";
        AppConfig.DataConfig.OrigValue = inp.OrigValue ?? "";
        //标记报文不回写编辑器：检测页报文保持干净，利用标记只随注入点存入注入记录，
        //取数时在注入记录中选择对应注入点（恢复记录）才加载带标记的报文
        _lastHitRequestTxt = inp.RequestTxt;
        _lastHitPoint = inp;
    }

    /// <summary>本轮检测已应用配置的命中点价值分（UpdateData按ExploitPriority收敛，慢通道命中不覆盖快通道配置）</summary>
    private int _appliedHitPriority = -1;

    /// <summary>
    /// 命中即时落记录：检测引擎onHit回调来自工作线程（ConfigureAwait(false)），
    /// 封送到UI线程同步执行UpdateData，保证ObservableCollection/绑定属性单线程写；
    /// 检测全程async await不阻塞UI线程，Wait()不会死锁
    /// </summary>
    private void ApplyHitImmediate(InjectPoint hit)
    {
        if (Avalonia.Application.Current == null || Dispatcher.UIThread.CheckAccess())
        {
            UpdateData(hit);
        }
        else
        {
            Dispatcher.UIThread.InvokeAsync(() => UpdateData(hit)).Wait();
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

    /// <summary>最后一个命中点对象（变体精确识别据此取通道/判定依据/标记报文）</summary>
    private InjectPoint? _lastHitPoint;

    /// <summary>
    /// 变体/Fork纠偏回写注入记录：命中点识别出fork（如KingbaseES/MariaDB）后，
    /// 同步更新注入记录列表中同注入点全部记录的库型与Fork名，重新落盘并登记通道注册表，刷新筛选视图
    /// </summary>
    private void WriteBackDbVariant(InjectPoint hit, DBType refined, string forkName = "")
    {
        bool changed = false;
        foreach (InjectRecord r in InjectRecords.Where(r =>
            r.PName == hit.PName && r.InjectType == hit.InjectType
            && r.RequestTxt == hit.RequestTxt && (r.DBType != refined || r.ForkName != forkName)).ToList())
        {
            r.DBType = refined;
            r.ForkName = forkName;
            InjectChannelRegistry.Register(AppConfig.Host, AppConfig.Port, r);
            changed = true;
        }
        if (changed)
        {
            SaveInjectRecords();
            RefreshInjectRecordFilters();
            Log.SysLog("注入记录库型已回写为 " + refined + (string.IsNullOrEmpty(forkName) ? "" : "(" + forkName + ")") + "（参数 " + hit.PName + "）");
        }
        //上下文与取数配置同步：fork overlay模板即时生效
        CurrentContext.DbForkName = forkName;
        AppConfig.DataConfig.SelectedForkName = forkName;
    }

    /// <summary>
    /// 检测命中后族→Fork精确识别（布尔盲注通道专用）：
    /// Union/报错通道的banner识别在ConfirmDbBanner内完成；时间/堆叠通道不识别（保持空Fork名）。
    /// 识别成功回写命中点Fork名与注入记录（库型保持族宿主，取数=族模板+fork overlay）
    /// </summary>
    private async Task ConfirmDbVariantAsync()
    {
        try
        {
            InjectPoint? hit = _lastHitPoint;
            if (hit == null || hit.DBType == DBType.UnKnow || hit.InjectType != InjectType.Blind)
            {
                return;
            }
            var result = await SuperSQLInjectionV2.Tools.Inject.DbVariantResolver.ResolveAsync(AppConfig, hit).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(result.ForkName) && result.ForkName != hit.ForkName)
            {
                hit.ForkName = result.ForkName;
                WriteBackDbVariant(hit, hit.DBType, result.ForkName);
            }
        }
        catch (Exception e)
        {
            //fork识别失败不影响检测结论与取数主链路
            Log.SysLog("Fork识别异常（保持族类型）：" + e.Message);
        }
    }

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
                ? PayloadFactory.BPTool.UnionAll(item.VerPayload, AppConfig.DataConfig.SumColumnCount, AppConfig.DataConfig.ShowColumnIndex, AppConfig.DataConfig.EffectiveUnionFill)
                //报错vector模式（[QUERY]槽位发送期装配）：塞裸表达式，vector分隔符即提取标记，不叠ErrorData第二层触发函数
                : AppConfig.DataConfig.IsBareVectorQuery
                ? item.VerPayload
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
                //banner特征词识别族内fork（金仓/openGauss/达梦/MariaDB等），库型保持族宿主，Fork名记入记录
                string fork = SuperSQLInjectionV2.Tools.Inject.DbVariantResolver.IdentifyFork(banner, db);
                if (!string.IsNullOrEmpty(fork) && _lastHitPoint != null && _lastHitPoint.ForkName != fork)
                {
                    Log.Success("Fork库识别：" + db + " 族fork为 " + fork + "（取数=" + db + "族模板+fork overlay）");
                    _lastHitPoint.ForkName = fork;
                    WriteBackDbVariant(_lastHitPoint, db, fork);
                }
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
        string forkSuffix = string.IsNullOrEmpty(CurrentContext.DbForkName) ? "" : "(" + CurrentContext.DbForkName + ")";
        ContextSummaryText = $"{RequestMethod} {CurrentContext.ParamName} · {CurrentContext.InjectType} · {CurrentContext.DbType}{forkSuffix} · {CurrentContext.DbEncoding}";
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
        //手工指定的Fork选择（Fork下拉）同步到取数配置：fork overlay模板即时生效
        AppConfig.DataConfig.SelectedForkName = CurrentContext.DbForkName ?? "";
        //编码已改为直接绑定全局配置（AppConfig.DataConfig.DbEncoding），此处仅同步回上下文用于摘要显示
        CurrentContext.DbEncoding = AppConfig.DataConfig.DbEncoding;
        //Union列数/显示列/填充已直绑DataConfig（通道配置即改即生效），不再经CurrentContext中转覆盖
        //手工指定上下文与注入记录无关，复位vector取数模式防止残留记录状态污染
        AppConfig.DataConfig.ResetVectorMode();
        CurrentContext.Source = InjectContextSource.Manual;
        CurrentContext.SourceDetail = "手动覆盖";
        Log.Success($"已手工指定注入上下文：{CurrentContext.InjectType} · {CurrentContext.DbType}{(string.IsNullOrEmpty(CurrentContext.DbForkName) ? "" : "(" + CurrentContext.DbForkName + ")")} · {CurrentContext.DbEncoding}（Union {AppConfig.DataConfig.SumColumnCount} 列，显示列 {AppConfig.DataConfig.ShowColumnIndex}），取数等利用将按此执行");
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
        InjectRecord record = BuildInjectRecord(inp, AppConfig.Host, AppConfig.Port);
        //每注入点生成随机回显标记（防固定短串与页面内容冲突），随记录持久化并立即生效
        Payload.EchoMarkers.Use(record, Payload.PayloadFactory.BasePayload);
        UpsertInjectRecord(record, AppConfig.Host, AppConfig.Port, true);
    }

    /// <summary>
    /// 批量检测命中写入注入记录（BatchDetectViewModel回调，UI线程执行）：
    /// 只落记录与通道注册表，不切换当前注入上下文、不改动全局回显标记（其他目标仍在并发检测，避免互相污染）
    /// </summary>
    public void AddBatchInjectRecord(InjectPoint inp, string host, int port)
    {
        InjectRecord record = BuildInjectRecord(inp, host, port);
        UpsertInjectRecord(record, host, port, false);
    }

    /// <summary>由命中点构造注入记录（含随机回显标记生成；Target取调用方给定的主机/端口）</summary>
    private InjectRecord BuildInjectRecord(InjectPoint inp, string host, int port)
    {
        InjectRecord record = new InjectRecord
        {
            Time = DateTime.Now,
            Target = host + ":" + port,
            PName = inp.PName ?? "",
            DBType = inp.DBType,
            ForkName = inp.ForkName ?? "",
            InjectType = inp.InjectType,
            BoolInjectType = inp.BoolInjectType,
            CheckValue = inp.CheckValue ?? "",
            Revers = inp.Revers,
            SimilarTemplate = inp.SimilarTemplate ?? "",
            SimilarMode = inp.SimilarMode ?? "",
            SimilarCutoff = inp.SimilarCutoff,
            DynamicFeatures = inp.DynamicFeatures,
            SumColumnCount = inp.SumColumnCount,
            ShowColumnIndex = inp.ShowColumnIndex,
            UnionFill = inp.UnionFill ?? "",
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
        //每注入点生成随机回显标记（防固定短串与页面内容冲突），随记录持久化；
        //报错vector复用的命中已在烘焙前预生成标记（vector分隔符按该标记组合烘焙），此处优先复用保持一致
        if (!string.IsNullOrEmpty(inp.StartMark) && !string.IsNullOrEmpty(inp.EndMark) && !string.IsNullOrEmpty(inp.SplitMark))
        {
            record.StartMark = inp.StartMark;
            record.EndMark = inp.EndMark;
            record.SplitMark = inp.SplitMark;
        }
        else
        {
            (record.StartMark, record.EndMark, record.SplitMark) = Payload.EchoMarkers.Generate();
        }
        return record;
    }

    /// <summary>注入记录去重落库（同参数/类型/目标/报文替换，否则置顶插入）+ 通道注册表登记；updateContext=true时同步建立注入上下文</summary>
    private void UpsertInjectRecord(InjectRecord record, string host, int port, bool updateContext)
    {
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
        InjectChannelRegistry.Register(host, port, record);
        Log.Success("已记录注入点到注入记录列表：" + record.PName + "（" + record.InjectTypeDesc + "，" + record.DBType + "）");

        if (!updateContext)
        {
            return;
        }
        //检测命中 → 建立注入上下文（来源：自动检测）
        CurrentContext.Source = InjectContextSource.AutoDetect;
        CurrentContext.SourceDetail = record.Target;
        CurrentContext.ParamName = record.PName;
        CurrentContext.InjectType = record.InjectType;
        CurrentContext.DbType = record.DBType;
        CurrentContext.DbForkName = record.ForkName ?? "";
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
        //保证标记形态与当前编码/取数链路一致；定位失败时RebakeRecordRequest内部回退存储报文。
        //报文+URL成对回写期间挂同步守卫：URL变更触发"一律按新URL重建默认请求"会冲掉刚加载的标记报文，
        //URL/请求方式由SyncUrlFromRecord显式回写，无需联动回路参与
        //回显标记随记录恢复（记录无标记的旧数据回退模板默认值）——必须先于RebakeRecordRequest：
        //报错vector重烘焙的分隔符对齐当前EchoMarkers组合（Start+Split/Split+End），顺序颠倒会用上一个记录的标记烘焙
        Payload.EchoMarkers.Use(record, Payload.PayloadFactory.BasePayload);
        _requestSyncGuard = true;
        try
        {
            AppConfig.TxtRequest.Text = RequestRewriter.RebakeRecordRequest(AppConfig, record);
            SyncUrlFromRecord(record);
        }
        finally
        {
            _requestSyncGuard = false;
        }
        //旧记录迁移：Bool盲注+时间判定 升级为独立的时间盲注类型
        if (record.InjectType == InjectType.Blind && record.BoolInjectType == BoolInjectType.Time)
        {
            record.InjectType = InjectType.Time;
        }
        AppConfig.DataConfig.InjectParamName = record.PName;
        //fork化归一：旧记录可能存变体库型，归一到族宿主（setter内自动归一）+Fork名随后写入
        AppConfig.DataConfig.SelectedDBType = record.DBType;
        string recordFork = !string.IsNullOrEmpty(record.ForkName)
            ? record.ForkName
            : SuperSQLInjectionV2.Payload.DbProfile.ToFamilyFork(record.DBType).ForkName;
        AppConfig.DataConfig.SelectedForkName = recordFork ?? "";
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
        //检测期自动适配的编码工具随记录恢复：自动启用对应工具（磁盘脚本优先，注册表兜底）
        if (!string.IsNullOrEmpty(record.AutoTamper))
        {
            try
            {
                EncodeToolModel? item = AppConfig.ByPassConfig.EncodeTools.FirstOrDefault(s =>
                    string.Equals(s.Key, record.AutoTamper, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(s.Name, record.AutoTamper, StringComparison.OrdinalIgnoreCase));
                if (item == null)
                {
                    item = Bypass.RuleStore.LoadToolByKey(record.AutoTamper);
                    if (item != null)
                    {
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
            //相似度oracle基准随记录恢复（高动态三档兜底取数依赖）
            AppConfig.DataConfig.SimilarTemplate = record.SimilarTemplate ?? "";
            AppConfig.DataConfig.SimilarMode = record.SimilarMode ?? "";
            AppConfig.DataConfig.SimilarCutoff = record.SimilarCutoff;
            AppConfig.DataConfig.SimilarFeatures = record.DynamicFeatures;
            //时间盲注延时秒数随记录带出到通道配置时间盲注组
            SyncTimeSleepFromCheckValue();
        }
        if (record.InjectType == InjectType.Union)
        {
            AppConfig.DataConfig.SumColumnCount = record.SumColumnCount;
            AppConfig.DataConfig.ShowColumnIndex = record.ShowColumnIndex;
            //检测成功的填充字符随记录回填（空=旧记录无此字段，取数回退模板UnionFillStr；人工可再改）
            AppConfig.DataConfig.UnionFill = record.UnionFill ?? "";
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
        //fork化归一：旧记录可能存的是变体库型（金仓/openGauss/达梦），归一到族宿主+Fork名
        var (familyDb, familyFork) = SuperSQLInjectionV2.Payload.DbProfile.ToFamilyFork(record.DBType);
        CurrentContext.DbType = familyDb;
        CurrentContext.DbForkName = !string.IsNullOrEmpty(record.ForkName) ? record.ForkName : familyFork;
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
                //请求方式回同步：记录恢复走同步守卫，SyncUrlFromDataRequest不参与，此处显式回写
                string m = firstParts[0].ToUpperInvariant();
                if ((m == "GET" || m == "POST") && m != AppConfig.DataMethod)
                {
                    AppConfig.DataMethod = m;
                }
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
        //配置检查通过：输出当前生效配置摘要（取数/文件/命令/自定义SQL统一入口），便于核对与问题定位
        LogDataOpConfig(config, type);
        return true;
    }

    /// <summary>数据操作前的配置摘要日志：目标/库/注入类型/参数/通道关键参数/编码链/网络参数（GUI/Cmd 共用）</summary>
    public static void LogDataOpConfig(AppConfig config, InjectType type)
    {
        DataConfig dc = config.DataConfig;
        var sb = new StringBuilder("当前配置：目标=");
        sb.Append(config.Url)
          .Append("，数据库=").Append(dc.SelectedDBType)
          .Append("，注入类型=").Append(type)
          .Append("，注入参数=").Append(string.IsNullOrWhiteSpace(dc.InjectParamName) ? "-" : dc.InjectParamName);
        if (type == InjectType.Union)
        {
            sb.Append("，Union列数=").Append(dc.SumColumnCount).Append("/显示位=").Append(dc.ShowColumnIndex);
        }
        if (type is InjectType.Blind or InjectType.Time or InjectType.Stacked or InjectType.Dns)
        {
            sb.Append("，判断值=").Append(dc.CheckValue).Append(dc.Reverse ? "（取反）" : "");
        }
        if (type == InjectType.Dns)
        {
            sb.Append("，DNSLog=").Append(dc.DnsLogDomain);
        }
        string chain = string.Join("→", config.ByPassConfig.EncodeTools
            .Where(t => t.Enable).OrderBy(t => t.Seq).Select(t => t.Name));
        sb.Append("，编码链=").Append(chain.Length == 0 ? "无" : chain)
          .Append("，超时=").Append(config.TimeOut).Append("s")
          .Append("，线程=").Append(config.ThreadSize)
          .Append("，重试=").Append(config.RetryCount);
        Log.Show(sb.ToString());
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
            if (inp.IsInject && inp.BoolInjectType == BoolInjectType.Time)
            {
                //时间判断实锤确认：发一个sleep真条件（延时=通道配置SleepInjectMaxTime），响应确实延时才采纳，
                //避免真假都快时把时间oracle误判可用（CheckTheKey时间分支只看响应快于阈值）
                if (!await DataComm.CheckCondition(AppConfig, "1=1"))
                {
                    inp.IsInject = false;
                    Log.Show("时间判断值复核未通过（sleep真条件未触发延时），未采纳时间oracle！");
                }
            }
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
        bool isTimeChannel = AppConfig.DataConfig.EffectiveBoolType == BoolInjectType.Time;
        if (!isTimeChannel && string.IsNullOrEmpty(AppConfig.DataConfig.CheckValue))
        {
            Log.Warning("大侠，请先设置判断值！");
            return;
        }
        AppConfig.ResetStop();
        IsRuning = true;
        bool isok = false;
        try
        {
            bool truep, falsep;
            if (isTimeChannel)
            {
                //时间通道：真假条件经sleep包装发送（延时秒数=通道配置SleepInjectMaxTime，与取数同源），
                //按响应耗时判定——裸发1=1/1=2真假都快，无法验证时间oracle
                truep = await DataComm.CheckCondition(AppConfig, "1=1");
                falsep = await DataComm.CheckCondition(AppConfig, "1=2");
            }
            else
            {
                HttpRequest hr = new HttpRequest(AppConfig);
                hr.Payload = ConstData.TruePayload;
                HttpResponse trueServer = await HTTPTool.SendRequestRetryAsync(hr);
                HttpRequest hr1 = new HttpRequest(AppConfig);
                hr1.Payload = ConstData.FalsePayload;
                HttpResponse falseServer = await HTTPTool.SendRequestRetryAsync(hr1);

                truep = TruthOracle.IsTrue(trueServer, AppConfig.DataConfig.CheckValue, AppConfig.DataConfig.Reverse, AppConfig.DataConfig.EffectiveBoolType,
                    AppConfig.DataConfig.SimilarTemplate, AppConfig.DataConfig.SimilarMode, AppConfig.DataConfig.SimilarCutoff);
                falsep = TruthOracle.IsTrue(falseServer, AppConfig.DataConfig.CheckValue, AppConfig.DataConfig.Reverse, AppConfig.DataConfig.EffectiveBoolType,
                    AppConfig.DataConfig.SimilarTemplate, AppConfig.DataConfig.SimilarMode, AppConfig.DataConfig.SimilarCutoff);
            }
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
    public double NavSidebarWidth => IsNavCollapsed ? 70 : 240;

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
                //不带子索引时保留上次选中的选项卡；带子索引（如4.7）时直达对应选项卡
                if (parts.Length > 1 && int.TryParse(parts[1], out int tab) && tab >= 0 && tab <= 7)
                {
                    DataOpTabIndex = tab;
                }
            }
            SelectedNavIndex = page;
        }
    }

    /// <summary>检测页请求区选项卡索引：0请求报文 1跳过参数（TabControl.SelectedIndex双向绑定）</summary>
    [ObservableProperty] private int _requestSubTabIndex = 0;

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
            string json = File.ReadAllText(AppDomain.CurrentDomain.BaseDirectory + "/config/lastconfig.json");
            AppConfig? config = JsonSerializer.Deserialize(json, Source.JsonCtx.CompactInfo<AppConfig>());

            if (config != null)
            {
                //旧版配置一次性迁移（v2.0.2 智能模式整合）：旧「非动态不检测」开关已删除，
                //旧用户 DetectStopOnNonDynamic=true（默认省时）且未显式开过智能模式时，迁移为智能模式开，
                //保持"默认省时"语义；用户显式关过智能模式（SmartMode=false 且非动态停止也关）则尊重原选择
                try
                {
                    using JsonDocument doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("DataConfig", out JsonElement dc)
                        && dc.TryGetProperty("DetectStopOnNonDynamic", out JsonElement snd)
                        && snd.ValueKind == JsonValueKind.True
                        && dc.TryGetProperty("SmartMode", out JsonElement sm)
                        && sm.ValueKind == JsonValueKind.False)
                    {
                        config.DataConfig.SmartMode = true;
                        Log.SysLog("配置迁移：旧「非动态不检测」开关已整合进智能模式，已自动开启智能模式（Level≥3 保留时间/堆叠检测）！");
                    }
                }
                catch (Exception)
                {
                    //迁移探测失败不影响配置加载
                }
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
    /// 请求日志导出保存文件选择回调，由View注入（建议文件名request_log.csv）
    /// </summary>
    public Func<Task<string?>>? RequestLogSaveFilePicker { get; set; }

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

    /// <summary>编辑代理（弹窗修改主机/端口/类型/账号密码/启用状态）</summary>
    [RelayCommand]
    private async Task EditProxy(Proxy? proxy)
    {
        if (proxy == null)
        {
            return;
        }
        var vm = Dialogs.ProxyEditViewModel.FromItem(proxy);
        var options = new OverlayDialogOptions
        {
            FullScreen = false,
            HorizontalAnchor = HorizontalPosition.Center,
            VerticalAnchor = VerticalPosition.Center,
            Mode = DialogMode.None,
            Buttons = DialogButton.None,
            Title = "编辑代理",
            CanLightDismiss = true,
            CanDragMove = true,
            IsCloseButtonVisible = true,
            CanResize = true,
        };
        await OverlayDialog.ShowStandardAsync<Dialogs.ProxyEditView, Dialogs.ProxyEditViewModel>(vm, options: options);
        if (!vm.Confirmed)
        {
            return;
        }
        //防重复：修改后与列表中其他代理同主机同端口则拒绝
        if (AppConfig.ProxyConfig.ProxyItems.Any(p => !ReferenceEquals(p, proxy)
            && p.Host.Equals(vm.Host?.Trim(), StringComparison.OrdinalIgnoreCase) && p.Port == vm.Port))
        {
            NotificationManager?.Show("已存在相同主机和端口的代理，未保存！");
            return;
        }
        vm.ApplyTo(proxy);
        SavaConfig();
        NotificationManager?.Show("代理已保存！");
    }

    /// <summary>把选中代理设为固定代理：移到列表首位（固定模式取第一个可用代理）并启用，代理模式切为固定</summary>
    [RelayCommand]
    private void SetFixedProxy(Proxy? proxy)
    {
        if (proxy == null)
        {
            return;
        }
        var items = AppConfig.ProxyConfig.ProxyItems;
        int idx = items.IndexOf(proxy);
        if (idx < 0)
        {
            return;
        }
        if (idx > 0)
        {
            items.Move(idx, 0);
        }
        proxy.IsEnabled = true;
        AppConfig.ProxyConfig.SelectProxyType = ProxyType.Fixed;
        if (!AppConfig.ProxyConfig.ProxyEnable)
        {
            AppConfig.ProxyConfig.ProxyEnable = true;
        }
        AppConfig.ProxyConfig.CurrentProxyText = proxy.Host + ":" + proxy.Port;
        SavaConfig();
        Log.Show("已设固定代理：" + proxy.Host + ":" + proxy.Port + "（代理模式=固定，已启用）！");
    }

    [RelayCommand]
    private async Task CheckAllProxy()
    {
        if (AppConfig.ProxyConfig.ProxyItems.Count == 0)
        {
            Log.Warning("大侠，代理列表为空，请先添加代理！");
            return;
        }        Log.Show("开始验证所有代理，共：" + AppConfig.ProxyConfig.ProxyItems.Count + "个！");
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
        //LoadAll 回填规则发生在 AppConfig 赋值（OnAppConfigChanged 刷新过滤视图）之后，此处补刷新，否则动态规则/脚本库页显示空快照
        RefreshDynRuleFilter();
        RefreshScriptLibFilter();
        AppConfig.TxtRequest.Text = AppConfig.RequestTxt;
        //旧配置无DetectUrl字段（序列化缺省）时用取数页URL兜底初始化
        if (string.IsNullOrWhiteSpace(AppConfig.DetectUrl))
        {
            AppConfig.DetectUrl = AppConfig.Url;
        }
        //检测页独立文档：优先载入持久化的检测报文；旧配置无此字段时用剥离标记后的取数报文兜底
        AppConfig.TxtDetectRequest.Text = string.IsNullOrWhiteSpace(AppConfig.DetectRequestTxt)
            ? RequestRewriter.StripRequestMarks(AppConfig.RequestTxt)
            : AppConfig.DetectRequestTxt;

        //URL/请求方式 ⇄ 报文 双向联动（检测页DetectUrl/DetectMethod与取数页Url/DataMethod各自独立，两页报文互不影响）：
        //① URL变化→报文与URL语义不一致时一律按新URL构造默认请求（注入标记/定制请求头不保留；语义一致的回声不重建）；
        //   请求方式切换→定制报文用ChangeRequestFormat原地转换（参数迁移、请求头与注入标记保留）；
        //② 报文变化→解析请求行/Host头回同步请求方式与URL（_requestSyncGuard防循环）
        AppConfig.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(AppConfig.DetectUrl))
            {
                RegenerateDetectRequest(false);
            }
            else if (e.PropertyName == nameof(AppConfig.Url))
            {
                //取数页URL变化：按新URL重建取数报文（检测页报文不受取数页URL影响）
                RegenerateDataRequest(false);
            }
            else if (e.PropertyName == nameof(AppConfig.DataMethod))
            {
                //取数页请求方式切换：定制报文原地转换（参数迁移、请求头与注入标记保留）
                RegenerateDataRequest(true);
            }
            else if (e.PropertyName == nameof(AppConfig.DetectMethod))
            {
                RegenerateDetectRequest(true);
            }
        };
        AppConfig.TxtDetectRequest.TextChanged += (_, _) => SyncUrlFromDetectRequest();
        //取数页报文变化→回同步URL（StripRequestMarks后提取，标记报文也能正确回同步）
        AppConfig.TxtRequest.TextChanged += (_, _) => SyncUrlFromDataRequest();

        //自愈：清理历史AOT源生成序列化丢失属性产生的空壳条目（{}反序列化出的默认实例）
        try
        {
            var shellTools = AppConfig.ByPassConfig.EncodeTools.Where(s => string.IsNullOrWhiteSpace(s.Code)).ToList();
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