using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Platform;
using Avalonia.VisualTree;
using AvaloniaEdit;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Models.Data;
using SuperSQLInjectionV2.Tools;
using SuperSQLInjectionV2.Tools.Http;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Ursa.Controls;

namespace SuperSQLInjectionV2.Views;

public partial class MainView : UserControl
{
        private static readonly string[] s_txtPatterns = { "*.txt" };
        private static readonly string[] s_allPatterns = { "*" };
        private static readonly string[] s_csvPatterns = { "*.csv" };
        private static readonly string[] s_jsonPatterns = { "*.json" };

    private MainViewViewModel? _viewModel;

    /// <summary>HTTP请求报文编辑器集合（检测页/数据操作页请求配置/请求日志页请求区共用同一套浅暗主题）</summary>
    private TextEditor[] HttpEditors => new[] { RequestTxtBox, RequestTxtBox2, RequestLogBox };

    /// <summary>响应区编辑器集合（请求日志页响应区，应用 HttpData 高亮：SQL报错指纹/HTML标签/hex段）</summary>
    private TextEditor[] HttpDataEditors => new[] { ResponseLogBox };

    public MainView()
    {
        InitializeComponent();

        //TableView(Avalonia12.1)的SelectionMode暂不支持XAML字符串赋值，统一在代码中设置多选（Multiple=按住Ctrl/Shift多选，对应DataGrid的Extended；检测用例页保持默认单选）
        VersDataGrid.SelectionMode = SelectionMode.Multiple;
        HashDataGrid.SelectionMode = SelectionMode.Multiple;
        PrivDataGrid.SelectionMode = SelectionMode.Multiple;
        UaDataGrid.SelectionMode = SelectionMode.Multiple;
        RequestLogTable.SelectionMode = SelectionMode.Multiple;
        InjectRecordTable.SelectionMode = SelectionMode.Multiple;
        ProxyDataGrid.SelectionMode = SelectionMode.Multiple;
        ReplaceDataGrid.SelectionMode = SelectionMode.Multiple;
        EncodeDataGrid.SelectionMode = SelectionMode.Multiple;
        PayloadTemplateDataGrid.SelectionMode = SelectionMode.Multiple;
        DynamicDataGrid.SelectionMode = SelectionMode.Multiple;

        //HTTP报文编辑器主题：自定义xshd高亮（浅/深两套），外观色取自Dsg设计令牌，跟随应用主题切换
        EditorThemeTool.ApplyHttpEditorTheme(HttpEditors);
        EditorThemeTool.FollowAppTheme(HttpEditors);
        EditorThemeTool.ApplyHttpDataEditorTheme(HttpDataEditors);
        EditorThemeTool.FollowAppThemeData(HttpDataEditors);

        //请求日志页：payload/请求包/响应包右键"解码"子菜单（7种解码方式，选区优先无选区取全文）
        BuildDecodeMenuItems();

        //编码处理页：行拖拽排序（TableView无内置行拖拽，指针事件实现；行内开关/下拉/按钮上不启动拖拽）
        //Pressed走Tunnel（到达行之前先记录起点）；Moved/Released必须handledEventsToo=true——
        //TableView行选择在内部把指针事件标记Handled，默认Bubble订阅收不到，拖拽永远不触发
        EncodeDataGrid.AddHandler(PointerPressedEvent, EncodeGrid_PointerPressed, RoutingStrategies.Tunnel);
        EncodeDataGrid.AddHandler(PointerMovedEvent, EncodeGrid_PointerMoved, RoutingStrategies.Bubble, true);
        EncodeDataGrid.AddHandler(PointerReleasedEvent, EncodeGrid_PointerReleased, RoutingStrategies.Bubble, true);

        RequestTxtBox.AddHandler(PointerWheelChangedEvent, (o, i) =>
        {
            if (i.KeyModifiers != KeyModifiers.Control) return;
            if (i.Delta.Y > 0) RequestTxtBox.FontSize++;
            else RequestTxtBox.FontSize = RequestTxtBox.FontSize > 1 ? RequestTxtBox.FontSize - 1 : 1;
        }, RoutingStrategies.Bubble, true);

    }

    /// <summary>当前活动的请求编辑器（数据操作页-请求配置选项卡使用共享文档的第二编辑器）</summary>
    private TextEditor ActiveRequestEditor =>
        (_viewModel != null && _viewModel.NavPage4Visible && _viewModel.DataOpTabIndex == 0)
            ? RequestTxtBox2
            : RequestTxtBox;

    /// <summary>请求报文面板：复制全部报文</summary>
    private void CopyRequestC(object? sender, RoutedEventArgs e)
    {
        string text = ActiveRequestEditor.Text;
        if (!string.IsNullOrEmpty(text))
        {
            TopLevel.GetTopLevel(this)?.Clipboard?.SetTextAsync(text);
        }
    }

    /// <summary>请求报文面板：切换自动换行</summary>
    private void ToggleWrapC(object? sender, RoutedEventArgs e)
    {
        TextEditor editor = ActiveRequestEditor;
        editor.WordWrap = !editor.WordWrap;
    }

    /// <summary>请求报文面板：清空报文</summary>
    private void ClearRequestC(object? sender, RoutedEventArgs e)
    {
        ActiveRequestEditor.Document.Text = "";
    }

    //---------------- 请求日志页：剪切/复制/粘贴 + 右键解码 ----------------

    /// <summary>解码方式列表（与编码工具页同源，避免两处维护漂移）</summary>
    private static readonly string[] s_decodeMethods = new EncodeToolsViewModel().DecodeMethods.ToArray();

    /// <summary>构造payload/请求包/响应包三处右键菜单的"解码"子菜单项（Tag挂文本取值委托，点击时取选区或全文）</summary>
    private void BuildDecodeMenuItems()
    {
        foreach ((MenuItem menu, Func<string?> getter) in new (MenuItem, Func<string?>)[]
        {
            (DecodePayloadSubMenu, GetPayloadMenuText),
            (DecodeRequestSubMenu, GetRequestLogMenuText),
            (DecodeResponseSubMenu, GetResponseLogMenuText)
        })
        {
            foreach (string method in s_decodeMethods)
            {
                var item = new MenuItem { Header = method, Tag = getter };
                item.Click += DecodeMenuC;
                menu.Items.Add(item);
            }
        }
    }

    /// <summary>payload框：选区优先，无选区取全文</summary>
    private string? GetPayloadMenuText()
    {
        return !string.IsNullOrEmpty(RequestLogPayloadBox.SelectedText) ? RequestLogPayloadBox.SelectedText : RequestLogPayloadBox.Text;
    }

    /// <summary>请求包编辑器：选区优先，无选区取全文</summary>
    private string? GetRequestLogMenuText()
    {
        return !string.IsNullOrEmpty(RequestLogBox.SelectedText) ? RequestLogBox.SelectedText : RequestLogBox.Text;
    }

    /// <summary>响应包编辑器：选区优先，无选区取全文</summary>
    private string? GetResponseLogMenuText()
    {
        return !string.IsNullOrEmpty(ResponseLogBox.SelectedText) ? ResponseLogBox.SelectedText : ResponseLogBox.Text;
    }

    /// <summary>右键解码：按菜单项Header对应方式解码，结果弹窗展示并输出日志</summary>
    private async void DecodeMenuC(object? sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem mi || mi.Tag is not Func<string?> getter)
        {
            return;
        }
        string method = mi.Header as string ?? "";
        string text = getter() ?? "";
        if (string.IsNullOrWhiteSpace(text))
        {
            Log.Warning("没有可解码的内容（可先选中要解码的文本，无选区时将对全文解码）！");
            return;
        }
        try
        {
            string result = EncodeToolsViewModel.DecodeByMethod(method, text);
            Log.Show("右键解码（" + method + "）：" + (result.Length > 300 ? result[..300] + " ……（完整结果见弹窗）" : result));
            var options = new OverlayDialogOptions
            {
                FullScreen = false,
                HorizontalAnchor = HorizontalPosition.Center,
                VerticalAnchor = VerticalPosition.Center,
                Mode = DialogMode.None,
                Buttons = DialogButton.None,
                Title = "解码结果 · " + method,
                CanLightDismiss = true,
                CanDragMove = true,
                IsCloseButtonVisible = true,
                CanResize = true,
            };
            await OverlayDialog.ShowStandardAsync<Dialogs.DecodeResultView, Dialogs.DecodeResultViewModel>(
                new Dialogs.DecodeResultViewModel(method, text, result), options: options);
        }
        catch (Exception ex)
        {
            Log.Warning("解码（" + method + "）失败：" + ex.Message);
        }
    }

    /// <summary>请求日志payload框：剪切</summary>
    private void PayloadCutC(object? sender, RoutedEventArgs e) => RequestLogPayloadBox.Cut();

    /// <summary>请求日志payload框：复制</summary>
    private void PayloadCopyC(object? sender, RoutedEventArgs e) => RequestLogPayloadBox.Copy();

    /// <summary>请求日志payload框：粘贴</summary>
    private void PayloadPasteC(object? sender, RoutedEventArgs e) => RequestLogPayloadBox.Paste();

    /// <summary>请求日志请求包：剪切</summary>
    private void RequestLogCutC(object? sender, RoutedEventArgs e) => RequestLogBox.Cut();

    /// <summary>请求日志请求包：粘贴</summary>
    private void RequestLogPasteC(object? sender, RoutedEventArgs e) => RequestLogBox.Paste();

    /// <summary>请求日志响应包：复制（选区优先，无选区复制全文）</summary>
    private void ResponseLogCopyC(object? sender, RoutedEventArgs e)
    {
        string text = ResponseLogBox.SelectedText;
        if (string.IsNullOrEmpty(text))
        {
            text = ResponseLogBox.Text;
        }
        if (!string.IsNullOrEmpty(text))
        {
            TopLevel.GetTopLevel(this)?.Clipboard?.SetTextAsync(text);
        }
    }

    /// <summary>网络设置DNSLog页：应用内置DNS接收服务配置（按开关/端口/域名启停）</summary>
    private void ApplyDnsServerC(object? sender, RoutedEventArgs e)
    {
        if (DataContext is SuperSQLInjectionV2.ViewModels.MainViewViewModel vm)
        {
            SuperSQLInjectionV2.Models.Data.DnsServerManager.EnsureState(vm.AppConfig);
        }
    }

    /// <summary>日志面板：导出日志到文件</summary>
    private async void LogExportC(object? sender, RoutedEventArgs e)
    {
        if (_viewModel?.SaveFilePicker == null)
        {
            return;
        }
        string? path = await _viewModel.SaveFilePicker();
        if (string.IsNullOrEmpty(path))
        {
            return;
        }
        try
        {
            await System.IO.File.WriteAllTextAsync(path, TxtLog.Text ?? "");
            _viewModel.NotificationManager?.Show("日志已导出：" + path);
        }
        catch (Exception ex)
        {
            _viewModel.NotificationManager?.Show("日志导出失败：" + ex.Message, Avalonia.Controls.Notifications.NotificationType.Error);
        }
    }

    public void SetEncodingPointC(object? sender, RoutedEventArgs e)
    {
        TextEditor editor = ActiveRequestEditor;
        if (!string.IsNullOrEmpty(editor.SelectedText))
        {
            editor.SelectedText = ConstData.GetEncodingPoint(editor.SelectedText);
        }
        else
        {
            editor.Document.Insert(editor.CaretOffset, ConstData.GetEncodingPoint(""));
        }

    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _viewModel = DataContext as MainViewViewModel;
        //_viewModel.AppConfig.DataDump.InitializeData(DynamicDataGrid);

        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel is null || _viewModel is null)
            return;
        _viewModel.Clipboard = topLevel?.Clipboard;

        //注入保存文件对话框回调，用于导出数据
        _viewModel.AppConfig.DataDump.SaveFilePicker = PickSaveFile;
        //注入打开文件对话框回调，用于加载库表列结构
        _viewModel.AppConfig.DataDump.OpenFilePicker = PickOpenFile;
        //注入文件对话框回调，用于绕过模板与配置导入导出
        _viewModel.SaveFilePicker = PickSaveFile;
        _viewModel.OpenFilePicker = PickOpenFile;
        //注入请求日志导出保存文件对话框回调
        _viewModel.RequestLogSaveFilePicker = PickRequestLogSaveFile;

        WindowNotificationManager? notify = WindowNotificationManager.TryGetNotificationManager(topLevel, out var manager)
            ? manager
            : new WindowNotificationManager(topLevel);
        _viewModel.InitLogTools(notify, TxtLog);

        //动态规则菜单预填充：空MenuFlyout无法正常弹出，须在打开前就绪；规则增删后同步刷新
        if (!_companionMenusHooked)
        {
            _companionMenusHooked = true;
            _viewModel.AppConfig.CompanionRules.CollectionChanged += (_, _) => RefreshCompanionMenus();
        }
        RefreshCompanionMenus();

    }

    private bool _companionMenusHooked;

    /// <summary>预填充全部动态规则菜单（两个请求编辑器的右键子菜单 + 工具栏"动态值"Flyout），保证菜单打开前已有内容</summary>
    private void RefreshCompanionMenus()
    {
        if (_viewModel == null)
        {
            return;
        }
        foreach (var editor in new[] { RequestTxtBox, RequestTxtBox2 })
        {
            if (editor.ContextMenu is not { } cm)
            {
                continue;
            }
            foreach (var item in cm.Items)
            {
                if (item is MenuItem mi && Equals(mi.Header, "动态值（可多选）"))
                {
                    RebuildBeforeRuleItems(mi.Items);
                }
                else if (item is MenuItem mi2 && Equals(mi2.Header, "二次注入（单选）"))
                {
                    RebuildAfterRuleItems(mi2.Items);
                }
            }
        }
        MenuFlyout? flyout = this.FindControl<Button>("DynFlyoutBtn")?.Flyout as MenuFlyout;
        if (flyout != null)
        {
            RebuildBeforeRuleItems(flyout.Items);
        }
    }

    /// <summary>日志编辑器右键：复制选中内容（无选中时复制全部）</summary>
    private void LogCopyC(object? sender, RoutedEventArgs e)
    {
        string text = TxtLog.SelectedText;
        if (string.IsNullOrEmpty(text))
        {
            text = TxtLog.Text;
        }
        TopLevel.GetTopLevel(this)?.Clipboard?.SetTextAsync(text ?? "");
    }

    /// <summary>日志编辑器右键：全选</summary>
    private void LogSelectAllC(object? sender, RoutedEventArgs e)
    {
        TxtLog.SelectAll();
    }

    /// <summary>日志编辑器右键：清空日志</summary>
    private void LogClearC(object? sender, RoutedEventArgs e)
    {
        Log.ClearLog();
    }

    private void SetInjectPointC(object? sender, RoutedEventArgs e)
    {
        TextEditor editor = ActiveRequestEditor;
        editor.Document.Insert(editor.CaretOffset, ConstData.GetInjectPoint());
    }

    /// <summary>动态值规则菜单项点击（无选中态）：启用该规则并把&lt;DRule&gt;标记插入活动报文编辑器
    /// （有选区为&lt;DRule&gt;标记名:选区数据&lt;DRule&gt;，无选区为空标记&lt;DRule&gt;标记名&lt;DRule&gt;）；规则停用只在动态规则页管理</summary>
    private void ToggleBeforeRuleC(object? sender, RoutedEventArgs e)
    {
        if (sender is MenuItem mi && mi.Tag is CompanionRequestConfig rule)
        {
            rule.Enabled = true;
            TextEditor editor = ActiveRequestEditor;
            //SelectedText赋值：有选区替换选区、无选区在光标处插入
            editor.SelectedText = ConstData.GetDRulePoint(editor.SelectedText ?? "", rule.TagName);
        }
    }

    /// <summary>二次注入规则菜单项点击：单选开启（选中规则启用、其余二次注入规则全部关闭；关闭项=全部停用）</summary>
    private void SelectAfterRuleC(object? sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem mi || _viewModel == null)
        {
            return;
        }
        CompanionRequestConfig? selected = mi.Tag as CompanionRequestConfig;
        foreach (var rule in _viewModel.AppConfig.CompanionRules)
        {
            if (rule.Kind == 1)
            {
                rule.Enabled = selected != null && ReferenceEquals(rule, selected);
            }
        }
    }

    /// <summary>请求报文右键菜单打开时：重建"插入动态值"（点击插入标记）与"二次注入"（单选）子菜单</summary>
    private void RequestMenuOpenedC(object? sender, RoutedEventArgs e)
    {
        if (sender is not ContextMenu menu)
        {
            return;
        }
        foreach (var item in menu.Items)
        {
            if (item is MenuItem mi && Equals(mi.Header, "插入动态值"))
            {
                RebuildBeforeRuleItems(mi.Items);
            }
            else if (item is MenuItem mi2 && Equals(mi2.Header, "二次注入（单选）"))
            {
                RebuildAfterRuleItems(mi2.Items);
            }
        }
    }

    /// <summary>数据管理工具栏"动态值"按钮Flyout打开时：重建动态值规则项（点击插入标记）</summary>
    private void DynFlyoutOpeningC(object? sender, EventArgs e)
    {
        if (sender is MenuFlyout flyout)
        {
            RebuildBeforeRuleItems(flyout.Items);
        }
    }

    /// <summary>重建动态值规则项：普通菜单项无选中态，点击启用该规则并在报文中插入其&lt;DRule&gt;标记（规则变动后每次打开菜单时刷新）</summary>
    private void RebuildBeforeRuleItems(Avalonia.Controls.ItemCollection items)
    {
        items.Clear();
        if (_viewModel == null)
        {
            return;
        }
        bool any = false;
        foreach (var rule in _viewModel.AppConfig.CompanionRules)
        {
            if (rule.Kind != 0)
            {
                continue;
            }
            any = true;
            var item = new MenuItem
            {
                Header = rule.InsertMenuHeader,
                Tag = rule,
            };
            item.Click += ToggleBeforeRuleC;
            items.Add(item);
        }
        if (!any)
        {
            items.Add(new MenuItem { Header = "（无动态值规则，请在防护绕过-动态规则页新增）", IsEnabled = false });
        }
    }

    /// <summary>重建二次注入规则项：单选样式，选中一条启用并关闭其余，含"关闭"项全部停用</summary>
    private void RebuildAfterRuleItems(Avalonia.Controls.ItemCollection items)
    {
        items.Clear();
        if (_viewModel == null)
        {
            return;
        }
        bool any = false;
        bool anyEnabled = false;
        var afterItems = new List<MenuItem>();
        foreach (var rule in _viewModel.AppConfig.CompanionRules)
        {
            if (rule.Kind != 1)
            {
                continue;
            }
            any = true;
            anyEnabled |= rule.Enabled;
            var item = new MenuItem
            {
                Header = rule.InsertMenuHeader,
                Tag = rule,
                ToggleType = MenuItemToggleType.Radio,
                IsChecked = rule.Enabled,
            };
            item.Click += SelectAfterRuleC;
            afterItems.Add(item);
        }
        if (!any)
        {
            items.Add(new MenuItem { Header = "（无二次注入规则，请在防护绕过-动态规则页新增）", IsEnabled = false });
            return;
        }
        var offItem = new MenuItem
        {
            Header = "关闭二次注入（不启用任何规则）",
            ToggleType = MenuItemToggleType.Radio,
            IsChecked = !anyEnabled,
        };
        offItem.Click += SelectAfterRuleC;
        items.Add(offItem);
        foreach (var item in afterItems)
        {
            items.Add(item);
        }
    }

    /// <summary>
    /// 请求报文格式转换：GET / POST表单 / POST JSON / POST multipart复杂格式
    /// </summary>
    public void ChangeRequestFormatC(object? sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem mi || mi.Tag is not string fmt)
        {
            return;
        }
        TextEditor editor = ActiveRequestEditor;
        string request = editor.Text;
        if (string.IsNullOrEmpty(request))
        {
            return;
        }
        if (!Enum.TryParse(fmt, out SuperSQLInjectionV2.Tools.Http.RequestFormat target))
        {
            return;
        }
        string newRequest = RequestRewriter.ChangeRequestFormat(request, target);
        if (!request.Equals(newRequest, StringComparison.Ordinal))
        {
            editor.Document.Text = newRequest;
        }
    }

    /// <summary>
    /// 根据配置中心URL生成GET请求报文，覆盖当前请求包编辑区
    /// </summary>
    public void BuildRequestFromUrlC(object? sender, RoutedEventArgs e)
    {
        string url = _viewModel?.AppConfig?.Url ?? "";
        string request = RequestRewriter.BuildGetRequestFromUrl(url);
        if (string.IsNullOrEmpty(request))
        {
            _viewModel?.NotificationManager?.Show("URL无效，无法生成请求包！请检查配置中心的URL地址。");
            return;
        }
        ActiveRequestEditor.Document.Text = request;
    }

    /// <summary>
    /// 伴随请求规则列表双击：编辑选中规则
    /// </summary>
    private void CompanionRuleTable_DoubleTapped(object? sender, TappedEventArgs e)
    {
        if (_viewModel?.SelectedCompanionRule != null)
        {
            _viewModel.EditCompanionRuleCommand.Execute(_viewModel.SelectedCompanionRule);
        }
    }

    /// <summary>
    /// 表格行勾选框点击：联动选中当前行（勾选框拦截点击不触发行选中，联动后"修改/进入数据操作"等单行操作对勾选行生效）
    /// </summary>
    private void RowCheckSelectC(object? sender, RoutedEventArgs e)
    {
        if (sender is CheckBox cb && cb.DataContext != null)
        {
            TableView? tv = cb.FindAncestorOfType<TableView>();
            if (tv != null)
            {
                tv.SelectedItem = cb.DataContext;
            }
        }
    }

    private void RemoveProxySelect(object? sender, RoutedEventArgs e)
    {
        ProxyDataGrid.SelectedItems?.Cast<Proxy>().ToList().ForEach(x =>
        {
            _viewModel?.AppConfig?.ProxyConfig.ProxyItems.Remove(x);
        });

    }

    /// <summary>
    /// 选择Access表名/字段名外部字典txt（网络设置页"浏览"按钮）
    /// </summary>
    private async void BrowseAccessTableDictC(object? sender, RoutedEventArgs e)
    {
        string? path = await PickDictFile("选择Access表名字典（每行一个表名）");
        if (!string.IsNullOrEmpty(path) && _viewModel?.AppConfig?.DataConfig != null)
        {
            _viewModel.AppConfig.DataConfig.AccessTableDictPath = path;
            _viewModel.ReloadDictWords();
        }
    }

    private async void BrowseAccessColumnDictC(object? sender, RoutedEventArgs e)
    {
        string? path = await PickDictFile("选择Access字段名字典（每行一个字段名）");
        if (!string.IsNullOrEmpty(path) && _viewModel?.AppConfig?.DataConfig != null)
        {
            _viewModel.AppConfig.DataConfig.AccessColumnDictPath = path;
            _viewModel.ReloadDictWords();
        }
    }

    /// <summary>
    /// 删除选中的字典词条（网络设置-字典管理页，删除后立即保存回字典文件）
    /// </summary>
    private void RemoveDictSelect(object? sender, RoutedEventArgs e)
    {
        var items = DictWordListBox.SelectedItems?.Cast<string>().ToList();
        if (items != null && items.Count > 0)
        {
            _viewModel?.RemoveDictWords(items);
        }
    }

    private async Task<string?> PickDictFile(string title)
    {
        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel == null)
        {
            return null;
        }
        var files = await topLevel.StorageProvider.OpenFilePickerAsync(new Avalonia.Platform.Storage.FilePickerOpenOptions
        {
            Title = title,
            AllowMultiple = false,
            FileTypeFilter = new[]
            {
                new Avalonia.Platform.Storage.FilePickerFileType("字典文本") { Patterns = s_txtPatterns },
                new Avalonia.Platform.Storage.FilePickerFileType("所有文件") { Patterns = s_allPatterns }
            }
        });
        return files.Count > 0 ? files[0].Path.LocalPath : null;
    }

    /// <summary>二进制上传：选择本地文件并装载字节</summary>
    private async void PickBinaryLocalFile(object? sender, RoutedEventArgs e)
    {
        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel == null)
        {
            return;
        }
        var files = await topLevel.StorageProvider.OpenFilePickerAsync(new Avalonia.Platform.Storage.FilePickerOpenOptions
        {
            Title = "选择要上传的本地文件",
            AllowMultiple = false,
            FileTypeFilter = new[]
            {
                new Avalonia.Platform.Storage.FilePickerFileType("所有文件") { Patterns = s_allPatterns }
            }
        });
        if (files.Count > 0)
        {
            _viewModel?.AppConfig?.FileCmd.LoadLocalFile(files[0].Path.LocalPath);
        }
    }

    /// <summary>二进制下载：保存取回的字节到本地文件</summary>
    private async void SaveBinaryLocalFile(object? sender, RoutedEventArgs e)
    {
        var vm = _viewModel?.AppConfig?.FileCmd;
        if (vm == null)
        {
            return;
        }
        if (vm.FileBytes == null || vm.FileBytes.Length == 0)
        {
            Log.Warning("暂无已下载的二进制内容，请先执行二进制下载！");
            return;
        }
        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel == null)
        {
            return;
        }
        var file = await topLevel.StorageProvider.SaveFilePickerAsync(new Avalonia.Platform.Storage.FilePickerSaveOptions
        {
            Title = "保存二进制文件到本地",
            SuggestedFileName = System.IO.Path.GetFileName(vm.FilePath)
        });
        if (file != null)
        {
            vm.SaveFileBytesTo(file.Path.LocalPath);
        }
    }

    /// <summary>
    /// 验证选中的代理是否可用
    /// </summary>
    private void CheckProxySelect(object? sender, RoutedEventArgs e)
    {
        ProxyDataGrid.SelectedItems?.Cast<Proxy>().ToList().ForEach(x =>
        {
            _viewModel?.CheckProxyCommand.Execute(x);
        });
    }

    /// <summary>
    /// 删除选中的重发关键词
    /// </summary>
    private void RemoveRetryKeySelect(object? sender, RoutedEventArgs e)
    {
        RetryKeyListBox.SelectedItems?.Cast<string>().ToList().ForEach(x =>
        {
            _viewModel?.AppConfig?.RetryKeyItems.Remove(x);
        });
    }

    private void RemoveUaSelect(object? sender, RoutedEventArgs e)
    {
        UaDataGrid.SelectedItems?.Cast<SuperSQLInjectionV2.Models.UaItem>().ToList().ForEach(x =>
        {
            _viewModel?.AppConfig?.ByPassConfig.UaItemList.Remove(x);
        });
    }

    private void RemoveJumpkeySelect(object? sender, RoutedEventArgs e)
    {
        var keys = JumpkeyListBox.SelectedItems?.Cast<string>().ToList();
        if (keys != null && keys.Count > 0)
        {
            _viewModel?.RemoveJumpkeys(keys);
        }
    }

    private void RemoveBypassSelect(object? sender, RoutedEventArgs e)
    {
        //多选删除按行类型分流（变换类出编码链，动态值类清规则引用）
        EncodeDataGrid.SelectedItems?.Cast<ScriptLibRow>().ToList().ForEach(x =>
        {
            _viewModel?.RemoveTokenScriptCommand.Execute(x);
        });
    }

    //---- 脚本库页行拖拽排序（仅编码链脚本参与，动态值脚本不拖拽） ----
    private Point _encodeDragStart;
    private ScriptLibRow? _encodeDragItem;
    private bool _encodeDragging;

    private void EncodeGrid_PointerPressed(object? sender, PointerPressedEventArgs e)
    {
        _encodeDragging = false;
        _encodeDragItem = null;
        if (!e.GetCurrentPoint(EncodeDataGrid).Properties.IsLeftButtonPressed || e.Source is not Visual v)
        {
            return;
        }
        //行内交互控件（开关/下拉/按钮）按下时不启动拖拽，留给原交互
        if (v.FindAncestorOfType<ToggleSwitch>() != null || v.FindAncestorOfType<ComboBox>() != null || v.FindAncestorOfType<Button>() != null)
        {
            return;
        }
        if (EncodeRowItem(v) is { IsTransform: true } item)
        {
            _encodeDragItem = item;
            _encodeDragStart = e.GetPosition(EncodeDataGrid);
        }
    }

    /// <summary>按可视树向上找行项：优先TableViewRow，兜底逐级查DataContext（行容器类型变更时仍可用）</summary>
    private static ScriptLibRow? EncodeRowItem(Visual v)
    {
        if (v.FindAncestorOfType<TableViewRow>()?.DataContext is ScriptLibRow m)
        {
            return m;
        }
        for (Visual? cur = v; cur != null; cur = cur.GetVisualParent())
        {
            if (cur.DataContext is ScriptLibRow m2)
            {
                return m2;
            }
        }
        return null;
    }

    private void EncodeGrid_PointerMoved(object? sender, PointerEventArgs e)
    {
        if (_encodeDragItem == null)
        {
            return;
        }
        PointerPoint pt = e.GetCurrentPoint(EncodeDataGrid);
        if (!pt.Properties.IsLeftButtonPressed)
        {
            _encodeDragItem = null;
            _encodeDragging = false;
            return;
        }
        Point pos = pt.Position;
        if (!_encodeDragging && (Math.Abs(pos.X - _encodeDragStart.X) > 6 || Math.Abs(pos.Y - _encodeDragStart.Y) > 6))
        {
            _encodeDragging = true;
            EncodeDataGrid.Cursor = new Cursor(StandardCursorType.SizeAll);
        }
    }

    private void EncodeGrid_PointerReleased(object? sender, PointerReleasedEventArgs e)
    {
        //拖拽中指针被原行捕获，e.Source仍是起始行——目标行需按松开位置重新命中测试
        if (_encodeDragging && _encodeDragItem != null)
        {
            IInputElement? hit = EncodeDataGrid.InputHitTest(e.GetPosition(EncodeDataGrid));
            //目标必须是编码链脚本行（动态值脚本不参与排序，落在其上忽略）
            if (hit is Visual hv && EncodeRowItem(hv) is { IsTransform: true } target)
            {
                _viewModel?.MoveEncodeTool(_encodeDragItem.Tool, _viewModel.AppConfig.ByPassConfig.EncodeTools.IndexOf(target.Tool!));
            }
        }
        _encodeDragItem = null;
        _encodeDragging = false;
        EncodeDataGrid.Cursor = Cursor.Default;
    }

    private void RemoveTemplateRow(object? sender, RoutedEventArgs e)
    {
        PayloadTemplateDataGrid.SelectedItems?.Cast<PayloadTemplateItem>().ToList().ForEach(x =>
        {
            _viewModel?.TemplateItems.Remove(x);
        });
    }

    private void ViewPayloadRow(object? sender, RoutedEventArgs e)
    {
        if ((sender as Control)?.Tag is SuperSQLInjectionV2.Models.Detect.PayloadItem item)
        {
            _viewModel?.ViewPayloadCommand.Execute(item);
        }
    }

    private void DeletePayloadRow(object? sender, RoutedEventArgs e)
    {
        if ((sender as Control)?.Tag is SuperSQLInjectionV2.Models.Detect.PayloadItem item)
        {
            _viewModel?.DeletePayloadCommand.Execute(item);
        }
    }

    private void ViewInjectRecordRow(object? sender, RoutedEventArgs e)
    {
        if ((sender as Control)?.Tag is SuperSQLInjectionV2.Models.InjectRecord record)
        {
            _viewModel?.ViewInjectRecordCommand.Execute(record);
        }
    }

    private void EditFingerprintRow(object? sender, RoutedEventArgs e)
    {
        if ((sender as Control)?.Tag is SuperSQLInjectionV2.Models.Detect.FingerprintItem item)
        {
            _viewModel?.EditFingerprintCommand.Execute(item);
        }
    }

    private void DeleteFingerprintRow(object? sender, RoutedEventArgs e)
    {
        if ((sender as Control)?.Tag is SuperSQLInjectionV2.Models.Detect.FingerprintItem item)
        {
            _viewModel?.DeleteFingerprintCommand.Execute(item);
        }
    }

    private void DeleteInjectRecordRow(object? sender, RoutedEventArgs e)
    {
        if ((sender as Control)?.Tag is SuperSQLInjectionV2.Models.InjectRecord record)
        {
            _viewModel?.DeleteInjectRecordCommand.Execute(record);
        }
    }

    private void EnterDataOpRow(object? sender, RoutedEventArgs e)
    {
        if ((sender as Control)?.Tag is SuperSQLInjectionV2.Models.InjectRecord record)
        {
            _viewModel?.EnterDataOpWithRecordCommand.Execute(record);
        }
    }

    private void RemoveReplaceSelect(object? sender, RoutedEventArgs e)
    {
        ReplaceDataGrid.SelectedItems?.Cast<ReplaceModel>().ToList().ForEach(x =>
        {
            _viewModel?.AppConfig?.ByPassConfig.ReplaceItems.Remove(x);
        });
    }

    /// <summary>
    /// 复制选中的环境变量值到剪贴板
    /// </summary>
    private void CopyVersValueC(object? sender, RoutedEventArgs e)
    {
        if (_viewModel?.Clipboard == null)
        {
            return;
        }
        List<VersModel>? items = VersDataGrid.SelectedItems?.Cast<VersModel>().ToList();
        if (items == null || items.Count == 0)
        {
            return;
        }
        string text = string.Join(Environment.NewLine, items.Select(x => x.Value));
        _viewModel.Clipboard.SetTextAsync(text);
    }

    /// <summary>
    /// 复制选中的Hash值到剪贴板（换行分隔）
    /// </summary>
    private void CopyHashValueC(object? sender, RoutedEventArgs e)
    {
        if (_viewModel?.Clipboard == null)
        {
            return;
        }
        List<VersModel>? items = HashDataGrid.SelectedItems?.Cast<VersModel>().ToList();
        if (items == null || items.Count == 0)
        {
            return;
        }
        string text = string.Join(Environment.NewLine, items.Select(x => x.Value));
        _viewModel.Clipboard.SetTextAsync(text);
    }

    private void CopyPrivValueC(object? sender, RoutedEventArgs e)
    {
        if (_viewModel?.Clipboard == null)
        {
            return;
        }
        List<VersModel>? items = PrivDataGrid.SelectedItems?.Cast<VersModel>().ToList();
        if (items == null || items.Count == 0)
        {
            return;
        }
        string text = string.Join(Environment.NewLine, items.Select(x => x.Value));
        _viewModel.Clipboard.SetTextAsync(text);
    }

    /// <summary>
    /// 复制选中的数据行到剪贴板（按制表符分隔列，换行分隔行）
    /// </summary>
    private void CopyDumpRowsC(object? sender, RoutedEventArgs e)
    {
        if (_viewModel?.Clipboard == null)
        {
            return;
        }
        List<DynamicDataItem>? items = DynamicDataGrid.SelectedItems?.Cast<DynamicDataItem>().ToList();
        if (items == null || items.Count == 0)
        {
            return;
        }
        List<string> columns = _viewModel.AppConfig.DataDump.Columns.Select(c => c.PropertyName).ToList();
        StringBuilder sb = new StringBuilder();
        foreach (DynamicDataItem row in items)
        {
            sb.AppendLine(string.Join("\t", columns.Select(c => row[c])));
        }
        _viewModel.Clipboard.SetTextAsync(sb.ToString().TrimEnd());
    }

    /// <summary>
    /// 弹出保存文件对话框，返回选择的保存路径
    /// </summary>
    private Task<string?> PickSaveFile()
    {
        return PickSaveFileAs("导出数据", "dump_data.csv");
    }

    /// <summary>
    /// 弹出保存文件对话框（请求日志导出），返回选择的保存路径
    /// </summary>
    private Task<string?> PickRequestLogSaveFile()
    {
        return PickSaveFileAs("导出请求日志", "request_log.csv");
    }

    /// <summary>
    /// 弹出保存文件对话框（CSV/文本），返回选择的保存路径
    /// </summary>
    private async Task<string?> PickSaveFileAs(string title, string suggestedName)
    {
        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel == null)
        {
            return null;
        }
        var file = await topLevel.StorageProvider.SaveFilePickerAsync(new Avalonia.Platform.Storage.FilePickerSaveOptions
        {
            Title = title,
            SuggestedFileName = suggestedName,
            DefaultExtension = "csv",
            FileTypeChoices = new[]
            {
                new Avalonia.Platform.Storage.FilePickerFileType("CSV文件") { Patterns = s_csvPatterns },
                new Avalonia.Platform.Storage.FilePickerFileType("文本文件") { Patterns = s_txtPatterns }
            }
        });
        return file?.Path.LocalPath;
    }

    /// <summary>
    /// 弹出打开文件对话框，返回选择的文件路径
    /// </summary>
    private async Task<string?> PickOpenFile()
    {
        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel == null)
        {
            return null;
        }
        var files = await topLevel.StorageProvider.OpenFilePickerAsync(new Avalonia.Platform.Storage.FilePickerOpenOptions
        {
            Title = "加载库表列结构",
            AllowMultiple = false,
            FileTypeFilter = new[]
            {
                new Avalonia.Platform.Storage.FilePickerFileType("JSON文件") { Patterns = s_jsonPatterns },
                new Avalonia.Platform.Storage.FilePickerFileType("所有文件") { Patterns = s_allPatterns }
            }
        });
        return files.Count > 0 ? files[0].Path.LocalPath : null;
    }

    /// <summary>
    /// 节点编辑框失去焦点时结束编辑
    /// </summary>
    private void TreeNodeEditLostFocus(object? sender, RoutedEventArgs e)
    {
        if (sender is TextBox tb && tb.DataContext is DBStruct node)
        {
            node.IsEdit = false;
        }
    }

    /// <summary>
    /// 获取树中选中的节点列表
    /// </summary>
    private List<DBStruct> GetSelectedTreeNodes()
    {
        return DBStructTree.SelectedItems.Cast<DBStruct>().ToList();
    }

    /// <summary>
    /// 为选中节点添加子节点
    /// </summary>
    private void AddSubTreeNodeC(object? sender, RoutedEventArgs e)
    {
        List<DBStruct> nodes = GetSelectedTreeNodes();
        if (nodes.Count == 0)
        {
            _viewModel?.AppConfig?.DataDump.AddDBStructNodeCommand.Execute(null);
            return;
        }
        foreach (DBStruct node in nodes)
        {
            if (node.Type == DBStructType.ColumnName)
            {
                Log.Warning("字段节点不能再添加子节点！");
                continue;
            }
            DBStructType subType = node.Type == DBStructType.DBName ? DBStructType.TableName : DBStructType.ColumnName;
            string subName = node.Type == DBStructType.DBName ? "NewTable" : "NewColumn";
            node.SubItems.Add(new DBStruct { Type = subType, Value = subName, Parent = node, IsEdit = true });
            node.IsExpanded = true;
        }
    }

    /// <summary>
    /// 修改节点（进入编辑模式）
    /// </summary>
    private void EditTreeNodeC(object? sender, RoutedEventArgs e)
    {
        foreach (DBStruct node in GetSelectedTreeNodes())
        {
            node.IsEdit = true;
        }
    }

    /// <summary>
    /// 删除选中的节点
    /// </summary>
    private void DeleteTreeNodeC(object? sender, RoutedEventArgs e)
    {
        List<DBStruct> nodes = GetSelectedTreeNodes();
        if (nodes.Count == 0 || _viewModel == null)
        {
            return;
        }
        foreach (DBStruct node in nodes)
        {
            //删除前取消选中，同步移除数据列
            node.IsSelected = false;
            if (node.Parent != null)
            {
                node.Parent.SubItems.Remove(node);
            }
            else
            {
                _viewModel.AppConfig.DataDump.DBStructItems.Remove(node);
            }
        }
    }

    /// <summary>
    /// 全选子节点
    /// </summary>
    private void SelectAllSubNodeC(object? sender, RoutedEventArgs e)
    {
        foreach (DBStruct node in GetSelectedTreeNodes())
        {
            DataDumpViewModel.SetSubNodesSelected(node, true);
        }
    }

    /// <summary>
    /// 反选子节点
    /// </summary>
    private void ReverseSubNodeC(object? sender, RoutedEventArgs e)
    {
        foreach (DBStruct node in GetSelectedTreeNodes())
        {
            DataDumpViewModel.ReverseSubNodesSelected(node);
        }
    }
}