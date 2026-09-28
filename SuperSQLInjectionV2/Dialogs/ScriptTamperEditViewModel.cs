using AvaloniaEdit.Document;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Irihi.Avalonia.Shared.Contracts;
using SuperSQLInjectionV2.Bypass;
using SuperSQLInjectionV2.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Dialogs;

/// <summary>
/// 编码工具编辑弹窗（编码处理/tamper合并后的统一编辑入口）：
/// 名称/作用域/执行次数/代码编辑（AvaloniaEdit代码控件）+ 输入payload验证执行结果。
/// 内置项（Builtin=true）：代码区只读展示功能描述，可改名称/作用域/执行次数，验证执行走C#内置实现；
/// 自定义项：JS脚本（QuickJS执行，约定 function tamper(payload){...}）。
/// </summary>
public partial class ScriptTamperEditViewModel : ObservableObject, IDialogContext
{
    [ObservableProperty] private string _name = "新编码工具";

    [ObservableProperty] private ScriptScope _scope = ScriptScope.Payload;

    /// <summary>适用位置（Payload级内细分；内置项以注册表为准此处仅展示）</summary>
    [ObservableProperty] private EncodePos _applyPos = EncodePos.Any;

    [ObservableProperty] private int _doCount = 1;

    /// <summary>内置项标识（仅展示用，保存时不动模型的Builtin/Key/Code）</summary>
    [ObservableProperty] private bool _builtin;

    /// <summary>内置项功能描述（代码区只读展示）</summary>
    [ObservableProperty] private string _builtinDescription = "";

    /// <summary>内置项注册表键（编辑时保留，验证执行按Key解析实现）</summary>
    private string _key = "";

    [ObservableProperty] private TextDocument _codeDocument = new TextDocument("");

    [ObservableProperty] private string _testInput = DefaultTestPayload;

    [ObservableProperty] private string _testOutput = "";

    [ObservableProperty] private string _testStatus = "";

    [ObservableProperty] private bool _isTesting;

    public List<ScriptScope> ScopeList { get; } = Enum.GetValues<ScriptScope>().ToList();

    public List<EncodePos> PosList { get; } = Enum.GetValues<EncodePos>().ToList();

    public List<int> DoCountItems { get; } = new List<int> { 1, 2, 3 };

    /// <summary>代码区是否只读（内置项不可编辑）</summary>
    public bool IsCodeReadOnly => Builtin;

    /// <summary>弹窗结果：true=保存，false=取消/关闭</summary>
    public bool Confirmed { get; private set; }

    /// <summary>默认脚本模板（JS，Payload级）</summary>
    public static string DefaultCode()
    {
        return DefaultCodeFor(ScriptScope.Payload);
    }

    /// <summary>按作用域给默认模板：Payload级输入为Encode块内payload；报文级输入为整份HTTP报文</summary>
    public static string DefaultCodeFor(ScriptScope scope)
    {
        if (scope == ScriptScope.Request)
        {
            return "// 报文级：输入为整份HTTP报文（请求行+请求头+请求体），返回改写后的完整报文\n"
                + "function tamper(request){\n"
                + "    // 示例：追加X-Forwarded-For头\n"
                + "    return request.replace('\\r\\n\\r\\n', '\\r\\nX-Forwarded-For: 127.0.0.1\\r\\n\\r\\n');\n"
                + "}";
        }
        return "// Payload级：输入为Encode块内payload文本，返回变换后的payload\n"
            + "function tamper(payload){\n"
            + "    return payload.replaceAll(' ', '/**/');\n"
            + "}";
    }

    /// <summary>默认测试输入（Payload级）</summary>
    public const string DefaultTestPayload = "and 1=1 union select version()";

    /// <summary>默认测试输入（报文级：完整HTTP报文样例）</summary>
    public const string DefaultTestRequest = "GET /t?id=1 HTTP/1.1\r\nHost: target\r\nCookie: a=1\r\n\r\n";

    /// <summary>当前是否Payload级（报文级恒执行1次，执行次数下拉禁用）</summary>
    public bool IsPayloadScope => Scope == ScriptScope.Payload;

    /// <summary>作用域切换联动：代码/测试输入未被用户改动过（空或仍是任一默认模板）时，自动换成新作用域对应的模板</summary>
    partial void OnScopeChanged(ScriptScope value)
    {
        string cur = CodeDocument?.Text ?? "";
        if (string.IsNullOrWhiteSpace(cur)
            || cur == DefaultCodeFor(ScriptScope.Payload)
            || cur == DefaultCodeFor(ScriptScope.Request))
        {
            CodeDocument = new TextDocument(DefaultCodeFor(value));
        }
        if (string.IsNullOrWhiteSpace(TestInput) || TestInput == DefaultTestPayload || TestInput == DefaultTestRequest)
        {
            TestInput = value == ScriptScope.Request ? DefaultTestRequest : DefaultTestPayload;
        }
        OnPropertyChanged(nameof(IsPayloadScope));
    }

    /// <summary>从已有模型创建（编辑），为空则新建自定义项并填默认模板</summary>
    public static ScriptTamperEditViewModel FromModel(EncodeToolModel? item)
    {
        var vm = new ScriptTamperEditViewModel();
        if (item != null)
        {
            vm.Name = item.Name;
            vm.Scope = item.Scope;
            vm.DoCount = item.DoCount;
            vm.Builtin = item.Builtin;
            vm._key = item.Key ?? "";
            //内置项位置以注册表为准（弹窗展示实际生效值）；自定义项取模型配置
            if (item.Builtin)
            {
                string posKey = !string.IsNullOrEmpty(item.Key) ? item.Key : item.Name;
                vm.ApplyPos = EncodeToolRegistry.TryGet(posKey, out EncodeTool posTool) ? posTool.Pos : EncodePos.Any;
            }
            else
            {
                vm.ApplyPos = item.ApplyPos;
            }
            if (item.Builtin)
            {
                string key = !string.IsNullOrEmpty(item.Key) ? item.Key : item.Name;
                vm.BuiltinDescription = EncodeToolRegistry.TryGet(key, out EncodeTool tool)
                    ? "【内置C#实现】 " + tool.Description + "\r\n\r\n内置工具不可编辑代码；如需自定义改写，请新建自定义工具。"
                    : "【内置C#实现】注册表中未找到对应实现，将按自定义JS项保存。";
                vm.CodeDocument = new TextDocument(vm.BuiltinDescription);
            }
            else
            {
                vm.CodeDocument = new TextDocument(item.Code ?? "");
            }
        }
        else
        {
            vm.CodeDocument = new TextDocument(DefaultCode());
        }
        return vm;
    }

    /// <summary>把编辑内容写回模型（内置项仅更新名称/作用域/执行次数，代码保持空；位置仅自定义项生效）</summary>
    public void ApplyTo(EncodeToolModel item)
    {
        item.Name = string.IsNullOrWhiteSpace(Name) ? "未命名工具" : Name;
        item.Scope = Scope;
        item.DoCount = DoCount;
        if (!item.Builtin)
        {
            item.Code = CodeDocument?.Text ?? "";
            item.ApplyPos = ApplyPos;
        }
    }

    /// <summary>生成新模型（自定义JS项）</summary>
    public EncodeToolModel ToModel()
    {
        var item = new EncodeToolModel();
        ApplyTo(item);
        return item;
    }

    /// <summary>验证执行：以测试输入为payload跑一遍tamper函数，展示输出或异常（内置项走C#实现）</summary>
    [RelayCommand]
    private async Task TestRun()
    {
        if (IsTesting)
        {
            return;
        }
        IsTesting = true;
        TestStatus = "执行中……";
        TestOutput = "";
        try
        {
            var item = new EncodeToolModel
            {
                Name = Name,
                Key = _key,
                Scope = Scope,
                DoCount = DoCount,
                Builtin = Builtin,
                Code = Builtin ? "" : (CodeDocument?.Text ?? ""),
                Enable = true
            };
            string input = TestInput ?? "";
            //引擎执行放后台线程（JS脚本可能耗时），避免阻塞弹窗UI
            string output = await Task.Run( ()=> ScriptTamperEngine.TamperStrict(item, input));
            TestOutput = output;
            TestStatus = Builtin ? "执行成功（内置C#实现）" : "执行成功，耗时正常";
        }
        catch (Exception e)
        {
            TestOutput = "";
            TestStatus = "执行异常：" + e.Message;
        }
        finally
        {
            IsTesting = false;
        }
    }

    [RelayCommand]
    private void Confirm()
    {
        if (!Builtin && string.IsNullOrWhiteSpace(CodeDocument?.Text))
        {
            TestStatus = "脚本内容不能为空！";
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
