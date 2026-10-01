using AvaloniaEdit.Document;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Irihi.Avalonia.Shared.Contracts;
using SuperSQLInjectionV2.Bypass;
using SuperSQLInjectionV2.Models;
using System;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Dialogs;

/// <summary>
/// 脚本编辑弹窗（脚本库统一编辑入口）：名称 + 用途（Payload变换/报文变换/响应提取/值生成）+ JS脚本（QuickJS执行）+ 粘贴测试数据验证执行。
/// 脚本约定 function tamper(input){...}：Payload变换=输入为Encode块内payload；报文变换=输入为整份HTTP报文；
/// 响应提取=输入为抓取请求返回的完整HTTP响应报文（响应头+\r\n\r\n+响应体）；值生成=输入为主请求报文，返回值即为动态值（API签名等场景）。
/// ShowTransformUsages=false 时下拉仅展示动态值两种用途（动态规则弹窗内嵌添加场景）。
/// </summary>
public partial class TokenScriptEditViewModel : ObservableObject, IDialogContext
{
    [ObservableProperty] private string _name = "新脚本";

    /// <summary>脚本用途（ScriptUsage枚举值）：0=Payload变换，1=报文变换，2=响应提取，3=值生成</summary>
    [ObservableProperty] private int _usage = (int)ScriptUsage.ResponseExtract;

    /// <summary>是否展示全部4种用途（脚本库统一添加/编辑=true；动态规则弹窗内嵌添加=false，仅动态值两种）</summary>
    [ObservableProperty] private bool _showTransformUsages = true;

    /// <summary>全部用途选项</summary>
    public static string[] AllUsageNames { get; } =
    [
        "Payload变换（编码链：输入=Encode块内payload）",
        "报文变换（编码链：输入=整份HTTP报文）",
        "响应提取（动态值：输入=抓取响应报文）",
        "值生成（动态值：输入=主请求报文，输出=动态值）"
    ];

    /// <summary>当前可选用途（ShowTransformUsages=false时仅动态值两种）</summary>
    public string[] UsageChoices => ShowTransformUsages ? AllUsageNames : AllUsageNames[2..];

    /// <summary>下拉选中索引（与Usage双向映射：隐藏变换类时索引0/1对应extract/generate）</summary>
    public int UsageIndex
    {
        get => ShowTransformUsages ? Usage : Usage - 2;
        set => Usage = ShowTransformUsages ? value : value + 2;
    }

    /// <summary>旧接口兼容：动态值脚本类型（0=请求抓取 1=自主生成），与Usage互映射</summary>
    public int Kind
    {
        get => ScriptUsages.ToKind((ScriptUsage)Usage);
        set => Usage = value == 1 ? (int)ScriptUsage.ValueGenerate : (int)ScriptUsage.ResponseExtract;
    }

    /// <summary>旧接口兼容：动态值类型选项</summary>
    public string[] KindNames { get; } = ["请求抓取（输入=抓取响应报文）", "自主生成（输入=主请求报文，输出=动态值）"];

    /// <summary>当前用途是否编码链变换类（payload/request）</summary>
    public bool IsTransformUsage => ScriptUsages.IsTransform((ScriptUsage)Usage);

    [ObservableProperty] private TextDocument _codeDocument = new TextDocument(DefaultCodeForUsage((int)ScriptUsage.ResponseExtract));

    [ObservableProperty] private string _testInput = DefaultTestResponse;

    /// <summary>测试输入框占位提示（按用途切换）</summary>
    [ObservableProperty] private string _testInputPlaceholder = TestPlaceholderFetch;

    [ObservableProperty] private string _testOutput = "";

    [ObservableProperty] private string _testStatus = "";

    [ObservableProperty] private bool _isTesting;

    /// <summary>弹窗结果：true=保存，false=取消/关闭</summary>
    public bool Confirmed { get; private set; }

    /// <summary>默认脚本模板（JS，旧接口兼容）：kind=0请求抓取（输入=抓取响应报文），kind=1自主生成（输入=主请求报文，输出=动态值）</summary>
    public static string DefaultCode(int kind = 0)
    {
        return DefaultCodeForUsage(kind == 1 ? (int)ScriptUsage.ValueGenerate : (int)ScriptUsage.ResponseExtract);
    }

    /// <summary>按用途给默认脚本模板</summary>
    public static string DefaultCodeForUsage(int usage)
    {
        return (ScriptUsage)usage switch
        {
            ScriptUsage.PayloadTransform => DefaultCodeFor(ScriptScope.Payload),
            ScriptUsage.RequestTransform => DefaultCodeFor(ScriptScope.Request),
            ScriptUsage.ValueGenerate => DefaultCodeGenerate,
            _ => DefaultCodeFetch
        };
    }

    /// <summary>按作用域给变换类默认模板：Payload级输入为Encode块内payload；报文级输入为整份HTTP报文</summary>
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
    public const string DefaultTestRequestTransform = "GET /t?id=1 HTTP/1.1\r\nHost: target\r\nCookie: a=1\r\n\r\n";

    /// <summary>按用途给默认测试输入</summary>
    public static string DefaultTestInputForUsage(int usage)
    {
        return (ScriptUsage)usage switch
        {
            ScriptUsage.PayloadTransform => DefaultTestPayload,
            ScriptUsage.RequestTransform => DefaultTestRequestTransform,
            ScriptUsage.ValueGenerate => DefaultTestRequest,
            _ => DefaultTestResponse
        };
    }

    /// <summary>按用途给测试输入占位提示</summary>
    public static string PlaceholderForUsage(int usage)
    {
        return (ScriptUsage)usage switch
        {
            ScriptUsage.PayloadTransform => "粘贴payload文本（Encode块内payload）",
            ScriptUsage.RequestTransform => "粘贴整份HTTP报文（请求行+请求头+空行+请求体）",
            ScriptUsage.ValueGenerate => TestPlaceholderGenerate,
            _ => TestPlaceholderFetch
        };
    }

    /// <summary>请求抓取模板：从抓取请求返回的完整HTTP响应报文中提取动态值</summary>
    public const string DefaultCodeFetch = "// 请求抓取：输入为抓取请求返回的完整HTTP响应报文（响应头+空行+响应体）\n"
        + "// 返回从响应中提取的动态值字符串\n"
        + "function tamper(response){\n"
        + "    // 示例：从响应体中提取 token 字段\n"
        + "    var m = response.match(/token[\"']?\\s*[:=]\\s*[\"']?([0-9a-zA-Z]+)/);\n"
        + "    return m ? m[1] : '';\n"
        + "}";

    /// <summary>自主生成模板：输入为主请求报文，返回动态值（API签名/时间戳等场景）</summary>
    public const string DefaultCodeGenerate = "// 自主生成：输入为主请求报文（请求行+请求头+空行+请求体）\n"
        + "// 返回动态值字符串，回填主请求的 <DRule> 标记（API签名/时间戳/随机数等场景）\n"
        + "function tamper(request){\n"
        + "    // 示例1：时间戳动态值\n"
        + "    // return String(Date.now());\n"
        + "    // 示例2：取主请求参数参与计算（如API签名）\n"
        + "    var m = request.match(/[?&]id=([^&\\s]+)/);\n"
        + "    var id = m ? m[1] : '';\n"
        + "    return 'sig-' + id + '-' + Date.now();\n"
        + "}";

    /// <summary>默认测试输入（请求抓取：完整HTTP响应报文样例）</summary>
    public const string DefaultTestResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nSet-Cookie: token=abc123; Path=/\r\n\r\n<html><body>token=abc123</body></html>";

    /// <summary>默认测试输入（自主生成：主请求报文样例）</summary>
    public const string DefaultTestRequest = "GET /api/list?id=1&sign=<DRule>sign<DRule> HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";

    public const string TestPlaceholderFetch = "粘贴抓取请求返回的完整HTTP响应报文（响应头+空行+响应体）";
    public const string TestPlaceholderGenerate = "粘贴主请求报文（请求行+请求头+空行+请求体）";

    private static bool IsAnyDefaultCode(string code)
    {
        return code == DefaultCodeFetch || code == DefaultCodeGenerate
            || code == DefaultCodeFor(ScriptScope.Payload)
            || code == DefaultCodeFor(ScriptScope.Request);
    }

    private static bool IsAnyDefaultTestInput(string input)
    {
        return input == DefaultTestResponse || input == DefaultTestRequest
            || input == DefaultTestPayload || input == DefaultTestRequestTransform;
    }

    /// <summary>用途切换：同步测试数据占位提示；代码/测试数据仍是默认模板未改动时，联动换成新用途模板</summary>
    partial void OnUsageChanged(int value)
    {
        TestInputPlaceholder = PlaceholderForUsage(value);
        var code = CodeDocument?.Text ?? "";
        if (string.IsNullOrWhiteSpace(code) || IsAnyDefaultCode(code))
        {
            CodeDocument = new TextDocument(DefaultCodeForUsage(value));
        }
        if (string.IsNullOrWhiteSpace(TestInput) || IsAnyDefaultTestInput(TestInput))
        {
            TestInput = DefaultTestInputForUsage(value);
        }
        OnPropertyChanged(nameof(UsageIndex));
        OnPropertyChanged(nameof(Kind));
        OnPropertyChanged(nameof(IsTransformUsage));
    }

    partial void OnShowTransformUsagesChanged(bool value)
    {
        OnPropertyChanged(nameof(UsageChoices));
        OnPropertyChanged(nameof(UsageIndex));
    }

    /// <summary>从已有模型创建（编辑），为空则新建并填默认模板；presetKind指定新建时的脚本类型（0请求抓取/1自主生成）。仅动态值用途（动态规则弹窗内嵌添加场景）</summary>
    public static TokenScriptEditViewModel FromModel(ScriptTamperModel? item, int presetKind = 0)
    {
        var vm = new TokenScriptEditViewModel { ShowTransformUsages = false };
        if (item != null)
        {
            vm.Name = item.Name;
            vm.Kind = item.Kind;
            vm.CodeDocument = new TextDocument(item.Code ?? "");
        }
        else
        {
            vm.Kind = presetKind;
        }
        return vm;
    }

    /// <summary>脚本库统一添加：全部4种用途可选（payload/request保存为编码链自定义节点，extract/generate保存为动态值脚本）</summary>
    public static TokenScriptEditViewModel FromUsage(ScriptTamperModel? item, ScriptUsage preset = ScriptUsage.ResponseExtract)
    {
        var vm = new TokenScriptEditViewModel { ShowTransformUsages = true };
        if (item != null)
        {
            vm.Name = item.Name;
            vm.Kind = item.Kind;
            vm.CodeDocument = new TextDocument(item.Code ?? "");
        }
        else
        {
            vm.Usage = (int)preset;
        }
        return vm;
    }

    /// <summary>脚本库行编辑（编码链变换节点）：全部4种用途可选并选中当前用途；名称/用途/代码以模型（磁盘脚本物化）为准</summary>
    public static TokenScriptEditViewModel FromEncodeTool(EncodeToolModel item)
    {
        var vm = new TokenScriptEditViewModel { ShowTransformUsages = true };
        vm.Usage = (int)ScriptUsages.FromScope(item.Scope); //先设用途（联动模板/测试数据），再覆盖回真实代码
        vm.Name = item.Name;
        vm.CodeDocument = new TextDocument(item.Code ?? "");
        vm.TestInput = DefaultTestInputForUsage(vm.Usage);
        return vm;
    }

    /// <summary>把编辑内容写回编码链节点（代码随模型落盘 scripts/&lt;key&gt;.js，即时生效）</summary>
    public void ApplyToEncodeTool(EncodeToolModel item)
    {
        item.Name = string.IsNullOrWhiteSpace(Name) ? "未命名脚本" : Name;
        item.Scope = ScriptUsages.ToScope((ScriptUsage)Usage);
        item.Code = CodeDocument?.Text ?? "";
    }

    /// <summary>把编辑内容写回模型</summary>
    public void ApplyTo(ScriptTamperModel item)
    {
        item.Name = string.IsNullOrWhiteSpace(Name) ? "未命名脚本" : Name;
        item.Kind = Kind;
        item.Code = CodeDocument?.Text ?? "";
    }

    /// <summary>生成新模型（动态值脚本，extract/generate用途时调用）</summary>
    public ScriptTamperModel ToModel()
    {
        var item = new ScriptTamperModel { Enable = true };
        ApplyTo(item);
        return item;
    }

    /// <summary>生成编码链自定义节点（payload/request用途时调用；默认不启用，需在编码处理页开启入链）</summary>
    public EncodeToolModel ToEncodeTool()
    {
        return new EncodeToolModel
        {
            Name = string.IsNullOrWhiteSpace(Name) ? "未命名脚本" : Name,
            Scope = ScriptUsages.ToScope((ScriptUsage)Usage),
            Code = CodeDocument?.Text ?? "",
            Enable = false
        };
    }

    /// <summary>验证执行：以测试输入（响应报文）跑一遍tamper函数，展示提取结果或异常</summary>
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
            //按用途构造执行项：变换类走编码链节点视图，动态值类走动态值脚本视图
            ITamperItem item = IsTransformUsage
                ? new EncodeToolModel
                {
                    Name = Name,
                    Scope = ScriptUsages.ToScope((ScriptUsage)Usage),
                    Code = CodeDocument?.Text ?? "",
                    Enable = true
                }
                : new ScriptTamperModel
                {
                    Name = Name,
                    Code = CodeDocument?.Text ?? "",
                    Enable = true
                };
            string input = TestInput ?? "";
            //引擎执行放后台线程（JS脚本可能耗时），避免阻塞弹窗UI；计时反馈脚本实际执行耗时（毫秒）
            var sw = System.Diagnostics.Stopwatch.StartNew();
            string output = await Task.Run(() => ScriptTamperEngine.TamperStrict(item, input));
            sw.Stop();
            TestOutput = output;
            TestStatus = $"执行成功（耗时 {sw.ElapsedMilliseconds} 毫秒），结果见下方";
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
        if (string.IsNullOrWhiteSpace(CodeDocument?.Text))
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
