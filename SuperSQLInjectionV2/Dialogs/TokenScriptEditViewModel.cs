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
/// 动态值脚本编辑弹窗：名称 + 类型（请求抓取/自主生成）+ JS脚本（QuickJS执行）+ 粘贴报文验证执行。
/// 脚本约定 function tamper(input){...}：请求抓取=输入为抓取请求返回的完整HTTP响应报文（响应头+\r\n\r\n+响应体）；
/// 自主生成=输入为主请求报文，返回值即为动态值（API签名等场景）。
/// </summary>
public partial class TokenScriptEditViewModel : ObservableObject, IDialogContext
{
    [ObservableProperty] private string _name = "新动态值脚本";

    /// <summary>脚本类型：0=请求抓取，1=自主生成</summary>
    [ObservableProperty] private int _kind = 0;

    /// <summary>类型选项</summary>
    public string[] KindNames { get; } = ["请求抓取（输入=抓取响应报文）", "自主生成（输入=主请求报文，输出=动态值）"];

    [ObservableProperty] private TextDocument _codeDocument = new TextDocument(DefaultCode(0));

    [ObservableProperty] private string _testInput = DefaultTestResponse;

    /// <summary>测试输入框占位提示（按类型切换）</summary>
    [ObservableProperty] private string _testInputPlaceholder = TestPlaceholderFetch;

    [ObservableProperty] private string _testOutput = "";

    [ObservableProperty] private string _testStatus = "";

    [ObservableProperty] private bool _isTesting;

    /// <summary>弹窗结果：true=保存，false=取消/关闭</summary>
    public bool Confirmed { get; private set; }

    /// <summary>默认脚本模板（JS）：kind=0请求抓取（输入=抓取响应报文），kind=1自主生成（输入=主请求报文，输出=动态值）</summary>
    public static string DefaultCode(int kind = 0)
    {
        return kind == 1 ? DefaultCodeGenerate : DefaultCodeFetch;
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

    /// <summary>类型切换：同步测试数据占位提示；代码/测试数据仍是默认模板未改动时，联动换成新类型模板</summary>
    partial void OnKindChanged(int value)
    {
        TestInputPlaceholder = value == 1 ? TestPlaceholderGenerate : TestPlaceholderFetch;
        var code = CodeDocument?.Text ?? "";
        if (code == DefaultCodeFetch || code == DefaultCodeGenerate || string.IsNullOrWhiteSpace(code))
        {
            CodeDocument = new TextDocument(DefaultCode(value));
        }
        if (TestInput == DefaultTestResponse || TestInput == DefaultTestRequest || string.IsNullOrWhiteSpace(TestInput))
        {
            TestInput = value == 1 ? DefaultTestRequest : DefaultTestResponse;
        }
    }

    /// <summary>从已有模型创建（编辑），为空则新建并填默认模板；presetKind指定新建时的脚本类型（0请求抓取/1自主生成）</summary>
    public static TokenScriptEditViewModel FromModel(ScriptTamperModel? item, int presetKind = 0)
    {
        var vm = new TokenScriptEditViewModel();
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

    /// <summary>把编辑内容写回模型</summary>
    public void ApplyTo(ScriptTamperModel item)
    {
        item.Name = string.IsNullOrWhiteSpace(Name) ? "未命名脚本" : Name;
        item.Kind = Kind;
        item.Code = CodeDocument?.Text ?? "";
    }

    /// <summary>生成新模型</summary>
    public ScriptTamperModel ToModel()
    {
        var item = new ScriptTamperModel { Enable = true };
        ApplyTo(item);
        return item;
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
            var item = new ScriptTamperModel
            {
                Name = Name,
                Code = CodeDocument?.Text ?? "",
                Enable = true
            };
            string input = TestInput ?? "";
            //引擎执行放后台线程（JS脚本可能耗时），避免阻塞弹窗UI
            string output = await Task.Run(() => ScriptTamperEngine.TamperStrict(item, input));
            TestOutput = output;
            TestStatus = "执行成功，动态值结果见下方";
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
