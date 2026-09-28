using Avalonia.Threading;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Models.Data;
using SuperSQLInjectionV2.Payload;
using SuperSQLInjectionV2.Tools;
using SuperSQLInjectionV2.Tools.Inject;
using SuperSQLInjectionV2.ViewModels;
using SuperSQLInjectionV2.ViewModels.Tools;

/// <summary>
/// GUI取数链路无头集成测试：与界面操作完全同路径——
/// 检测 → 恢复Union/盲注记录 → DataDumpViewModel（消息+Dispatcher）→ DBStructTools取库/表/列 → 勾选列 → DataTools取行数据，
/// 断言树节点/DataGrid行真实落库。harness的DataComm直测跳过消息与Dispatcher层，本测试补齐这段GUI专属链路。
/// </summary>
static class GuiFlowTest
{
    private static int _pass, _fail;

    private static void Check(bool ok, string name, string actual = "")
    {
        Console.WriteLine($"  [{name}] {(ok ? "PASS" : "FAIL")} {actual}");
        if (ok) _pass++; else _fail++;
    }

    private static void Pump()
    {
        //工作线程上冲刷UI队列：排一个空动作等它执行完，之前的Post全部落地（主线程在Run里持续RunJobs，不会死锁）
        Dispatcher.UIThread.InvokeAsync( ()=> { }).GetAwaiter().GetResult();
    }

    public static async Task Run()
    {
        XshdSnapshot.SetupHeadless();
        //AppConfig内含AvaloniaEdit TextDocument（线程亲和UI线程），必须在主线程（=UI线程）创建
        var config = new AppConfig();
        //检测/取数链路会向UI线程Post界面更新；主线程必须持续泵消息，不能死在顶层await上
        var work = Task.Run( ()=> RunInner(config));
        while (!work.IsCompleted)
        {
            Dispatcher.UIThread.RunJobs();
            Thread.Sleep(20);
        }
        await work;
    }

    /// <summary>UI线程写请求报文（TextDocument线程亲和）</summary>
    private static void SetRequest(AppConfig config, string text)
    {
        Dispatcher.UIThread.InvokeAsync( ()=> config.TxtRequest.Text = text).GetAwaiter().GetResult();
    }

    private static async Task RunInner(AppConfig config)
    {
        Log.Sink = new LogTools { NotificationManager = null, TxtLog = null!, AppConfig = config };
        config.Host = "127.0.0.1";
        config.Port = int.TryParse(Environment.GetEnvironmentVariable("SQLI_TARGET_PORT"), out int p) ? p : 8090;
        config.IsSSL = false;
        config.TimeOut = 15;
        config.DataConfig.DetectLevel = 1;
        config.DataConfig.DetectRisk = 1;

        string requestTxt =
            "GET /JVApp/mysql.jsp?id=1 HTTP/1.1\r\n" +
            $"Host: 127.0.0.1:{config.Port}\r\n" +
            "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
            "Accept: */*\r\n" +
            "Connection: close\r\n\r\n";

        // ---------- 1. 注入检测 ----------
        List<InjectPoint> hits = await InjectDetectEngine.DetectParam(config, requestTxt, "id", "1", ParamPlace.Query, "") ?? new List<InjectPoint>();
        Console.WriteLine($"[guiflow] 检测命中 {hits.Count} 个注入点");
        var union = hits.FirstOrDefault(h => h.InjectType == InjectType.Union);
        var blind = hits.FirstOrDefault(h => h.InjectType == InjectType.Blind);
        Check(union != null, "检出Union通道");
        Check(blind != null, "检出Bool盲注通道");
        if (union == null || blind == null)
        {
            Console.WriteLine($"===== guiflow结果: PASS={_pass} FAIL={_fail} =====");
            return;
        }

        // ---------- 2. Union通道：模拟GUI恢复注入记录 ----------
        SetRequest(config, union.RequestTxt); //TextChanged同步RequestTxt镜像
        config.DataConfig.SelectedDBType = DBType.MySQL;
        config.DataConfig.SelectedInjectType = InjectType.Union;
        config.DataConfig.SumColumnCount = union.SumColumnCount;
        config.DataConfig.ShowColumnIndex = union.ShowColumnIndex;
        PayloadFactory.Init(DBType.MySQL);
        Check(config.RequestTxt.Contains("$sql$"), "RequestTxt镜像含注入标记");
        Check(config.DataConfig.SumColumnCount > 0 && config.DataConfig.ShowColumnIndex > 0,
            $"Union列数/显示位  cols={config.DataConfig.SumColumnCount} show={config.DataConfig.ShowColumnIndex}");

        var dump = config.DataDump;

        // ---------- 3. 获取库（GUI"获取库"按钮同路径） ----------
        await DBStructTools.GetDBSByUnion(config);
        Pump();
        Check(dump.DBStructItems.Count > 0, "Union获取库", $"count={dump.DBStructItems.Count}");
        Check(dump.DBStructItems.Any(x => x.Value.Equals("information_schema", StringComparison.OrdinalIgnoreCase)), "库列表含information_schema");

        // ---------- 4. 勾选全部库 → 获取表 ----------
        foreach (var node in dump.DBStructItems) node.IsSelected = true;
        Pump();
        await DBStructTools.GetTablesByUnion(config);
        Pump();
        var newsTable = dump.DBStructItems.SelectMany(x => x.SubItems).FirstOrDefault(t => t.Value.Equals("news", StringComparison.OrdinalIgnoreCase));
        Check(newsTable != null, "Union获取表含news", newsTable == null ? "" : $"parent={newsTable.Parent?.Value}");

        // ---------- 5. 勾选news表 → 获取列 ----------
        DBStruct? newsDb = newsTable?.Parent;
        foreach (var node in dump.DBStructItems) node.IsSelected = false;
        Pump();
        if (newsDb != null && newsTable != null)
        {
            newsTable.IsSelected = true; //级联选中父库
        }
        Pump();
        await DBStructTools.GetColumnsByUnion(config);
        Pump();
        Check(newsTable != null && newsTable.SubItems.Count > 0, "Union获取列", $"count={newsTable?.SubItems.Count ?? 0} cols={string.Join(",", newsTable?.SubItems.Select(c => c.Value) ?? Array.Empty<string>())}");

        // ---------- 6. 勾选列（触发AddColumnMsg→DataGrid列） → 取行数据 ----------
        if (newsTable != null)
        {
            foreach (var col in newsTable.SubItems) col.IsSelected = true;
        }
        Pump();
        Check(dump.Columns.Count > 0, "DataGrid列同步", $"columns={string.Join(",", dump.Columns.Select(c => c.Header))}");
        Check(string.Equals(dump.TableName, "news", StringComparison.OrdinalIgnoreCase), "VM表名上下文", dump.TableName);

        dump.DumpCount = 2;
        dump.DataDumpStart = 0;
        var tools = new DataTools(newsDb?.Value ?? "", "news", dump.Columns.Select(c => c.Header).ToList());
        await tools.GetDataUnion(config);
        Pump();
        Check(dump.Rows.Count == 2, "Union行数据行数", $"rows={dump.Rows.Count}");
        string row0 = dump.Rows.Count > 0 ? string.Join("|", dump.Columns.Select(c => dump.Rows[0][c.PropertyName])) : "";
        Console.WriteLine($"  [guiflow] Union首行: {row0}");
        Check(dump.Rows.Count > 0 && dump.Columns.Any(c => !string.IsNullOrEmpty(dump.Rows[0][c.PropertyName])), "Union行数据非空", row0);

        // ---------- 7. Bool盲注通道：恢复盲注记录取1行1列 ----------
        SetRequest(config, blind.RequestTxt);
        config.DataConfig.SelectedInjectType = InjectType.Blind;
        config.DataConfig.SelectBoolInject = blind.BoolInjectType;
        config.DataConfig.CheckValue = blind.CheckValue;
        config.DataConfig.Reverse = blind.Revers;
        Console.WriteLine($"[guiflow] 盲注记录: type={blind.BoolInjectType} check='{blind.CheckValue}' revers={blind.Revers}");
        Check(config.RequestTxt.Contains("$sql$"), "盲注RequestTxt镜像含注入标记");
        dump.DumpCount = 1;
        dump.DataDumpStart = 0;
        var blindTools = new DataTools(newsDb?.Value ?? "", "news", new List<string> { "id" });
        await blindTools.GetDataByBool(config);
        Pump();
        string blindVal = dump.Rows.Count > 0 ? dump.Rows[^1]["id"] : "";
        Check(blindVal == "1", "Bool盲注行数据(id首行=1)", $"val='{blindVal}'");

        Console.WriteLine($"===== guiflow结果: PASS={_pass} FAIL={_fail} =====");
    }
}
