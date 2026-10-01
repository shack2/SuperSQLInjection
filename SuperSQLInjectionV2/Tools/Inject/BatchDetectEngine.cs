using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Models.Detect;
using SuperSQLInjectionV2.Source;
using SuperSQLInjectionV2.Tools.Http;

namespace SuperSQLInjectionV2.Tools.Inject
{
    /// <summary>单个目标的批量检测结果</summary>
    public sealed class BatchTargetResult
    {
        public required string Url { get; init; }
        /// <summary>命中点（含目标主机/端口，供写入注入记录）</summary>
        public List<(InjectPoint Point, string Host, int Port)> Hits { get; } = new();
        public string Error { get; set; } = "";
        public TimeSpan Elapsed { get; set; }

        public string TypeSummary => string.Join("/", Hits.Select(h => h.Point.InjectType).Distinct());
        public string DbSummary => string.Join("/", Hits.Select(h => h.Point.DBType).Where(d => d != DBType.UnKnow).Distinct());
    }

    /// <summary>
    /// 批量注入检测引擎：每个目标克隆一份独立配置（JSON深拷贝+规则集合引用共享，检测只读不改），
    /// 用与单目标检测相同的多技术引擎（InjectDetectEngine）逐参数检测；
    /// 日志经 Log.PushScope 挂接前缀Sink（[目标URL]），多目标并发时主日志可区分来源且不弹通知。
    /// 命中点只返回不落地——写入注入记录由调用方在UI线程执行（全局回显标记/注入上下文不随批量命中切换）。
    /// </summary>
    public static class BatchDetectEngine
    {
        /// <summary>URL规整：补全缺失的scheme（默认http），非法URL返回null</summary>
        public static Uri? NormalizeUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
            {
                return null;
            }
            url = url.Trim();
            if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                url = "http://" + url;
            }
            return Uri.TryCreate(url, UriKind.Absolute, out Uri? uri) && !string.IsNullOrEmpty(uri.Host) ? uri : null;
        }

        /// <summary>由URL构造最简GET请求报文（Host/UA/Accept头；Cookie等认证头请在单目标模式用完整报文检测）</summary>
        public static string BuildGetRequestText(Uri uri)
        {
            string path = string.IsNullOrEmpty(uri.PathAndQuery) ? "/" : uri.PathAndQuery;
            string hostHeader = uri.IsDefaultPort ? uri.Host : uri.Host + ":" + uri.Port;
            return "GET " + path + " HTTP/1.1\r\n"
                 + "Host: " + hostHeader + "\r\n"
                 + "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36\r\n"
                 + "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                 + "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n"
                 + "Connection: keep-alive\r\n\r\n";
        }

        /// <summary>
        /// 克隆检测配置：lastconfig同口径JSON深拷贝（界面状态/网络/检测参数），
        /// 规则集合（编码链/字符替换/UA池/动态规则/动态值脚本/代理池）引用共享——检测链路只读消费，快照由BypassPlan自建
        /// </summary>
        public static AppConfig CloneConfigForTarget(AppConfig template, Uri uri)
        {
            string json = JsonSerializer.Serialize(template, JsonCtx.CompactInfo<AppConfig>());
            AppConfig clone = JsonSerializer.Deserialize(json, JsonCtx.CompactInfo<AppConfig>()) ?? new AppConfig();
            clone.ByPassConfig.EncodeTools = template.ByPassConfig.EncodeTools;
            clone.ByPassConfig.ReplaceItems = template.ByPassConfig.ReplaceItems;
            clone.ByPassConfig.UaItemList = template.ByPassConfig.UaItemList;
            clone.TokenScripts = template.TokenScripts;
            clone.CompanionRules = template.CompanionRules;
            clone.ProxyConfig.ProxyItems = template.ProxyConfig.ProxyItems;
            //Url setter联动Host/Port/IsSSL
            clone.Url = uri.AbsoluteUri;
            clone.ResetStop();
            return clone;
        }

        /// <summary>
        /// 检测单个目标：GET参数逐一过检测引擎（跳过Token参数），再按level测扩展位置（JSON/XML/Cookie/头部/URI段）。
        /// 取消信号联动配置的停止标记（引擎内部CheckStop抛OperationCanceledException收敛）。
        /// </summary>
        public static async Task<BatchTargetResult> DetectOne(AppConfig template, string url, string tag, CancellationToken ct)
        {
            var result = new BatchTargetResult { Url = url };
            Uri? uri = NormalizeUrl(url);
            if (uri == null)
            {
                result.Error = "URL格式无效";
                return result;
            }
            var sw = Stopwatch.StartNew();
            //日志前缀用目标URL（原[T序号]无法直观对应目标；并发批量时每行日志可据此归属）
            using (Log.PushScope(new PrefixLogSink("[" + uri.AbsoluteUri + "] ", Log.Sink)))
            {
                try
                {
                    AppConfig config = CloneConfigForTarget(template, uri);
                    Log.Highlight("开始检测目标：" + uri.AbsoluteUri + "（" + tag + "）");
                    using CancellationTokenRegistration reg = ct.Register(config.SignalStop);
                    string requestTxt = BuildGetRequestText(uri);
                    config.RequestTxt = requestTxt;
                    var request = new HttpRequest(config, requestTxt);
                    if (request.Params.Count < 1)
                    {
                        //无查询参数也继续：扩展位置（URI段/头部）仍可能命中
                        Log.SysLog("未发现查询参数，仅检测扩展注入位置（URI段/Cookie/头部）");
                    }

                    bool wafChecked = false;
                    foreach (KeyValuePair<string, string> kv in request.Params)
                    {
                        ct.ThrowIfCancellationRequested();
                        if (ConstData.JumpkeyList.ContainsKey(kv.Key))
                        {
                            Log.SysLog("跳过Token参数检测！" + kv.Key);
                            continue;
                        }
                        if (!wafChecked)
                        {
                            wafChecked = true;
                            await InjectTools.CheckWaf(config, requestTxt, kv.Key, kv.Value).ConfigureAwait(false);
                        }
                        List<InjectPoint> hits = await InjectDetectEngine.DetectParam(config, requestTxt, kv.Key, kv.Value).ConfigureAwait(false);
                        CollectHits(result, hits, config);
                        //检出即停：本目标已检出注入，跳过后续参数与扩展位置，直接下一目标
                        if (hits.Count > 0 && config.DataConfig.DetectStopOnHit)
                        {
                            Log.SysLog("已检出注入点，按「检出即停」设置跳过本目标剩余参数检测！");
                            break;
                        }
                    }

                    //扩展注入位置（与单目标同一枚举：URI段任意level，level>=2 Cookie，level>=3 UA/Referer）
                    int level = Math.Max(1, Math.Min(5, config.DataConfig.DetectLevel));
                    foreach (var t in ParamTargetDiscovery.DiscoverExtended(request, requestTxt, level))
                    {
                        ct.ThrowIfCancellationRequested();
                        //检出即停：主参数已命中则不再检测扩展位置
                        if (result.Hits.Count > 0 && config.DataConfig.DetectStopOnHit)
                        {
                            break;
                        }
                        List<InjectPoint> hits = await InjectDetectEngine.DetectParam(config, requestTxt, t.Name, t.Value, t.Place, t.Header, t.UriIdx).ConfigureAwait(false);
                        CollectHits(result, hits, config);
                        if (hits.Count > 0 && config.DataConfig.DetectStopOnHit)
                        {
                            Log.SysLog("已检出注入点，按「检出即停」设置跳过本目标剩余扩展位置检测！");
                            break;
                        }
                    }

                    Log.Success("目标检测完成：命中 " + result.Hits.Count + " 个注入点，耗时 " + sw.Elapsed.TotalSeconds.ToString("F1") + "s");
                }
                catch (OperationCanceledException)
                {
                    result.Error = "已停止";
                    Log.SysLog("目标检测已停止");
                }
                catch (SuperSQLInjectionV2.Tools.Http.TargetUnreachableException tue)
                {
                    //目标不可达：本目标快速判死，不拖垮整批，继续下一目标
                    result.Error = "目标无法连接";
                    Log.Error("目标不可达，跳过本目标剩余检测：" + tue.Message);
                }
                catch (Exception e)
                {
                    result.Error = e.Message;
                    Log.Error("目标检测异常：" + e.Message);
                }
            }
            result.Elapsed = sw.Elapsed;
            return result;
        }

        private static void CollectHits(BatchTargetResult result, List<InjectPoint> hits, AppConfig config)
        {
            foreach (InjectPoint inp in hits)
            {
                if (inp.IsInject)
                {
                    result.Hits.Add((inp, config.Host, config.Port));
                    Log.Success("发现注入点：" + inp.PName + "（" + inp.InjectType + "，" + inp.DBType + "）");
                }
            }
        }
    }
}
