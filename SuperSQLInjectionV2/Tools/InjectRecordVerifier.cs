using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Models.Data;
using SuperSQLInjectionV2.Tools.Http;
using SuperSQLInjectionV2.Tools.Inject;
using System.Globalization;

namespace SuperSQLInjectionV2.Tools;

/// <summary>重放注入记录保存的检出证据，不修改取数通道配置。</summary>
public static class InjectRecordVerifier
{
    public static async Task<(bool Passed, string Detail)> VerifyAsync(AppConfig config, InjectRecord record)
    {
        using var payloadScope = Payload.PayloadFactory.Activate(config);
        if (string.IsNullOrWhiteSpace(record.TrueRequestTxt))
        {
            return (false, "该记录没有可重放的检出证据（旧记录可重新检测后生成）");
        }
        HttpResponse trueResponse = await HTTPTool.SendRequestRetryAsync(
            new HttpRequest(config, record.TrueRequestTxt)).ConfigureAwait(false);
        if (!trueResponse.IsUsable)
        {
            return (false, "真值证据请求失败或响应不完整");
        }

        switch (record.InjectType)
        {
            case InjectType.Blind:
            {
                if (string.IsNullOrWhiteSpace(record.FalseRequestTxt)) return (false, "缺少假值证据请求");
                HttpResponse falseResponse = await HTTPTool.SendRequestRetryAsync(
                    new HttpRequest(config, record.FalseRequestTxt)).ConfigureAwait(false);
                if (!falseResponse.IsUsable) return (false, "假值证据请求失败或响应不完整");
                bool t = TruthOracle.IsTrue(trueResponse, record.CheckValue, record.Revers, record.BoolInjectType,
                    record.SimilarTemplate, record.SimilarMode, record.SimilarCutoff, record.DynamicFeatures);
                bool f = TruthOracle.IsTrue(falseResponse, record.CheckValue, record.Revers, record.BoolInjectType,
                    record.SimilarTemplate, record.SimilarMode, record.SimilarCutoff, record.DynamicFeatures);
                return (t && !f, $"布尔回放：真值={t}，假值判真={f}（{record.BoolInjectType}={record.CheckValue}）");
            }
            case InjectType.Time:
            case InjectType.Stacked:
            {
                if (!double.TryParse(record.CheckValue, NumberStyles.Float, CultureInfo.InvariantCulture, out double seconds))
                {
                    seconds = Math.Max(0.5, config.SleepInjectMaxTime);
                }
                long threshold = Math.Max(1, (long)(seconds * 1000) - MyTools.deviation);
                bool delayed = trueResponse.RunTime >= threshold;
                string detail = $"时间回放：延时响应={trueResponse.RunTime}ms，阈值={threshold}ms";
                bool passed = delayed;
                if (!string.IsNullOrWhiteSpace(record.FalseRequestTxt))
                {
                    HttpResponse baseline = await HTTPTool.SendRequestRetryAsync(
                        new HttpRequest(config, record.FalseRequestTxt)).ConfigureAwait(false);
                    bool quick = baseline.IsUsable && baseline.RunTime < threshold;
                    detail += $"，原始对照={baseline.RunTime}ms";
                    passed &= quick;
                }
                return (passed, detail);
            }
            case InjectType.Error:
            {
                string text = (trueResponse.BodyTxt ?? "") + "\n" + trueResponse.HeaderTxt;
                bool found = !string.IsNullOrEmpty(record.EvidenceExpected)
                    && text.Contains(record.EvidenceExpected, StringComparison.OrdinalIgnoreCase);
                return (found, found ? "报错证据按原随机标记精确复现" : "未复现原报错随机标记/预期值");
            }
            case InjectType.Union:
            {
                bool found = string.IsNullOrEmpty(record.EvidenceExpected)
                    ? !InjectTools.IsDbErrorPage(trueResponse.BodyTxt)
                    : (trueResponse.BodyTxt ?? "").Contains(record.EvidenceExpected, StringComparison.Ordinal);
                return (found, $"Union证据回放：列数={record.SumColumnCount}，显示位={record.ShowColumnIndex}，" + (found ? "响应符合检出特征" : "未复现检出特征"));
            }
            case InjectType.Dns:
            {
                if (string.IsNullOrWhiteSpace(record.EvidenceExpected)) return (false, "缺少DNS证据token");
                var tokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { record.EvidenceExpected };
                HashSet<string> hits = await DnsExfilTool.PollDnsLogForTokens(config, tokens, 25).ConfigureAwait(false);
                return (hits.Contains(record.EvidenceExpected), hits.Count > 0 ? "DNSLog再次回收证据token" : "25秒内未回收DNS证据token");
            }
            default:
                return (false, "该注入类型暂不支持证据复核");
        }
    }
}
