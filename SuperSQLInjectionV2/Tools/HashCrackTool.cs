using SuperSQLInjectionV2.Models;
using System;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Tools
{
    /// <summary>
    /// Hash在线解密引擎：独立 HttpClient 直连解密API站点（UseProxy=false，不走注入代理池/系统代理——
    /// 解密接口与注入目标无关，注入代理故障不应误伤解密查询）。
    /// URL/POST数据中 {hash} 占位符替换为urlencoded后的hash；配置令牌预取正则时先对同URL发GET
    /// 提取令牌替换 {token} 再正式查询（cmd5类ASP.NET VIEWSTATE两步站点，Cookie自动携带）；
    /// 提取正则命名组 (?&lt;result&gt;) 优先，无则取第1组，再退整段匹配；空匹配视为未收录。
    /// 多接口轮询由调用方编排（命中即停）。
    /// </summary>
    public static class HashCrackTool
    {
        /// <summary>共享直连客户端（静态复用避免TIME_WAIT堆积；CookieContainer支撑VIEWSTATE两步站点的会话保持）</summary>
        private static readonly HttpClient s_client = CreateClient();

        private static HttpClient CreateClient()
        {
            var client = new HttpClient(new HttpClientHandler { UseProxy = false, CookieContainer = new CookieContainer() });
            client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36");
            return client;
        }

        /// <summary>单接口查询结果</summary>
        public sealed record CrackReply(string ApiName, bool Found, string Text, long CostMs, string? Error);

        /// <summary>用指定接口查询hash明文；Found=true 时 Text 为解密结果，否则 Error 为失败原因</summary>
        public static async Task<CrackReply> QueryOneAsync(AppConfig config, HashApiConfig api, string hash)
        {
            long ts = Stopwatch.GetTimestamp();
            try
            {
                if (string.IsNullOrWhiteSpace(api.Regex))
                {
                    return new CrackReply(api.Name, false, "", Cost(ts), "未配置提取正则");
                }
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(Math.Max(5, config.TimeOut)));

                string enc = Uri.EscapeDataString(hash.Trim());
                string url = (api.Url ?? "").Replace(HashApiConfig.HashPlaceholder, enc).Trim();
                if (url.Length == 0)
                {
                    return new CrackReply(api.Name, false, "", Cost(ts), "接口URL为空");
                }
                if (!url.Contains("://", StringComparison.Ordinal))
                {
                    url = "http://" + url;
                }

                //令牌预取（可选）：先GET同URL提取令牌（VIEWSTATE等），替换 {token}
                string encToken = "";
                if (!string.IsNullOrWhiteSpace(api.TokenRegex))
                {
                    string tokenPage = await GetAsync(url, cts.Token).ConfigureAwait(false);
                    Match tm = Regex.Match(tokenPage, api.TokenRegex, RegexOptions.Singleline, TimeSpan.FromSeconds(5));
                    string token = !tm.Success ? "" :
                        tm.Groups["result"].Success ? tm.Groups["result"].Value :
                        tm.Groups.Count > 1 ? tm.Groups[1].Value : tm.Value;
                    if (token.Length == 0)
                    {
                        return new CrackReply(api.Name, false, "", Cost(ts), "令牌预取失败（页面结构可能已变，请检查令牌正则）");
                    }
                    encToken = Uri.EscapeDataString(token);
                    url = url.Replace(HashApiConfig.TokenPlaceholder, encToken);
                }

                if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? uri))
                {
                    return new CrackReply(api.Name, false, "", Cost(ts), "接口URL无效");
                }

                string body;
                if ("POST".Equals(api.Method, StringComparison.OrdinalIgnoreCase))
                {
                    string postData = (api.PostData ?? "").Replace(HashApiConfig.HashPlaceholder, enc)
                                                           .Replace(HashApiConfig.TokenPlaceholder, encToken);
                    string contentType = string.IsNullOrWhiteSpace(api.PostContentType)
                        ? "application/x-www-form-urlencoded" : api.PostContentType.Trim();
                    //StringContent(mediaType)不含charset时默认补utf-8，与浏览器表单行为一致
                    string mediaType = contentType.Split(';')[0].Trim();
                    using var content = new StringContent(postData, Encoding.UTF8, mediaType);
                    using var req = new HttpRequestMessage(HttpMethod.Post, uri) { Content = content };
                    //表单站普遍校验Referer（cmd5无Referer直接回首页导致提取不到结果）
                    req.Headers.TryAddWithoutValidation("Referer", url);
                    HttpResponseMessage resp = await s_client.SendAsync(req, cts.Token).ConfigureAwait(false);
                    body = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
                }
                else
                {
                    body = await GetAsync(url, cts.Token).ConfigureAwait(false);
                }

                Match m = Regex.Match(body, api.Regex, RegexOptions.Singleline | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(5));
                string val = !m.Success ? "" :
                    m.Groups["result"].Success ? m.Groups["result"].Value :
                    m.Groups.Count > 1 ? m.Groups[1].Value : m.Value;
                val = WebUtility.HtmlDecode(val).Trim();
                if (val.Length == 0)
                {
                    //短响应原文带进提示（CMD5-ERROR:-22 这类错误码直接可见，不再只报"未收录"）
                    string snippet = body.Trim().Replace("\r", " ").Replace("\n", " ");
                    string hint = snippet.Length > 0 && snippet.Length <= 200
                        ? "：" + (snippet.Length > 80 ? snippet[..80] + "…" : snippet) : "";
                    return new CrackReply(api.Name, false, "", Cost(ts), "未匹配到明文（可能未收录）" + hint);
                }
                return new CrackReply(api.Name, true, val, Cost(ts), null);
            }
            catch (OperationCanceledException)
            {
                return new CrackReply(api.Name, false, "", Cost(ts), "请求超时");
            }
            catch (HttpRequestException e)
            {
                return new CrackReply(api.Name, false, "", Cost(ts), "连接失败：" + e.Message);
            }
            catch (RegexMatchTimeoutException)
            {
                return new CrackReply(api.Name, false, "", Cost(ts), "提取正则执行超时");
            }
            catch (Exception e)
            {
                return new CrackReply(api.Name, false, "", Cost(ts), e.Message);
            }
        }

        /// <summary>GET并读响应文本（令牌预取与GET查询共用）</summary>
        private static async Task<string> GetAsync(string url, CancellationToken ct)
        {
            HttpResponseMessage resp = await s_client.GetAsync(url, ct).ConfigureAwait(false);
            return await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        }

        private static long Cost(long ts) => (long)Stopwatch.GetElapsedTime(ts).TotalMilliseconds;
    }
}
