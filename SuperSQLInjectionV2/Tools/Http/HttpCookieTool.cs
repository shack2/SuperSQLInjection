using SuperSQLInjectionV2.Models;
using System.Net;
using System.Text.RegularExpressions;

namespace SuperSQLInjectionV2.Tools.Http
{
    /// <summary>按AppConfig隔离的可选Cookie会话罐；显式Cookie头中的同名项优先于服务端会话值。</summary>
    internal static class HttpCookieTool
    {
        public static void Apply(AppConfig config, HttpRequest request)
        {
            if (!config.CookieJarEnabled) return;
            try
            {
                Uri uri = BuildUri(request);
                string stored;
                lock (config.CookieJarSync) stored = config.CookieJar.GetCookieHeader(uri);
                if (string.IsNullOrWhiteSpace(stored)) return;

                var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (string pair in stored.Split(';', StringSplitOptions.RemoveEmptyEntries))
                {
                    int eq = pair.IndexOf('=', StringComparison.Ordinal);
                    if (eq > 0) values[pair[..eq].Trim()] = pair[(eq + 1)..].Trim();
                }
                string text = request.HeaderAndBody;
                Match existing = Regex.Match(text, "(?im)^Cookie:[^\r\n]*");
                if (existing.Success)
                {
                    string original = existing.Value[(existing.Value.IndexOf(':') + 1)..];
                    foreach (string pair in original.Split(';', StringSplitOptions.RemoveEmptyEntries))
                    {
                        int eq = pair.IndexOf('=', StringComparison.Ordinal);
                        if (eq > 0) values[pair[..eq].Trim()] = pair[(eq + 1)..].Trim();
                    }
                }
                string merged = "Cookie: " + string.Join("; ", values.Select(kv => kv.Key + "=" + kv.Value));
                if (existing.Success)
                {
                    request.HeaderAndBody = text.Remove(existing.Index, existing.Length).Insert(existing.Index, merged);
                }
                else
                {
                    int headEnd = text.IndexOf(HttpConst.CTRL, StringComparison.Ordinal);
                    if (headEnd > 0) request.HeaderAndBody = text.Insert(headEnd, "\r\n" + merged);
                }
            }
            catch (Exception ex)
            {
                Log.SysLog("Cookie会话应用失败（保持原报文）：" + ex.Message);
            }
        }

        public static void Store(AppConfig config, HttpRequest request, HttpResponse response)
        {
            if (!config.CookieJarEnabled || string.IsNullOrEmpty(response.HeaderTxt)) return;
            try
            {
                Uri uri = BuildUri(request);
                lock (config.CookieJarSync)
                {
                    foreach (string line in response.HeaderTxt.Split("\r\n", StringSplitOptions.None))
                    {
                        if (!line.StartsWith("Set-Cookie:", StringComparison.OrdinalIgnoreCase)) continue;
                        string cookie = line[(line.IndexOf(':') + 1)..].Trim();
                        if (cookie.Length > 0)
                        {
                            try { config.CookieJar.SetCookies(uri, cookie); }
                            catch (CookieException ex) { Log.SysLog("忽略无效Set-Cookie：" + ex.Message); }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.SysLog("Cookie会话保存失败：" + ex.Message);
            }
        }

        private static Uri BuildUri(HttpRequest request)
        {
            string path = string.IsNullOrWhiteSpace(request.PathAndQuery) ? "/" : request.PathAndQuery;
            return new Uri($"{(request.IsSSL ? "https" : "http")}://{request.Host}:{request.Port}{path}");
        }
    }
}
