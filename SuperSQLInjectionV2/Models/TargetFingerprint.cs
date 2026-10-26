using System.Security.Cryptography;
using System.Text;

namespace SuperSQLInjectionV2.Models
{
    /// <summary>
    /// 注入目标与请求会话的统一指纹。缓存不能只按host:port隔离，否则同主机不同路径、
    /// 不同报文或不同登录态会共享长度、通道和元数据。
    /// </summary>
    public static class TargetFingerprint
    {
        public static string ForConfig(AppConfig config, string? parameter = null, string? requestTxt = null)
        {
            return Create(config.Host, config.Port, config.IsSSL, requestTxt ?? config.RequestTxt, parameter);
        }

        public static string ForRecord(InjectRecord record, bool isSsl = false)
        {
            string host = record.Target ?? "";
            int port = 0;
            int colon = host.LastIndexOf(':');
            if (colon > 0 && int.TryParse(host[(colon + 1)..], out int parsed))
            {
                port = parsed;
                host = host[..colon];
            }
            return Create(host, port, isSsl || record.IsSSL, record.RequestTxt, record.PName);
        }

        public static string Create(string? host, int port, bool isSsl, string? requestTxt, string? parameter = null)
        {
            string request = requestTxt ?? "";
            string path = ExtractPath(request);
            string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(request)))[..16];
            return $"{(isSsl ? "https" : "http")}://{host}:{port}{path}|{parameter ?? ""}|{hash}";
        }

        private static string ExtractPath(string requestTxt)
        {
            try
            {
                string firstLine = requestTxt.Split('\n', 2)[0].TrimEnd('\r');
                string[] parts = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) return "/";
                string target = parts[1];
                if (Uri.TryCreate(target, UriKind.Absolute, out Uri? absolute)) return absolute.PathAndQuery;
                return target.StartsWith('/') ? target : "/" + target;
            }
            catch
            {
                return "/";
            }
        }
    }
}
