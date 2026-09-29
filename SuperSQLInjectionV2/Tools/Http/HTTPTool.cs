using Avalonia.Threading;
using SuperSQLInjection.tools.http;
using SuperSQLInjectionV2.Bypass;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
namespace SuperSQLInjectionV2.Tools.Http
{
    public partial class HTTPTool
    {
        public const string Socks5ProxyType = "Socks5";

        /// <summary>Connection头匹配（每请求调用，源生成替代静态Regex缓存查表）</summary>
        [GeneratedRegex("(?im)^Connection:[^\r\n]*")]
        private static partial Regex ConnectionHeaderRegex();
        /// <summary>Accept-Encoding头匹配</summary>
        [GeneratedRegex("(?im)^Accept-Encoding:[^\r\n]*")]
        private static partial Regex AcceptEncodingHeaderRegex();
        /// <summary>Proxy-Authorization头匹配（防重复注入）</summary>
        [GeneratedRegex("(?im)^Proxy-Authorization:[^\r\n]*")]
        private static partial Regex ProxyAuthorizationHeaderRegex();
        /// <summary>CONNECT响应状态行</summary>
        [GeneratedRegex(@"^HTTP/\d(?:\.\d)?\s+(\d{3})")]
        private static partial Regex ConnectStatusRegex();

        public static HttpResponse sendRequestRetry(HttpRequest request)
        {
            return sendRequestRetry(request, false);
        }

        /// <summary>
        /// 发送请求（带重试），isSubRequest为true时表示Token/二次注入等子请求，不再触发Token替换与二次注入。
        /// 同步入口：委托异步版实现（Task.Run跳到无线程上下文的后台线程，避免UI同步上下文捕获await造成死锁），消除同步/异步双份逻辑（A3）
        /// </summary>
        private static HttpResponse sendRequestRetry(HttpRequest request, bool isSubRequest)
        {
            return Task.Run( ()=> SendRequestRetryAsync(request, isSubRequest), CancellationToken.None).GetAwaiter().GetResult();
        }

        /// <summary>
        /// 异步发送请求（带重试）。全程不阻塞线程：
        /// 频率控制用信号量预约时间槽+Task.Delay，Token/二次注入子请求同样异步
        /// </summary>
        public static Task<HttpResponse> SendRequestRetryAsync(HttpRequest request)
        {
            return SendRequestRetryAsync(request, false);
        }

        /// <summary>
        /// 异步发送请求（带重试），isSubRequest为true时表示Token/二次注入等子请求，不再触发Token替换与二次注入。
        /// internal：BypassPipeline的Token抓取子请求复用此入口
        /// </summary>
        internal static async Task<HttpResponse> SendRequestRetryAsync(HttpRequest request, bool isSubRequest)
        {
            //检查停止信号，一旦停止立即中断所有发包
            request.AppConfig.CheckStop();
            //P0-1：绕过管道一次段（Token→Rand/payload/Encode块→报文级脚本），产物供多轮重试复用
            HttpRequest newRequest = await BypassPipeline.ApplyOnceAsync(request, isSubRequest).ConfigureAwait(false);
            //P4-1：保存绕过处理后的原始报文，每轮重试从此重建，防止随机UA/HPP/chunked等改写层层叠加污染
            string originalHeaderAndBody = newRequest.HeaderAndBody;
            HttpResponse server = new HttpResponse(request.AppConfig);
            server.HttpRequest = newRequest;
            for (int i = 1; i <= request.AppConfig.RetryCount; i++)
            {
                try
                {
                    newRequest.HeaderAndBody = originalHeaderAndBody;
                    //P0-1：绕过管道重试段（限速→随机UA→随机源IP→HPP/参数名混淆/chunked）
                    await BypassPipeline.ApplyPerRetryAsync(newRequest).ConfigureAwait(false);
                    //HTTP认证（auth-type 能力）：Basic preemptive / Digest已缓存挑战时 preemptive
                    HttpAuthTool.ApplyPreemptive(request.AppConfig, newRequest);
                    server = await SendRequestAsync(request.AppConfig, newRequest).ConfigureAwait(false);
                    //Digest挑战-响应：401+WWW-Authenticate时写入认证头原报文重发一次
                    if (server.StatusCode == 401 && HttpAuthTool.TryHandleChallenge(request.AppConfig, newRequest, server))
                    {
                        server = await SendRequestAsync(request.AppConfig, newRequest).ConfigureAwait(false);
                    }
                    if (server.StatusCode == 0)
                    {
                        continue;
                    }
                    //后置伴随请求（二次注入）：请求回显页面并以其响应替代主响应取数。
                    //报文含<Sencond:标记名>指令时按标记名关联规则，否则取第一条启用且已配置的后置规则
                    Models.CompanionRequestConfig? afterRule = null;
                    if (!isSubRequest)
                    {
                        if (!string.IsNullOrEmpty(newRequest.SencondTag))
                        {
                            afterRule = request.AppConfig.FindCompanionRule(1, newRequest.SencondTag);
                            if (afterRule != null && !afterRule.IsConfigured)
                            {
                                Log.SysLog($"标记名[{newRequest.SencondTag}]对应的二次注入规则未配置请求来源（报文/URL）！");
                                afterRule = null;
                            }
                            if (afterRule == null)
                            {
                                Log.SysLog($"未找到标记名[{newRequest.SencondTag}]对应的已启用二次注入规则！请在防护绕过-动态规则页检查规则标记名与启用状态。");
                            }
                        }
                        else
                        {
                            afterRule = request.AppConfig.ActiveCompanionAfter;
                        }
                    }
                    if (afterRule != null)
                    {
                        HttpRequest? sencondRequest = afterRule.BuildRequest(request.AppConfig, "请求二次注入页面");
                        if (sencondRequest != null)
                        {
                            //流内配对：复用本次注入请求实际使用的随机值（多线程安全，不再依赖全局LastRand）
                            sencondRequest.FlowRand = newRequest.FlowRand;
                            HttpResponse sencondResponse = await SendRequestRetryAsync(sencondRequest, true).ConfigureAwait(false);
                            if (sencondResponse.StatusCode == 0)
                            {
                                continue;
                            }
                            server = sencondResponse;
                        }
                    }
                    //响应内容包含重发关键词时，重新发送数据包
                    if (request.AppConfig.FindRetryKey(server.BodyTxt))
                    {
                        Log.SysLog("HTTP响应中发现重发关键词，重新发送数据包！");
                        continue;
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception e)
                {
                    if (LogTools.Headless)
                    {
                        Console.WriteLine("[HTTP异常] " + e.Message);
                    }
                    Log.SysLog("HTTP异常：" + e.Message);
                    continue;
                }
            }
            return server;
        }



        private static Proxy? GetProxy(AppConfig config)
        {
            List<Proxy> list = config.ProxyConfig.ProxyItems.Where(p => p.IsEnabled && p.IsOk).ToList();

            if (list.Count == 0)
            {
                return null;
            }
            if (config.ProxyConfig.SelectProxyType.Equals(ProxyType.Fixed))
            {
                return list.First();
            }
            //随机模式
            return list[Random.Shared.Next(list.Count)];
        }

        /// <summary>
        /// 异步版代理验证：全异步TCP连接/Socks5握手，不占线程池线程（UI批量验证代理时使用）
        /// </summary>
        public static async Task<bool> CheckProxyAsync(AppConfig config, Proxy proxy)
        {
            int timeOut = config.TimeOut * 1000;
            try
            {
                if (Socks5ProxyType.Equals(proxy.proxyType, StringComparison.Ordinal))
                {
                    SocketProxy sp = new SocketProxy();
                    using TcpClient client = await sp.CreatProxySocketAsync(proxy.Host, proxy.Port, timeOut).ConfigureAwait(false);
                    bool isok = await sp.ConnectProxyServerAsync(config.Host, config.Port, client, proxy.username, proxy.password, config.TimeOut).ConfigureAwait(false);
                    proxy.UseTime = sp.ConectProxyUseTime;
                    return isok;
                }
                else
                {
                    //HTTP代理，V2采用直接替换IP和端口的方式发包，验证TCP连通即可
                    long ts = Stopwatch.GetTimestamp();
                    try
                    {
                        using TcpClient client = new TcpClient();
                        using CancellationTokenSource cts = new CancellationTokenSource(timeOut);
                        await client.ConnectAsync(proxy.Host, proxy.Port, cts.Token).ConfigureAwait(false);
                        proxy.UseTime = (int)Stopwatch.GetElapsedTime(ts).TotalMilliseconds;
                        return client.Connected;
                    }
                    catch
                    {
                        return false;
                    }
                }
            }
            catch (Exception e)
            {
                Log.SysLog("验证代理" + proxy.Host + ":" + proxy.Port + "发生异常！" + e.Message);
                return false;
            }
        }



        /// <summary>响应头终止符\r\n\r\n</summary>
        private static readonly byte[] HeaderTerminator = { (byte)'\r', (byte)'\n', (byte)'\r', (byte)'\n' };

        /// <summary>
        /// 异步发送入口（供异步调用链直接使用）
        /// </summary>
        public static async Task<HttpResponse> SendRequestAsync(AppConfig config, HttpRequest request)
        {
            CancellationToken ct = config.RunCts?.Token ?? CancellationToken.None;
            return await SendWithRedirectAsync(config, request, ct).ConfigureAwait(false);
        }

        /// <summary>
        /// 302/301跳转的发送（递归改迭代，限次数，防跳转链栈溢出）
        /// </summary>
        private static async Task<HttpResponse> SendWithRedirectAsync(AppConfig config, HttpRequest request, CancellationToken ct)
        {
            for (int redirectCount = 0; ; redirectCount++)
            {
                HttpResponse response = await SendOnceAsync(config, request, ct).ConfigureAwait(false);
                if ((response.StatusCode == 302 || response.StatusCode == 301) && config.FollowRedirect
                    && redirectCount < 5
                    && response.Headers.TryGetValue("location", out string? location)
                    && !string.IsNullOrEmpty(location))
                {
                    if (ApplyRedirect(request, location))
                    {
                        Log.SysLog("跟随跳转到：" + location);
                        continue;
                    }
                }
                return response;
            }
        }

        /// <summary>
        /// 应用跳转：改写请求地址，跨域时更新Host/Port/SSL与Host头，POST转GET并丢弃body
        /// </summary>
        private static bool ApplyRedirect(HttpRequest request, string location)
        {
            try
            {
                string hab = request.HeaderAndBody;
                string newPath;
                if (location.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                {
                    Uri u = new Uri(location);
                    newPath = string.IsNullOrEmpty(u.PathAndQuery) ? "/" : u.PathAndQuery;
                    request.Host = u.Host;
                    request.Port = u.Port;
                    request.IsSSL = u.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);
                    //先改Host头（长度变化），再算请求行位置
                    hab = Regex.Replace(hab, "(?im)^Host:[^\r\n]*", "Host: " + u.Host + (u.IsDefaultPort ? "" : ":" + u.Port));
                }
                else
                {
                    int qs = hab.IndexOf(' ', StringComparison.Ordinal);
                    int qe = hab.IndexOf(" HTTP", StringComparison.Ordinal);
                    string oldPath = (qs > 0 && qe > qs) ? hab.Substring(qs + 1, qe - qs - 1) : "/";
                    newPath = location.StartsWith('/') ? location : RequestRewriter.GetCurrentPath(oldPath) + location;
                }
                newPath = newPath.Replace(" ", "%20", StringComparison.Ordinal);

                int urlStart = hab.IndexOf(' ', StringComparison.Ordinal) + 1;
                int urlEnd = hab.IndexOf(" HTTP", StringComparison.Ordinal);
                if (urlStart <= 0 || urlEnd <= urlStart) return false;
                StringBuilder rsb = new StringBuilder(hab);
                rsb.Remove(urlStart, urlEnd - urlStart);
                rsb.Insert(urlStart, newPath);
                string newReq = rsb.ToString();
                if (newReq.StartsWith("POST", StringComparison.Ordinal))
                {
                    newReq = string.Concat("GET", newReq.AsSpan(4));
                    newReq = Regex.Replace(newReq, "(?im)^Content-Length:.*\r\n", "");
                    newReq = Regex.Replace(newReq, "(?im)^Content-Type:.*\r\n", "");
                    int bsep = newReq.IndexOf(HttpConst.CTRL, StringComparison.Ordinal);
                    if (bsep > 0)
                    {
                        newReq = newReq.Substring(0, bsep + HttpConst.CTRL.Length);
                    }
                }
                request.HeaderAndBody = newReq;
                return true;
            }
            catch (Exception e)
            {
                Log.SysLog("跳转地址解析异常：" + e.Message);
                return false;
            }
        }

        /// <summary>
        /// TLS协商协议链：None由系统协商（默认TLS1.2/1.3）；失败兜底TLS1.0/1.1/1.2兼容老网站
        /// 注：SSLv3/.NET不再支持，极老站点需系统层组件；TLS1.0/1.1需操作系统支持（Windows注册表）
        /// </summary>
#pragma warning disable SYSLIB0039 // TLS1.0/1.1 仅为兼容极老目标的回退选项，默认链首选 None（OS 默认）
        private static readonly SslProtocols[] TlsFallbackChain = { SslProtocols.None, SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls };
#pragma warning restore SYSLIB0039

        /// <summary>
        /// 建立连接（含代理），SSL按协议链重试：握手失败重建TCP再用老协议
        /// </summary>
        private static async Task<PooledConnection> ConnectAsync(AppConfig config, HttpRequest request, Proxy? cproxy, string poolKey, int timeOutMs, CancellationToken ct)
        {
            Exception? lastError = null;
            int attempts = request.IsSSL ? TlsFallbackChain.Length : 1;
            for (int i = 0; i < attempts; i++)
            {
                TcpClient? client = null;
                try
                {
                    client = await ConnectTcpAsync(config, request, cproxy, timeOutMs, ct).ConfigureAwait(false);
                    Stream stream = client.GetStream();
                    if (!request.IsSSL)
                    {
                        return new PooledConnection { Client = client, Stream = stream, Key = poolKey };
                    }
                    SslProtocols protocol = TlsFallbackChain[i];
                    //证书校验回调只能挂一处：SslClientAuthenticationOptions已带，构造函数再传会抛ArgumentException
                    SslStream ssl = new SslStream(stream, false);
                    SslClientAuthenticationOptions opts = new SslClientAuthenticationOptions
                    {
                        TargetHost = request.Host,
                        EnabledSslProtocols = protocol,
                        RemoteCertificateValidationCallback = (s, c, ch, e) => true
                    };
                    using CancellationTokenSource sslCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    sslCts.CancelAfter(timeOutMs);
                    await ssl.AuthenticateAsClientAsync(opts, sslCts.Token).ConfigureAwait(false);
                    return new PooledConnection { Client = client, Stream = ssl, Key = poolKey };
                }
                catch (Exception e) when (!ct.IsCancellationRequested)
                {
                    lastError = e;
                    try { client?.Close(); } catch { }
                    if (request.IsSSL && i < attempts - 1)
                    {
                        Log.SysLog("TLS握手失败（" + TlsFallbackChain[i] + "），重建连接尝试兼容老协议：" + e.Message);
                    }
                }
            }
            Log.SysLog("主机：" + request.Host + ":" + request.Port + "无法连接！");
            throw lastError ?? new Exception("连接失败");
        }

        /// <summary>
        /// 建立TCP连接：直连/HTTP代理连代理地址/Socks5完整握手；ConnectAsync原生支持取消，淘汰TimeOutSocket
        /// </summary>
        private static async Task<TcpClient> ConnectTcpAsync(AppConfig config, HttpRequest request, Proxy? cproxy, int timeOutMs, CancellationToken ct)
        {
            if (cproxy != null && Socks5ProxyType.Equals(cproxy.proxyType, StringComparison.Ordinal))
            {
                //全异步握手：原生await ConnectAsync + 异步流读写，不再Task.Run包同步方法空占线程池线程
                SocketProxy sp = new SocketProxy();
                TcpClient? client = await sp.CreatProxySocketAsync(cproxy.Host, cproxy.Port, timeOutMs, ct).ConfigureAwait(false);
                if (client == null)
                {
                    throw new Exception("Socks5代理" + cproxy.Host + ":" + cproxy.Port + "连接失败");
                }
                bool isok = await sp.ConnectProxyServerAsync(request.Host, request.Port, client, cproxy.username, cproxy.password, config.TimeOut, ct).ConfigureAwait(false);
                if (!isok)
                {
                    client.Close();
                    throw new Exception("Socks5代理" + cproxy.Host + ":" + cproxy.Port + "握手失败");
                }
                return client;
            }
            //HTTP代理：直连代理IP端口；HTTPS目标先CONNECT建隧道（之后由ConnectAsync在隧道上TLS握手），
            //HTTP目标不改连接，由SendOnceAsync发absolute-form请求行（对齐RFC7231）
            string host = cproxy?.Host ?? request.Host;
            int port = cproxy?.Port ?? request.Port;
            TcpClient tcp = new TcpClient();
            using CancellationTokenSource connCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connCts.CancelAfter(timeOutMs);
            try
            {
                await tcp.ConnectAsync(host, port, connCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                tcp.Close();
                throw new TimeoutException("连接" + host + ":" + port + "超时（" + timeOutMs + "ms）");
            }
            catch
            {
                tcp.Close();
                throw;
            }
            if (cproxy != null && request.IsSSL)
            {
                try
                {
                    await HttpProxyConnectTunnelAsync(tcp, request, cproxy, timeOutMs, ct).ConfigureAwait(false);
                }
                catch
                {
                    tcp.Close();
                    throw;
                }
            }
            return tcp;
        }

        /// <summary>
        /// HTTP代理CONNECT隧道握手：发CONNECT host:port，期望代理返回200。
        /// 带代理凭据时附加Proxy-Authorization: Basic。HttpStreamReader.Dispose不碰底层流，握手后流可继续用于TLS
        /// </summary>
        private static async Task HttpProxyConnectTunnelAsync(TcpClient tcp, HttpRequest request, Proxy cproxy, int timeOutMs, CancellationToken ct)
        {
            StringBuilder sb = new StringBuilder(128);
            sb.Append("CONNECT ").Append(request.Host).Append(':').Append(request.Port).Append(" HTTP/1.1\r\n");
            sb.Append("Host: ").Append(request.Host).Append(':').Append(request.Port).Append("\r\n");
            if (!string.IsNullOrEmpty(cproxy.username))
            {
                string cred = Convert.ToBase64String(Encoding.UTF8.GetBytes(cproxy.username + ":" + cproxy.password));
                sb.Append("Proxy-Authorization: Basic ").Append(cred).Append("\r\n");
            }
            sb.Append("Proxy-Connection: keep-alive\r\n\r\n");
            Stream stream = tcp.GetStream();
            await stream.WriteAsync(Encoding.ASCII.GetBytes(sb.ToString()), ct).ConfigureAwait(false);
            using CancellationTokenSource readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            readCts.CancelAfter(timeOutMs);
            using HttpStreamReader reader = new HttpStreamReader(stream);
            byte[] head;
            try
            {
                head = await reader.ReadUntilAsync(HeaderTerminator, readCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                throw new TimeoutException("HTTP代理" + cproxy.Host + ":" + cproxy.Port + " CONNECT响应超时");
            }
            string headTxt = Encoding.ASCII.GetString(head);
            Match m = ConnectStatusRegex().Match(headTxt);
            if (!m.Success)
            {
                throw new Exception("HTTP代理" + cproxy.Host + ":" + cproxy.Port + " CONNECT返回无效响应");
            }
            if (m.Groups[1].Value != "200")
            {
                throw new Exception("HTTP代理" + cproxy.Host + ":" + cproxy.Port + " CONNECT被拒绝（code " + m.Groups[1].Value + "）");
            }
        }

        /// <summary>
        /// HTTP代理下的报文改写：HTTPS走CONNECT隧道后报文保持origin-form；
        /// HTTP目标改absolute-form请求行（GET http://host[:port]/path HTTP/1.1），带凭据时补Proxy-Authorization头
        /// </summary>
        private static void ApplyHttpProxyForm(HttpRequest request, Proxy cproxy)
        {
            if (!string.IsNullOrEmpty(cproxy.username))
            {
                string cred = Convert.ToBase64String(Encoding.UTF8.GetBytes(cproxy.username + ":" + cproxy.password));
                string txt = request.HeaderAndBody;
                if (!ProxyAuthorizationHeaderRegex().IsMatch(txt))
                {
                    int lineEnd = txt.IndexOf(HttpConst.CT, StringComparison.Ordinal);
                    if (lineEnd > 0)
                    {
                        request.HeaderAndBody = txt.Insert(lineEnd, "\r\nProxy-Authorization: Basic " + cred);
                    }
                }
            }
            if (request.IsSSL)
            {
                return; //隧道内TLS，报文保持origin-form
            }
            string hab = request.HeaderAndBody;
            int end = hab.IndexOf(HttpConst.CT, StringComparison.Ordinal);
            if (end <= 0)
            {
                return;
            }
            string requestLine = hab.Substring(0, end);
            int sp1 = requestLine.IndexOf(' ', StringComparison.Ordinal);
            int sp2 = requestLine.LastIndexOf(' ');
            if (sp1 <= 0 || sp2 <= sp1)
            {
                return;
            }
            string path = requestLine.Substring(sp1 + 1, sp2 - sp1 - 1);
            if (path.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || path.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                return; //已是absolute-form
            }
            string authority = request.Host + (request.Port == 80 ? "" : ":" + request.Port);
            string newLine = string.Concat(requestLine.AsSpan(0, sp1 + 1), "http://" + authority,
                             path.StartsWith('/') ? path : "/" + path, requestLine.AsSpan(sp2));
            request.HeaderAndBody = string.Concat(newLine, hab.AsSpan(end));
        }

        /// <summary>
        /// 池化前提：请求头统一声明Connection: keep-alive
        /// </summary>
        private static void EnsureKeepAlive(HttpRequest request)
        {
            string txt = request.HeaderAndBody;
            //注意：在默认规则下会匹配\r，必须用 [^\r\n]* 否则吃掉行尾 \r 导致头体分隔符被破坏
            if (ConnectionHeaderRegex().IsMatch(txt))
            {
                request.HeaderAndBody = ConnectionHeaderRegex().Replace(txt, "Connection: keep-alive");
            }
            else
            {
                int headEnd = txt.IndexOf(HttpConst.CTRL, StringComparison.Ordinal);
                if (headEnd > 0)
                {
                    request.HeaderAndBody = txt.Insert(headEnd, "\r\nConnection: keep-alive");
                }
            }
            EnsureAcceptEncoding(request);
        }

        /// <summary>
        /// P1①：Accept-Encoding能力对齐——粘贴的浏览器报文常声明 zstd 等本工具解不了的编码，
        /// 服务端真返回时BodyTxt变二进制乱码、检测/取数静默失败。发包前统一重写为当前解码能力集（gzip/deflate/br）。
        /// 仅在该头存在时重写，不主动新增（部分WAF对缺失/新增头敏感）。
        /// </summary>
        private static void EnsureAcceptEncoding(HttpRequest request)
        {
            string txt = request.HeaderAndBody;
            Match m = AcceptEncodingHeaderRegex().Match(txt);
            if (!m.Success)
            {
                return;
            }
            //已是对齐值则跳过（避免每请求字符串重建）
            if (m.Value.Equals("Accept-Encoding: gzip, deflate, br", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
            request.HeaderAndBody = txt.Remove(m.Index, m.Length).Insert(m.Index, "Accept-Encoding: gzip, deflate, br");
        }

        /// <summary>
        /// 单次HTTP事务：连接池租用/新建 -> 异步写请求 -> 缓冲读header -> 按CL/chunked/close读body -> 归还或丢弃连接
        /// </summary>
        private static async Task<HttpResponse> SendOnceAsync(AppConfig config, HttpRequest request, CancellationToken ct)
        {
            HttpResponse response = new HttpResponse(config) { HttpRequest = request };
            //统一换行符（兼容LF-only粘贴报文）
            request.HeaderAndBody = request.HeaderAndBody.Replace(HttpConst.CT, HttpConst.ST, StringComparison.Ordinal).Replace(HttpConst.ST, HttpConst.CT, StringComparison.Ordinal);
            string index = Interlocked.Increment(ref config.RequestTmpCount).ToString();
            long startTs = Stopwatch.GetTimestamp();
            int timeOutMs = config.TimeOut * 1000;
            PooledConnection? conn = null;
            bool reusable = false;
            //本请求实际使用的代理（ip:port），空=直连；写入请求日志与控制台HTTP日志
            string proxyInfo = "";
            MemoryStream bodyData = new MemoryStream();
            try
            {
                if (request.Port <= 0 || request.Port > 65535)
                {
                    return response;
                }
                //代理选择
                Proxy? cproxy = null;
                if (config.ProxyConfig.ProxyEnable)
                {
                    cproxy = GetProxy(config);
                    proxyInfo = cproxy == null ? "" : cproxy.Host + ":" + cproxy.Port;
                    string proxyText = cproxy == null ? "无可用代理，直连" : proxyInfo;
                    //T2：代理状态文本值变化才刷UI（盲注高频发包不再每请求Post一次）
                    if (config.ProxyConfig.CurrentProxyText != proxyText)
                    {
                        Dispatcher.UIThread.Post( ()=> config.ProxyConfig.CurrentProxyText = proxyText);
                    }
                }
                string poolKey = cproxy == null
                    ? request.PoolKeySuffix
                    : $"px:{cproxy.proxyType}:{cproxy.Host}:{cproxy.Port}->{request.PoolKeySuffix}";

                //信号量槽位制：租不到时排队等归还（线程数>池大小不再新建-丢弃造成握手风暴）
                bool dbgHttp = Environment.GetEnvironmentVariable("SQLI_DEBUG_HTTP") == "1";
                long tsRent = Stopwatch.GetTimestamp();
                conn = await HttpConnectionPool.RentAsync(poolKey, ct).ConfigureAwait(false);
                long tsRented = Stopwatch.GetTimestamp();
                bool newConn = conn == null;
                if (conn == null)
                {
                    try
                    {
                        conn = await ConnectAsync(config, request, cproxy, poolKey, timeOutMs, ct).ConfigureAwait(false);
                        HttpConnectionPool.AttachSlot(conn);
                    }
                    catch
                    {
                        //新建失败必须释放已占槽位，否则后续请求永久排队
                        HttpConnectionPool.ReleaseSlot(poolKey);
                        throw;
                    }
                }
                if (dbgHttp)
                {
                    Console.WriteLine($"[HTTP-T] rent={Stopwatch.GetElapsedTime(tsRent, tsRented).TotalMilliseconds:F0}ms new={newConn} connect={Stopwatch.GetElapsedTime(tsRented).TotalMilliseconds:F0}ms");
                }
                //NTLM连接级认证：未认证连接先发Type1/Type3握手（同一连接），认证成功后标记并复用
                if (HttpAuthTool.IsNtlm(config) && !conn.NtlmAuthenticated)
                {
                    bool ntlmOk = await HttpAuthTool.HandshakeNtlmAsync(config, request, conn, timeOutMs, ct).ConfigureAwait(false);
                    if (!ntlmOk)
                    {
                        HttpConnectionPool.Discard(conn);
                        conn = null;
                        Log.SysLog("NTLM认证握手失败（凭据错误或服务器拒绝NTLMv1）！");
                        return response;
                    }
                    conn.NtlmAuthenticated = true;
                }
                EnsureKeepAlive(request);
                //HTTP代理（非Socks5）：HTTP目标改absolute-form请求行/补Proxy-Authorization；HTTPS目标CONNECT隧道已建好，报文不动
                if (cproxy != null && !Socks5ProxyType.Equals(cproxy.proxyType, StringComparison.Ordinal))
                {
                    ApplyHttpProxyForm(request, cproxy);
                }
                byte[] sendBytes = Encoding.UTF8.GetBytes(request.HeaderAndBody);
                long tsWrite = Stopwatch.GetTimestamp();
                await conn.Stream.WriteAsync(sendBytes, ct).ConfigureAwait(false);
                long tsWrote = Stopwatch.GetTimestamp();

                //读取超时预算 = 总超时 - 已耗时（P0-3修复：不再出现负值SendTimeout）
                using CancellationTokenSource readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                int remain = timeOutMs - (int)Stopwatch.GetElapsedTime(startTs).TotalMilliseconds;
                readCts.CancelAfter(Math.Max(1000, remain));
                CancellationToken rct = readCts.Token;

                using HttpStreamReader reader = new HttpStreamReader(conn.Stream);
                //缓冲读header（替代逐字节ReadByte；over-read字节留给body）
                byte[] headBytes;
                try
                {
                    headBytes = await reader.ReadUntilAsync(HeaderTerminator, rct).ConfigureAwait(false);
                    if (dbgHttp)
                    {
                        long rh = (long)Stopwatch.GetElapsedTime(tsWrote).TotalMilliseconds;
                        Console.WriteLine($"[HTTP-T] write={Stopwatch.GetElapsedTime(tsWrite, tsWrote).TotalMilliseconds:F0}ms readHead={rh}ms headLen={headBytes.Length}");
                        if (rh > 1000)
                        {
                            Console.WriteLine("[HTTP-T] 慢请求原始报文<<<" + (request.HeaderAndBody ?? "") + ">>>");
                            Console.WriteLine("[HTTP-T] 慢响应头<<<" + Encoding.ASCII.GetString(headBytes) + ">>>");
                        }
                    }
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    //读header超时：返回未完成响应（StatusCode=0触发上层重试）
                    return response;
                }
                if (headBytes.Length < HeaderTerminator.Length)
                {
                    throw new IOException("对端关闭连接或未返回有效HTTP响应头");
                }
                response.HeaderTxt = Encoding.ASCII.GetString(headBytes);
                if (response.StatusCode > 501 && response.StatusCode < 505)
                {
                    throw new Exception("http访问异常-code:" + response.StatusCode + "！");
                }

                //按响应头读取body
                bool responseClose = response.Headers.TryGetValue(HttpConst.Connection, out string? connHeader)
                                     && connHeader.Contains("close", StringComparison.OrdinalIgnoreCase);
                bool zeroLength = response.HeaderTxt.Contains(HttpConst.Content_Length_Zero, StringComparison.Ordinal);
                bool hasContentLength = response.Headers.ContainsKey(HttpConst.Content_Length) && !zeroLength;
                //NullBody空体模式（null-connection 能力）：取数时按注入记录判断类型自动置单请求hint
                //（长度类/状态码/时间判断只看响应头），body字节不消费（JudgeLength取Content-Length头比对）；
                //连接残留body不可复用，直接丢弃。不做全局开关：检测阶段相似度比对必须读全文
                bool nullConn = request.NullBodyHint && hasContentLength;
                try
                {
                    if (nullConn)
                    {
                        reusable = false;
                    }
                    else if (hasContentLength)
                    {
                        long got = await reader.ReadExactAsync(bodyData, response.ContentLength, rct).ConfigureAwait(false);
                        reusable = got >= response.ContentLength && !responseClose;
                    }
                    else if (response.Headers.ContainsKey(HttpConst.Transfer_Encoding))
                    {
                        reusable = await ReadChunkedAsync(reader, bodyData, rct).ConfigureAwait(false) && !responseClose;
                    }
                    else if (zeroLength || response.StatusCode == 204 || response.StatusCode == 304)
                    {
                        reusable = !responseClose; //无body
                    }
                    else
                    {
                        //connection close模式：读到EOF，连接不可复用
                        await reader.ReadToEndAsync(bodyData, rct).ConfigureAwait(false);
                        reusable = false;
                    }
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    //读body超时：返回已读部分，连接不可复用
                    reusable = false;
                }
                response.BodyData = bodyData;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw; //用户停止信号，向上传播中断整个任务
            }
            catch (Exception e)
            {
                throw new Exception("HTTPS发包错误！错误消息：" + e.Message + "----发包编号：" + index);
            }
            finally
            {
                response.RunTime = (long)Stopwatch.GetElapsedTime(startTs).TotalMilliseconds;
                if (conn != null)
                {
                    if (reusable)
                    {
                        HttpConnectionPool.Return(conn);
                    }
                    else
                    {
                        HttpConnectionPool.Discard(conn);
                    }
                }

                if (config.IsOpenHTTPLog)
                {
                    if (LogTools.Headless)
                    {
                        // 无UI模式：HTTP日志直接输出到控制台
                        string firstLine = (request.HeaderAndBody ?? "").Split("\r\n")[0];
                        Console.WriteLine("[HTTP] " + response.StatusCode + " " + response.RunTime + "ms payload=[" + request.Payload + "] " + firstLine + (proxyInfo.Length > 0 ? " [代理:" + proxyInfo + "]" : ""));
                        // SQLI_DEBUG_REQ=1 时输出注入相关头/体，便于排查Cookie/Header/JSON位置注入
                        if (Environment.GetEnvironmentVariable("SQLI_DEBUG_REQ") == "1")
                        {
                            foreach (string line in (request.HeaderAndBody ?? "").Split("\r\n"))
                            {
                                if (line.StartsWith("Cookie:", StringComparison.OrdinalIgnoreCase)
                                    || line.StartsWith("User-Agent:", StringComparison.OrdinalIgnoreCase)
                                    || line.StartsWith("Referer:", StringComparison.OrdinalIgnoreCase))
                                {
                                    Console.WriteLine("[HTTP-DBG] " + line);
                                }
                            }
                            string hab = request.HeaderAndBody ?? "";
                            int bodyIdx = hab.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                            if (bodyIdx > 0 && hab.Length > bodyIdx + 4)
                            {
                                Console.WriteLine("[HTTP-DBG] Body: " + hab[(bodyIdx + 4)..]);
                            }
                        }
                    }
                    else
                    {
                        RequestLog requestLog = new RequestLog(request, response);
                        requestLog.index = index;
                        requestLog.UseTime = response.RunTime;
                        requestLog.Payload = request.Payload;
                        requestLog.Proxy = proxyInfo.Length > 0 ? proxyInfo : "直连";

                        Dispatcher.UIThread.Post( ()=>
                        {
                            config.RequestCount = config.RequestTmpCount;
                            //P2：环形缓冲——超限剔最旧（防长dump内存无限涨），优先级Normal（原MaxValue会在高频下发包时饿死渲染）
                            System.Collections.ObjectModel.ObservableCollection<RequestLog> items = config.RequestLog.Items;
                            while (items.Count >= RequestLogModel.MaxItems)
                            {
                                items.RemoveAt(0);
                            }
                            items.Add(requestLog);

                        }, DispatcherPriority.Normal);
                    }
                }
            }
            return response;
        }

        /// <summary>
        /// 读取chunked编码body（缓冲读取替代逐字节），完整读到块结束返回true（连接可复用）
        /// </summary>
        private static async Task<bool> ReadChunkedAsync(HttpStreamReader reader, MemoryStream dst, CancellationToken ct)
        {
            while (true)
            {
                string? sizeLine = await reader.ReadLineAsync(ct).ConfigureAwait(false);
                if (sizeLine == null) return false;
                if (sizeLine.Length == 0) continue; //容忍多余空行?
                int semi = sizeLine.IndexOf(';', StringComparison.Ordinal);
                if (semi >= 0)
                {
                    sizeLine = sizeLine.Substring(0, semi); //剥离chunk扩展
                }
                if (!int.TryParse(sizeLine, System.Globalization.NumberStyles.HexNumber, null, out int chunkSize))
                {
                    return false;
                }
                if (chunkSize == 0)
                {
                    //读掉trailer直到空行
                    while (true)
                    {
                        string? trailer = await reader.ReadLineAsync(ct).ConfigureAwait(false);
                        if (string.IsNullOrEmpty(trailer)) break;
                    }
                    return true;
                }
                long got = await reader.ReadExactAsync(dst, chunkSize, ct).ConfigureAwait(false);
                if (got < chunkSize) return false;
                //读掉块尾\r\n
                string? end = await reader.ReadLineAsync(ct).ConfigureAwait(false);
                if (end == null) return false;
            }
        }

        

        
    }
}