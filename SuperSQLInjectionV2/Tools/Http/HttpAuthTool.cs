using SuperSQLInjectionV2.Models;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SuperSQLInjectionV2.Tools.Http
{
    /// <summary>
    /// HTTP认证（auth-type 能力/--auth-cred）：
    /// Basic= preemptive Authorization头；Digest=挑战-响应（MD5，401后自动重发并缓存挑战后续 preemptive）；
    /// NTLM=NTLMv1连接级握手（Type1/Type2/Type3在同一连接上完成，认证后的连接归还池复用）。
    /// </summary>
    public static class HttpAuthTool
    {
        public const string TypeBasic = "Basic";
        public const string TypeDigest = "Digest";
        public const string TypeNtlm = "NTLM";

        public static bool IsEnabled(AppConfig config)
        {
            return config != null && !string.IsNullOrWhiteSpace(config.AuthType)
                && !string.IsNullOrEmpty(config.AuthUser);
        }

        /// <summary>
        /// 发包前 preemptive 应用认证头：Basic每次都带；Digest仅已有缓存挑战时带（nc递增）；NTLM走连接级握手不在此处理
        /// </summary>
        public static void ApplyPreemptive(AppConfig config, HttpRequest request)
        {
            if (!IsEnabled(config) || request == null)
            {
                return;
            }
            string type = config.AuthType.Trim();
            if (type.Equals(TypeBasic, StringComparison.OrdinalIgnoreCase))
            {
                SetAuthHeader(request, "Basic " + Convert.ToBase64String(
                    Encoding.UTF8.GetBytes(config.AuthUser + ":" + (config.AuthPass ?? ""))));
            }
            else if (type.Equals(TypeDigest, StringComparison.OrdinalIgnoreCase))
            {
                DigestState st = DigestStates.GetValue(config, _ => new DigestState());
                lock (st)
                {
                    if (st.Realm != null && st.Nonce != null)
                    {
                        SetAuthHeader(request, BuildDigestHeader(config, request, st));
                    }
                }
            }
        }

        /// <summary>
        /// 401挑战处理：Digest命中时缓存挑战并写入认证头，返回true提示调用方原报文重发一次
        /// </summary>
        public static bool TryHandleChallenge(AppConfig config, HttpRequest request, HttpResponse response)
        {
            if (!IsEnabled(config) || request == null || response == null || response.StatusCode != 401)
            {
                return false;
            }
            if (!config.AuthType.Trim().Equals(TypeDigest, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            string? wwwAuth = FindHeader(response.HeaderTxt, "WWW-Authenticate");
            if (string.IsNullOrEmpty(wwwAuth) || !wwwAuth.StartsWith("Digest", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            DigestState st = DigestStates.GetValue(config, _ => new DigestState());
            lock (st)
            {
                st.Realm = DigestParam(wwwAuth, "realm") ?? "";
                st.Nonce = DigestParam(wwwAuth, "nonce") ?? "";
                st.Opaque = DigestParam(wwwAuth, "opaque") ?? "";
                st.Qop = DigestParam(wwwAuth, "qop") ?? "";
                st.Algorithm = DigestParam(wwwAuth, "algorithm") ?? "MD5";
                st.Nc = 0;
                if (st.Nonce == null)
                {
                    return false;
                }
                SetAuthHeader(request, BuildDigestHeader(config, request, st));
            }
            Log.SysLog("HTTP Digest认证：已获取挑战并重发认证请求（realm=" + (st.Realm ?? "") + "）");
            return true;
        }

        //---- Digest（RFC 2617，MD5/MD5-sess，qop=auth）----

        private class DigestState
        {
            public string Realm = "", Nonce = "", Opaque = "", Qop = "", Algorithm = "";
            public int Nc;
        }

        private static readonly ConditionalWeakTable<AppConfig, DigestState> DigestStates = new();

        private static string? DigestParam(string? header, string name)
        {
            Match m = Regex.Match(header ?? "", name + "\\s*=\\s*(\"(?<v>[^\"]*)\"|(?<v>[^,\\s]*))", RegexOptions.IgnoreCase);
            return m.Success ? m.Groups["v"].Value : null;
        }

        private static string BuildDigestHeader(AppConfig config, HttpRequest request, DigestState st)
        {
            string method = request.Method.ToString().ToUpperInvariant();
            string uri = !string.IsNullOrEmpty(request.PathAndQuery) ? request.PathAndQuery
                : (!string.IsNullOrEmpty(request.Path) ? request.Path : "/");
            string user = config.AuthUser ?? "";
            string pass = config.AuthPass ?? "";
            string realm = st.Realm ?? "";
            string ha1 = Md5Hex(user + ":" + realm + ":" + pass);
            if (!string.IsNullOrEmpty(st.Algorithm) && st.Algorithm.Equals("MD5-sess", StringComparison.OrdinalIgnoreCase))
            {
                string cnonce0 = Guid.NewGuid().ToString("N").Substring(0, 16);
                ha1 = Md5Hex(ha1 + ":" + st.Nonce + ":" + cnonce0);
            }
            string ha2 = Md5Hex(method + ":" + uri);
            string response;
            string? qop = null;
            string? cnonce = null;
            string? ncStr = null;
            if (!string.IsNullOrEmpty(st.Qop))
            {
                //qop列表时优先auth
                qop = st.Qop.Split(',').Select(q => q.Trim()).FirstOrDefault(q => q.Equals("auth", StringComparison.OrdinalIgnoreCase))
                      ?? st.Qop.Split(',')[0].Trim();
                st.Nc++;
                ncStr = st.Nc.ToString("x8");
                cnonce = Guid.NewGuid().ToString("N").Substring(0, 16);
                response = Md5Hex(ha1 + ":" + st.Nonce + ":" + ncStr + ":" + cnonce + ":" + qop + ":" + ha2);
            }
            else
            {
                response = Md5Hex(ha1 + ":" + st.Nonce + ":" + ha2);
            }
            StringBuilder sb = new StringBuilder("Digest ");
            sb.Append("username=\"").Append(user).Append("\", ");
            sb.Append("realm=\"").Append(realm).Append("\", ");
            sb.Append("nonce=\"").Append(st.Nonce).Append("\", ");
            sb.Append("uri=\"").Append(uri).Append("\", ");
            sb.Append("response=\"").Append(response).Append('"');
            if (!string.IsNullOrEmpty(st.Opaque))
            {
                sb.Append(", opaque=\"").Append(st.Opaque).Append('"');
            }
            if (!string.IsNullOrEmpty(st.Algorithm))
            {
                sb.Append(", algorithm=").Append(st.Algorithm);
            }
            if (qop != null)
            {
                sb.Append(", qop=").Append(qop).Append(", nc=").Append(ncStr).Append(", cnonce=\"").Append(cnonce).Append('"');
            }
            return sb.ToString();
        }

        private static string Md5Hex(string s)
        {
            byte[] hash = MD5.HashData(Encoding.UTF8.GetBytes(s));
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        //---- 公共：Authorization头写入与响应头查找 ----

        /// <summary>替换或追加Authorization头（追加到头区末尾空行前）</summary>
        public static void SetAuthHeader(HttpRequest request, string value)
        {
            string txt = request.HeaderAndBody;
            if (Regex.IsMatch(txt, "(?im)^Authorization:[^\r\n]*"))
            {
                request.HeaderAndBody = Regex.Replace(txt, "(?im)^Authorization:[^\r\n]*", "Authorization: " + value);
                return;
            }
            int headEnd = txt.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (headEnd > 0)
            {
                request.HeaderAndBody = txt.Insert(headEnd, "\r\nAuthorization: " + value);
            }
        }

        private static string? FindHeader(string headerTxt, string name)
        {
            if (string.IsNullOrEmpty(headerTxt))
            {
                return null;
            }
            Match m = Regex.Match(headerTxt, "(?im)^" + Regex.Escape(name) + "\\s*:\\s*(?<v>[^\r\n]*)");
            return m.Success ? m.Groups["v"].Value.Trim (): null;
        }

        //---- NTLM（NTLMv1：MD4+DES，连接级握手）----

        /// <summary>当前配置是否为NTLM认证</summary>
        public static bool IsNtlm(AppConfig config)
        {
            return IsEnabled(config) && config.AuthType.Trim().Equals(TypeNtlm, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// 在指定连接上执行NTLM握手：Type1请求→401(Type2挑战)→Type3请求→非401即认证成功。
        /// 握手请求复用当前报文的请求行与头（仅替换Authorization），保证Host/路径一致。
        /// </summary>
        public static async Task<bool> HandshakeNtlmAsync(AppConfig config, HttpRequest request, PooledConnection conn, int timeOutMs, CancellationToken ct)
        {
            string type1 = Convert.ToBase64String(BuildType1(config.AuthDomain ?? ""));
            string req1 = WithAuth(request.HeaderAndBody, "NTLM " + type1);
            await conn.Stream.WriteAsync(Encoding.UTF8.GetBytes(req1), ct).ConfigureAwait(false);
            string head1 = await ReadAuthResponseHeadAsync(conn.Stream, timeOutMs, ct).ConfigureAwait(false);
            string? challenge = FindHeader(head1, "WWW-Authenticate");
            if (string.IsNullOrEmpty(challenge) || !challenge.StartsWith("NTLM ", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            byte[] type2;
            try
            {
                type2 = Convert.FromBase64String(challenge.Substring(5).Trim());
            }
            catch
            {
                return false;
            }
            byte[] type3 = BuildType3(config.AuthUser ?? "", config.AuthPass ?? "", config.AuthDomain ?? "", type2);
            string req3 = WithAuth(request.HeaderAndBody, "NTLM " + Convert.ToBase64String(type3));
            await conn.Stream.WriteAsync(Encoding.UTF8.GetBytes(req3), ct).ConfigureAwait(false);
            string head3 = await ReadAuthResponseHeadAsync(conn.Stream, timeOutMs, ct).ConfigureAwait(false);
            //Type3后非401即认证通过（200/302/500等均说明凭据被接受）
            Match sm = Regex.Match(head3 ?? "", "^HTTP/\\d(\\.\\d)?\\s+(?<code>\\d+)");
            return sm.Success && sm.Groups["code"].Value != "401";
        }

        /// <summary>替换报文中的Authorization头（握手子请求用，不改动原HttpRequest对象）</summary>
        private static string WithAuth(string headerAndBody, string value)
        {
            string txt = Regex.IsMatch(headerAndBody, "(?im)^Authorization:[^\r\n]*")
                ? Regex.Replace(headerAndBody, "(?im)^Authorization:[^\r\n]*", "Authorization: " + value)
                : headerAndBody.Insert(headerAndBody.IndexOf("\r\n\r\n", StringComparison.Ordinal) > 0 ? headerAndBody.IndexOf("\r\n\r\n", StringComparison.Ordinal) : headerAndBody.Length, "\r\nAuthorization: " + value);
            return txt;
        }

        private static readonly byte[] HeaderEnd = { (byte)'\r', (byte)'\n', (byte)'\r', (byte)'\n' };

        /// <summary>读取握手响应：响应头+按Content-Length/chunked读掉body（body内容丢弃，仅保证连接可复用）</summary>
        private static async Task<string> ReadAuthResponseHeadAsync(Stream stream, int timeOutMs, CancellationToken ct)
        {
            using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(Math.Max(3000, timeOutMs));
            using HttpStreamReader reader = new HttpStreamReader(stream);
            byte[] headBytes = await reader.ReadUntilAsync(HeaderEnd, cts.Token).ConfigureAwait(false);
            string head = Encoding.ASCII.GetString(headBytes);
            //读掉body保持连接干净
            using MemoryStream body = new MemoryStream();
            string? cl = FindHeader(head, "Content-Length");
            string? te = FindHeader(head, "Transfer-Encoding");
            if (long.TryParse(cl, out long len) && len > 0)
            {
                await reader.ReadExactAsync(body, len, cts.Token).ConfigureAwait(false);
            }
            else if (te != null && te.Contains("chunked", StringComparison.OrdinalIgnoreCase))
            {
                while (true)
                {
                    string? sizeLine = await reader.ReadLineAsync(cts.Token).ConfigureAwait(false);
                    if (sizeLine == null) break;
                    int semi = sizeLine.IndexOf(';', StringComparison.Ordinal);
                    if (semi >= 0) sizeLine = sizeLine.Substring(0, semi);
                    if (!int.TryParse(sizeLine, System.Globalization.NumberStyles.HexNumber, null, out int size)) break;
                    if (size == 0)
                    {
                        while (true)
                        {
                            string? trailer = await reader.ReadLineAsync(cts.Token).ConfigureAwait(false);
                            if (string.IsNullOrEmpty(trailer)) break;
                        }
                        break;
                    }
                    await reader.ReadExactAsync(body, size, cts.Token).ConfigureAwait(false);
                    await reader.ReadLineAsync(cts.Token).ConfigureAwait(false);
                }
            }
            return head;
        }

        /// <summary>NTLM Type1：协商Unicode+OEM+RequestTarget+NTLM，携带域名与工作station（均可空）</summary>
        private static byte[] BuildType1(string domain)
        {
            byte[] domBytes = Encoding.ASCII.GetBytes(domain ?? "");
            byte[] hostBytes = Encoding.ASCII.GetBytes(Environment.MachineName ?? "WORKSTATION");
            const uint flags = 0x00000001 | 0x00000002 | 0x00000004 | 0x00000200 | 0x00002000 | 0x00008000 | 0x02000000;
            using MemoryStream ms = new MemoryStream();
            using BinaryWriter w = new BinaryWriter(ms);
            w.Write(Encoding.ASCII.GetBytes("NTLMSSP\0"));
            w.Write(1u);
            w.Write(flags);
            //domain fields（offset=32+host len）
            w.Write((ushort)domBytes.Length);
            w.Write((ushort)domBytes.Length);
            w.Write(32 + hostBytes.Length);
            //workstation fields（offset=32）
            w.Write((ushort)hostBytes.Length);
            w.Write((ushort)hostBytes.Length);
            w.Write(32);
            w.Write(hostBytes);
            w.Write(domBytes);
            return ms.ToArray();
        }

        /// <summary>NTLM Type3：解析Type2挑战，计算LM/NT响应（NTLMv1）</summary>
        private static byte[] BuildType3(string user, string pass, string domain, byte[] type2)
        {
            if (type2.Length < 32 || Encoding.ASCII.GetString(type2, 0, 8) != "NTLMSSP\0")
            {
                throw new Exception("NTLM Type2消息格式非法");
            }
            byte[] challenge = new byte[8];
            Array.Copy(type2, 24, challenge, 0, 8);
            uint flags = BitConverter.ToUInt32(type2, 20);
            bool unicode = (flags & 0x00000001) != 0;
            Encoding enc = unicode ? Encoding.Unicode : Encoding.ASCII;

            byte[] lmResp = CalcLmResponse(pass, challenge);
            byte[] ntResp = CalcNtResponse(pass, challenge);
            byte[] domBytes = enc.GetBytes((domain ?? "").ToUpperInvariant());
            byte[] userBytes = enc.GetBytes((user ?? "").ToUpperInvariant());
            byte[] hostBytes = enc.GetBytes((Environment.MachineName ?? "WORKSTATION").ToUpperInvariant());

            int offset = 64;
            using MemoryStream ms = new MemoryStream();
            using BinaryWriter w = new BinaryWriter(ms);
            w.Write(Encoding.ASCII.GetBytes("NTLMSSP\0"));
            w.Write(3u);
            //LM response
            w.Write((ushort)lmResp.Length); w.Write((ushort)lmResp.Length); w.Write(offset);
            //NT response
            w.Write((ushort)ntResp.Length); w.Write((ushort)ntResp.Length); w.Write(offset + lmResp.Length);
            //domain
            w.Write((ushort)domBytes.Length); w.Write((ushort)domBytes.Length); w.Write(offset + lmResp.Length + ntResp.Length);
            //user
            w.Write((ushort)userBytes.Length); w.Write((ushort)userBytes.Length); w.Write(offset + lmResp.Length + ntResp.Length + domBytes.Length);
            //workstation
            w.Write((ushort)hostBytes.Length); w.Write((ushort)hostBytes.Length); w.Write(offset + lmResp.Length + ntResp.Length + domBytes.Length + userBytes.Length);
            //session key（空）
            w.Write((ushort)0); w.Write((ushort)0); w.Write(offset + lmResp.Length + ntResp.Length + domBytes.Length + userBytes.Length + hostBytes.Length);
            w.Write(flags);
            w.Write(lmResp); w.Write(ntResp); w.Write(domBytes); w.Write(userBytes); w.Write(hostBytes);
            return ms.ToArray();
        }

        /// <summary>LM响应：LM哈希（DES("KGS!@#$%")）填充21字节后3段DES挑战</summary>
        private static byte[] CalcLmResponse(string pass, byte[] challenge)
        {
            byte[] pw = Encoding.ASCII.GetBytes((pass ?? "").ToUpperInvariant());
            byte[] pw14 = new byte[14];
            Array.Copy(pw, 0, pw14, 0, Math.Min(pw.Length, 14));
            byte[] lmHash = new byte[16];
            byte[] kgs = Encoding.ASCII.GetBytes("KGS!@#$%");
            byte[] half1 = DesEncrypt(CreateDesKey(pw14, 0), kgs);
            byte[] half2 = DesEncrypt(CreateDesKey(pw14, 7), kgs);
            Array.Copy(half1, 0, lmHash, 0, 8);
            Array.Copy(half2, 0, lmHash, 8, 8);
            return ChallengeResponse(lmHash, challenge);
        }

        /// <summary>NT响应：NT哈希（MD4(UTF16LE(pass))）填充21字节后3段DES挑战</summary>
        private static byte[] CalcNtResponse(string pass, byte[] challenge)
        {
            byte[] ntHash = MD4.ComputeHash(Encoding.Unicode.GetBytes(pass ?? ""));
            return ChallengeResponse(ntHash, challenge);
        }

        /// <summary>16字节哈希填0到21字节，切3×7字节扩DES密钥分别加密8字节挑战，拼24字节响应</summary>
        private static byte[] ChallengeResponse(byte[] hash16, byte[] challenge)
        {
            byte[] key21 = new byte[21];
            Array.Copy(hash16, key21, 16);
            byte[] resp = new byte[24];
            for (int i = 0; i < 3; i++)
            {
                byte[] enc = DesEncrypt(CreateDesKey(key21, i * 7), challenge);
                Array.Copy(enc, 0, resp, i * 8, 8);
            }
            return resp;
        }

        /// <summary>7字节扩8字节DES密钥（str_to_key位扩展，奇偶位由DES忽略）</summary>
        private static byte[] CreateDesKey(byte[] src, int offset)
        {
            byte[] key = new byte[8];
            key[0] = (byte)(src[offset] >> 1);
            key[1] = (byte)(((src[offset] & 0x01) << 6) | (src[offset + 1] >> 2));
            key[2] = (byte)(((src[offset + 1] & 0x03) << 5) | (src[offset + 2] >> 3));
            key[3] = (byte)(((src[offset + 2] & 0x07) << 4) | (src[offset + 3] >> 4));
            key[4] = (byte)(((src[offset + 3] & 0x0F) << 3) | (src[offset + 4] >> 5));
            key[5] = (byte)(((src[offset + 4] & 0x1F) << 2) | (src[offset + 5] >> 6));
            key[6] = (byte)(((src[offset + 5] & 0x3F) << 1) | (src[offset + 6] >> 7));
            key[7] = (byte)(src[offset + 6] & 0x7F);
            //左移1位补奇偶位位置（DES规范每字节低7位有效，最高位为奇偶位——此处统一左移并置奇偶）
            for (int i = 0; i < 8; i++)
            {
                key[i] = (byte)(key[i] << 1);
            }
            return key;
        }

        private static byte[] DesEncrypt(byte[] key, byte[] data)
        {
            //.NET内置DES拒绝弱密钥（NTLM的LM/NT哈希派生键常见弱键，如全零段），必须用软件DES实现绕过弱键检查
            return SoftDes.EncryptBlock(key, data);
        }

        /// <summary>
        /// 软件DES单块ECB加密（NTLMv1专用）：.NET内置DES会对弱密钥抛CryptographicException，无法满足NTLM哈希派生键
        /// </summary>
        private static class SoftDes
        {
            private static readonly int[] IP = {
                58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
                62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
                57,49,41,33,25,17,9,1, 59,51,43,35,27,19,11,3,
                61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7 };
            private static readonly int[] FP = {
                40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
                38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
                36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
                34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25 };
            private static readonly int[] E = {
                32,1,2,3,4,5, 4,5,6,7,8,9, 8,9,10,11,12,13, 12,13,14,15,16,17,
                16,17,18,19,20,21, 20,21,22,23,24,25, 24,25,26,27,28,29, 28,29,30,31,32,1 };
            private static readonly int[] P = {
                16,7,20,21,29,12,28,17, 1,15,23,26,5,18,31,10,
                2,8,24,14,32,27,3,9, 19,13,30,6,22,11,4,25 };
            private static readonly int[] PC1 = {
                57,49,41,33,25,17,9, 1,58,50,42,34,26,18,
                10,2,59,51,43,35,27, 19,11,3,60,52,44,36,
                63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
                14,6,61,53,45,37,29, 21,13,5,28,20,12,4 };
            private static readonly int[] PC2 = {
                14,17,11,24,1,5, 3,28,15,6,21,10,
                23,19,12,4,26,8, 16,7,27,20,13,2,
                41,52,31,37,47,55, 30,40,51,45,33,48,
                44,49,39,56,34,53, 46,42,50,36,29,32 };
            private static readonly int[] Shifts = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
            private static readonly byte[,] S = {
                {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8, 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13},
                {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5, 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9},
                {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1, 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12},
                {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9, 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14},
                {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6, 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3},
                {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8, 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13},
                {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6, 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12},
                {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2, 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
            };

            public static byte[] EncryptBlock(byte[] key8, byte[] data8)
            {
                //生成16轮子密钥（每轮48位存于ulong）
                ulong[] sub = new ulong[16];
                ulong k = BytesToUlong(key8);
                //PC1：64→56位（C高28/D低28）
                ulong k56 = Permute(k, PC1, 64);
                uint c = (uint)(k56 >> 28) & 0x0FFFFFFF;
                uint d = (uint)k56 & 0x0FFFFFFF;
                for (int i = 0; i < 16; i++)
                {
                    c = Rol28(c, Shifts[i]);
                    d = Rol28(d, Shifts[i]);
                    ulong cd = ((ulong)c << 28) | d;
                    sub[i] = Permute(cd, PC2, 56);
                }
                //初始置换
                ulong v = Permute(BytesToUlong(data8), IP, 64);
                uint l = (uint)(v >> 32);
                uint r = (uint)v;
                for (int i = 0; i < 16; i++)
                {
                    uint t = r;
                    r = l ^ Feistel(r, sub[i]);
                    l = t;
                }
                //末轮不交换+逆置换
                ulong pre = ((ulong)r << 32) | l;
                return UlongToBytes(Permute(pre, FP, 64));
            }

            private static uint Feistel(uint r, ulong subKey)
            {
                ulong er = Permute(r, E, 32) ^ subKey;
                uint out32 = 0;
                for (int i = 0; i < 8; i++)
                {
                    byte six = (byte)((er >> (42 - i * 6)) & 0x3F);
                    int row = ((six & 0x20) >> 4) | (six & 0x01);
                    int col = (six >> 1) & 0x0F;
                    out32 = (out32 << 4) | S[i, row * 16 + col];
                }
                return (uint)Permute(out32, P, 32);
            }

            /// <summary>通用置换：table为1基位编号（从高位数），srcBits为输入位宽</summary>
            private static ulong Permute(ulong src, int[] table, int srcBits)
            {
                ulong result = 0;
                foreach (int t in table)
                {
                    result = (result << 1) | ((src >> (srcBits - t)) & 1);
                }
                return result;
            }

            private static uint Rol28(uint v, int n)
            {
                return ((v << n) | (v >> (28 - n))) & 0x0FFFFFFF;
            }

            private static ulong BytesToUlong(byte[] b)
            {
                ulong v = 0;
                for (int i = 0; i < 8; i++)
                {
                    v = (v << 8) | b[i];
                }
                return v;
            }

            private static byte[] UlongToBytes(ulong v)
            {
                byte[] b = new byte[8];
                for (int i = 0; i < 8; i++)
                {
                    b[i] = (byte)(v >> (56 - i * 8));
                }
                return b;
            }
        }

        /// <summary>
        /// 托管MD4实现（.NET无内置MD4，NTLMv1的NT哈希所需；RFC 1320）
        /// </summary>
        private static class MD4
        {
            public static byte[] ComputeHash(byte[] input)
            {
                //padding
                int origLen = input.Length;
                int padLen = (56 - (origLen + 1) % 64 + 64) % 64 + 1;
                byte[] msg = new byte[origLen + padLen + 8];
                Array.Copy(input, msg, origLen);
                msg[origLen] = 0x80;
                long bitLen = (long)origLen * 8;
                for (int i = 0; i < 8; i++)
                {
                    msg[msg.Length - 8 + i] = (byte)(bitLen >> (8 * i));
                }

                uint a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
                for (int off = 0; off < msg.Length; off += 64)
                {
                    uint[] x = new uint[16];
                    for (int i = 0; i < 16; i++)
                    {
                        x[i] = BitConverter.ToUInt32(msg, off + i * 4);
                    }
                    uint aa = a, bb = b, cc = c, dd = d;
                    //三轮操作：步序号j（0..15）决定更新变量（a,d,c,b循环）与旋转量；k由轮内表给出
                    int[][] kTab = {
                        new[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
                        new[] { 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 },
                        new[] { 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15 }
                    };
                    int[][] sTab = {
                        new[] { 3, 7, 11, 19 },
                        new[] { 3, 5, 9, 13 },
                        new[] { 3, 9, 11, 15 }
                    };
                    uint[] addTab = { 0u, 0x5a827999u, 0x6ed9eba1u };
                    for (int round = 0; round < 3; round++)
                    {
                        for (int j = 0; j < 16; j++)
                        {
                            int k = kTab[round][j];
                            int rot = sTab[round][j % 4];
                            uint add = addTab[round];
                            switch (j % 4)
                            {
                                case 0: a = Rol(a + Fn(round, b, c, d) + x[k] + add, rot); break;
                                case 1: d = Rol(d + Fn(round, a, b, c) + x[k] + add, rot); break;
                                case 2: c = Rol(c + Fn(round, d, a, b) + x[k] + add, rot); break;
                                case 3: b = Rol(b + Fn(round, c, d, a) + x[k] + add, rot); break;
                            }
                        }
                    }
                    a += aa; b += bb; c += cc; d += dd;
                }
                byte[] result = new byte[16];
                Array.Copy(BitConverter.GetBytes(a), 0, result, 0, 4);
                Array.Copy(BitConverter.GetBytes(b), 0, result, 4, 4);
                Array.Copy(BitConverter.GetBytes(c), 0, result, 8, 4);
                Array.Copy(BitConverter.GetBytes(d), 0, result, 12, 4);
                return result;
            }

            private static uint F(uint x, uint y, uint z) => (x & y) | (~x & z);
            private static uint G(uint x, uint y, uint z) => (x & y) | (x & z) | (y & z);
            private static uint H(uint x, uint y, uint z) => x ^ y ^ z;
            private static uint Fn(int round, uint x, uint y, uint z) => round == 0 ? F(x, y, z) : round == 1 ? G(x, y, z) : H(x, y, z);
            private static uint Rol(uint v, int n) => (v << n) | (v >> (32 - n));
        }
    }
}
