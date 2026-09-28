using System.Text;
using System.Text.RegularExpressions;
using SuperSQLInjectionV2.Models;
using System.Text.Json;

namespace SuperSQLInjectionV2.Tools.Http
{
    /// <summary>
    /// 报文格式转换目标
    /// </summary>
    public enum RequestFormat
        {
        GET,
        POST_FORM,      //application/x-www-form-urlencoded
        POST_JSON,      //application/json
        POST_MULTIPART  //multipart/form-data（复杂格式）
    }

    /// <summary>从 MyTools 拆分出的RequestRewriter内聚簇</summary>
    public partial class RequestRewriter
    {
        private static readonly char[] s_nameBreakChars = { ' ', '\t', '\r', '\n', '>' };

        /// <summary>
        /// 剥离请求报文中的人工/自动标记，还原为干净报文（注入检测前置处理）：
        /// &lt;Encode&gt;x&lt;/Encode&gt;→x、&lt;EncodeRaw&gt;同理、&lt;Rand&gt;x&lt;/Rand&gt;→x、&lt;DRule&gt;tag:x&lt;DRule&gt;→x、$sql$→删除，
        /// 未闭合的标记残余清除到行尾。已含利用模板的标记报文无法100%还原原始参数值（模板前后缀会残留），
        /// 但可保证标记符号本身不混入参数值污染检测探针。
        /// </summary>
        public static string StripRequestMarks(string requestTxt)
        {
            if (string.IsNullOrEmpty(requestTxt))
            {
                return requestTxt;
            }
            string s = requestTxt;
            //成对标记块：保留内部内容
            s = Regex.Replace(s, "<Encode>(.*?)</Encode>", "$1", RegexOptions.Singleline);
            s = Regex.Replace(s, "<EncodeRaw>(.*?)</EncodeRaw>", "$1", RegexOptions.Singleline);
            s = Regex.Replace(s, "<EncodeBase64>(.*?)</EncodeBase64>", "$1", RegexOptions.Singleline);
            s = Regex.Replace(s, "<EncodeBase64Raw>(.*?)</EncodeBase64Raw>", "$1", RegexOptions.Singleline);
            s = Regex.Replace(s, "<Rand>(.*?)</Rand>", "$1", RegexOptions.Singleline);
            //动态规则标记：保留占位值部分（<DRule>标记名:占位值<DRule> → 占位值；空标记 → 空）
            s = Regex.Replace(s, @"<DRule>[^:<>\s]*(?::([.\s\S]*?))?<DRule>", "$1", RegexOptions.Singleline);
            //未闭合标记残余：清除到行尾（[^\r\n]*自然止于行尾，无需$锚——.NET多行$不匹配\r\n的\r前位置）
            s = Regex.Replace(s, "<Encode(Raw|Base64|Base64Raw)?>[^\r\n]*", "");
            s = Regex.Replace(s, "<Rand>[^\r\n]*", "");
            s = Regex.Replace(s, "<DRule>[^\r\n]*", "");
            //注入标记：直接删除
            s = s.Replace(ConstData.InjectStr, "", StringComparison.Ordinal);
            return s;
        }

        public static string ChangeRequestMethod(string datapack)
        {
            if (datapack.StartsWith("GET", StringComparison.Ordinal))
            {
                int pl = datapack.IndexOf('?', StringComparison.Ordinal);
                if (pl != -1)
                {
                    int el = datapack.IndexOf(" ", pl, StringComparison.Ordinal);
                    if (el != -1)
                    {

                        string cparams = datapack.Substring(pl + 1, el - pl - 1);
                        datapack = datapack.Replace("?" + cparams, "", StringComparison.Ordinal);
                        int sl = datapack.IndexOf("\r\n", StringComparison.Ordinal);
                        datapack = datapack.Insert(sl, "\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 0");
                        if (!datapack.EndsWith("\r\n\r\n", StringComparison.Ordinal))
                        {

                            datapack += "\r\n\r\n";
                        }
                        datapack += cparams;

                        int me = datapack.IndexOf(' ', StringComparison.Ordinal);
                        if (me != -1)
                        {

                            datapack = string.Concat("POST", datapack.AsSpan(me));
                        }

                        return datapack;
                    }
                }
            }
            else if (datapack.Contains("Transfer-Encoding: chunked", StringComparison.Ordinal)) {
                return datapack;
            }
            else if (datapack.StartsWith("POST", StringComparison.Ordinal))
            {
                int ssl = datapack.IndexOf("\r\n\r\n", StringComparison.Ordinal);

                if (ssl != -1)
                {


                    string cparams = datapack.Substring(ssl + 4, datapack.Length - ssl - 4);
                    datapack = datapack.Substring(0, ssl + 1);
                    int cys = datapack.IndexOf("Content-Type", StringComparison.Ordinal);
                    int cye = datapack.IndexOf("\r\n", cys, StringComparison.Ordinal);

                    if (cye > cys)
                    {
                        datapack = datapack.Remove(cys, cye - cys + 2);
                    }
                    int cls = datapack.IndexOf("Content-Length", StringComparison.Ordinal);
                    int cle = datapack.IndexOf("\r\n", cls + 1, StringComparison.Ordinal);
                    if (cle > cls)
                    {
                        datapack = datapack.Remove(cls, cle - cls + 2);
                    }

                    int hl = datapack.IndexOf(" HTTP", StringComparison.Ordinal);
                    if (hl != -1)
                    {

                        datapack = datapack.Insert(hl, "?" + cparams);
                    }

                    int me = datapack.IndexOf(' ', StringComparison.Ordinal);

                    if (me != -1)
                    {

                        datapack = string.Concat("GET", datapack.AsSpan(me));
                    }
                }
            }
            
            return datapack;

        }

        /// <summary>
        /// 根据URL生成GET请求报文（请求包编辑区右键"根据URL生成请求包"）。
        /// URL无效时返回空串，由调用方提示。
        /// </summary>
        public static string BuildGetRequestFromUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                return "";
            }
            //PathAndQuery会对<>等字符做百分号重编码，导致<Rand>/<DRule>/注入标记被破坏：
            //从原始URL串手工截取路径+查询部分（剔除fragment），标记原样保留，编解码交由发送链路的编码块处理
            int schemeEnd = url.IndexOf("://", StringComparison.Ordinal);
            int pathStart = schemeEnd >= 0 ? url.IndexOf('/', schemeEnd + 3) : -1;
            string path = pathStart >= 0 ? url.Substring(pathStart) : "/";
            int frag = path.IndexOf('#', StringComparison.Ordinal);
            if (frag >= 0)
            {
                path = path.Substring(0, frag);
            }
            if (string.IsNullOrEmpty(path))
            {
                path = "/";
            }
            string host = uri.IsDefaultPort ? uri.Host : $"{uri.Host}:{uri.Port}";
            var sb = new StringBuilder();
            sb.Append($"GET {path} HTTP/1.1\r\n");
            sb.Append($"Host: {host}\r\n");
            sb.Append("Connection: keep-alive\r\n");
            sb.Append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36\r\n");
            sb.Append("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n");
            sb.Append("Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n");
            sb.Append("\r\n");
            return sb.ToString();
        }

        /// <summary>
        /// 请求报文格式转换：把参数（query/form-urlencoded/JSON/multipart来源均可）整体迁移到目标格式。
        /// 参数值原样保留不做编解码，确保注入标记&lt;*&gt;、编码标记等不被破坏。
        /// </summary>
        public static string ChangeRequestFormat(string datapack, RequestFormat target)
        {
            if (string.IsNullOrWhiteSpace(datapack)) return datapack;
            //统一换行符处理
            string text = datapack.Replace("\r\n", "\n", StringComparison.Ordinal).Replace("\r", "\n", StringComparison.Ordinal);
            int sep = text.IndexOf("\n\n", StringComparison.Ordinal);
            string head = sep >= 0 ? text.Substring(0, sep) : text;
            string body = sep >= 0 ? text.Substring(sep + 2) : "";
            string[] headLines = head.Split('\n');
            if (headLines.Length == 0) return datapack;

            //请求行
            string requestLine = headLines[0];
            int firstSp = requestLine.IndexOf(' ', StringComparison.Ordinal);
            int lastSp = requestLine.LastIndexOf(' ');
            if (firstSp <= 0 || lastSp <= firstSp) return datapack;
            string pathAndQuery = requestLine.Substring(firstSp + 1, lastSp - firstSp - 1);
            string version = requestLine.Substring(lastSp + 1);
            string path = pathAndQuery;
            string query = "";
            int qi = pathAndQuery.IndexOf('?', StringComparison.Ordinal);
            if (qi >= 0)
            {
                path = pathAndQuery.Substring(0, qi);
                query = pathAndQuery.Substring(qi + 1);
            }

            //头部（剔除与body相关的头，转换后按需重建）
            List<string> headers = new List<string>();
            string contentType = "";
            for (int i = 1; i < headLines.Length; i++)
            {
                string line = headLines[i];
                if (line.StartsWith("Content-Type:", StringComparison.OrdinalIgnoreCase))
                {
                    contentType = line.Substring(13).Trim();
                    continue;
                }
                if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase)
                    || line.StartsWith("Transfer-Encoding:", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                if (!string.IsNullOrWhiteSpace(line)) headers.Add(line);
            }

            //收集参数（保序，允许多值）
            //修复：编辑器粘贴的报文尾部常带多余\r\n，body级剥离，防止尾部换行混进最后一个参数值
            body = body?.TrimEnd('\r', '\n') ?? "";
            List<KeyValuePair<string, string>> paras = new List<KeyValuePair<string, string>>();
            ParseUrlEncodedInto(query, paras);
            if (!string.IsNullOrEmpty(body))
            {
                if (contentType.Contains("json", StringComparison.OrdinalIgnoreCase))
                {
                    ParseJsonInto(body, paras);
                }
                else if (contentType.Contains("multipart/form-data", StringComparison.OrdinalIgnoreCase))
                {
                    ParseMultipartInto(body, contentType, paras);
                }
                else
                {
                    ParseUrlEncodedInto(body, paras);
                }
            }

            //按目标格式重建
            StringBuilder sb = new StringBuilder();
            string newBody = "";
            string? newContentType = null;
            string method = target == RequestFormat.GET ? "GET" : "POST";
            string newPath = path;
            switch (target)
            {
                case RequestFormat.GET:
                    if (paras.Count > 0)
                    {
                        newPath = path + "?" + string.Join("&", paras.Select(p => p.Value.Length > 0 ? SanitizeInline(p.Key) + "=" + SanitizeInline(p.Value) : SanitizeInline(p.Key)));
                    }
                    break;
                case RequestFormat.POST_FORM:
                    newBody = string.Join("&", paras.Select(p => p.Value.Length > 0 ? SanitizeInline(p.Key) + "=" + SanitizeInline(p.Value) : SanitizeInline(p.Key)));
                    newContentType = "application/x-www-form-urlencoded";
                    break;
                case RequestFormat.POST_JSON:
                    newBody = BuildJsonBody(paras);
                    newContentType = "application/json";
                    break;
                case RequestFormat.POST_MULTIPART:
                    string boundary = "----SSQLIFormBoundary" + SuperSQLInjectionV2.Tools.MyTools.Md5_16(Guid.NewGuid().ToString());
                    newBody = BuildMultipartBody(paras, boundary);
                    newContentType = "multipart/form-data; boundary=" + boundary;
                    break;
            }
            sb.Append(method).Append(' ').Append(newPath).Append(' ').Append(version).Append("\r\n");
            foreach (string h in headers)
            {
                sb.Append(h).Append("\r\n");
            }
            if (target != RequestFormat.GET)
            {
                if (newContentType != null) sb.Append("Content-Type: ").Append(newContentType).Append("\r\n");
                sb.Append("Content-Length: ").Append(Encoding.UTF8.GetByteCount(newBody)).Append("\r\n");
            }
            sb.Append("\r\n");
            if (target != RequestFormat.GET) sb.Append(newBody);
            return sb.ToString();
        }

        private static void ParseUrlEncodedInto(string data, List<KeyValuePair<string, string>> paras)
        {
            if (string.IsNullOrEmpty(data)) return;
            foreach (string pair in data.Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                //跳过空白对（尾部换行/多余&产生的脏数据）
                if (string.IsNullOrWhiteSpace(pair)) continue;
                string clean = pair.Trim('\r', '\n');
                int eq = clean.IndexOf('=', StringComparison.Ordinal);
                if (eq >= 0)
                {
                    paras.Add(new KeyValuePair<string, string>(clean.Substring(0, eq), clean.Substring(eq + 1)));
                }
                else
                {
                    paras.Add(new KeyValuePair<string, string>(clean, ""));
                }
            }
        }

        /// <summary>
        /// 剥离key/value中裸CR/LF：进入请求行/query/urlencoded body时裸换行会破坏报文成帧（JSON/multipart输出保留原样）
        /// </summary>
        private static string SanitizeInline(string s)
        {
            return s.Replace("\r", "", StringComparison.Ordinal).Replace("\n", "", StringComparison.Ordinal);
        }

        private static void ParseJsonInto(string body, List<KeyValuePair<string, string>> paras)
        {
            try
            {
                using JsonDocument doc = JsonDocument.Parse(body);
                if (doc.RootElement.ValueKind == JsonValueKind.Object)
                {
                    foreach (JsonProperty prop in doc.RootElement.EnumerateObject())
                    {
                        string v = prop.Value.ValueKind switch
                        {
                            JsonValueKind.String => prop.Value.GetString ()?? "",
                            JsonValueKind.Null => "",
                            _ => prop.Value.GetRawText()
                        };
                        paras.Add(new KeyValuePair<string, string>(prop.Name, v));
                    }
                }
            }
            catch
            {
                //JSON解析失败时按urlencoded兜底
                ParseUrlEncodedInto(body, paras);
            }
        }

        private static void ParseMultipartInto(string body, string contentType, List<KeyValuePair<string, string>> paras)
        {
            Match m = Regex.Match(contentType, "boundary=([^;\\s]+)");
            if (!m.Success) return;
            string boundary = m.Groups[1].Value.Trim('"');
            foreach (string part in body.Split(new[] { "--" + boundary }, StringSplitOptions.RemoveEmptyEntries))
            {
                string p = part.Trim('\r', '\n');
                if (p == "--" || p.Length == 0) continue;
                Match nm = Regex.Match(p, "name=\"([^\"]+)\"");
                if (!nm.Success) continue;
                int bsep = p.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                if (bsep < 0) bsep = p.IndexOf("\n\n", StringComparison.Ordinal);
                if (bsep < 0) continue;
                string value = p.Substring(bsep).TrimStart('\r', '\n');
                paras.Add(new KeyValuePair<string, string>(nm.Groups[1].Value, value));
            }
        }

        private static readonly JsonSerializerOptions JsonRelaxed = new JsonSerializerOptions
        {
            //宽松转义：不在JSON文本中转义< > &等字符，确保注入标记<*>原样保留可被替换
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            //AOT：指定源生成resolver，配合下方JsonTypeInfo重载消除反射序列化（string类型JIT/AOT行为一致）
            TypeInfoResolver = Source.SourceGenerationContext.Default
        };

        /// <summary>宽松编码器的string TypeInfo缓存（Serialize(value, JsonTypeInfo)重载为AOT安全路径）</summary>
        private static readonly System.Text.Json.Serialization.Metadata.JsonTypeInfo<string> JsonRelaxedStringInfo =
            (System.Text.Json.Serialization.Metadata.JsonTypeInfo<string>)JsonRelaxed.GetTypeInfo(typeof(string));

        private static string BuildJsonBody(List<KeyValuePair<string, string>> paras)
        {
            //手工拼接，保留同名参数（后者覆盖前者在JSON语义下会丢失，这里用数组保留多值）
            StringBuilder sb = new StringBuilder("{");
            var groups = paras.GroupBy(p => p.Key);
            bool first = true;
            foreach (var g in groups)
            {
                if (!first) sb.Append(',');
                first = false;
                sb.Append(JsonSerializer.Serialize(g.Key, JsonRelaxedStringInfo)).Append(':');
                var vals = g.ToList();
                if (vals.Count == 1)
                {
                    sb.Append(JsonSerializer.Serialize(vals[0].Value, JsonRelaxedStringInfo));
                }
                else
                {
                    sb.Append('[').Append(string.Join(",", vals.Select(x => JsonSerializer.Serialize(x.Value, JsonRelaxedStringInfo)))).Append(']');
                }
            }
            sb.Append('}');
            return sb.ToString();
        }

        private static string BuildMultipartBody(List<KeyValuePair<string, string>> paras, string boundary)
        {
            StringBuilder sb = new StringBuilder();
            foreach (var p in paras)
            {
                sb.Append("--").Append(boundary).Append("\r\n");
                sb.Append("Content-Disposition: form-data; name=\"").Append(p.Key).Append("\"\r\n\r\n");
                sb.Append(p.Value).Append("\r\n");
            }
            sb.Append("--").Append(boundary).Append("--\r\n");
            return sb.ToString();
        }

        /// <summary>
        /// 恢复注入记录时按结构化字段重烘焙标记报文（方案C：不信任存储的RequestTxt烘焙快照）：
        /// 1) 剥离存储报文的全部标记得到干净基底；2) 按where语义计算基底值（1=原值/2=负随机/3=空）；
        /// 3) 用记录的Prefix/Suffix/DBType/VectorTemplate经InjectDetectEngine重新烘焙标记值；
        /// 4) 按Place整体替换注入参数值（烘焙残留随旧值一并清除）。
        /// 参数定位失败（如结构已变/URI旧记录无段序号）时回退存储报文并告警。
        /// </summary>
        public static string RebakeRecordRequest(AppConfig config, InjectRecord record)
        {
            string stored = record.RequestTxt ?? "";
            if (string.IsNullOrEmpty(stored))
            {
                return stored;
            }
            try
            {
                //干净基底：Encode/EncodeRaw块整体丢弃（利用烘焙的胶水/注释/$sql$全在块内，基底值在块外），
                //Rand/DRule块保留内部内容（与注入点无关的随机/动态值标记，DRule取占位值部分），$sql$兜底删除。
                //不能用StripRequestMarks（其保留Encode块内容会把" and #"等胶水残留在参数值里，污染二次解析）
                string baseReq = Regex.Replace(stored, "<Encode(Raw)?>.*?</Encode(Raw)?>", "", RegexOptions.Singleline);
                baseReq = Regex.Replace(baseReq, "<Encode(Raw)?>[^\r\n]*", "");
                baseReq = Regex.Replace(baseReq, "<Rand>(.*?)</Rand>", "$1", RegexOptions.Singleline);
                baseReq = Regex.Replace(baseReq, @"<DRule>[^:<>\s]*(?::([.\s\S]*?))?<DRule>", "$1", RegexOptions.Singleline);
                baseReq = baseReq.Replace(ConstData.InjectStr, "", StringComparison.Ordinal);
                string baseValue = record.Where switch
                {
                    3 => "",
                    2 => "-" + new Random().Next(1000, 99999).ToString(),
                    _ => record.OrigValue ?? ""
                };
                string? bakedVector = record.Where == 3
                    ? Inject.InjectDetectEngine.BakeVectorForRestore(record.VectorTemplate, record.OrigValue)
                    : null;
                string marked = Inject.InjectDetectEngine.BakeExploitMarkedValue(
                    baseValue, record.Prefix, record.Suffix, record.DBType, bakedVector);
                string rebaked = record.Place switch
                {
                    ParamPlace.Cookie => SetInjectCookie(baseReq, record.PName, marked),
                    ParamPlace.Header => SetInjectHeader(baseReq, record.HeaderName, marked),
                    ParamPlace.BodyJson => SetInjectJsonBody(baseReq, record.PName, marked),
                    ParamPlace.BodyXml => SetInjectXmlBody(baseReq, record.PName, marked),
                    ParamPlace.BodyMultipart => SetInjectMultipart(baseReq, record.PName, marked),
                    ParamPlace.Uri => record.UriIndex >= 0 ? SetInjectUriSegment(baseReq, record.UriIndex, marked) : stored,
                    _ => SetInjectToRequest(baseReq, SetInject(new HttpRequest(config, baseReq).Params, record.PName, marked))
                };
                if (rebaked.IndexOf(ConstData.InjectStr, StringComparison.Ordinal) < 0)
                {
                    SuperSQLInjectionV2.Tools.Log.Warning("注入记录重烘焙定位失败（参数" + record.PName + "），已回退为记录原始报文");
                    return stored;
                }
                return rebaked;
            }
            catch (Exception ex)
            {
                SuperSQLInjectionV2.Tools.Log.SysLog("注入记录重烘焙异常，回退原始报文：" + ex.Message);
                return stored;
            }
        }

        public static string SetInject(Dictionary<String, String> paramDatas, String injectParamName, String? injectParamData)        {

            StringBuilder sb = new StringBuilder();
            foreach (KeyValuePair<String, String> kv in paramDatas)
            {
                if (injectParamName.Equals(kv.Key, StringComparison.Ordinal))
                {
                    sb.Append(kv.Key + "=" + injectParamData + "&");
                }
                else
                {
                    sb.Append(kv.Key + "=" + kv.Value + "&");
                }
            }
            if (sb.Length > 0)
            {
                sb.Remove(sb.Length - 1, 1);
            }
            return sb.ToString();
        }

        public static string SetInjectToRequest(String oldRequest, String newParamDatas)
        {

            if (oldRequest.StartsWith("GET", StringComparison.Ordinal))
            {
                int start = oldRequest.IndexOf('?', StringComparison.Ordinal);
                if (start == -1)
                {
                    return oldRequest;
                }
                int end = oldRequest.IndexOf(' ', start);
                if (end > start)
                {
                    oldRequest = oldRequest.Remove(start + 1, end - start - 1);
                    oldRequest = oldRequest.Insert(start + 1, newParamDatas);
                    return oldRequest;
                }
                else
                {
                    return oldRequest;
                }

            }
            else
            {
                //POST替换参数
                String header = Regex.Split(oldRequest, "\r\n\r\n")[0];
                return header + "\r\n\r\n" + newParamDatas;

            }
        }

        /// <summary>
        /// Cookie位置注入：替换Cookie头中指定键的值（键不存在则追加到末尾）
        /// </summary>
        public static string SetInjectCookie(string oldRequest, string cookieName, string? newValue)
        {
            return Regex.Replace(oldRequest, "(?im)^Cookie:[^\r\n]*", m =>
            {
                string line = m.Value;
                string cookieBody = line.Substring(line.IndexOf(':', StringComparison.Ordinal) + 1).Trim();
                var pairs = cookieBody.Split(';', StringSplitOptions.RemoveEmptyEntries)
                    .Select(p => p.Trim()).ToList();
                bool replaced = false;
                for (int i = 0; i < pairs.Count; i++)
                {
                    string name = pairs[i].Contains('=', StringComparison.Ordinal) ? pairs[i][..pairs[i].IndexOf('=', StringComparison.Ordinal)] : pairs[i];
                    if (name.Equals(cookieName, StringComparison.OrdinalIgnoreCase))
                    {
                        pairs[i] = cookieName + "=" + newValue;
                        replaced = true;
                        break;
                    }
                }
                if (!replaced)
                {
                    pairs.Add(cookieName + "=" + newValue);
                }
                return "Cookie: " + string.Join("; ", pairs);
            });
        }

        /// <summary>
        /// HTTP头位置注入：替换指定请求头的值（头不存在则在头区末尾追加）
        /// </summary>
        public static string SetInjectHeader(string oldRequest, string headerName, string? newValue)
        {
            string esc = Regex.Escape(headerName);
            if (Regex.IsMatch(oldRequest, "(?im)^" + esc + "\\s*:"))
            {
                return Regex.Replace(oldRequest, "(?im)^" + esc + "\\s*:[^\r\n]*", headerName + ": " + newValue);
            }
            //头不存在：插入到头区末尾（空行前）
            int headEnd = oldRequest.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (headEnd < 0) headEnd = oldRequest.IndexOf("\n\n", StringComparison.Ordinal);
            if (headEnd < 0) return oldRequest + "\r\n" + headerName + ": " + newValue;
            return oldRequest.Insert(headEnd, "\r\n" + headerName + ": " + newValue);
        }

        /// <summary>
        /// <summary>
        /// 枚举URI路径段（PLACE.URI 能力）：取请求行path（不含query），按"/"切分返回非空段（index为非空段序号，0基）
        /// </summary>
        public static List<(int index, string value)> GetUriSegments(string requestTxt)
        {
            var result = new List<(int index, string value)>();
            if (string.IsNullOrEmpty(requestTxt))
            {
                return result;
            }
            int lineEnd = requestTxt.IndexOf("\r\n", StringComparison.Ordinal);
            string firstLine = lineEnd > 0 ? requestTxt.Substring(0, lineEnd) : requestTxt;
            int sp1 = firstLine.IndexOf(' ', StringComparison.Ordinal);
            int sp2 = firstLine.LastIndexOf(' ');
            if (sp1 <= 0 || sp2 <= sp1 + 1)
            {
                return result;
            }
            string path = firstLine.Substring(sp1 + 1, sp2 - sp1 - 1);
            int q = path.IndexOf('?', StringComparison.Ordinal);
            if (q >= 0)
            {
                path = path.Substring(0, q);
            }
            int idx = 0;
            foreach (string seg in path.Split('/'))
            {
                if (seg.Length > 0)
                {
                    result.Add((idx, seg));
                    idx++;
                }
            }
            return result;
        }

        /// URI路径段注入：把请求行path中第segIndex个非空段替换为标记值（段序号与GetUriSegments一致；query串不动）
        /// </summary>
        public static string SetInjectUriSegment(string requestTxt, int segIndex, string? markedValue)
        {
            if (string.IsNullOrEmpty(requestTxt) || segIndex < 0)
            {
                return requestTxt;
            }
            int lineEnd = requestTxt.IndexOf("\r\n", StringComparison.Ordinal);
            if (lineEnd <= 0)
            {
                return requestTxt;
            }
            string firstLine = requestTxt.Substring(0, lineEnd);
            int sp1 = firstLine.IndexOf(' ', StringComparison.Ordinal);
            int sp2 = firstLine.LastIndexOf(' ');
            if (sp1 <= 0 || sp2 <= sp1 + 1)
            {
                return requestTxt;
            }
            string path = firstLine.Substring(sp1 + 1, sp2 - sp1 - 1);
            string query = "";
            int q = path.IndexOf('?', StringComparison.Ordinal);
            if (q >= 0)
            {
                query = path.Substring(q);
                path = path.Substring(0, q);
            }
            //按非空段序号定位替换（保留原始斜杠结构，含尾斜杠）
            var segs = path.Split('/');
            int idx = 0;
            bool replaced = false;
            for (int i = 0; i < segs.Length; i++)
            {
                if (segs[i].Length == 0)
                {
                    continue;
                }
                if (idx == segIndex)
                {
                    segs[i] = markedValue ?? "";
                    replaced = true;
                    break;
                }
                idx++;
            }
            if (!replaced)
            {
                return requestTxt;
            }
            string newFirstLine = string.Concat(firstLine.AsSpan(0, sp1 + 1), string.Join("/", segs) + query, firstLine.AsSpan(sp2));
            return string.Concat(newFirstLine, requestTxt.AsSpan(lineEnd));
        }

        private static readonly System.Text.Json.JsonSerializerOptions RelaxedJsonOptions =
            new System.Text.Json.JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

        /// <summary>
        /// multipart/form-data 请求体注入写回：定位name对应的part，仅替换其值切片（其他part与文件二进制原样保留）
        /// </summary>
        public static string SetInjectMultipart(string oldRequest, string name, string? newValue)
        {
            int headEnd = oldRequest.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            string sep = "\r\n\r\n";
            if (headEnd < 0) { headEnd = oldRequest.IndexOf("\n\n", StringComparison.Ordinal); sep = "\n\n"; }
            if (headEnd < 0) return oldRequest;
            string head = oldRequest[..headEnd];
            string body = oldRequest[(headEnd + sep.Length)..];
            Match bm = Regex.Match(head, "boundary=(?<b>[^;\\s\"]+)", RegexOptions.IgnoreCase);
            if (!bm.Success) return oldRequest;
            string boundary = bm.Groups["b"].Value;
            //定位目标part：--boundary\r\n...name="xxx"...\r\n\r\n<value>\r\n--boundary
            Match pm = Regex.Match(body,
                "(?<prefix>--" + Regex.Escape(boundary) + "\\r?\\n[.\\s\\S]*?name=\"" + Regex.Escape(name) + "\"[.\\s\\S]*?\\r?\\n\\r?\\n)(?<value>[.\\s\\S]*?)(?<suffix>\\r?\\n--" + Regex.Escape(boundary) + ")");
            if (!pm.Success) return oldRequest;
            string newBody = body[..pm.Groups["value"].Index] + newValue + body[(pm.Groups["value"].Index + pm.Groups["value"].Length)..];
            return head + sep + newBody;
        }

        public static string SetInjectJsonBody(string oldRequest, string jsonPath, string? newValue)
        {
            int headEnd = oldRequest.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            string sep = "\r\n\r\n";
            if (headEnd < 0) { headEnd = oldRequest.IndexOf("\n\n", StringComparison.Ordinal); sep = "\n\n"; }
            if (headEnd < 0) return oldRequest;
            string head = oldRequest[..headEnd];
            string body = oldRequest[(headEnd + sep.Length)..];
            try
            {
                System.Text.Json.Nodes.JsonNode? root = System.Text.Json.Nodes.JsonNode.Parse(body);
                System.Text.Json.Nodes.JsonNode? node = root;
                foreach (string seg in jsonPath.Split('.'))
                {
                    string key = seg;
                    int arrIdx = -1;
                    Match am = Regex.Match(seg, @"^(?<key>[^\[\]]+)\[(?<idx>\d+)\]$");
                    if (am.Success)
                    {
                        key = am.Groups["key"].Value;
                        arrIdx = int.Parse(am.Groups["idx"].Value);
                    }
                    node = node is System.Text.Json.Nodes.JsonObject obj ? obj[key] : null;
                    if (node == null) return oldRequest;
                    if (arrIdx >= 0)
                    {
                        node = node is System.Text.Json.Nodes.JsonArray arr && arr.Count > arrIdx ? arr[arrIdx] : null;
                        if (node == null) return oldRequest;
                    }
                }
                //写回：替换父容器中的目标值（payload统一按字符串写入，应用侧拼接决定SQL语义）
                string lastSeg = jsonPath.Split('.').Last();
                string lastKey = lastSeg;
                int lastArr = -1;
                Match lm = Regex.Match(lastSeg, @"^(?<key>[^\[\]]+)\[(?<idx>\d+)\]$");
                if (lm.Success)
                {
                    lastKey = lm.Groups["key"].Value;
                    lastArr = int.Parse(lm.Groups["idx"].Value);
                }
                //重新定位父节点
                System.Text.Json.Nodes.JsonNode? parent = root;
                string[] segs = jsonPath.Split('.');
                for (int i = 0; i < segs.Length - 1; i++)
                {
                    string k = segs[i];
                    int ai = -1;
                    Match m2 = Regex.Match(segs[i], @"^(?<key>[^\[\]]+)\[(?<idx>\d+)\]$");
                    if (m2.Success) { k = m2.Groups["key"].Value; ai = int.Parse(m2.Groups["idx"].Value); }
                    parent = parent is System.Text.Json.Nodes.JsonObject o2 ? o2[k] : null;
                    if (parent == null) return oldRequest;
                    if (ai >= 0)
                    {
                        parent = parent is System.Text.Json.Nodes.JsonArray a2 && a2.Count > ai ? a2[ai] : null;
                        if (parent == null) return oldRequest;
                    }
                }
                if (parent is System.Text.Json.Nodes.JsonObject pobj)
                {
                    if (lastArr >= 0)
                    {
                        if (pobj[lastKey] is System.Text.Json.Nodes.JsonArray parr && parr.Count > lastArr)
                        {
                            parr[lastArr] = newValue;
                        }
                    }
                    else
                    {
                        pobj[lastKey] = newValue;
                    }
                    return head + sep + root!.ToJsonString(RelaxedJsonOptions);
                }
                return oldRequest;
            }
            catch (Exception e)
            {
                //JSON体重写失败静默回退原文会导致注入标记/参数替换丢失，必须留痕便于排查
                Tools.Log.SysLog("JSON报文重写失败（已回退原报文）：" + e.Message);
                return oldRequest;
            }
        }

        /// <summary>
        /// XML/SOAP体词法切分（注释/CDATA/PI/DOCTYPE整体跳过；标签去命名空间前缀）。
        /// 产出叶子元素文本节点：key=祖先路径(如 Envelope/Body/login/username)，同路径重复自动追加#2/#3序号；
        /// start/end为文本在body中的精确区间（注入写回用）
        /// </summary>
        [GeneratedRegex(@"<!--[\s\S]*?-->|<!\[CDATA\[[\s\S]*?\]\]>|<\?[\s\S]*?\?>|<![^>]*>|</?[^>\s/]+[^>]*?/?>|[^<]+")]
        private static partial Regex XmlTokenRegex();

        public static List<(string key, string value, int start, int end)> TokenizeXmlLeaves(string body)
        {
            var result = new List<(string key, string value, int start, int end)>();
            if (string.IsNullOrEmpty(body))
            {
                return result;
            }
            var stack = new List<string>();
            var pathCount = new Dictionary<string, int>();
            foreach (Match m in XmlTokenRegex().Matches(body))
            {
                string tok = m.Value;
                if (tok.Length == 0)
                {
                    continue;
                }
                if (tok[0] == '<')
                {
                    //注释/CDATA/PI/DOCTYPE/自闭合标签不进栈
                    if (tok.StartsWith("<!--", StringComparison.Ordinal) || tok.StartsWith("<!", StringComparison.Ordinal) || tok.StartsWith("<?", StringComparison.Ordinal) || tok.EndsWith("/>", StringComparison.Ordinal))
                    {
                        continue;
                    }
                    if (tok.StartsWith("</", StringComparison.Ordinal))
                    {
                        if (stack.Count > 0)
                        {
                            stack.RemoveAt(stack.Count - 1);
                        }
                        continue;
                    }
                    string name = tok.Substring(1);
                    int sp = name.IndexOfAny(s_nameBreakChars);
                    if (sp > 0)
                    {
                        name = name.Substring(0, sp);
                    }
                    int colon = name.IndexOf(':', StringComparison.Ordinal);
                    if (colon >= 0 && colon < name.Length - 1)
                    {
                        name = name.Substring(colon + 1);
                    }
                    stack.Add(name);
                    continue;
                }
                //文本节点：仅叶子（栈顶元素的直接文本）且非空白
                if (stack.Count == 0 || string.IsNullOrWhiteSpace(tok))
                {
                    continue;
                }
                string path = string.Join("/", stack);
                pathCount.TryGetValue(path, out int n);
                pathCount[path] = n + 1;
                string key = n == 0 ? path : path + "#" + (n + 1);
                result.Add((key, tok, m.Index, m.Index + m.Length));
            }
            return result;
        }

        /// <summary>XML/SOAP体叶子元素文本展平为 路径键值对（注入检测/利用按路径定位）</summary>
        public static Dictionary<string, string> GetXmlParams(string body)
        {
            var dict = new Dictionary<string, string>();
            foreach (var e in TokenizeXmlLeaves(body))
            {
                dict[e.key] = e.value.Trim();
            }
            return dict;
        }

        /// <summary>
        /// XML/SOAP请求体位置注入：按TokenizeXmlLeaves的路径key定位叶子元素，仅替换其文本切片（其余结构原样保留）。
        /// 注意：payload中的 &lt; &gt; &amp; 会破坏XML结构，必要时配合tamper/编码规则处理
        /// </summary>
        public static string SetInjectXmlBody(string oldRequest, string xmlPath, string? newValue)
        {
            int headEnd = oldRequest.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            string sep = "\r\n\r\n";
            if (headEnd < 0) { headEnd = oldRequest.IndexOf("\n\n", StringComparison.Ordinal); sep = "\n\n"; }
            if (headEnd < 0) return oldRequest;
            string head = oldRequest[..headEnd];
            string body = oldRequest[(headEnd + sep.Length)..];
            foreach (var e in TokenizeXmlLeaves(body))
            {
                if (e.key == xmlPath)
                {
                    string newBody = body[..e.start] + newValue + body[e.end..];
                    return head + sep + newBody;
                }
            }
            return oldRequest;
        }

        public static string ClearURLParams(string url)
        {
                int index = url.IndexOf('?', StringComparison.Ordinal);
                if (index > 0)
                {
                    return url.Substring(0,index);

                }
                else {

                    return url;
                }
        }

        public static string GetCurrentPath(string url)
        {
            int index =url.LastIndexOf('/');

            if (index != -1)
            {
                return string.Concat(url.AsSpan(0, index), "/");
            }
            else {
                return "";
            }
        }

        public static string GetRootDomain(string domain)
        {
            int index = domain.LastIndexOf('.');

            if (index>0)
            {
                int index2 = domain.LastIndexOf(".", index - 1, StringComparison.Ordinal);
                if (index2 != -1)
                {
                    return domain.Substring(index2+1);
                }
               
            }
            return domain;
        }

        public static string GetRequestURL(string header,bool isSSL,string ip,int port)
        {
            int start = header.IndexOf(' ', StringComparison.Ordinal);
            string url = "";
            if (start != -1) {
                int end = header.IndexOf(' ', start);
                if (end != -1) {
                    string str = header.Substring(start, end - start);
                    if (str.StartsWith('/'))
                    {
                        if (isSSL)
                        {
                            url = "https://" + ip + ":" + port + "/" + str;
                        }
                        else
                        {
                            url = "http://" + ip + ":" + port + "/" + str;
                        }
                    }
                    else {
                        url = str;
                    }
                }
            }
            return url;
        }

        public static string GetRequestURI(string header)
        {
            int start = header.IndexOf(' ', StringComparison.Ordinal);
            string uri = "";
            if (start != -1)
            {
                int end = header.IndexOf(' ', start + 1);
                if (end != -1)
                {
                    string str = header.Substring(start + 1, end - start);
                    if (str.StartsWith('/'))
                    {
                        int send = str.IndexOf('?', StringComparison.Ordinal);
                        if (send != -1)
                        {
                            uri = str.Substring(0, send);
                        }
                        else
                        {
                            uri = str;
                        }

                    }
                    else
                    {
                        Uri u = new Uri(str);
                        uri = u.AbsolutePath;
                    }
                }
            }
            return uri;
        }
    }
}
