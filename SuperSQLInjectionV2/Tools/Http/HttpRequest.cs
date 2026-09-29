using SuperSQLInjectionV2.Models;
using System.Collections.Specialized;
using System.Text;
using System.Text.RegularExpressions;
namespace SuperSQLInjectionV2.Tools.Http
{
    public class HttpRequest
    {
        private static readonly string[] s_lineSeparators = { "\r\n", "\n" };

        public string Payload { get; set; } = "";
        /// <summary>后置伴随规则指定标记名（&lt;Sencond:标记名&gt;&lt;/Sencond&gt;指令，StrReplaceCenter提取后从报文剔除）：
        /// 非空时本次请求的后置取数使用该标记名对应的规则，替代默认的第一条启用后置规则</summary>
        public string? SencondTag { get; set; }
        /// <summary>NullBody提示（单请求级，对标业界同类工具 --null-connection）：长度类/状态码/时间盲注取数置true，发送时只读响应头比对，不读body</summary>
        public bool NullBodyHint { get; set; } = false;
        public string Query { get; set; } = "";
        public string Path { get; set; } = "";
        public string Host { get; set; } = "";
        public bool IsSSL { get; set; } = false;
        public int Port { get; set; }=80;

        private string? _poolKeySuffix;
        /// <summary>连接池键后缀（host:port:ssl），首次访问时计算并缓存，盲注高频发包免每请求字符串插值</summary>
        internal string PoolKeySuffix => _poolKeySuffix ??= Host + ":" + Port + ":" + IsSSL;

        /// <summary>
        /// 请求方法 (如 GET, POST)
        /// </summary>
        public HttpMethod Method { get; set; }=HttpMethod.GET;
        /// <summary>
        /// 请求URI (包含路径和查询参数，如 /index.html?id=1)
        /// </summary>
        public string PathAndQuery { get; set; } = "";
        public AppConfig AppConfig{ get; set; }
        /// <summary>
        /// HTTP协议版本 (默认为 HTTP/1.1)
        /// </summary>
        public string Version { get; set; } = "HTTP/1.1";
        private string _headerAndBody="";
        public string HeaderAndBody
        {
            get {
                //_headerAndBody已含头体分隔（完整报文）时原样返回，避免重复拼接Body；
                //仅当头体分离状态（仅头部文本）时拼接CTRL+BodyText
                if (_headerAndBody != null && _headerAndBody.Contains(HttpConst.CTRL, StringComparison.Ordinal))
                {
                    return _headerAndBody;
                }
                //分隔符被意外破坏但Body已在文末时，禁止再追加Body（防止报文体重复、Content-Length失真）
                string body = BodyText;
                if (!string.IsNullOrEmpty(body) && _headerAndBody != null && _headerAndBody.EndsWith(body, StringComparison.Ordinal))
                {
                    return _headerAndBody;
                }
                return _headerAndBody + HttpConst.CTRL + body;
            }
            set {
                _headerAndBody=value;
            }
        }
        public string HeaderText { get; set; } = "";
        /// <summary>
        /// 请求头集合
        /// </summary>
        public Dictionary<string,string>  Headers{ get; set; } = new Dictionary<string, string>();
        public NameValueCollection QueryString { get; set; } = new NameValueCollection();
        public Dictionary<string, string> Params { get; set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        /// <summary>Cookie头解析出的键值对（注入位置：Cookie，level>=2 检测）</summary>
        public Dictionary<string, string> CookieParams { get; set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        /// <summary>JSON请求体展平的键值对（点路径->标量文本，如 user.id）</summary>
        public Dictionary<string, string> JsonParams { get; set; } = new Dictionary<string, string>();
        /// <summary>multipart/form-data 请求体中的文本字段（name->value，文件字段不纳入）</summary>
        public Dictionary<string, string> MultipartParams { get; set; } = new Dictionary<string, string>();
        /// <summary>请求体是否为 multipart/form-data</summary>
        public bool IsMultipartBody { get; private set; } = false;
        /// <summary>请求体是否为JSON</summary>
        public bool IsJsonBody { get; private set; } = false;
        /// <summary>XML/SOAP请求体叶子元素参数（路径→文本值，注入位置枚举用）</summary>
        public Dictionary<string, string> XmlParams { get; set; } = new Dictionary<string, string>();
        /// <summary>是否为XML/SOAP请求体</summary>
        public bool IsXmlBody { get; private set; } = false;
        /// <summary>获取指定请求头的值（忽略大小写），不存在返回null</summary>
        public string? GetHeader(string name)
        {
            foreach (var kv in Headers)
            {
                if (kv.Key.Equals(name, StringComparison.OrdinalIgnoreCase)) return kv.Value;
            }
            return null;
        }
        public Dictionary<string, string> BodyParams { get; set; } = new Dictionary<string, string>();
        /// <summary>
        /// 请求主体 (字节数组，用于处理二进制或大文件上传)
        /// </summary>
        public byte[]? Body { get; set; }
        /// <summary>
        /// 请求主体的字符串形式 (便捷属性，自动处理UTF-8编码)
        /// </summary>
        public string BodyText
        {
            get => Body != null ? Encoding.UTF8.GetString(Body) : "";
            set => Body = value != null ? Encoding.UTF8.GetBytes(value) : null;
        }
        /// <summary>
        /// 获取Content-Length
        /// </summary>
        public int ContentLength => Body?.Length ?? 0;
        //public string _payload  = "";

        public string ContentType { get; set; }="";
        /// <summary>
        /// 将HTTP请求报文文本转换为HttpRequest对象
        /// </summary>
        /// <param name="config">HTTP请求配置</param>
        /// <returns>解析后的HttpRequest对象</returns>
        public HttpRequest(AppConfig config):this(config,"")
        {

        }
        /// <summary>轻量构造（仅CreateForSend用）：跳过全部解析，只挂配置</summary>
        private HttpRequest(AppConfig config, bool light)
        {
            AppConfig = config;
        }
        /// <summary>
        /// 发送链路轻量构造（T1）：只设发送必需字段（Host/Port/SSL/HeaderAndBody/Method/Path），
        /// 跳过查询串/表单/Cookie/JSON/XML/multipart全量解析——发送路径不消费解析结果，
        /// 盲注高并发下省掉每请求两次DOM解析。需要参数枚举（注入位置检测）时必须用完整构造 new HttpRequest(config, requestTxt)。
        /// </summary>
        public static HttpRequest CreateForSend(AppConfig config, string headerAndBody)
        {
            HttpRequest req = new HttpRequest(config, true)
            {
                Host = config.Host,
                Port = config.Port,
                IsSSL = config.IsSSL,
                HeaderAndBody = headerAndBody ?? ""
            };
            //仅解析请求行（Digest认证需要Method/Path；其余解析结果发送路径不消费）
            string hb = req.HeaderAndBody;
            int lineEnd = hb.IndexOf('\n', StringComparison.Ordinal);
            string firstLine = (lineEnd > 0 ? hb.Substring(0, lineEnd) : hb).TrimEnd('\r');
            if (firstLine.Length > 0)
            {
                try
                {
                    req.ParseRequestLine(firstLine);
                }
                catch (ArgumentException) { /* 畸形请求行容忍：发送时按原文输出 */ }
            }
            return req;
        }
        /// <summary>
        /// 将HTTP请求报文文本转换为HttpRequest对象
        /// </summary>
        /// <param name="config">HTTP请求配置</param>
        /// <returns>解析后的HttpRequest对象</returns>
        public HttpRequest(AppConfig config, string requestTxt)
        {
            AppConfig=config;
            if (string.IsNullOrWhiteSpace(requestTxt)) {
                requestTxt=config.RequestTxt;
            }

            if (string.IsNullOrWhiteSpace(requestTxt))
                return;
            this.Host = config.Host;
            this.Port = config.Port;
            this.IsSSL = config.IsSSL;
            HeaderAndBody = requestTxt;
            // 使用正则表达式分割字符串
            string[] bds = Regex.Split(HeaderAndBody, HttpConst.CTRL);
            if (bds.Length == 0)
                return;
            HeaderText = bds[0];
            var lines = HeaderAndBody.Split(s_lineSeparators, StringSplitOptions.None);
            if (lines.Length == 0)
                return;
            // 解析请求行
            ParseRequestLine(lines[0]);
            // 解析请求头
            ParseHeaders(lines);
            // 解析查询字符串
            ParseQueryString();
            // 解析请求体（POST/PUT等，JSON/表单体依赖Body解析结果）
            ParseRequestBody(lines);
            // 解析POST参数（如果适用）
            ParsePostParams();
            // 解析Cookie键值对与JSON请求体（注入位置枚举用）
            ParseCookieParams();
            ParseJsonBodyParams();
            ParseMultipartParams();
            ParseXmlBodyParams();
            // 自动更新Content-Length
            UpdateContentLength();
        }
        private void UpdateContentLength()
        {
            //重新计算并设置Content-length
            //chunked发送数据不修正Content-Length
            if (HeaderText?.IndexOf("Transfer-Encoding: chunked", StringComparison.Ordinal) != -1)
            {
                return;
            }
            if (Body == null)
            {
                Headers.Remove("Content-Length");
                Headers.Add("Content-Length","0");
                HeaderText=Regex.Replace(HeaderText, HttpConst.Content_Length_Str_M + "\\d+", "Content-Length: 0");
                HeaderAndBody=HeaderText+HttpConst.CTRL+BodyText;
            }
            else {
                Headers.Remove("Content-Length");
                Headers.Add("Content-Length", Body.Length+"");
                HeaderText = Regex.Replace(HeaderText, HttpConst.Content_Length_Str_M + "\\d+", "Content-Length: "+ Body.Length);
                HeaderAndBody = HeaderText + HttpConst.CTRL + BodyText;
            }
        }
        /// <summary>
        /// 解析请求行（第一行）
        /// </summary>
        private void ParseRequestLine(string request)
        {
            var parts = request.Split(' ');
            if (parts.Length < 3)
                throw new ArgumentException("无效的请求行格式");
            HttpMethod  method;
            Enum.TryParse(parts[0].Trim().ToUpper(), out method);
            Method= method;
            PathAndQuery = parts[1].Trim();
            Version = parts[2].Trim();
            // 分离路径和查询字符串[6](@ref)
            int queryIndex = PathAndQuery.IndexOf('?', StringComparison.Ordinal);
            if (queryIndex >= 0)
            {
                Path = PathAndQuery.Substring(0, queryIndex);
                Query = PathAndQuery.Substring(queryIndex + 1);
            }
            else
            {
                Path = PathAndQuery;
                Query = string.Empty;
            }
        }
        /// <summary>
        /// 解析请求头
        /// </summary>
        private void ParseHeaders(string[] lines)
        {
            int i = 1; // 从第二行开始，第一行是请求行
            while (i < lines.Length && !string.IsNullOrEmpty(lines[i]))
            {
                var line = lines[i];
                var separatorIndex = line.IndexOf(':', StringComparison.Ordinal);
                if (separatorIndex > 0)
                {
                    var key = line.Substring(0, separatorIndex).Trim();
                    var value = line.Substring(separatorIndex + 1).Trim();
                    Headers.Add(key, value);
                }
                i++;
            }
        }
        /// <summary>
        /// 解析查询字符串[7](@ref)
        /// </summary>
        private void ParseQueryString()
        {
            if (string.IsNullOrEmpty(Query))
                return;
            var queryParams = Query.Split('&');
            foreach (var param in queryParams)
            {
                //按首个'='切分：值本身可含'='（如base64填充"MQ=="），Split('=')全切会把这类参数整条丢弃
                int eq = param.IndexOf('=', StringComparison.Ordinal);
                if (eq > 0)
                {
                   QueryString[param[..eq]] = Uri.UnescapeDataString(param[(eq + 1)..]);
                    Params[param[..eq]] = Uri.UnescapeDataString(param[(eq + 1)..]);
                }
                else if (eq < 0 && param.Length > 0)
                {
                    QueryString[param] = string.Empty;
                    Params[param] = string.Empty;
                }
            }
        }
        /// <summary>
        /// 解析请求体
        /// </summary>
        private void ParseRequestBody(string[] lines)
        {
            // 查找空行分隔符[7](@ref)
            int bodyStartIndex = -1;
            for (int i = 1; i < lines.Length; i++)
            {
                if (string.IsNullOrEmpty(lines[i]))
                {
                    bodyStartIndex = i + 1;
                    break;
                }
            }
            if (bodyStartIndex > 0 && bodyStartIndex < lines.Length)
            {
                BodyText = string.Join("\r\n", lines, bodyStartIndex, lines.Length - bodyStartIndex);
                Body= Encoding.UTF8.GetBytes(BodyText);
            }
        }
        /// <summary>
        /// 解析POST请求参数[7](@ref)
        /// </summary>
        private void ParsePostParams()
        {
            if (!(Method.Equals(HttpMethod.POST) || Method.Equals(HttpMethod.PUT)) || string.IsNullOrEmpty(BodyText))
                return;
            // 检查Content-Type
            string contentType = GetHeader("Content-Type")?.ToLower ()?? "";
            if (contentType.Contains("application/x-www-form-urlencoded", StringComparison.Ordinal))
            {
                ParseUrlEncodedBody();
            }
            // JSON体由ParseJsonBodyParams展平到JsonParams（注入位置枚举用），此处不做整体反序列化
        }
        /// <summary>
        /// 解析URL编码的请求体
        /// </summary>
        private void ParseUrlEncodedBody()
        {
            var bodyParams = BodyText.Split('&');
            foreach (var param in bodyParams)
            {
                //按首个'='切分：值本身可含'='（如base64填充），避免整条参数被丢弃
                int eq = param.IndexOf('=', StringComparison.Ordinal);
                if (eq > 0)
                {
                    BodyParams[param[..eq]] = Uri.UnescapeDataString(param[(eq + 1)..]);
                }
                else if (eq < 0 && param.Length > 0)
                {
                    BodyParams[param] = string.Empty;
                }
            }
        }
        /// <summary>
        /// 解析Cookie头为键值对（level>=2 时对每个Cookie键做注入检测）
        /// </summary>
        private void ParseCookieParams()
        {
            string? cookie = GetHeader("Cookie");
            if (string.IsNullOrWhiteSpace(cookie)) return;
            foreach (string pair in cookie.Split(';', StringSplitOptions.RemoveEmptyEntries))
            {
                int eq = pair.IndexOf('=', StringComparison.Ordinal);
                if (eq > 0)
                {
                    CookieParams[pair[..eq].Trim()] = pair[(eq + 1)..].Trim();
                }
                else
                {
                    CookieParams[pair.Trim()] = "";
                }
            }
        }
        /// <summary>
        /// JSON请求体展平为点路径键值对（仅标量叶子，数组按 路径[下标] 展开），注入检测/利用按路径定位
        /// </summary>
        private void ParseJsonBodyParams()
        {
            string ct = GetHeader("Content-Type") ?? "";
            if (!ct.Contains("json", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(BodyText))
            {
                return;
            }
            try
            {
                System.Text.Json.Nodes.JsonNode? root = System.Text.Json.Nodes.JsonNode.Parse(BodyText);
                IsJsonBody = true;
                if (root != null) FlattenJson(root, "", JsonParams);
            }
            catch (Exception)
            {
                //非法JSON体不展平
            }
        }
        /// <summary>
        /// XML/SOAP请求体展平为路径键值对（叶子元素文本，SOAP报文Body内参数），注入检测/利用按路径定位。
        /// Content-Type含xml/soap，或body以'<'开头且能切出叶子文本时生效
        /// </summary>
        private void ParseXmlBodyParams()
        {
            if (IsJsonBody || IsMultipartBody || string.IsNullOrWhiteSpace(BodyText))
            {
                return;
            }
            string ct = GetHeader("Content-Type") ?? "";
            bool xmlish = ct.Contains("xml", StringComparison.OrdinalIgnoreCase) || ct.Contains("soap", StringComparison.OrdinalIgnoreCase);
            if (!xmlish && !BodyText.TrimStart().StartsWith('<'))
            {
                return;
            }
            try
            {
                var leaves = RequestRewriter.TokenizeXmlLeaves(BodyText);
                if (leaves.Count == 0)
                {
                    return;
                }
                IsXmlBody = true;
                foreach (var e in leaves)
                {
                    XmlParams[e.key] = e.value.Trim();
                }
            }
            catch (Exception)
            {
                //非法XML体不展平
            }
        }
        /// <summary>
        /// multipart/form-data 请求体解析：提取文本字段name->value（注入检测/利用按字段名定位），文件字段跳过
        /// </summary>
        private void ParseMultipartParams()
        {
            string ct = GetHeader("Content-Type") ?? "";
            if (!ct.Contains("multipart/form-data", StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(BodyText))
            {
                return;
            }
            Match bm = Regex.Match(ct, "boundary=(?<b>[^;\\s]+)");
            if (!bm.Success)
            {
                return;
            }
            string boundary = bm.Groups["b"].Value.Trim('"');
            IsMultipartBody = true;
            //按boundary切分，逐段解析part头与值
            string[] parts = BodyText.Split(new[] { "--" + boundary }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string part in parts)
            {
                string p = part.Trim('\r', '\n');
                if (p == "--" || string.IsNullOrWhiteSpace(p))
                {
                    continue;
                }
                int headEnd = p.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                if (headEnd < 0)
                {
                    continue;
                }
                string partHead = p[..headEnd];
                string partValue = p[(headEnd + 4)..];
                Match nm = Regex.Match(partHead, "name=\"(?<n>[^\"]+)\"");
                if (!nm.Success)
                {
                    continue;
                }
                //文件字段（带filename）不纳入文本注入枚举
                if (partHead.Contains("filename=", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                MultipartParams[nm.Groups["n"].Value] = partValue;
            }
        }
        private static void FlattenJson(System.Text.Json.Nodes.JsonNode node, string path, Dictionary<string, string> result)
        {
            switch (node)
            {
                case System.Text.Json.Nodes.JsonObject obj:
                    foreach (var kv in obj)
                    {
                        if (kv.Value != null)
                        {
                            FlattenJson(kv.Value, string.IsNullOrEmpty(path) ? kv.Key : path + "." + kv.Key, result);
                        }
                    }
                    break;
                case System.Text.Json.Nodes.JsonArray arr:
                    for (int i = 0; i < arr.Count; i++)
                    {
                        if (arr[i] != null)
                        {
                            var item = arr[i]; if (item != null) FlattenJson(item, path + "[" + i + "]", result);
                        }
                    }
                    break;
                case System.Text.Json.Nodes.JsonValue val:
                    result[path] = val.ToString();
                    break;
            }
        }

    }
}