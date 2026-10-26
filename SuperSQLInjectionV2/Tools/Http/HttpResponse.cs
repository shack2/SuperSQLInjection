using SuperSQLInjectionV2.Models;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace SuperSQLInjectionV2.Tools.Http
{
    public class HttpResponse
    {
        public AppConfig AppConfig { get; }
        public HttpResponse(AppConfig config)
        {
            AppConfig=config;
        }

        public string BodyClearText { get; set; } = "";

        /// <summary>
        /// HTTP协议版本
        /// </summary>
        public string Version { get; set; } = "HTTP/1.1";

        public long RunTime { get; set; } = 0;

        /// <summary>响应Body是否按协议完整读取；不完整响应禁止参与相似度、布尔和取数解析。</summary>
        public bool IsBodyComplete { get; set; }

        /// <summary>读取或解压过程中是否发生超时。</summary>
        public bool IsTimedOut { get; set; }

        /// <summary>响应是否因大小上限被截断。</summary>
        public bool IsTruncated { get; set; }

        /// <summary>响应完整性异常说明，仅用于诊断，不参与页面内容比较。</summary>
        public string? IntegrityError { get; set; }

        /// <summary>可进入上层协议判定的响应；状态码为0或Body不完整时不可用。</summary>
        public bool IsUsable => StatusCode > 0 && IsBodyComplete && !IsTruncated;

        /// <summary>
        /// HTTP协议版本
        /// </summary>
        public string ContentType { get; set; } = "";

        public HttpRequest HttpRequest { get; set; } = null!;

        public MemoryStream _bodyData { get; set; } = null!;

        public MemoryStream BodyData
        {
            get
            {
                return _bodyData;
            }
            set
            {
                _bodyData = value;
                try
                {
                    ParseBodyByEncoding();
                }
                catch (HttpResponseLimitException ex)
                {
                    IsBodyComplete = false;
                    IsTruncated = true;
                    IntegrityError = ex.Message;
                    Body = Array.Empty<byte>();
                }
            }
        }

        private string _headerTxt = string.Empty; // 缓存
        public string HeaderTxt
        {
            get => _headerTxt;
            set
            {
                _headerTxt = value;
                ParseHeader();
            }
        }

        public string HeaderAndBody
        {
            get => HeaderTxt+HttpConst.CTRL+BodyTxt;
        }

        public long BodyLength => Body?.Length ?? 0;

        public long ContentLength { get; set; } = 0;

        /// <summary>长度判断用的有效长度：null-connection模式不读body时取Content-Length头，否则取实际body长度</summary>
        public long JudgeLength => ContentLength > 0 ? ContentLength : BodyLength;

        /// <summary>
        /// 状态码 (如 200, 404)
        /// </summary>
        public int StatusCode { get; set; } = 0;

        /// <summary>
        /// 响应头集合
        /// </summary>
        public Dictionary<string,string> Headers { get; set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// 响应主体 (字节数组)
        /// </summary>
        public byte[]? Body { get; set; }

        public string PageEncoding { get; set; }= HttpConst.DefaultEncoding;

        /// <summary>
        /// 响应主体的字符串形式
        /// </summary>
        public string? BodyTxt
        {
            get
            {
                if (Body == null) return null;
                // 实际开发中应根据 Content-Type 中的 Charset 来选择编码，此处默认为 UTF-8

                Encoding encoding = Encoding.GetEncoding(HttpConst.DefaultEncoding);

                if (AppConfig.AutoEncode&&!string.IsNullOrEmpty(PageEncoding))
                {
                    encoding = Encoding.GetEncoding(PageEncoding);
                }
                else {
                    encoding = Encoding.GetEncoding((string)AppConfig.PageEncoding);
                }

                return encoding.GetString(Body);

            } 
        }

        private void ParseHeader()
        {
            try
            {
                string[] headers = Regex.Split(HeaderTxt, HttpConst.CT);
                int index= 0;
                //排除Set-Cookie
                headers.ToList().ForEach(line => {

                    index++;
                    if (index == 1)
                    {
                        string[] codesplit = line.Split(' ');
                        if (codesplit.Length > 0)
                        {
                            string[] sh = line.Split(' ');
                            if (sh.Length > 1)
                            {
                                int code= 0;
                                int.TryParse(sh[1],out code);
                                StatusCode = code;
                            }
                        }
                    }
                    else
                    {
                        if (string.IsNullOrEmpty(line) || line.ToLower().Contains(HttpConst.SetCookie, StringComparison.Ordinal)) {
                            return;
                        }
                        string[] kv = Regex.Split(line, ": ");

                        string value = "";

                        if (kv.Length<1)
                        {
                            return;
                        }
                        if (kv.Length > 1)
                        {
                           value = kv[1];
                        }
                        //处理重复键值
                        if (!Headers.ContainsKey(kv[0]))
                        {
                            Headers.Add(kv[0], value);
                        }
                        else {
                            //存在重复头
                            if (!Headers[kv[0]].Equals(kv[1], StringComparison.Ordinal))
                            {
                                Headers[kv[0]] = Headers[kv[0]] + ", " + value;
                            }
                            //相同值丢弃一个
                        }
                    }
                });
                //读取Header编码
                ParseHeaderEncoding();

                //读取响应长度
                ParseHeaderLength();
            }
            catch (Exception e)
            {
                //响应头解析异常不阻断主流程，但记录便于排查畸形响应
                SuperSQLInjectionV2.Tools.Log.SysLog("响应头解析异常：" + e.Message);
            }

        }

        private void ParseBodyByEncoding()
        {
            int rawLimit = Math.Max(1, AppConfig.MaxResponseBodyBytes);
            if (BodyData.Length > rawLimit)
            {
                throw new HttpResponseLimitException($"响应体超过上限 {rawLimit} 字节");
            }
            if (Headers.ContainsKey(HttpConst.Content_Encoding))
            {
                if (Headers[HttpConst.Content_Encoding].Contains("gzip", StringComparison.Ordinal))
                {
                    Body = UnGzip();
                }
                else if (Headers[HttpConst.Content_Encoding].Contains("deflate", StringComparison.Ordinal))
                {
                    Body = UnDeflate();
                }
                else if (Headers[HttpConst.Content_Encoding].Contains("br", StringComparison.Ordinal))
                {
                    Body = UnBrotli();
                }
                else
                {
                    Body = BodyData.ToArray();
                }
            }
            else
            {
                Body = BodyData.ToArray();
            }
        }

        public byte[] UnGzip() => DecodeBody(() => new GZipStream(BodyData, CompressionMode.Decompress, true));

        public byte[] UnDeflate() => DecodeBody(() => new DeflateStream(BodyData, CompressionMode.Decompress, true));

        /// <summary>Brotli解压（.NET内置BrotliStream，无需第三方依赖）</summary>
        public byte[] UnBrotli() => DecodeBody(() => new BrotliStream(BodyData, CompressionMode.Decompress, true));

        private byte[] DecodeBody(Func<Stream> streamFactory)
        {
            if (BodyData.CanSeek)
            {
                BodyData.Position = 0;
            }
            int limit = Math.Max(1, AppConfig.MaxDecompressedBodyBytes);
            using Stream decoder = streamFactory();
            using MemoryStream output = new MemoryStream();
            byte[] buffer = new byte[81920];
            int read;
            while ((read = decoder.Read(buffer, 0, buffer.Length)) > 0)
            {
                if (output.Length > limit - (long)read)
                {
                    throw new HttpResponseLimitException($"解压后响应体超过上限 {limit} 字节");
                }
                output.Write(buffer, 0, read);
            }
            return output.ToArray();
        }

        private void ParseHeaderEncoding (){

            if (Headers.TryGetValue(HttpConst.ContentType, out string? value)) {
                PageEncoding = getHTMLEncoding(value, "");
            }

        }

        private void ParseHeaderLength()
        {
            if (Headers.TryGetValue(HttpConst.Content_Length, out string? value))
            {
                long length = 0;
                long.TryParse(value, out length);
                ContentLength = length;
            }

        }

        private  string getHTMLEncoding(string header, string body)
        {
            if (string.IsNullOrEmpty(header) && string.IsNullOrEmpty(body))
            {
                return "";
            }
            string encode = "";
            Match m = Regex.Match(header, @"charset=(?<charset>[\w\-]+)", RegexOptions.IgnoreCase);
            if (m.Success)
            {
                encode = m.Groups["charset"].Value.ToUpper();
            }
            else
            {
                if (string.IsNullOrEmpty(body))
                {
                    return "";
                }
                m = Regex.Match(body, @"charset=['""]{0,1}(?<charset>[\w\-]+)['""]{0,1}", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    encode = m.Groups["charset"].Value.ToUpper();
                }
            }
            if ("UTF8".Equals(encode, StringComparison.Ordinal))
            {
                encode = "UTF-8";
            }
            return encode.ToUpper();

        }

    }
}
