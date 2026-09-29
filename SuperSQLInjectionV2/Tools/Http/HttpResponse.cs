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
                ParseBodyByEncoding();
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
                    //Brotli解码兜底：浏览器报文常带Accept-Encoding: br，服务端真返回br时避免BodyTxt变二进制乱码
                    Body = UnBrotli();
                }
                else
                {
                    Body=BodyData.ToArray();
                }

            }
            else
            {
                Body = BodyData.ToArray();
            }
        }

        public byte[] UnGzip()
        {
            //BodyData写入后Position在末尾，解压前归位；leaveOpen=true防止包装流关闭时连带关闭BodyData
            if (BodyData.CanSeek)
            {
                BodyData.Position = 0;
            }
            GZipStream gs = new GZipStream(BodyData, CompressionMode.Decompress, true);
            MemoryStream outbuf = new MemoryStream();
            byte[] block = new byte[1024];

            try
            {
                while (true)
                {
                    int bytesRead = gs.Read(block, 0, block.Length);
                    if (bytesRead <= 0)
                    {
                        break;
                    }
                    else
                    {
                        outbuf.Write(block, 0, bytesRead);
                    }
                }
            }
            catch
            {
                throw;
            }
            finally
            {
                outbuf.Close();
                gs.Close();
            }
            return outbuf.ToArray();

        }

        public byte[] UnDeflate()
        {
            if (BodyData.CanSeek)
            {
                BodyData.Position = 0;
            }
            DeflateStream ds = new DeflateStream(BodyData, CompressionMode.Decompress, true);
            MemoryStream outbuf = new MemoryStream();
            byte[] block = new byte[1024];
            try
            {
                while (true)
                {
                    int bytesRead = ds.Read(block, 0, block.Length);
                    if (bytesRead <= 0)
                    {
                        break;
                    }
                    else
                    {
                        outbuf.Write(block, 0, bytesRead);
                    }
                }
            }
            catch
            {
                throw;

            }
            finally
            {
                outbuf.Close();
                ds.Close();

            }
            return outbuf.ToArray();

        }

        /// <summary>Brotli解压（.NET内置BrotliStream，无需第三方依赖）</summary>
        public byte[] UnBrotli()
        {
            //BodyData写入后Position在末尾，解压前必须归位，否则读到0字节（gzip/deflate同理）
            if (BodyData.CanSeek)
            {
                BodyData.Position = 0;
            }
            using BrotliStream bs = new BrotliStream(BodyData, CompressionMode.Decompress, true);
            using MemoryStream outbuf = new MemoryStream();
            bs.CopyTo(outbuf);
            return outbuf.ToArray();
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
