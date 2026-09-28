using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Tools;
using SuperSQLInjectionV2.Tools.Http;
using System.Linq;
namespace SuperSQLInjectionV2.Bypass
{
    public partial class StringReplace
    {
        /// <summary>
        /// 随机值缓存（P1-4：状态收归AppConfig实例，多目标/多任务隔离，见AppConfig.RandCache/LastRand）：
        /// 同一请求报文重发时复用同一随机值（二次注入页面对比/反射剔除依赖幂等）。
        /// 超容LRU剔最旧20%（替代整表Clear，避免幂等性瞬间整体失效）。
        /// 二次注入页请求复用该配置最近一次随机值（与刚发出的注入请求配对，不受报文差异影响）。
        /// </summary>
        private const int RandCacheCap = 500;

        /// <summary>Encode块匹配（T4：命名组一次捕获块类型t与块体body；配对闭合，避免旧lookbehind方案的跨块误判；
        /// EncodeRaw为历史标记，仅做兼容匹配，编码策略统一按块位置推断）</summary>
        [GeneratedRegex("\\<(?<t>Encode|EncodeRaw)\\>(?<body>[.\\s\\S]*?)\\<\\/\\k<t>\\>", RegexOptions.CultureInvariant)]
        private static partial Regex EncodeBlockRegex();

        /// <summary>Content-Type头提取（体位置编码策略判定用）</summary>
        [GeneratedRegex("(?im)^Content-Type:\\s*(?<ct>[^;\\r\\n]+)", RegexOptions.CultureInvariant)]
        private static partial Regex ContentTypeRegex();

        /// <summary>Rand块整体替换（每请求一次，源生成）</summary>
        [GeneratedRegex("(\\<Rand\\>[.\\s\\S]*?\\<\\/Rand\\>)")]
        private static partial Regex RandBlockRegex();

        /// <summary>后置伴随规则指定指令（&lt;Sencond:标记名&gt;&lt;/Sencond&gt;）：提取标记名后从报文剔除，随请求流传递</summary>
        [GeneratedRegex("\\<Sencond:(?<tag>[^>\\s]+)\\>[.\\s\\S]*?\\<\\/Sencond\\>")]
        private static partial Regex SencondDirectiveRegex();

        /// <summary>版本注释包裹的标识符切分</summary>
        [GeneratedRegex("[a-zA-Z_\\.\\(\\@]{2,50}")]
        private static partial Regex VersionCommentTokenRegex();

        /// <summary>
        /// 按块在报文中的位置推断编码策略（EncodeRaw标记废除后，Raw语义由位置承载）：
        /// 请求行（query/URI路径段）与urlencoded体=需URL编码（false）；头区（Cookie/各HTTP头）与JSON/XML/multipart体=保持原文（true）
        /// </summary>
        private static bool IsRawPosition(int blockIndex, int reqLineEnd, int headEnd, bool bodyUrlEncoded)
        {
            if (reqLineEnd > 0 && blockIndex < reqLineEnd)
            {
                return false;
            }
            if (headEnd > 0 && blockIndex < headEnd)
            {
                return true;
            }
            return !bodyUrlEncoded;
        }
        /// <summary>同步包装（仅控制台/TestHarness旧链路使用；UI与异步发送链路必须走StrReplaceCenterAsync，避免Roslyn脚本阻塞）</summary>
        public static HttpRequest StrReplaceCenter(HttpRequest request)
            => StrReplaceCenterAsync(request).GetAwaiter().GetResult();

        public static async System.Threading.Tasks.Task<HttpRequest> StrReplaceCenterAsync(HttpRequest request)
        {
            AppConfig config = request.AppConfig;
            BypassPlan plan = config.ByPassConfig.Plan;

            //后置伴随规则指定指令：<Sencond:标记名></Sencond>提取标记名随请求流传递（HTTPTool据此选择后置规则），指令本身从报文剔除
            //无指令的报文（常态）短路跳过正则扫描
            string? sencondTag = null;
            Match sencondMatch = request.HeaderAndBody.Contains("<Sencond:", StringComparison.Ordinal)
                ? SencondDirectiveRegex().Match(request.HeaderAndBody)
                : Match.Empty;
            if (sencondMatch.Success)
            {
                sencondTag = sencondMatch.Groups["tag"].Value;
                request.HeaderAndBody = SencondDirectiveRegex().Replace(request.HeaderAndBody, "");
            }

            //修改随机值：同报文复用缓存的随机值，不同报文（含不同目标/不同payload）各自独立；
            //无<Rand>块的请求不进缓存（缓存只服务块替换幂等），命中直接复用免锁免重复入队
            string rand;
            bool hasRandBlock = request.HeaderAndBody.Contains("<Rand>", StringComparison.Ordinal);
            if (request.Payload.Equals("请求二次注入页面", StringComparison.Ordinal))
            {
                //优先取请求流内携带的配对随机值（FlowRand，多线程安全）；退化为配置级LastRand（兼容控制台/TestHarness旧链路）
                rand = request.FlowRand ?? config.LastRand;
                if (string.IsNullOrEmpty(rand))
                {
                    rand = System.Guid.NewGuid().ToString("N");
                }
            }
            else if (!hasRandBlock)
            {
                //无<Rand>块：仍生成随机值随请求流传递（FlowRand供二次注入页配对），但不写缓存
                rand = System.Guid.NewGuid().ToString("N");
            }
            else if (!config.RandCache.TryGetValue(request.HeaderAndBody, out rand!))
            {
                rand = System.Guid.NewGuid().ToString("N");
                //T5：LRU淘汰——超容剔最旧20%（队列中重复键TryRemove自然容忍），不整体Clear；
                //锁内复查：同报文并发miss时复用先插入者的值，保证同报文同随机值（幂等）
                lock (config.RandCacheLock)
                {
                    if (config.RandCache.TryGetValue(request.HeaderAndBody, out string? existing))
                    {
                        rand = existing;
                    }
                    else
                    {
                        if (config.RandCache.Count > RandCacheCap)
                        {
                            int evict = RandCacheCap / 5;
                            while (evict-- > 0 && config.RandCacheLru.Count > 0)
                            {
                                config.RandCache.TryRemove(config.RandCacheLru.Dequeue(), out _);
                            }
                        }
                        config.RandCache[request.HeaderAndBody] = rand;
                        config.RandCacheLru.Enqueue(request.HeaderAndBody);
                    }
                }
            }
            config.LastRand = rand;

            //无<Rand>块的报文（盲注高并发常态）短路跳过正则扫描
            if (hasRandBlock)
            {
                request.HeaderAndBody = RandBlockRegex().Replace(request.HeaderAndBody, rand);
            }

            //替换request
            request.HeaderAndBody = request.HeaderAndBody.Replace(ConstData.InjectStr, request.Payload, StringComparison.Ordinal);

            //找到需要处理的字符（编码策略按块位置推断：请求行/urlencoded体=URL编码；头区/JSON/XML/multipart体=原文）
            //T4+Q1：单次命名组正则同时捕获块类型与块体（替代旧lookbehind匹配+每块3次全报文Contains判定）
            //无Encode块的报文（盲注高并发常态）短路跳过正则扫描；位置基线与ContentType判定仅在存在块时计算
            MatchCollection mc = request.HeaderAndBody.Contains("<Encode", StringComparison.Ordinal)
                ? EncodeBlockRegex().Matches(request.HeaderAndBody)
                : EncodeBlockRegex().Matches(string.Empty);
            //位置基线一次算好（m.Index基于匹配时的原文；逐块替换不改判定基准）
            int reqLineEnd = request.HeaderAndBody.IndexOf("\r\n", StringComparison.Ordinal);
            int headEnd = request.HeaderAndBody.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            Match ctMatch = mc.Count > 0 && headEnd > 0 ? ContentTypeRegex().Match(request.HeaderAndBody.Substring(0, headEnd)) : Match.Empty;
            bool bodyUrlEncoded = ctMatch.Success
                && ctMatch.Groups["ct"].Value.Contains("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase);
            string str = "";
            foreach (Match m in mc)
            {
                str = m.Groups["body"].Value;
                //该块是否保持原文（按位置：头区与非urlencoded体=原文位，跳过兜底URL编码）
                bool isRawBlock = IsRawPosition(m.Index, reqLineEnd, headEnd, bodyUrlEncoded);


                //替换字符（P0-2：计划快照驱动，热路径零ToList/零启用过滤）
                foreach ((string src, string target) in plan.ReplaceSteps)
                {
                    str = str.Replace(src, target, StringComparison.Ordinal);
                }

                //统一编码工具链（编码处理/tamper合并）：内置走C#委托，自定义走QuickJS；DoCount已在计划中展开
                //位置作用域：QueryOnly步骤跳过原文位块（换行/控制符产物在原文位会被防护剔除，提前跳过避免静默失效与无效计算）；
                //RawOnly步骤跳过编码位块
                foreach (BypassPlan.PayloadStep step in plan.PayloadSteps)
                {
                    if (step.Pos == EncodePos.QueryOnly && isRawBlock)
                    {
                        continue;
                    }
                    if (step.Pos == EncodePos.RawOnly && !isRawBlock)
                    {
                        continue;
                    }
                    if (step.Impl != null)
                    {
                        str = step.Impl(str);
                    }
                    else
                    {
                        str = await ScriptTamperEngine.TamperAsync(step.Js!, str).ConfigureAwait(false);
                    }
                }

                //兜底URL编码：仅编码位（请求行query/URI段、urlencoded体）且未显式启用UrlEncode项时默认编码一次，
                //保证payload中的空格/引号/&/#等字符在请求行中合法（对标业界同类工具默认URL编码行为）；
                //原文位（Cookie/HTTP头/JSON/XML/multipart体）不兜底编码，保持payload原文
                if (!isRawBlock && !plan.HasUrlEncodeItem)
                {
                    str = UrlEncoding(str);
                }

                //原文位CRLF防护：Cookie/HTTP头位置出现换行=头注入/畸形请求，剔除并告警
                //（换行版space2dash/space2hash等编码工具仅适用于查询位，原文位被剔除属预期行为）
                if (isRawBlock && (str.Contains('\r', StringComparison.Ordinal) || str.Contains('\n', StringComparison.Ordinal)))
                {
                    Log.Warning("原文位（头/体）块处理后内容含换行符，已剔除（防HTTP头注入）：请检查编码工具链，换行类编码仅适用于查询位");
                    str = str.Replace("\r", "", StringComparison.Ordinal).Replace("\n", "", StringComparison.Ordinal);
                }

                //整块替换：m.Value为含标记的完整块（<Encode>..</Encode>），直接替换为处理后内容
                request.HeaderAndBody = request.HeaderAndBody.Replace(m.Value, str, StringComparison.Ordinal);
            }
            //httpRequest.HeaderAndBody.Replace(ConstData.InjectStr, UrlEncoding(httpRequest.Payload));

            //Encode块/Rand/Token/payload替换改变了body长度，必须重算Content-Length：
            //完整构造在标记未替换时算的长度已失真（JSON/XML/multipart/urlencoded体位置注入时，
            //长度偏大会让服务器苦等剩余body字节卡数秒，偏小则残留字节污染同连接下一请求）
            request.HeaderAndBody = FixContentLength(request.HeaderAndBody);

            //重建请求后必须带回Payload：请求日志/HTTP日志均从此取值展示注入payload
            //T1：发送链路用轻量构造，跳过JSON/XML/multipart等全量解析（发送路径只用原文+Method/Path）
            HttpRequest result = HttpRequest.CreateForSend(request.AppConfig, request.HeaderAndBody);
            result.Payload = request.Payload ?? "";
            result.NullBodyHint = request.NullBodyHint;
            //请求流内随机值传递：本次<Rand>实际使用的值随请求流带出，供后置伴随请求（二次注入页）同流配对
            result.FlowRand = rand;
            //后置伴随规则指定标记名随请求流传递（HTTPTool据此选择后置规则）
            result.SencondTag = sencondTag;
            return result;
        }

        public static string UrlEncoding(string str)
        {

            str = URLEncode.UrlEncode(str);
            return str;

        }

        /// <summary>Content-Length头匹配（重算修正用）</summary>
        [GeneratedRegex("(?im)^Content-Length:\\s*\\d+", RegexOptions.CultureInvariant)]
        private static partial Regex ContentLengthRegex();

        /// <summary>
        /// 按当前body实际UTF8字节数重算Content-Length头。
        /// 仅当报文已带Content-Length头且非chunked时修正（GET/无body不新增头；chunked由ApplyChunked剥离CL，不干预）。
        /// 绕过链路的Encode块/Rand/Token/payload/报文脚本替换都会改变body长度，发送前必须调用本方法收敛。
        /// </summary>
        public static string FixContentLength(string headerAndBody)
        {
            if (string.IsNullOrEmpty(headerAndBody))
            {
                return headerAndBody;
            }
            int headEnd = headerAndBody.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (headEnd < 0)
            {
                return headerAndBody;
            }
            string head = headerAndBody[..headEnd];
            if (head.Contains("Transfer-Encoding: chunked", StringComparison.OrdinalIgnoreCase))
            {
                return headerAndBody;
            }
            Match m = ContentLengthRegex().Match(head);
            if (!m.Success)
            {
                return headerAndBody;
            }
            string body = headerAndBody[(headEnd + 4)..];
            int len = Encoding.UTF8.GetByteCount(body);
            return string.Concat(head[..m.Index], "Content-Length: ", len.ToString(), head[(m.Index + m.Length)..], "\r\n\r\n", body);
        }


        /// <summary>标识符包裹MySQL内联执行注释（kw→/*!kw*/，includecomment内置工具的实现）。含@的标识符（@@系统变量等）跳过不包裹</summary>
        public static string IncludeString(string str)
        {
            if (string.IsNullOrEmpty(str))
            {
                return str;
            }
            MatchCollection mc = VersionCommentTokenRegex().Matches(str);
            if (mc.Count == 0)
            {
                return str;
            }
            StringBuilder sb = new StringBuilder(str.Length + mc.Count * 5);
            int pos = 0;
            foreach (Match m in mc)
            {
                if (m.Value.Contains('@', StringComparison.Ordinal))
                {
                    continue;
                }
                sb.Append(str, pos, m.Index - pos);
                sb.Append("/*!").Append(m.Value).Append("*/");
                pos = m.Index + m.Length;
            }
            sb.Append(str, pos, str.Length - pos);
            return sb.ToString();
        }

    }
}
