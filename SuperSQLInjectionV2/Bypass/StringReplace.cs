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
        /// <summary>Encode块匹配（T4：命名组一次捕获块类型t与块体body；配对闭合，避免旧lookbehind方案的跨块误判）</summary>
        [GeneratedRegex("\\<(?<t>Encode)\\>(?<body>[.\\s\\S]*?)\\<\\/\\k<t>\\>", RegexOptions.CultureInvariant)]
        private static partial Regex EncodeBlockRegex();

        /// <summary>Content-Type头提取（体位置编码策略判定用）</summary>
        [GeneratedRegex("(?im)^Content-Type:\\s*(?<ct>[^;\\r\\n]+)", RegexOptions.CultureInvariant)]
        private static partial Regex ContentTypeRegex();

        /// <summary>后置伴随规则指定指令（&lt;Sencond:标记名&gt;&lt;/Sencond&gt;）：提取标记名后从报文剔除，随请求流传递</summary>
        [GeneratedRegex("\\<Sencond:(?<tag>[^>\\s]+)\\>[.\\s\\S]*?\\<\\/Sencond\\>")]
        private static partial Regex SencondDirectiveRegex();

        /// <summary>
        /// 按块在报文中的位置推断编码策略：
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

        public static async Task<HttpRequest> StrReplaceCenterAsync(HttpRequest request)
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

            //替换request（vector原文复用模式：发送期把payload装进检出vector的[INFERENCE]/[QUERY]槽位再替换标记——
            //标记报文保持简单胶水可读，vector模板随注入记录持久化，分隔符按当前回显标记渲染永不失配）
            string injectPayload = request.Payload ?? "";
            if (!request.SkipVectorRender
                && config.DataConfig.IsVectorMode
                && request.HeaderAndBody.Contains(ConstData.InjectStr, StringComparison.Ordinal))
            {
                //时间通道[SLEEPTIME]取通道配置延时秒数SleepInjectMaxTime（与sleep发包/oracle阈值同源，支持0.5小数值）；
                //非时间通道（bool判断值是页面特征词，非数字）回退占位符默认1秒
                double sleep = config.DataConfig.IsTimeChannel ? Math.Max(0.5, config.SleepInjectMaxTime) : 1;
                injectPayload = Tools.Inject.InjectDetectEngine.RenderVectorForSend(
                    config.DataConfig.VectorTemplate, injectPayload, config.DataConfig.OrigValue, config.DataConfig.SelectedDBType,
                    sleep > 0 ? sleep : 1);
            }
            request.HeaderAndBody = request.HeaderAndBody.Replace(ConstData.InjectStr, injectPayload, StringComparison.Ordinal);

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

                //统一编码工具链（编码处理/tamper合并）：全部经QuickJS池化执行（内置项按Key从注册表取JS实现）
                foreach (BypassPlan.PayloadStep step in plan.PayloadSteps)
                {
                    str = await ScriptTamperEngine.TamperAsync(step.Js, str).ConfigureAwait(false);
                }

                //兜底URL编码：仅编码位（请求行query/URI段、urlencoded体）且未显式启用UrlEncode项时默认编码一次，
                //保证payload中的空格/引号/&/#等字符在请求行中合法（对标业界同类工具默认URL编码行为）；
                //原文位（Cookie/HTTP头/JSON/XML/multipart体）不兜底编码，保持payload原文
                //（base64encode工具启用时作为链上一步在其后执行：base64产物的+/=在查询位被此处转义）
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

            //Encode块/Token/payload替换改变了body长度，必须重算Content-Length：
            //完整构造在标记未替换时算的长度已失真（JSON/XML/multipart/urlencoded体位置注入时，
            //长度偏大会让服务器苦等剩余body字节卡数秒，偏小则残留字节污染同连接下一请求）
            request.HeaderAndBody = FixContentLength(request.HeaderAndBody);

            //重建请求后带回Payload：请求日志/HTTP日志展示用。
            //记录发送期实际装配后的完整payload（injectPayload：vector模式含触发函数前缀/分隔符/后缀的完整注入串，
            //非vector模式=原始表达式），而非仅query部分表达式，便于日志直接还原实际注入内容
            //T1：发送链路用轻量构造，跳过JSON/XML/multipart等全量解析（发送路径只用原文+Method/Path）
            HttpRequest result = HttpRequest.CreateForSend(request.AppConfig, request.HeaderAndBody);
            result.Payload = injectPayload;
            result.NullBodyHint = request.NullBodyHint;
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
        /// 仅当报文已带Content-Length头且非chunked时修正（GET/无body不新增头；chunked报文由脚本层剥离CL，不干预）。
        /// 绕过链路的Encode块/Token/payload/报文脚本替换都会改变body长度，发送前必须调用本方法收敛。
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

    }
}
