using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Tools;
using SuperSQLInjectionV2.Tools.Http;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Bypass
{
    /// <summary>
    /// 绕过管道（P0-1）：显式有序Stage，替代原先散落在HTTPTool/StringReplace的6个隐式挂点。
    /// ApplyOnceAsync（每逻辑请求一次，产物可被多轮重试复用）：
    ///   Stage1 Token替换 → Stage2 payload/Encode块处理（StringReplace，计划快照驱动）→ Stage3 报文级脚本（eval语义）
    /// ApplyPerRetryAsync（每轮重试执行，作用于Stage产物副本，改写不叠加）：
    ///   Stage4 限速（--delay/--safe-freq）→ Stage5 随机UA（--random-agent）→ Stage5.5 随机源IP
    /// HPP/参数名混淆/chunked等协议级绕过已由脚本层实现（脚本库内置示例脚本，Stage3报文级脚本执行）。
    /// 认证/Digest/重试循环/二次注入仍由HTTPTool负责（属于传输语义，非绕过变换）。
    /// 全部Stage读取BypassPlan快照（P0-2），配置变更经Revision失效重建，热路径零集合拷贝。
    /// </summary>
    public static partial class BypassPipeline
    {
        /// <summary>动态规则标记块整体替换（每逻辑请求一次）；格式 &lt;DRule&gt;标记名:占位值&lt;DRule&gt;（占位值可省），按标记名关联规则</summary>
        [GeneratedRegex("(?<block>\\<DRule\\>(?<tag>[^:<>\\s]*)(?::(?<val>[.\\s\\S]*?))?\\<DRule\\>)")]
        private static partial Regex TokenBlockRegex();
        /// <summary>User-Agent头匹配（[^\r\n]* 避免吃掉行尾\r）</summary>
        [GeneratedRegex("(?im)^User-Agent:[^\r\n]*")]
        private static partial Regex UserAgentHeaderRegex();
        /// <summary>
        /// 每逻辑请求执行一次的绕过变换链。isSubRequest为true（Token/二次注入子请求）时跳过Token替换防递归。
        /// 返回处理后的新请求（原request不被Stage2/3改写后的内容污染）。
        /// </summary>
        public static async Task<HttpRequest> ApplyOnceAsync(HttpRequest request, bool isSubRequest)
        {
            //Stage1：动态规则标记替换（每次请求刷新；支持页面抓取或脚本计算两种来源）
            if (!isSubRequest)
            {
                await ReplaceTokenAsync(request).ConfigureAwait(false);
            }
            //Stage2：注入串替换/Encode块（字符替换→编码项→Payload级tamper→兜底URL编码）
            HttpRequest newRequest = await StringReplace.StrReplaceCenterAsync(request).ConfigureAwait(false);
            //Stage3：报文级脚本（eval语义）：tamper/编码处理后、发送前改写整份报文
            //注意：脚本只改报文文本，连接目标仍以原Host/Port为准（面向签名/token类改写）
            await ApplyRequestScriptsAsync(request.AppConfig, newRequest).ConfigureAwait(false);
            //报文脚本可能改写body长度，发送前收敛Content-Length（StrReplaceCenter内已修一次；
            //无报文级脚本时Stage3不可能改写报文，跳过本次全报文扫描）
            if (request.AppConfig.ByPassConfig.Plan.RequestTools.Length > 0)
            {
                newRequest.HeaderAndBody = StringReplace.FixContentLength(newRequest.HeaderAndBody);
            }
            return newRequest;
        }

        /// <summary>
        /// 每轮重试执行一次的传输侧绕过（调用方须先把HeaderAndBody复位为ApplyOnceAsync产物，保证改写不层层叠加）
        /// </summary>
        public static async Task ApplyPerRetryAsync(HttpRequest request)
        {
            BypassPlan plan = request.AppConfig.ByPassConfig.Plan;
            //Stage4：频率控制（固定延时+每秒最大请求数，AppConfig实例级串行限速）
            await ApplyFreqAsync(request.AppConfig, plan).ConfigureAwait(false);
            //Stage5：随机UA
            ApplyRandomUa(request, plan);
            //Stage5.5：随机源IP头伪造
            ApplyRandomIp(request, plan);
        }

        /// <summary>清空Token缓存（测试/重置场景用；状态为AppConfig实例字段，按配置维度清理）</summary>
        public static void ResetTokenCache(AppConfig config)
        {
            config.LastToken = "";
        }

        //---- Stage1：动态规则标记（DRule） ----

        /// <summary>
        /// 替换请求中的动态规则<DRule>标记（每次请求刷新）。流程：先按配置的请求来源（报文/URL）抓取动态值页面响应，
        /// 再按抓取方式提取——字符串截取（开始/结束字符）或脚本提取（输入为完整HTTP响应报文：头+body，输出随机值）。
        /// P1-4：上次Token值收归AppConfig.LastToken（原静态字典按配置分槽的等效语义）。
        /// </summary>
        /// <summary>
        /// 按动态值规则抓取并提取/生成动态值（管道Token替换与弹窗"测试获取"共用的唯一实现）。
        /// 来源：报文/URL抓取HTTP响应后提取（截取或脚本）；脚本生成（SourceMode=2）不发HTTP请求，脚本输入为主请求报文（scriptInput），输出即为动态值（API签名等场景）。
        /// 返回动态值；失败时Error为可读原因（未配置/请求失败/未配置脚本或截取规则/异常）。
        /// </summary>
        public static async Task<(string Token, string? Error)> FetchTokenAsync(AppConfig config, CompanionRequestConfig before, string payloadTag, string? scriptInput = null)
        {
            try
            {
                //脚本生成：不发HTTP请求，脚本直接生成动态值（输入为主请求报文，空输入传空串）；按自主生成类型解析脚本
                if (before.SourceMode == 2)
                {
                    ScriptTamperModel? gen = config.ResolveTokenScript(before, 1);
                    if (gen == null || string.IsNullOrWhiteSpace(gen.Code))
                    {
                        return ("", "请求中存在<DRule>标记，但脚本生成模式未配置动态值脚本！请在防护绕过-脚本库-动态规则脚本页新增脚本并在规则中选择。");
                    }
                    return (ScriptTamperEngine.Tamper(gen, scriptInput ?? "") ?? "", null);
                }
                HttpRequest? tokenRequest = before.BuildRequest(config, payloadTag);
                if (tokenRequest == null)
                {
                    return ("", payloadTag + "：动态规则未配置或无效（报文/URL），请检查动态值规则配置！");
                }
                HttpResponse tokenResponse = await HTTPTool.SendRequestRetryAsync(tokenRequest, true).ConfigureAwait(false);
                if (tokenResponse == null || tokenResponse.StatusCode == 0)
                {
                    return ("", payloadTag + "：请求失败，请检查网络或请求包是否正确！");
                }
                if (before.UseScript)
                {
                    //脚本提取：按请求抓取类型解析脚本
                    ScriptTamperModel? script = config.ResolveTokenScript(before, 0);
                    if (script == null || string.IsNullOrWhiteSpace(script.Code))
                    {
                        return ("", "请求中存在<DRule>标记，但未配置动态值抓取脚本！请在防护绕过-脚本库-动态规则脚本页新增脚本并在规则中选择。");
                    }
                    //脚本提取：输入为抓取请求返回的完整HTTP响应报文（头+\r\n\r\n+body），输出随机值
                    return (ScriptTamperEngine.Tamper(script, tokenResponse.HeaderAndBody) ?? "", null);
                }
                if (string.IsNullOrEmpty(before.SubStart) && string.IsNullOrEmpty(before.SubEnd))
                {
                    return ("", "请求中存在<DRule>标记，但未配置动态值截取规则（开始/结束字符至少填一项）！");
                }
                return (MyTools.Substr(tokenResponse.BodyTxt, before.SubStart, before.SubEnd) ?? "", null);
            }
            catch (SuperSQLInjectionV2.Tools.Http.TargetUnreachableException)
            {
                //目标不可达：上抛快速终止，不降级为「动态值获取失败」让主请求继续空跑
                throw;
            }
            catch (Exception e)
            {
                return ("", "获取动态值异常：" + e.Message);
            }
        }

        private static async Task ReplaceTokenAsync(HttpRequest request)
        {
            AppConfig config = request.AppConfig;
            string headerAndBody = request.HeaderAndBody;
            if (!headerAndBody.Contains("<DRule>", StringComparison.Ordinal))
            {
                return;
            }
            //按标记名分组：同名标记共享一次抓取（一个请求内同名<DRule>tag<DRule>块取同一动态值）
            var groups = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (Match m in TokenBlockRegex().Matches(headerAndBody))
            {
                string tag = m.Groups["tag"].Success ? m.Groups["tag"].Value : "";
                if (!groups.TryGetValue(tag, out List<string>? blocks))
                {
                    blocks = new List<string>();
                    groups[tag] = blocks;
                }
                blocks.Add(m.Groups["block"].Value);
            }
            foreach (KeyValuePair<string, List<string>> kv in groups)
            {
                //解析规则：无标记名=第一条启用的前置规则；有标记名=按标记名关联
                CompanionRequestConfig? before = kv.Key.Length == 0
                    ? config.ActiveCompanionBefore
                    : config.FindCompanionRule(0, kv.Key);
                if (before == null)
                {
                    Log.SysLog(kv.Key.Length == 0
                        ? "请求中存在动态规则<DRule>标记，但未启用动态值规则！请在防护绕过-动态规则页新增并启用规则。"
                        : $"请求中存在动态规则<DRule>标记（标记名 {kv.Key}），但未找到对应的已启用动态值规则！");
                    continue;
                }
                //脚本生成来源时主请求报文作为脚本输入（签名类场景）；抓取来源忽略该参数
                (string token, string? error) = await FetchTokenAsync(config, before, "获取动态值", headerAndBody).ConfigureAwait(false);
                if (error != null)
                {
                    Log.SysLog(error);
                    continue;
                }
                foreach (string block in kv.Value)
                {
                    headerAndBody = headerAndBody.Replace(block, token, StringComparison.Ordinal);
                }
                config.LastToken = token;
            }
            request.HeaderAndBody = headerAndBody;
        }

        //---- Stage3：报文级脚本 ----

        /// <summary>报文级编码工具链（计划快照中已按序过滤启用项）：空输出保持当前报文，异常由引擎内兜底返回原文</summary>
        private static async Task ApplyRequestScriptsAsync(AppConfig config, HttpRequest request)
        {
            BypassPlan plan = config.ByPassConfig.Plan;
            if (plan.RequestTools.Length == 0)
            {
                return;
            }
            string txt = request.HeaderAndBody;
            foreach (EncodeToolModel item in plan.RequestTools)
            {
                string rewritten = await ScriptTamperEngine.TamperAsync(item, txt).ConfigureAwait(false);
                if (!string.IsNullOrEmpty(rewritten))
                {
                    txt = rewritten;
                }
            }
            request.HeaderAndBody = txt;
        }

        //---- Stage4：频率控制 ----

        /// <summary>
        /// 发包前频率控制（固定延时+每秒最大请求数）。限速语义为AppConfig实例级串行（多目标互不占槽，
        /// 状态已从进程级static收归实例），等待用Task.Delay而非Thread.Sleep，盲注高并发时不堆积阻塞线程
        /// </summary>
        private static async Task ApplyFreqAsync(AppConfig config, BypassPlan plan)
        {
            int delay = Math.Max(0, plan.DelayMs);
            int minInterval = plan.SafeFreq > 0 ? 1000 / plan.SafeFreq : 0;
            if (delay <= 0 && minInterval <= 0)
            {
                return;
            }
            int sleep;
            await config.ThrottleSem.WaitAsync().ConfigureAwait(false);
            try
            {
                double sinceLast = (DateTime.Now - config.ThrottleLastSend).TotalMilliseconds;
                sleep = Math.Max(delay, (int)Math.Ceiling(Math.Max(0, minInterval - sinceLast)));
                //预约时间槽：下一请求从预约结束时刻起算间隔，保证限速
                config.ThrottleLastSend = DateTime.Now.AddMilliseconds(sleep);
            }
            finally
            {
                config.ThrottleSem.Release();
            }
            if (sleep > 0)
            {
                await Task.Delay(sleep).ConfigureAwait(false);
            }
        }

        //---- Stage5：随机UA ----

        /// <summary>内置UA池（random-agent 能力，覆盖主流浏览器）</summary>
        private static readonly string[] UaPool = {
            //PC·Windows（Win10/11 同为 Windows NT 10.0）
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
            //PC·macOS
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
            //PC·Linux
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0",
            //手机·iPhone
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.7 Mobile/15E148 Safari/604.1",
            //手机·Android
            "Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 15; SM-S9280) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 14; 23113RKC6C Build/UKQ1.230917.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Mobile Safari/537.36",
            //手机·HarmonyOS
            "Mozilla/5.0 (Linux; Android 12; HarmonyOS; ALN-AL00; HMSCore 6.15.0.300) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Phone; OpenHarmony 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36 ArkWeb/4.1.6.1"
        };

        /// <summary>内置UA池（UA池页"导入内置UA"按钮用）</summary>
        public static string[] BuiltinUaPool => UaPool;

        /// <summary>随机UA替换（random-agent 能力）：自定义池快照非空时优先，否则用内置池</summary>
        private static void ApplyRandomUa(HttpRequest request, BypassPlan plan)
        {
            if (!plan.RandomUa)
            {
                return;
            }
            string ua = plan.CustomUaPool.Length > 0
                ? plan.CustomUaPool[Random.Shared.Next(plan.CustomUaPool.Length)]
                : UaPool[Random.Shared.Next(UaPool.Length)];
            string txt = request.HeaderAndBody;
            //[^\r\n]* 避免吃掉行尾 \r（默认匹配 \r，会破坏头体分隔符）
            //单趟 Match+Span 拼接：存在判定与替换共用一次扫描（原 IsMatch+Replace 双趟扫描合并，项9）
            Match m = UserAgentHeaderRegex().Match(txt);
            if (m.Success)
            {
                request.HeaderAndBody = string.Concat(txt.AsSpan(0, m.Index), "User-Agent: ", ua, txt.AsSpan(m.Index + m.Length));
            }
            else
            {
                //无UA头则追加到头区末尾（请求行后）
                int headEnd = txt.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                if (headEnd > 0)
                {
                    request.HeaderAndBody = txt.Insert(headEnd, "\r\nUser-Agent: " + ua);
                }
            }
        }

        //---- Stage5.5：随机源IP ----

        /// <summary>伪造源IP的三个头（名固定，正则预编译；[^\r\n]* 避免吃掉行尾\r）</summary>
        private static readonly (string Name, Regex Line)[] IpSpoofHeaders =
        {
            ("X-Forwarded-For", new Regex("(?im)^X-Forwarded-For:[^\r\n]*", RegexOptions.CultureInvariant | RegexOptions.Compiled)),
            ("X-Real-IP", new Regex("(?im)^X-Real-IP:[^\r\n]*", RegexOptions.CultureInvariant | RegexOptions.Compiled)),
            ("Client-IP", new Regex("(?im)^Client-IP:[^\r\n]*", RegexOptions.CultureInvariant | RegexOptions.Compiled))
        };

        /// <summary>随机源IP伪造（random-ip 能力）：每轮重试生成随机IPv4，替换/追加 X-Forwarded-For、X-Real-IP、Client-IP 头，
        /// 绕过基于源IP的访问控制/频率限制（仅作用于头区，不触碰body）</summary>
        private static void ApplyRandomIp(HttpRequest request, BypassPlan plan)
        {
            if (!plan.RandomIpEnabled)
            {
                return;
            }
            string txt = request.HeaderAndBody;
            int headEnd = txt.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (headEnd <= 0)
            {
                return;
            }
            //首段1-223（避开组播/保留段）、末段1-254，生成公网观感IPv4
            string ip = string.Concat(
                Random.Shared.Next(1, 224).ToString(), ".",
                Random.Shared.Next(0, 256).ToString(), ".",
                Random.Shared.Next(0, 256).ToString(), ".",
                Random.Shared.Next(1, 255).ToString());
            string head = txt[..headEnd];
            foreach ((string name, Regex line) in IpSpoofHeaders)
            {
                //与随机UA同款单趟合并：Match一次完成存在判定与替换定位
                Match m = line.Match(head);
                string headerLine = name + ": " + ip;
                head = m.Success
                    ? string.Concat(head.AsSpan(0, m.Index), headerLine, head.AsSpan(m.Index + m.Length))
                    : head + "\r\n" + headerLine;
            }
            request.HeaderAndBody = string.Concat(head, "\r\n\r\n", txt[(headEnd + 4)..]);
        }

    }
}
