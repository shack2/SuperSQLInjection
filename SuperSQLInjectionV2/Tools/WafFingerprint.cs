using System;
using System.Collections.Generic;
using System.Linq;
using SuperSQLInjectionV2.Tools.Http;

namespace SuperSQLInjectionV2.Tools
{
    /// <summary>
    /// WAF/IPS 指纹识别库（对标 waf 脚本 + nmap http-waf-fingerprint）。
    /// 规则命中位置：Server头 / 任意响应头 / Set-Cookie / 响应体。
    /// 被动识别（正常响应即暴露厂商特征，如 cf-ray 头）与主动识别（攻击特征串触发拦截页特征）共用同一规则表。
    /// </summary>
    public static class WafFingerprint
    {
        private static readonly string[] s_builtinTamperNames = { "space2comment", "randomcase", "equaltolike" };

        public enum Where { Server, Header, Cookie, Body }

        public class Rule
        {
            public string Vendor;
            public Where Location;
            public string Pattern;      //不区分大小写子串
            public bool ActiveOnly;     //true=仅在攻击响应中出现才算（避免正常页面内容误报）
            public Rule(string vendor, Where location, string pattern, bool activeOnly = false)
            {
                Vendor = vendor; Location = location; Pattern = pattern; ActiveOnly = activeOnly;
            }
        }

        private static readonly List<Rule> Rules = new List<Rule>
        {
            //---- 国外主流 ----
            new Rule("Cloudflare", Where.Header, "cf-ray"),
            new Rule("Cloudflare", Where.Server, "cloudflare"),
            new Rule("Cloudflare", Where.Cookie, "__cfduid"),
            new Rule("Cloudflare", Where.Cookie, "cf_clearance"),
            new Rule("Imperva Incapsula", Where.Cookie, "incap_ses"),
            new Rule("Imperva Incapsula", Where.Cookie, "visid_incap"),
            new Rule("Imperva Incapsula", Where.Header, "x-iinfo"),
            new Rule("Akamai Kona", Where.Server, "akamaighost"),
            new Rule("Akamai Kona", Where.Header, "akamai-"),
            new Rule("F5 BIG-IP ASM", Where.Cookie, "bigipserver"),
            new Rule("F5 BIG-IP ASM", Where.Cookie, "ts0", true),
            new Rule("F5 BIG-IP ASM", Where.Body, "the requested url was rejected. please consult with your administrator", true),
            new Rule("Barracuda", Where.Cookie, "barra_counter_session"),
            new Rule("Barracuda", Where.Body, "barracuda", true),
            new Rule("Fortinet FortiWeb", Where.Cookie, "fortiwafsid"),
            new Rule("Sucuri", Where.Header, "x-sucuri-id"),
            new Rule("Sucuri", Where.Server, "sucuri"),
            new Rule("ModSecurity", Where.Body, "mod_security", true),
            new Rule("ModSecurity", Where.Body, "modsecurity", true),
            new Rule("WebKnight", Where.Server, "webknight"),
            new Rule("dotDefender", Where.Header, "x-dotdefender"),
            new Rule("AWS WAF", Where.Header, "x-amzn-waf"),
            new Rule("AWS CloudFront", Where.Header, "x-amz-cf-id"),
            new Rule("DenyAll rWeb", Where.Cookie, "sessioncookie=", true),

            //---- 国内主流 ----
            new Rule("安全狗", Where.Server, "safedog"),
            new Rule("安全狗", Where.Cookie, "safedog-flow-item"),
            new Rule("安全狗", Where.Body, "safedog.cn", true),
            new Rule("安全狗", Where.Body, "waf.safedog.cn", true),
            new Rule("云锁", Where.Server, "yunsuo"),
            new Rule("云锁", Where.Cookie, "yunsuo_session"),
            new Rule("云锁", Where.Body, "yunsuologo", true),
            new Rule("D盾", Where.Body, "d盾", true),
            new Rule("创宇盾(知道创宇)", Where.Cookie, "365waf"),
            new Rule("创宇盾(知道创宇)", Where.Header, "365waf"),
            new Rule("创宇盾(知道创宇)", Where.Body, "365wzws", true),
            new Rule("创宇盾(知道创宇)", Where.Header, "x-pingback"),
            new Rule("玄武盾", Where.Cookie, "xwaf"),
            new Rule("安恒明御WAF", Where.Server, "waf/"),
            new Rule("安恒明御WAF", Where.Header, "waf/"),
            new Rule("阿里云盾", Where.Body, "errors.aliyun.com", true),
            new Rule("阿里云盾", Where.Body, "aliyunwaf", true),
            new Rule("阿里云盾", Where.Cookie, "aliyungf_tc"),
            new Rule("腾讯T-Sec WAF", Where.Body, "waf.tencentcloud.com", true),
            new Rule("腾讯T-Sec WAF", Where.Cookie, "tcwaf"),
            new Rule("百度云加速", Where.Header, "yjs-id"),
            new Rule("百度云加速", Where.Server, "yunjiasu"),
            new Rule("华为云WAF", Where.Header, "hwclouds"),
            new Rule("安全雷池SafeLine", Where.Cookie, "sl-session"),
            new Rule("安全雷池SafeLine", Where.Body, "safeline", true),
            new Rule("奇安信网神WAF", Where.Header, "qianxin"),
            new Rule("绿盟WAF", Where.Header, "nsfocus"),
            new Rule("网宿WAF", Where.Header, "wswaf"),
            new Rule("长亭雷池/牧云", Where.Header, "chaitin"),
            new Rule("宝塔WAF", Where.Server, "btwaf"),
            new Rule("宝塔WAF", Where.Cookie, "btwaf"),
            new Rule("极验WAF", Where.Header, "geetest"),
        };

        /// <summary>
        /// 对单个响应做指纹匹配，返回命中的厂商及依据（去重）。
        /// </summary>
        /// <param name="response">响应</param>
        /// <param name="isAttackResponse">是否为攻击特征串触发的响应（ActiveOnly规则只在此类响应上匹配）</param>
        public static List<string> Identify(HttpResponse response, bool isAttackResponse)
        {
            var hits = new List<string>();
            if (response == null)
            {
                return hits;
            }
            string headerAll = response.HeaderTxt ?? "";
            string? server = null;
            response.Headers?.TryGetValue("server", out server);
            //HttpResponse.ParseHeader刻意排除了Set-Cookie（防会话Cookie进头集合），这里从原始头文本提取
            string cookies = string.Join(";",
                System.Text.RegularExpressions.Regex.Matches(headerAll, "(?im)^set-cookie:\\s*(.+)$")
                    .Select(m => m.Groups[1].Value.Trim()));
            string body = response.BodyTxt ?? "";

            foreach (Rule r in Rules)
            {
                if (r.ActiveOnly && !isAttackResponse)
                {
                    continue;
                }
                string hay = r.Location switch
                {
                    Where.Server => server ?? "",
                    Where.Header => headerAll,
                    Where.Cookie => cookies,
                    _ => body
                };
                if (!string.IsNullOrEmpty(hay) && hay.Contains(r.Pattern, StringComparison.OrdinalIgnoreCase))
                {
                    string hit = $"{r.Vendor}（{r.Location}:{r.Pattern}）";
                    if (!hits.Contains(hit))
                    {
                        hits.Add(hit);
                    }
                }
            }
            return hits;
        }

        /// <summary>厂商名去重汇总（只保留厂商名列表）</summary>
        public static List<string> Vendors(List<string> hits)
        {
            return hits.Select(h => h.Split('（')[0]).Distinct().ToList();
        }

        //---------------- identywaf 正则指纹层（90家厂商） ----------------

        private static volatile List<(string Key, string Name, System.Text.RegularExpressions.Regex Re)>? _identYwafRules;

        /// <summary>惰性编译identywaf指纹（个别Python方言正则在.NET非法时跳过该条，不影响整体）</summary>
        private static List<(string Key, string Name, System.Text.RegularExpressions.Regex Re)> IdentYwafRules
        {
            get
            {
                if (_identYwafRules == null)
                {
                    var list = new List<(string, string, System.Text.RegularExpressions.Regex)>();
                    foreach (var (key, name, pattern) in Waf.WafIdentYwafData.Entries)
                    {
                        try
                        {
                            list.Add((key, name, new System.Text.RegularExpressions.Regex(pattern,
                                System.Text.RegularExpressions.RegexOptions.IgnoreCase
                                | System.Text.RegularExpressions.RegexOptions.CultureInvariant,
                                System.TimeSpan.FromSeconds(1))));
                        }
                        catch
                        {
                            //个别指纹正则方言不兼容，跳过
                        }
                    }
                    _identYwafRules = list;
                }
                return _identYwafRules;
            }
        }

        /// <summary>
        /// identywaf正则指纹识别：对响应头+体整体匹配90家厂商正则。
        /// isAttackResponse语义同Identify——正则层不区分主被动，由调用方决定用哪个响应
        /// </summary>
        public static List<string> IdentifyByIdentYwaf(HttpResponse response)
        {
            var hits = new List<string>();
            if (response == null)
            {
                return hits;
            }
            string raw = (response.HeaderTxt ?? "") + "\n" + (response.BodyTxt ?? "");
            if (raw.Length <= 1)
            {
                return hits;
            }
            foreach (var (key, name, re) in IdentYwafRules)
            {
                try
                {
                    if (re.IsMatch(raw))
                    {
                        hits.Add($"{name}（identywaf:{key}）");
                    }
                }
                catch (System.Text.RegularExpressions.RegexMatchTimeoutException)
                {
                    //单条超时跳过，不打断其余指纹
                }
            }
            return hits;
        }

        //---------------- 厂商→编码工具/tamper 推荐（识别后给候选优先级提示，不自动改行为） ----------------

        /// <summary>厂商关键词→推荐编码工具key（按有效性排序，仅覆盖有公认绕过脚本的厂商）</summary>
        private static readonly (string VendorKey, string[] Tampers)[] TamperRecommendations =
        {
            ("modsecurity", new[] { "modsecurityversioned", "space2comment", "equaltolike", "between" }),
            ("cloudflare", new[] { "space2comment", "randomcase", "between", "percentage" }),
            ("safedog", new[] { "halfversionedmorekeywords", "space2comment", "randomcase" }),
            ("安全狗", new[] { "halfversionedmorekeywords", "space2comment", "randomcase" }),
            ("imperva", new[] { "space2comment", "percentage", "randomcase" }),
            ("incapsula", new[] { "space2comment", "percentage", "randomcase" }),
            ("big-ip", new[] { "space2comment", "randomcase", "between" }),
            ("f5", new[] { "space2comment", "randomcase", "between" }),
            ("fortiweb", new[] { "space2comment", "randomcase" }),
            ("fortinet", new[] { "space2comment", "randomcase" }),
            ("barracuda", new[] { "space2comment", "randomcase" }),
            ("akamai", new[] { "randomcase", "space2randomblank", "percentage" }),
            ("sucuri", new[] { "space2comment", "randomcase" }),
            ("雷池", new[] { "space2comment", "randomcase", "space2randomblank" }),
            ("safeline", new[] { "space2comment", "randomcase", "space2randomblank" }),
        };

        /// <summary>按识别到的厂商名给出编码工具候选优先级（命中厂商专属映射在前，通用三件套兜底；仅提示不自动启用）</summary>
        public static List<string> RecommendTampers(List<string> vendors)
        {
            var result = new List<string>();
            foreach (string v in vendors)
            {
                string lv = v.ToLowerInvariant();
                foreach (var (vendorKey, tampers) in TamperRecommendations)
                {
                    if (lv.Contains(vendorKey, StringComparison.Ordinal))
                    {
                        foreach (string t in tampers)
                        {
                            if (!result.Contains(t))
                            {
                                result.Add(t);
                            }
                        }
                    }
                }
            }
            if (result.Count == 0 && vendors.Count > 0)
            {
                result.AddRange(s_builtinTamperNames);
            }
            return result;
        }
    }
}
