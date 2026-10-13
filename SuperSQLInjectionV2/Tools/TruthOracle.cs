using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Tools.Http;

namespace SuperSQLInjectionV2.Tools
{
    /// <summary>从 MyTools 拆分出的TruthOracle内聚簇</summary>
    public partial class TruthOracle
    {
        /// <summary>非空白字符判定（原逐循环new Regex的每次重建，源生成静态复用）</summary>
        [GeneratedRegex("[\\S]+")]
        private static partial Regex NonSpaceRegex();

        /// <summary>
        /// 判断页面注入true或false
        /// </summary>
        /// <param name="server">服务器响应对象ServerInfo</param>
        /// <param name="isUseCode">是否使用状态码判断</param>
        /// <param name="key">关键字</param>
        /// <param name="simTemplate">相似度判定比对基准（仅BoolInjectType.Similarity用，检测期确定后随注入记录携带）</param>
        /// <param name="simMode">相似度投影模式（""/skeleton/text）</param>
        /// <param name="simCutoff">相似度判定阈值</param>
        /// <param name="simFeatures">动态特征表（simMode=""时先清动态再比对，否则噪声压平ratio真假不可分）</param>
        /// <returns></returns>
        public static bool IsTrue(HttpResponse response, string key, bool reverKey, BoolInjectType keyType,
            string simTemplate = "", string simMode = "", double simCutoff = 0.95, List<ChangeFeature>? simFeatures = null)
        {
            switch (keyType) {

                case BoolInjectType.KeyWord:

                    //用关键字判断
                    if (!string.IsNullOrEmpty(response.BodyTxt) && response.BodyTxt.Contains(key, StringComparison.Ordinal))
                    {
                        if (reverKey)
                        {
                            return false;
                        }
                        else {
                            return true;
                        }

                    }
                    else
                    {
                        if (reverKey)
                        {
                            return true;
                        }
                        return false;
                    }

                case BoolInjectType.RegexWord:

                    //用正则判断
                    if (!string.IsNullOrEmpty(response.BodyTxt) && Regex.IsMatch(response.BodyTxt, key))
                    {
                        if (reverKey)
                        {
                            return false;
                        }
                        return true;
                    }
                    else
                    {
                        if (reverKey)
                        {
                            return true;
                        }
                        return false;
                    }
                case BoolInjectType.Code:
                    //用状态码判断
                    if (response.StatusCode> 0 && key.Equals(response.StatusCode + "", StringComparison.Ordinal))
                    {
                        if (reverKey)
                        {
                            return false;
                        }
                        return true;
                    }
                    else
                    {
                        if (reverKey)
                        {
                            return true;
                        }
                        return false;
                    }

                case BoolInjectType.Time:
                    //由于计数器有误差（可能客户端计数小于服务端，如果页面正常响应时间非常快，可能导致返回时间可能提前，所以考虑设置一个误差值）
                    int time = MyTools.ConvertToInt(key);
                    if (response.RunTime > (time*1000-(time*MyTools.deviation)))
                    {
                        if (reverKey)
                        {
                            return false;
                        }
                        return true;
                    }
                    else
                    {
                        if (reverKey)
                        {
                            return true;
                        }
                        return false;
                    }

                case BoolInjectType.BodyLength:
                    //用长度判断
                    if (key.Equals(response.JudgeLength.ToString(), StringComparison.Ordinal))
                    {
                        if (reverKey)
                        {
                            return false;
                        }
                        return true;
                    }
                    else
                    {
                        if (reverKey)
                        {
                            return true;
                        }
                        return false;
                    }

                case BoolInjectType.MaxLength:
                    //用长度判断
                    if (response.JudgeLength > MyTools.ConvertToInt(key))
                    {
                        if (reverKey)
                        {
                            return false;
                        }
                        return true;
                    }
                    else
                    {
                        if (reverKey)
                        {
                            return true;
                        }
                        return false;
                    }
                case BoolInjectType.MinLength:
                    //用长度判断
                    if (response.JudgeLength < MyTools.ConvertToInt(key))
                    {
                        if (reverKey)
                        {
                            return false;
                        }
                        return true;
                    }
                    else
                    {
                        if (reverKey)
                        {
                            return true;
                        }
                        return false;
                    }

                case BoolInjectType.Similarity:
                    //页面相似度判断（sqlmap同款取数oracle）：高动态页面离散判断依据不可靠时的三档兜底。
                    //三段式硬判（检测期/一次性校验场景）：≥0.98快判真、≤0.02快判假、其余按阈值分界；
                    //取数链路应改用JudgeSimilarity（灰区返回null交由上层重发）。基准缺失时判假（不误判真）
                    {
                        bool hit = !string.IsNullOrEmpty(simTemplate)
                                   && SimRatio(response, simTemplate, simMode, simFeatures) >= simCutoff;
                        return reverKey ? !hit : hit;
                    }

            }
            return false;

        }

        /// <summary>相似度比对：清动态模板模式（""）先用特征表清掉响应动态区（与模板同口径），再按模式投影算ratio</summary>
        private static double SimRatio(HttpResponse response, string simTemplate, string simMode, List<ChangeFeature>? simFeatures)
        {
            string? body = response.BodyTxt;
            if (simMode == "" && simFeatures is { Count: > 0 })
            {
                body = WebPageDiffAnalyzer.ClearDynamicText(simFeatures, body ?? "");
            }
            string projection = WebPageDiffAnalyzer.ProjectForMode(body, simMode);
            return PageLikeTool.CalculateSimilarity(simTemplate, projection);
        }

        /// <summary>
        /// 相似度三段式判定（sqlmap comparison同款）：ratio≥0.98快判真、≤0.02快判假、
        /// 与阈值距离&lt;灰区半宽（0.01）返回null=不可判定（取数链路据此重发而非硬猜）；
        /// 基准缺失返回false（绝不误判真）。返回值不含取反，取反由调用方应用
        /// </summary>
        public static bool? JudgeSimilarity(HttpResponse response, string simTemplate, string simMode, double simCutoff,
            List<ChangeFeature>? simFeatures = null)
        {
            if (string.IsNullOrEmpty(simTemplate))
            {
                return false;
            }
            double ratio = SimRatio(response, simTemplate, simMode, simFeatures);
            if (ratio >= Inject.DetectTuning.UpperBound)
            {
                return true;
            }
            if (ratio <= Inject.DetectTuning.LowerBound)
            {
                return false;
            }
            if (Math.Abs(ratio - simCutoff) < Inject.DetectTuning.SimGrayZone)
            {
                return null;
            }
            return ratio >= simCutoff;
        }

        public static string FindKeyByStr(string? trueString, string? falseString, string? oldString)
        {
            try
            {   //以时间判断
               if (trueString == null || falseString == null || oldString == null) { return ""; }
                string key = "";

               String[] Keys = Regex.Split(oldString, "[^\\u0080-\\uFFFF\\w\\d]+");

               foreach (string ckey in Keys) {
                    if (!falseString.Contains(ckey, StringComparison.Ordinal) && trueString.Contains(ckey, StringComparison.Ordinal)) {
                        return ckey;
                    }
               }
                for (int length = 5; length >= 1; length--)
                {
                        for (int i = 0; i < trueString.Length - length; i++)
                        {
                            if (trueString.Length <= length && !trueString.Equals(falseString, StringComparison.Ordinal))
                            {
                                return trueString;
                            }
                            string tempKey = trueString.Substring(i, length);
                            if (!falseString.Contains(tempKey, StringComparison.Ordinal) && oldString.Contains(key, StringComparison.Ordinal))
                            {
                                key = tempKey;
                                //非制表符，返回结果，否则继续查看是否还有其他关键词
                                if (NonSpaceRegex().IsMatch(key)) {
                                    return key;
                                }
                            }

                        }

                }
                return key;

            }
            catch (Exception e)
            {

                Log.SysLog("FindKeyByStr:" + e.Message);

            }
            return "";
        }

        public static int FindKeyByCode(int trueCode, int falseCode)
        {
            if (trueCode != falseCode) {
                return trueCode;
            }
            return 0;

        }

        public static int FindKeyCount(string str,string key)
        {
            int count = 0;
            try
            {
                if (!String.IsNullOrEmpty(str))
                {
                    int index = 0;

                    while (index != -1)
                    {
                        index = str.IndexOf(key, index + 1, StringComparison.Ordinal);
                        if (index != -1)
                        {
                            count++;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Log.SysLog("FindKeyCount:" + e.Message);
            }
            return count;

        }
    }
}
