using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Tools;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace SuperSQLInjectionV2.Bypass
{
    /// <summary>编码工具条目（内置C#实现，零解释开销））</summary>
    public sealed class EncodeTool
    {
        /// <summary>唯一键（持久化到配置；内置项按Key解析实现）</summary>
        public required string Key { get; init; }
        /// <summary>显示名</summary>
        public required string Name { get; init; }
        /// <summary>功能说明</summary>
        public required string Description { get; init; }
        /// <summary>变换实现</summary>
        public required Func<string, string> Impl { get; init; }
        /// <summary>是否在"添加内置工具"列表可见（false=仅兼容旧配置的遗留变体）</summary>
        public required bool Visible { get; init; }
        /// <summary>适用位置：产出换行/控制符的工具标QueryOnly（原文位会被CRLF防护剔除而静默失效，直接在计划层跳过）</summary>
        public EncodePos Pos { get; init; } = EncodePos.Any;
    }

    /// <summary>
    /// 统一编码工具注册表（tamper/编码处理合并后的唯一事实源）：
    /// 以31个内置tamper为基底，吸收原EncodeType 19项——语义相同者去重（base64/space2comment/space2randomblank/
    /// apostrophemask/versionedmorekeywords等），语义更优者替换实现（space2dash/space2hash用换行版、equisetolike用安全正则、
    /// between用版、uppercase用引号感知版），原EncodeType独有能力保留（urlencode/hex/lowercase/altcase/unicode/includecomment）。
    /// 遗留变体（Visible=false）仅为旧配置保行为：charunicodeencodeall（全字符%uXXXX）、halfversionedmorekeywords-full（全包裹/*!0KW*/）。
    /// </summary>
    public static class EncodeToolRegistry
    {
        public static IReadOnlyDictionary<string, EncodeTool> All { get; } = Build();

        /// <summary>添加列表可见的工具（按名称排序）</summary>
        public static IReadOnlyList<EncodeTool> VisibleTools { get; } =
            All.Values.Where(t => t.Visible).OrderBy(t => t.Key, StringComparer.OrdinalIgnoreCase).ToArray();

        public static bool TryGet(string key, out EncodeTool tool)
        {
            return All.TryGetValue(key ?? "()", out tool!);
        }

        private static Dictionary<string, EncodeTool> Build()
        {
            var d = new Dictionary<string, EncodeTool>(StringComparer.OrdinalIgnoreCase);
            void Reg(string key, string name, string desc, Func<string, string> impl, bool visible = true)
                => d[key] = new EncodeTool { Key = key, Name = name, Description = desc, Impl = impl, Visible = visible };

            //---- 基底：31个内置tamper（实现见BuiltinTampers）----
            var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["space2comment"] = "空格转注释", ["space2plus"] = "空格转加号", ["uppercase"] = "全大写",
                ["randomcase"] = "随机大小写", ["unionalltounion"] = "UNION ALL转UNION", ["equaltolike"] = "等号转LIKE",
                ["symboliclogical"] = "逻辑符转符号", ["between"] = "比较转BETWEEN", ["greatest"] = "大于转GREATEST",
                ["commalessmid"] = "MID无逗号", ["concat2concatws"] = "CONCAT转CONCAT_WS",
                ["ifnull2ifisnull"] = "IFNULL转IF-ISNULL", ["ifnull2casewhenisnull"] = "IFNULL转CASE-WHEN",
                ["modsecurityversioned"] = "ModSecurity版本注释", ["versionedmorekeywords"] = "关键字版本注释",
                ["halfversionedmorekeywords"] = "关键字半版本注释", ["multiplespaces"] = "多空格",
                ["escapequotes"] = "引号转义", ["base64encode"] = "Base64编码", ["charencode"] = "逐字符URL编码",
                ["chardoubleencode"] = "双重URL编码", ["charunicodeencode"] = "Unicode宽字符编码",
                ["htmlencode"] = "HTML实体编码", ["percentage"] = "百分号前缀", ["apostrophemask"] = "单引号掩码",
                ["apostrophenullencode"] = "单引号NUL编码", ["space2dash"] = "空格转--注释",
                ["space2hash"] = "空格转#注释", ["space2randomblank"] = "空格转随机空白",
                ["space2mssqlblank"] = "空格转MSSQL控制符", ["randomcomments"] = "关键字内插注释",
            };
            foreach (var bt in BuiltinTampers.All.Values)
            {
                Reg(bt.Name, names.TryGetValue(bt.Name, out string? cn) ? cn : bt.Name, bt.Description, bt.Impl);
            }
            //产出换行/控制符的工具标QueryOnly：原文位（头/Cookie/JSON体）中这些字符会被CRLF防护剔除导致静默失效
            foreach (string qkey in new[] { "space2randomblank", "space2mssqlblank" })
            {
                if (d.TryGetValue(qkey, out EncodeTool? qt))
                {
                    d[qkey] = new EncodeTool { Key = qt.Key, Name = qt.Name, Description = qt.Description + "（仅编码位生效）", Impl = qt.Impl, Visible = qt.Visible, Pos = EncodePos.QueryOnly };
                }
            }

            //---- 语义更优实现覆盖（原EncodeType版）----
            //space2dash/space2hash：换行版（真换行由兜底URL编码为%0A；原JS字面%0a经兜底会被编成%250a导致失效）
            d["space2dash"] = new EncodeTool { Key = "space2dash", Name = "空格转--注释", Description = "空格→破折号注释+随机串+换行（--x%0a，MySQL/MSSQL；仅编码位生效）", Impl = s => Space2CommentLineNewline(s, "--"), Visible = true, Pos = EncodePos.QueryOnly };
            d["space2hash"] = new EncodeTool { Key = "space2hash", Name = "空格转#注释", Description = "空格→井号注释+随机串+换行（#x%0a，MySQL；仅编码位生效）", Impl = s => Space2CommentLineNewline(s, "#"), Visible = true, Pos = EncodePos.QueryOnly };
            //equaltolike：安全正则（避开<= >= != ==，原tamper版会误伤复合运算符）
            d["equaltolike"] = new EncodeTool { Key = "equaltolike", Name = "等号转LIKE", Description = "等号比较→LIKE比较（避开<=/>=/!=/==）", Impl = s => Regex.Replace(s, @"(?<![\<\>\!\=])\=(?![\=])", " LIKE "), Visible = true };

            //---- 原EncodeType独有能力保留 ----
            Reg("urlencode", "URL编码", "整段URL编码（特殊字符%XX；抑制Encode块兜底编码）", StringReplace.UrlEncoding);
            Reg("hex", "Hex编码", "整段转十六进制串（UTF-8字节）", s => TextCodec.StrToHex(s, "UTF-8"));
            Reg("lowercase", "全小写", "关键字字母全部小写（库名.表/全局变量/字符串不处理）", s => ToLowerOrUpperCase(s, " ", 3));
            Reg("altcase", "交替大小写", "关键字字母按位交替大小写（库名.表/全局变量/字符串不处理）", s => ToLowerOrUpperCase(s, " ", 1));
            Reg("unicode", "Unicode宽字符编码", "整段字符→%uXXXX（UTF-16宽字符，ASP/IIS场景）", TextCodec.String2Unicode);
            Reg("includecomment", "关键字内联注释", "标识符包裹MySQL内联执行注释（kw→/*!kw*/）", StringReplace.IncludeString);

            //---- 遗留变体（仅兼容旧配置，不在添加列表出现）----
            Reg("charunicodeencodeall", "Unicode宽字符编码(全字符)", "每个字符→%uXXXX（含字母数字，旧版CharUnicodeEncode行为）", CharUnicodeEncodeAll, visible: false);
            Reg("halfversionedmorekeywords-full", "关键字半版本注释(全包裹)", "MySQL关键字全包裹半版本注释（UNION→/*!0UNION*/，旧版行为）", s => VersionedKeywordsFull(s, "0"), visible: false);

            return d;
        }

        //======== 原EncodeType独有/更优实现（迁移自StringReplace）========

        /// <summary>space2dash/space2hash换行版：空格→注释符+随机串+真换行（随后由兜底URL编码为%0A）</summary>
        private static string Space2CommentLineNewline(string str, string comment)
        {
            StringBuilder sb = new StringBuilder();
            foreach (char c in str)
            {
                if (c == ' ')
                {
                    sb.Append(comment).Append(RandAlnum(6)).Append('\n');
                }
                else
                {
                    sb.Append(c);
                }
            }
            return sb.ToString();
        }

        private static string RandAlnum(int len)
        {
            const string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
            char[] buf = new char[len];
            for (int i = 0; i < len; i++)
            {
                buf[i] = chars[Random.Shared.Next(chars.Length)];
            }
            return new string(buf);
        }

        /// <summary>原LowerCase/UpperCase/LowerUperRand实现（库名.表、@变量、引号字符串、函数调用不处理）</summary>
        private static string ToLowerOrUpperCase(string oldStr, string split, int changeType)
        {
            StringBuilder sb = new StringBuilder();
            try
            {
                MatchCollection mc = Regex.Matches(oldStr, "([a-zA-Z_\\.]+|\\@+[a-zA-Z_]+|[a-zA-Z_]\\(\\)+|\\'[a-zA-Z_\\-]+\\')");
                foreach (Match m in mc)
                {
                    string keyStr = m.Groups[0].Value;
                    if (keyStr.Contains("'", StringComparison.Ordinal) || keyStr.Contains(".", StringComparison.Ordinal) || keyStr.Contains("@", StringComparison.Ordinal) || keyStr.Contains("()", StringComparison.Ordinal))
                    {
                        continue;
                    }
                    if (changeType == 1)
                    {
                        oldStr = oldStr.Replace(keyStr, AlternateCase(keyStr), StringComparison.Ordinal);
                    }
                    if (changeType == 2)
                    {
                        oldStr = oldStr.Replace(keyStr, keyStr.ToUpper(), StringComparison.Ordinal);
                    }
                    if (changeType == 3)
                    {
                        oldStr = oldStr.Replace(keyStr, keyStr.ToLower(), StringComparison.Ordinal);
                    }
                }

                string[] strs = Regex.Split(oldStr, split);
                for (int i = 0; i < strs.Length; i++)
                {
                    string s = strs[i];
                    if (s.Contains(".", StringComparison.Ordinal) || s.Contains("@", StringComparison.Ordinal) || s.Contains("(", StringComparison.Ordinal))
                    {
                        sb.Append(s);
                    }
                    else
                    {
                        sb.Append(AlternateCase(s));
                    }
                    if (i + 1 != strs.Length)
                    {
                        sb.Append(split);
                    }
                }
            }
            catch (Exception)
            {
                //忽略，返回已处理部分
            }
            return oldStr.Replace("0X", "0x", StringComparison.Ordinal);
        }

        private static string AlternateCase(string key)
        {
            StringBuilder sb = new StringBuilder();
            char[] cs = key.ToCharArray(0, key.Length);
            for (int j = 0; j < cs.Length; j++)
            {
                sb.Append(j % 2 == 0 ? char.ToUpper(cs[j]) : char.ToLower(cs[j]));
            }
            return sb.ToString();
        }

        /// <summary>MySQL关键字集合（旧版全包裹versionedkeywords用）</summary>
        private static readonly string[] MySqlKeywords = {
            "UNION","SELECT","FROM","WHERE","AND","OR","GROUP","ORDER","BY","LIMIT",
            "INSERT","UPDATE","DELETE","VALUES","INTO","CONCAT","CHAR","FLOOR","RAND","COUNT",
            "SLEEP","BENCHMARK","IF","LIKE","BETWEEN","IN","NOT","NULL","DISTINCT","ALL","AS",
            "JOIN","LEFT","RIGHT","INNER","OUTER","CROSS","HAVING","EXISTS","CAST","CONVERT",
            "SUBSTRING","MID","ASCII","ORD","HEX","UNHEX","DATABASE","USER","VERSION","SCHEMA"
        };

        /// <summary>旧版全包裹版本注释：MySQL关键字包裹为 /*!verKW*/（单引号内不处理，已在注释内的不重复包裹）</summary>
        private static string VersionedKeywordsFull(string str, string version)
        {
            string[] segs = str.Split('\'');
            for (int i = 0; i < segs.Length; i += 2)
            {
                foreach (string kw in MySqlKeywords)
                {
                    segs[i] = Regex.Replace(segs[i],
                        "(?<!/\\*!\\d{0,6})\\b" + kw + "\\b(?!\\*/)",
                        "/*!" + version + kw + "*/",
                        RegexOptions.IgnoreCase);
                }
            }
            return string.Join("'", segs);
        }

        /// <summary>旧版CharUnicodeEncode：每个字符都做%uXXXX编码（含字母数字）</summary>
        private static string CharUnicodeEncodeAll(string str)
        {
            StringBuilder sb = new StringBuilder();
            foreach (char c in str)
            {
                sb.Append("%u").Append(((int)c).ToString("X4"));
            }
            return sb.ToString();
        }
    }
}
