using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using SuperSQLInjectionV2.Tools;

namespace SuperSQLInjectionV2.Bypass
{
    /// <summary>内置tamper条目（C#实现，零解释开销；名称与原JS脚本一致）</summary>
    public sealed class BuiltinTamper
    {
        public required string Name { get; init; }
        public required string Description { get; init; }
        public required Func<string, string> Impl { get; init; }
    }

    /// <summary>
    /// 内置tamper库（移植自tamper，共31个）：
    /// 内置项在编码处理页以"内置"标识展示（不可编辑代码，可启停/删除），执行时直接走C#委托不经过QuickJS。
    /// </summary>
    public static class BuiltinTampers
    {
        public static IReadOnlyDictionary<string, BuiltinTamper> All { get; } = BuildAll();

        public static bool TryGet(string name, out BuiltinTamper tamper)
        {
            return All.TryGetValue(name ?? "", out tamper!);
        }

        private static Dictionary<string, BuiltinTamper> BuildAll()
        {
            var d = new Dictionary<string, BuiltinTamper>(StringComparer.OrdinalIgnoreCase);
            void Reg(string name, string desc, Func<string, string> impl)
                => d[name] = new BuiltinTamper { Name = name, Description = desc, Impl = impl };

            //---- 固定/正则替换类 ----
            Reg("space2comment", "空格→内联注释/**/", s => s.Replace(" ", "/**/", StringComparison.Ordinal));
            Reg("space2plus", "空格→加号（查询串中等价空格，绕过只过滤空格的WAF）", s => s.Replace(" ", "+", StringComparison.Ordinal));
            Reg("uppercase", "关键字字母全部大写（跳过引号内字面量）", QuoteAwareCase(false));
            Reg("randomcase", "每个字母随机大小写（跳过引号内字面量）", QuoteAwareCase(true));
            Reg("unionalltounion", "UNION ALL→UNION（绕过只过滤UNION ALL的WAF）",
                s => Regex.Replace(s, @"\bUNION\s+ALL\b", "UNION", RegexOptions.IgnoreCase));
            Reg("equaltolike", "等号比较→LIKE比较（= → LIKE）",
                s => Regex.Replace(s, @"\s*=\s*", " LIKE "));
            Reg("symboliclogical", "AND→&&，OR→||（过滤AND/OR关键字的WAF）",
                s => Regex.Replace(Regex.Replace(s, @"\bAND\b", "&&", RegexOptions.IgnoreCase), @"\bOR\b", "||", RegexOptions.IgnoreCase));
            Reg("between", "a>b→a NOT BETWEEN 0 AND b；a=b→a BETWEEN b AND b（避开复合运算符）", Between);
            Reg("greatest", "a>b→GREATEST(a,b+1)=a（MySQL/MSSQL，与between互补）",
                s => Regex.Replace(s, @"\s*(?<![<])>(?!=)\s*(\d+|'[^']+'|\w+\(\d+\))", " GREATEST($1+1)=$1"));
            Reg("commalessmid", "MID(x,a,b)→MID(x FROM a FOR b)（MySQL逗号被过滤时）",
                s => Regex.Replace(s, @"MID\((.+?),\s*(\d+)\s*,\s*(\d+)\)", "MID($1 FROM $2 FOR $3)", RegexOptions.IgnoreCase));
            Reg("concat2concatws", "CONCAT(a,b)→CONCAT_WS(MID(CHAR(0),0,0),a,b)（MySQL CONCAT被过滤时）",
                s => Regex.Replace(s, @"\bCONCAT\(", "CONCAT_WS(MID(CHAR(0),0,0),", RegexOptions.IgnoreCase));
            Reg("ifnull2ifisnull", "IFNULL(A,B)→IF(ISNULL(A),B,A)（MySQL）",
                s => Regex.Replace(s, @"IFNULL\(([^,]+),\s*([^\)]+)\)", "IF(ISNULL($1), $2, $1)", RegexOptions.IgnoreCase));
            Reg("ifnull2casewhenisnull", "IFNULL(A,B)→CASE WHEN ISNULL(A) THEN B ELSE A END（各库通用）",
                s => Regex.Replace(s, @"IFNULL\(([^,]+),\s*([^\)]+)\)", "CASE WHEN ISNULL($1) THEN $2 ELSE $1 END", RegexOptions.IgnoreCase));
            Reg("modsecurityversioned", "整段payload包裹MySQL版本化注释/*!30000 ...*/（ModSecurity）",
                s => "/*!30000 " + s + "*/");
            Reg("versionedmorekeywords", "MySQL关键字包裹版本化注释（UNION→/*!50000UNION*/）",
                s => VersionedKeywords(s, "50000"));
            Reg("halfversionedmorekeywords", "MySQL关键字加半版本化注释前缀（UNION→/*!0UNION）",
                s => HalfVersionedKeywords(s));
            Reg("multiplespaces", "单空格→1~4个随机数量空格", MultipleSpaces);
            Reg("escapequotes", "单双引号加反斜杠转义（'→\\' \"→\\\"）",
                s => s.Replace("'", "\\'", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal));

            //---- 编码类 ----
            Reg("base64encode", "整段payload Base64编码（UTF-8）",
                s => Convert.ToBase64String(Encoding.UTF8.GetBytes(s)));
            Reg("charencode", "每个字符URL编码一次（字母数字也编码，已有%跳过）", s => CharPercentEncode(s, false));
            Reg("chardoubleencode", "每个字符双重URL编码（%25XX，已有%跳过）", s => CharPercentEncode(s, true));
            Reg("charunicodeencode", "非字母数字→%uXXXX（ASP/IIS宽字符场景）", CharUnicodeEncode);
            Reg("htmlencode", "非字母数字→HTML实体&#xXX;", HtmlEncode);
            Reg("percentage", "每个字符前加%（ASP/IIS宽松解析场景）", PercentagePrefix);
            Reg("apostrophemask", "单引号→UTF-8全角右单引号%EF%BC%87", s => s.Replace("'", "%EF%BC%87", StringComparison.Ordinal));
            Reg("apostrophenullencode", "单引号→%00%27（NUL+单引号）", s => s.Replace("'", "%00%27", StringComparison.Ordinal));

            //---- 随机空白/注释类 ----
            Reg("space2dash", "空格→破折号注释+随机串+换行（--x%0a，MySQL/MSSQL）", s => Space2CommentLine(s, "--", false));
            Reg("space2hash", "空格→井号注释+随机串+换行（%23x%0a，MySQL）", s => Space2CommentLine(s, "#", true));
            Reg("space2randomblank", "空格→随机空白符（空格/Tab/LF/CR/VT/FF）", Space2RandomBlank);
            Reg("space2mssqlblank", "空格→随机控制符%01-%1F（MSSQL视为空白）", Space2MssqlBlank);
            Reg("randomcomments", "SQL关键字内部随机插入内联注释（SELECT→S/**/ELECT）", RandomComments);

            return d;
        }

        //======== 实现细节（与 config/tamper/*.js 逐字对齐）========

        /// <summary>randomcase/uppercase 共用：引号外字母做大小写变换（random=true随机，false全大写）</summary>
        private static Func<string, string> QuoteAwareCase(bool random) => payload =>
        {
            StringBuilder sb = new StringBuilder(payload.Length);
            bool inQuote = false;
            char quote = '\0';
            foreach (char c in payload)
            {
                if (c == '\'' || c == '"')
                {
                    if (!inQuote) { inQuote = true; quote = c; }
                    else if (c == quote) { inQuote = false; }
                    sb.Append(c);
                }
                else if (!inQuote && char.IsAsciiLetter(c))
                {
                    sb.Append(random
                        ? (Random.Shared.Next(2) == 0 ? char.ToLower(c) : char.ToUpper(c))
                        : char.ToUpper(c));
                }
                else
                {
                    sb.Append(c);
                }
            }
            return sb.ToString();
        };

        /// <summary>between：AND/OR语境或裸比较中的 > 替换为NOT BETWEEN；无>时 = 替换为BETWEEN..AND..</summary>
        private static string Between(string payload)
        {
            if (string.IsNullOrEmpty(payload))
            {
                return payload;
            }
            string ret = payload;
            var m = Regex.Match(ret, @"(\b(AND|OR)\b\s+)(?!.*\b(AND|OR)\b)([^>]+?)\s*(?<![<])>(?!=)\s*([^>]+)\s*$", RegexOptions.IgnoreCase);
            if (m.Success)
            {
                string rep = m.Groups[2].Value + " " + m.Groups[4].Value + " NOT BETWEEN 0 AND " + m.Groups[5].Value;
                ret = ret.Replace(m.Value, rep, StringComparison.Ordinal);
            }
            else
            {
                ret = Regex.Replace(ret, @"\s*(?<![<])>(?!=)\s*(\d+|'[^']+'|\w+\(\d+\))", " NOT BETWEEN 0 AND $1");
            }
            if (ret == payload)
            {
                var m2 = Regex.Match(ret, "(\\b(AND|OR)\\b\\s+)(?!.*\\b(AND|OR)\\b)([^=]+?)\\s*(?<![<>!])=(?!=)\\s*([\\w()]+)\\s*", RegexOptions.IgnoreCase);
                if (m2.Success)
                {
                    string rep2 = m2.Groups[2].Value + " " + m2.Groups[4].Value + " BETWEEN " + m2.Groups[5].Value + " AND " + m2.Groups[5].Value;
                    ret = ret.Replace(m2.Value, rep2, StringComparison.Ordinal);
                }
            }
            return ret;
        }

        /// <summary>charencode/chardoubleencode：逐字符%XX（%自身跳过；double=true时%25XX）</summary>
        private static string CharPercentEncode(string payload, bool doubleEncode)
        {
            StringBuilder sb = new StringBuilder(payload.Length * 3);
            foreach (char c in payload)
            {
                if (c == '%')
                {
                    sb.Append(c);
                }
                else
                {
                    sb.Append(doubleEncode ? "%25" : "%").Append(((int)c).ToString("X2"));
                }
            }
            return sb.ToString();
        }

        private static string CharUnicodeEncode(string payload)
        {
            StringBuilder sb = new StringBuilder(payload.Length * 6);
            foreach (char c in payload)
            {
                sb.Append(char.IsAsciiLetterOrDigit(c) ? c : "%u" + ((int)c).ToString("X4"));
            }
            return sb.ToString();
        }

        private static string HtmlEncode(string payload)
        {
            StringBuilder sb = new StringBuilder(payload.Length * 6);
            foreach (char c in payload)
            {
                if (char.IsAsciiLetterOrDigit(c))
                {
                    sb.Append(c);
                }
                else
                {
                    sb.Append("&#x").Append(((int)c).ToString("X2")).Append(';');
                }
            }
            return sb.ToString();
        }

        private static string PercentagePrefix(string payload)
        {
            StringBuilder sb = new StringBuilder(payload.Length * 2);
            foreach (char c in payload)
            {
                sb.Append(c == ' ' ? c : "%" + c);
            }
            return sb.ToString();
        }

        private static string MultipleSpaces(string payload)
        {
            StringBuilder sb = new StringBuilder(payload.Length * 2);
            foreach (char c in payload)
            {
                if (c == ' ')
                {
                    sb.Append(' ', 1 + Random.Shared.Next(4));
                }
                else
                {
                    sb.Append(c);
                }
            }
            return sb.ToString();
        }

        /// <summary>space2dash/space2hash：空格→注释符+随机小写字母+字面%0a（与原JS一致：%0a为字面序列，兜底URL编码会再编%）</summary>
        private static string Space2CommentLine(string payload, string comment, bool encodeComment)
        {
            const string letters = "abcdefghijklmnopqrstuvwxyz";
            StringBuilder sb = new StringBuilder(payload.Length * 4);
            string prefix = encodeComment ? "%23" : comment;
            foreach (char c in payload)
            {
                if (c == ' ')
                {
                    sb.Append(prefix).Append(letters[Random.Shared.Next(letters.Length)]).Append("%0a");
                }
                else
                {
                    sb.Append(c);
                }
            }
            return sb.ToString();
        }

        private static readonly char[] RandomBlanks = { ' ', '\t', '\n', '\r', '\v', '\f' };

        private static string Space2RandomBlank(string payload)
        {
            StringBuilder sb = new StringBuilder(payload.Length);
            foreach (char c in payload)
            {
                sb.Append(c == ' ' ? RandomBlanks[Random.Shared.Next(RandomBlanks.Length)] : c);
            }
            return sb.ToString();
        }

        private static string Space2MssqlBlank(string payload)
        {
            StringBuilder sb = new StringBuilder(payload.Length * 3);
            foreach (char c in payload)
            {
                if (c == ' ')
                {
                    int n = 1 + Random.Shared.Next(31);
                    if (n is 0x09 or 0x0a or 0x0d)
                    {
                        n = 0x0b; //跳过常规空白提高迷惑性
                    }
                    sb.Append('%').Append(n.ToString("X2"));
                }
                else
                {
                    sb.Append(c);
                }
            }
            return sb.ToString();
        }

        private static readonly string[] RandomCommentKeywords =
            { "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "AND", "OR", "GROUP", "ORDER", "HAVING", "LIMIT", "OFFSET" };

        private static string RandomComments(string payload)
        {
            string ret = payload;
            foreach (string kw in RandomCommentKeywords)
            {
                ret = Regex.Replace(ret, kw, m =>
                {
                    string w = m.Value;
                    if (w.Length < 3)
                    {
                        return w;
                    }
                    int pos = 1 + Random.Shared.Next(w.Length - 2);
                    return string.Concat(w.AsSpan(0, pos), "/**/", w.AsSpan(pos));
                }, RegexOptions.IgnoreCase);
            }
            return ret;
        }

        //---- versioned keywords 系列：复用StringReplace的关键字表与引号外处理思路 ----

        private static readonly string[] VersionedKeywordList = {
            "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE", "AND", "OR", "GROUP", "ORDER",
            "HAVING", "LIMIT", "CONCAT", "CHAR", "SLEEP", "BENCHMARK", "IF", "MID", "SUBSTRING", "LENGTH", "COUNT"
        };

        private static string VersionedKeywords(string payload, string version)
        {
            string ret = payload;
            foreach (string kw in VersionedKeywordList)
            {
                ret = Regex.Replace(ret, @"\b" + kw + @"\b", m => "/*!" + version + m.Value + "*/", RegexOptions.IgnoreCase);
            }
            return ret;
        }

        private static string HalfVersionedKeywords(string payload)
        {
            string ret = payload;
            foreach (string kw in VersionedKeywordList)
            {
                ret = Regex.Replace(ret, @"\b" + kw + @"\b", m => "/*!0" + m.Value, RegexOptions.IgnoreCase);
            }
            return ret;
        }
    }
}
