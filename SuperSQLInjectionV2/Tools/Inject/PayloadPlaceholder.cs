using System;

namespace SuperSQLInjectionV2.Tools.Inject
{
    /// <summary>
    /// 检测 payload 占位符上下文。
    /// 每个检测用例实例化一次，保证同一用例内所有 [RANDNUM] 等占位符取值一致。
    /// </summary>
    public class PayloadPlaceholder
    {
        private static readonly Random _rand = new Random();
        private const string LowerChars = "abcdefghijklmnopqrstuvwxyz";
        private const string HexChars = "0123456789abcdef";

        public int RandNum { get; }
        public int RandNum1 { get; }
        public int RandNum2 { get; }
        public int RandNum3 { get; }
        public int RandNum4 { get; }
        public int RandNum5 { get; }
        public string RandStr { get; }
        public string RandStr1 { get; }
        public string RandStr2 { get; }
        /// <summary>
        /// 报错注入分隔符原始随机串（如 qvxjka）：grep/解析侧使用。
        /// SQL侧永不直接出现该文本——payload/vector中分隔符按库编码（hex/chr）发送，
        /// 由服务端解码输出原始串，页面反射的payload只含编码形态，物理上不可能被grep误命中。
        /// </summary>
        public string RawDelimiterStart { get; }
        public string RawDelimiterStop { get; }
        /// <summary>
        /// 报错注入分隔符（hex形式，如 0x7176726a71，由RawDelimiterStart派生；保留兼容，新代码用Raw+按库编码）
        /// </summary>
        public string DelimiterStart { get; }
        public string DelimiterStop { get; }
        /// <summary>
        /// 通用SQL注释（-- 加随机串）
        /// </summary>
        public string GenericSqlComment { get; }
        /// <summary>延时秒数（支持0.5等小数值，检测均值标定/取数自适应下调可能产生非整数秒）</summary>
        public double SleepTime { get; set; }

        /// <summary>延时秒数SQL文本：整数输出无小数点（SLEEP(2)），小数走不变文化（SLEEP(0.5)，防区域文化逗号分隔符破坏SQL语法）</summary>
        public static string FormatSeconds(double t)
        {
            return t == Math.Floor(t)
                ? ((long)t).ToString()
                : t.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        public PayloadPlaceholder(double sleepTime = 1)
        {
            RandNum = NextNum();
            RandNum1 = NextNumExcept(RandNum);
            RandNum2 = NextNum();
            RandNum3 = NextNum();
            RandNum4 = NextNum();
            RandNum5 = NextNum();
            RandStr = NextStr(6);
            RandStr1 = NextStr(5);
            RandStr2 = NextStr(5);
            RawDelimiterStart = NextStr(6);
            RawDelimiterStop = NextStr(6);
            DelimiterStart = "0x" + HexOf(RawDelimiterStart);
            DelimiterStop = "0x" + HexOf(RawDelimiterStop);
            GenericSqlComment = "-- " + NextStr(5);
            SleepTime = sleepTime;
        }

        private static int NextNum()
        {
            return _rand.Next(1000, 99999);
        }

        private static int NextNumExcept(int except)
        {
            int v = NextNum();
            return v == except ? v + 1 : v;
        }

        private static string NextStr(int len)
        {
            char[] chars = new char[len];
            for (int i = 0; i < len; i++)
            {
                chars[i] = LowerChars[_rand.Next(LowerChars.Length)];
            }
            return new string(chars);
        }

        private static string HexOf(string s)
        {
            //随机串的hex形式（与旧版NextHexStr输出同分布：小写字母→两字符hex）
            char[] chars = new char[s.Length * 2];
            for (int i = 0; i < s.Length; i++)
            {
                byte b = (byte)s[i];
                chars[i * 2] = HexChars[b >> 4];
                chars[i * 2 + 1] = HexChars[b & 0xF];
            }
            return new string(chars);
        }

        /// <summary>
        /// 替换模板中的全部占位符。
        /// 同时剥离用例xml中的"!"前缀标记（如!SLEEP(...)）：用于标识不做转义的DBMS专属函数，
        /// 实际发送前会剥离（仅MySQL能把!SLEEP侥幸解析为NOT SLEEP，PG/Oracle/MSSQL直接语法错误）。
        /// </summary>
        public string Replace(string? template)
        {
            if (string.IsNullOrEmpty(template))
            {
                return template ?? "";
            }
            template = System.Text.RegularExpressions.Regex.Replace(template, "!(?=[A-Za-z]+\\()", "");
            return template
                .Replace("[RANDNUM1]", RandNum1.ToString(), StringComparison.Ordinal)
                .Replace("[RANDNUM2]", RandNum2.ToString(), StringComparison.Ordinal)
                .Replace("[RANDNUM3]", RandNum3.ToString(), StringComparison.Ordinal)
                .Replace("[RANDNUM4]", RandNum4.ToString(), StringComparison.Ordinal)
                .Replace("[RANDNUM5]", RandNum5.ToString(), StringComparison.Ordinal)
                .Replace("[RANDNUM]", RandNum.ToString(), StringComparison.Ordinal)
                .Replace("[RANDSTR1]", RandStr1, StringComparison.Ordinal)
                .Replace("[RANDSTR2]", RandStr2, StringComparison.Ordinal)
                .Replace("[RANDSTR]", RandStr, StringComparison.Ordinal)
                .Replace("[DELIMITER_START]", RawDelimiterStart, StringComparison.Ordinal)
                .Replace("[DELIMITER_STOP]", RawDelimiterStop, StringComparison.Ordinal)
                .Replace("[GENERIC_SQL_COMMENT]", GenericSqlComment, StringComparison.Ordinal)
                .Replace("[SLEEPTIME]", FormatSeconds(SleepTime), StringComparison.Ordinal)
                .Replace("[DELAYED]", FormatSeconds(SleepTime), StringComparison.Ordinal)
                .Replace("[SPACE_REPLACE]", " ", StringComparison.Ordinal)
                .Replace("[HASH_REPLACE]", "#", StringComparison.Ordinal)
                .Replace("[DOLLAR_REPLACE]", "$", StringComparison.Ordinal)
                .Replace("[AT_REPLACE]", "@", StringComparison.Ordinal);
        }

        /// <summary>
        /// SQL上下文渲染（payload/vector）：引号包裹的分隔符占位符（'[DELIMITER_START]'）整体替换为
        /// 按库编码表达式（MySQL=0x hex字面量、Oracle/PG/DB2=chr()||、MSSQL=char()+、SQLite/H2=char()||、
        /// Access=chr()&amp;、未知库=引号原文回退），服务端解码输出原始随机串；
        /// 页面反射的payload只含编码形态，grep（匹配原始串）物理上不可能误命中反射。
        /// 编码器与取数方言（DialectFactory.MarkerEncoder）同源，由调用方按库选择。
        /// </summary>
        public string ReplaceSql(string? template, SuperSQLInjectionV2.Payload.LiteralEncoder enc)
        {
            return ReplaceSql(template, enc, null, null);
        }

        /// <summary>
        /// SQL上下文渲染（显式分隔符版）：rawStart/rawStop非空时代替本实例随机分隔符。
        /// 利用期vector烘焙用——把vector自带的[DELIMITER_START]/[DELIMITER_STOP]对齐为取数回显标记组合
        /// （EchoMarkers.Start+Split / Split+End），使vector分隔符本身就是提取标记，
        /// [QUERY]槽位塞裸表达式即可（不再叠ConcatData第二层标记，报错回显容量不被双重标记吃光）。
        /// </summary>
        public string ReplaceSql(string? template, SuperSQLInjectionV2.Payload.LiteralEncoder enc, string? rawStart, string? rawStop)
        {
            if (string.IsNullOrEmpty(template))
            {
                return template ?? "";
            }
            string start = rawStart ?? RawDelimiterStart;
            string stop = rawStop ?? RawDelimiterStop;
            string t = template
                .Replace("'[DELIMITER_START]'", SuperSQLInjectionV2.Payload.TemplateDialect.Encode(start, enc), StringComparison.Ordinal)
                .Replace("'[DELIMITER_STOP]'", SuperSQLInjectionV2.Payload.TemplateDialect.Encode(stop, enc), StringComparison.Ordinal);
            //未加引号的分隔符占位符（若有）也按显式值替换，避免Replace回退到本实例随机串
            if (rawStart != null)
            {
                t = t.Replace("[DELIMITER_START]", start, StringComparison.Ordinal);
            }
            if (rawStop != null)
            {
                t = t.Replace("[DELIMITER_STOP]", stop, StringComparison.Ordinal);
            }
            return Replace(t);
        }
    }
}
