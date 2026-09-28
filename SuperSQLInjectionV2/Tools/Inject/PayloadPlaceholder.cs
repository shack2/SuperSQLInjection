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
        /// 报错注入分隔符（hex形式，如 0x7176726a71）
        /// </summary>
        public string DelimiterStart { get; }
        public string DelimiterStop { get; }
        /// <summary>
        /// 通用SQL注释（-- 加随机串）
        /// </summary>
        public string GenericSqlComment { get; }
        public int SleepTime { get; set; }

        public PayloadPlaceholder(int sleepTime = 1)
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
            DelimiterStart = "0x" + NextHexStr(6);
            DelimiterStop = "0x" + NextHexStr(6);
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

        private static string NextHexStr(int len)
        {
            //模拟随机字符串的hex形式
            char[] chars = new char[len * 2];
            for (int i = 0; i < len; i++)
            {
                byte b = (byte)LowerChars[_rand.Next(LowerChars.Length)];
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
                .Replace("[DELIMITER_START]", DelimiterStart, StringComparison.Ordinal)
                .Replace("[DELIMITER_STOP]", DelimiterStop, StringComparison.Ordinal)
                .Replace("[GENERIC_SQL_COMMENT]", GenericSqlComment, StringComparison.Ordinal)
                .Replace("[SLEEPTIME]", SleepTime.ToString(), StringComparison.Ordinal)
                .Replace("[DELAYED]", SleepTime.ToString(), StringComparison.Ordinal)
                .Replace("[SPACE_REPLACE]", " ", StringComparison.Ordinal)
                .Replace("[HASH_REPLACE]", "#", StringComparison.Ordinal)
                .Replace("[DOLLAR_REPLACE]", "$", StringComparison.Ordinal)
                .Replace("[AT_REPLACE]", "@", StringComparison.Ordinal);
        }
    }
}
