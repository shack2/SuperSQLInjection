using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using SuperSQLInjectionV2.Models;

namespace SuperSQLInjectionV2.Tools
{
    /// <summary>从 MyTools 拆分出的TextCodec内聚簇</summary>
    public class TextCodec
    {
        public static string unHexByUnicode(int unicode,string encoding){

            int c = TextCodec.UnicodeInt2UTF8Int(unicode);
            return TextCodec.unHex(Convert.ToString(c, 16), encoding);
        
        }

        public static string hexToRaw(string str,string encoding){
            if (str.Length % 2 == 0)
            {
                byte[] b = new byte[str.Length / 2];
                int j = 0;  
                for (int i = 0; i < str.Length; i += 2){
                    byte by = Convert.ToByte(str.Substring(i, 2), 16);//取两个字符，转换成对应的字节
                    b[j] = by;
                    j++;
                }
                return Encoding.GetEncoding(encoding).GetString(b);
            }
            else{
                throw new Exception("不能将该字符串转换成String类型!");
            }
        }

        /// <summary>
        /// Hex解码
        /// </summary>
        /// <param name="hex">Hex编码</param>
        /// <param name="charset">字符编码</param>
        /// <returns></returns>
        public static string unHex(string hex, string charset){
            if (hex == null)throw new ArgumentNullException("hex");
            hex = hex.Replace(",", "", StringComparison.Ordinal);
            hex = hex.Replace("\n", "", StringComparison.Ordinal);
            hex = hex.Replace("\\", "", StringComparison.Ordinal);
            hex = hex.Replace(" ", "", StringComparison.Ordinal); 
            if (hex.Length % 2 != 0){
                hex += "20";//空格
            }
            // 需要将 hex 转换成 byte 数组。              
            byte[] bytes = new byte[hex.Length / 2];            
            for (int i = 0; i < bytes.Length; i++){ 
            try{
                // 每两个字符是一个 byte。
                bytes[i] = byte.Parse(hex.Substring(i * 2, 2),
                System.Globalization.NumberStyles.HexNumber);
            } catch{
                // Rethrow an exception with custom message.
                throw new ("unHex解码错误---hex is not a valid hex number!");
            }
            }
            Encoding chs = Encoding.GetEncoding(charset);
            return chs.GetString(bytes);
        }

        public static string StringToHexString(string s, Encoding encode)
        {
            byte[] b = encode.GetBytes(s);//按照指定编码将string编程字节数组
            string result = string.Empty;
            for (int i = 0; i < b.Length; i++)//逐字节变为16进制字符
            {
                result += Convert.ToString(b[i], 16);
            }
            return result;
        }

        public static string HexStringToString(string hs, string encodeStr)
        {
            try
            {
                Encoding encode = Encoding.GetEncoding(encodeStr);
                string strTemp = "";
                byte[] b = new byte[hs.Length / 2];
                for (int i = 0; i < hs.Length / 2; i++)
                {
                    strTemp = hs.Substring(i * 2, 2);
                    b[i] = Convert.ToByte(strTemp, 16);
                }
                return encode.GetString(b);
            }
            catch (Exception e)
            {
                Log.SysLog("HexStringToString:" + e.Message);
            }
            return "";
        }

        public static string StrToHex(string str)
        {
            return StrToHex(str, "UTF-8");
        }

        public static string StrToHex(string str, string encode)
        {
            try
            {
                StringBuilder sb = new StringBuilder();//  存储转换后的编码
                Byte[] strByte;
                try
                {
                    strByte = Encoding.GetEncoding(encode).GetBytes(str);
                }
                catch
                {
                    //编码不可用（如未注册CodePagesEncodingProvider时GB2312抛异常）时回退UTF-8，避免返回空串导致payload静默失效
                    strByte = Encoding.UTF8.GetBytes(str);
                }
                foreach (Byte s in strByte)
                {
                    sb.Append(s.ToString("x").PadLeft(2, '0'));
                }
                return "0x" + sb.ToString();


            }
            catch (Exception e)
            {
                Log.SysLog("StrToHex:" + e.Message);
            }
            return "";
        }

        /// <summary>
        /// byte[]转hex，udf调用
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string BytesToHex(byte[] bytes)
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                if (bytes != null && bytes.Length > 0) {
                    foreach (Byte s in bytes)
                    {
                        sb.Append(s.ToString("x").PadLeft(2, '0'));
                    }
                   
                }
                return sb.ToString();
            }
            catch (Exception e)
            {
                Log.SysLog("BytesToHex:" + e.Message);
            }
            return "";
        }

        /// <summary>
        /// byte[]转hex，udf调用
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string FileToHex(string path,Encoding encode)
        {
            try
            {
                byte[] filedata=FileTool.readFileToByte(path, encode);
                return BytesToHex(filedata);
            }
            catch (Exception e)
            {
                Log.SysLog("FileToHex:" + e.Message);
            }
            return "";
        }

        public static string StrToChr(string str, string encode)
        {
            return StrToChr(str, encode, "||");
        }

        public static string StrToChr(string str, string encode, string joinStr)
        {
            return StrToChrOrChar(str, "chr", joinStr, encode);
        }

        public static string StrToChrOrChar(string str, string charFunction,string charConcatStr,string encode)
        {
            try
            {

                StringBuilder sb = new StringBuilder();
                Byte[] strByte = Encoding.GetEncoding(encode).GetBytes(str);
                foreach (Byte s in strByte)
                {
                    sb.Append(charFunction+"(" + s + ")"+ charConcatStr);
                }
                return sb.Remove(sb.Length - charConcatStr.Length, charConcatStr.Length).ToString();
            }
            catch (Exception e)
            {
                Log.SysLog("StrToChrOrChar:" + e.Message);
            }
            return "";
        }

        public static string ChrOrCharToStr(string str, string charFunction, string encode)
        {
            try
            {
                String[] chars = str.Split(' ');
                if (chars.Length > 0) {

                    Byte[] bs = new Byte[chars.Length];
                    int index = 0;
                    foreach (string s in chars)
                    {
                        string cs = s.Replace(charFunction,"", StringComparison.Ordinal).Replace(charFunction + "(", "", StringComparison.Ordinal).Replace(charFunction + ")", "", StringComparison.Ordinal);
                        Byte b = (Byte)MyTools.ConvertToInt(cs);
                        bs[index] = b;
                        index++;
                    }
                    return Encoding.GetEncoding(encode).GetString(bs);
                   
                }
                    
            }
            catch (Exception e)
            {
                Log.SysLog("ChrOrCharToStr:" + e.Message);
            }
            return "";
        }

        /// <summary>
        /// 转换chr供SQLServer替换库名，防止单引号被拦截或过滤
        /// </summary>
        /// <param name="str"></param>
        /// <param name="encode"></param>
        /// <returns></returns>
        public static string StrToChar(string str, string encode, string joinStr)
        {
            return StrToChrOrChar(str, "char", joinStr, encode);
        }

        public static string StrToChar(string str, string encode)
        {
            return StrToChrOrChar(str, "char", "+", encode);
        }

        public static string InformixStrToChr(string randstr)
        {
            return "to_char("+ randstr + ")";
        }

        public static int UnicodeInt2UTF8Int(int UnicodeInt)
        {
            if (UnicodeInt < 128)
            {
                return UnicodeInt;
            }
            int num = UnicodeInt >> 12 & 15;
            int num2 = UnicodeInt >> 6 & 63;
            int num3 = UnicodeInt & 63;
            return (num + 224 << 16) + (num2 + 128 << 8) + (num3 + 128);
        }

        public static int UTF8Int2UnicodeInt(int UTF8Int)
        {
            if (UTF8Int < 128)
            {
                return UTF8Int;
            }
            int num = UTF8Int >> 16 & 15;
            int num2 = UTF8Int >> 8 & 63;
            int num3 = UTF8Int & 63;
            return (num << 12) + (num2 << 6) + num3;
        }

        public static string StringToAscii(string str)
        {
            char[] cstr = str.ToCharArray();
            StringBuilder sb = new StringBuilder();
            foreach (char c in cstr) {
                sb.Append(Convert.ToInt32(c) + " ");
            }
            if (sb.Length > 1) {
                sb.Remove(sb.Length - 1, 1);
            }
            return sb.ToString();
        }

        public static string AsciiToString(string str)
        {
            try
            {
                String[] sstr = str.Split(' ');
                StringBuilder sb = new StringBuilder();
                foreach (string c in sstr)
                {
                    sb.Append(((char)(int.Parse(c))));
                }
                return sb.ToString();
            }
            catch (Exception e) {

                Log.SysLog("AsciiToString:" + e.Message);

            }
            return "";
        }

        public static string String2Unicode(string source)
        {
            var bytes = Encoding.Unicode.GetBytes(source);
            var stringBuilder = new StringBuilder();
            for (var i = 0; i < bytes.Length; i += 2)
            {
                stringBuilder.AppendFormat("%u{0}{1}", bytes[i + 1].ToString("x").PadLeft(2, '0'), bytes[i].ToString("x").PadLeft(2, '0'));
            }
            return stringBuilder.ToString();
        }
    }
}
