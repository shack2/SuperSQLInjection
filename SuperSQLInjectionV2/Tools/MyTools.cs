using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Tools.Http;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;

namespace SuperSQLInjectionV2.Tools
{
    public class MyTools
    {
        //由于计数器有误差（可能客户端计数小于服务端，，如果页面正常响应时间非常快，可能导致返回时间可能提前，所以考虑设置一个误差值）
        public const int deviation = 20;

        /// <summary>
        /// 随机生成小写字母
        /// </summary>
        /// <param name="len"></param>
        /// <returns></returns>
        public static string RandStr(int len)
        {
            StringBuilder str = new StringBuilder();
            Random rd = new Random();
            for (int i=0;i<len;i++) {
                char c=(char)rd.Next(97, 122);
                str.Append(c);
            }
            return str.ToString();
        }

        /// <summary>
        /// 随机生成小写字母
        /// </summary>
        /// <param name="len"></param>
        /// <returns></returns>
        public static string RandNum(int len)
        {
            StringBuilder str = new StringBuilder();
            Random rd = new Random();
            for (int i = 0; i < len; i++)
            {
                char c = (char)rd.Next(49, 58);
                str.Append(c);
            }
            return str.ToString();
        }

        /// <summary>
        /// 二分法取较大整数，用于盲注判断
        /// </summary>
        /// <param name="start"></param>
        /// <param name="end"></param>
        /// <returns></returns>
        public static int getLargeNum(int start,int end){

            int sum=start+end;
            if (sum == 1) {
                return 0;
            }
            if (sum % 2 == 0)
            {
                return sum / 2;
             }
             else {
                    return sum / 2;
             }

        }

        public static void DelFile(string filepath)
        {
            try
            {
                File.Delete(filepath);
            }
            catch (Exception e)
            {
                Log.SysLog("DelFile:" + e.Message);
            }
        }

        /// <summary>
        /// 将字符串转换成数字，错误返回0
        /// </summary>
        /// <param name="strs">字符串</param>
        /// <returns></returns>
        public static int ConvertToInt(string str)
        {

            try
            {
                return int.Parse(str);
            }
            catch (Exception e) {
                Log.SysLog("ConvertToInt:" + e.Message);
            }
            return 0;

        }

        /**
         字符转unicode
         */

        public static string Md5_16(string str){
            using var md5 = MD5.Create();
            string t2 = BitConverter.ToString(md5.ComputeHash(UTF8Encoding.UTF8.GetBytes(str)), 4, 8);
            t2 = t2.Replace("-", "", StringComparison.Ordinal);
            t2 = t2.ToLower();
            return t2;
        }
        public static string Md5_32(string str)
        {
            MD5 md5 = MD5.Create();//实例化一个md5对像
            // 加密后是一个字节类型的数组，这里要注意编码UTF8/Unicode等的选择　
            byte[] s = md5.ComputeHash(Encoding.UTF8.GetBytes(str));
            // 通过使用循环，将字节类型的数组转换为字符串，此字符串是常规字符格式化所得
            string pwd = "";
            for (int i = 0; i < s.Length; i++)
            {
                //将得到的字符串使用十六进制类型格式。格式后的字符是小写的字母，如果使用大写（X）则格式后的字符是大写字符 
                pwd = pwd + s[i].ToString("X");
            }
            return pwd;

        }

        public static string Substr(string? str, string startStr, string endStr) {
            try
            {
                if (!String.IsNullOrEmpty(str))
                {
                    if (String.IsNullOrEmpty(startStr) && String.IsNullOrEmpty(endStr)) {
                        return str;
                    }
                    int start = -1;
                    if (String.IsNullOrEmpty(startStr))
                    {
                        start = 0;
                    }
                    else {
                        start = str.IndexOf(startStr, StringComparison.Ordinal);
                    }
                    if (start != -1)
                    {
                        if (String.IsNullOrEmpty(endStr))
                        {
                            string token = str.Substring(start + startStr.Length);
                            return token;
                        }
                        else {
                            int end = str.IndexOf(endStr, start + startStr.Length, StringComparison.Ordinal);
                            if (end != -1)
                            {
                                string token = str.Substring(start + startStr.Length, end - start - startStr.Length);
                                return token;
                            }
                        }

                    }

                }
            }
            catch
            {

            }
            return "";

        }

        /// <summary>
        /// JSON请求体位置注入：按点路径（支持 arr[0] 下标）替换标量值，保持其余结构不变
        /// </summary>
        //JSON写回使用宽松转义：< > & ' 等字符保持原文（注入标记<Encode>/<EncodeRaw>与payload引号不能被\uXXXX转义）

    }

}
