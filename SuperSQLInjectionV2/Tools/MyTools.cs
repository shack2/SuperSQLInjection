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
        public const string httpLogPath = "logs/http/";

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



        public static Boolean checkEmpty(string str) {

            if (str != null && str.Length > 0)
            {
                return false;
            }
            else {
                return true;
            }
        }





        public static string RandIP()
        {
            Random rd = new Random();

            string ip = rd.Next(1, 255) + "." + rd.Next(1, 255) + "." + rd.Next(1, 255) + "." + rd.Next(1, 255);

            return ip;
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



        public static DBType CaseDBType(string dbname)
        {
                DBType db= DBType.UnKnow;
                Enum.TryParse(dbname, out db);
                return db;
        }


        //DB2的每列是数字或者字符的穷举
        private static String[] DB2_fillStr = { "1", "chr(32)"};


        private static String[] Infomix_fillStr = { "1", "''" };


       
        // 获得DB2的每列是数字或者字符的穷举
 
        public static List<String> GetDB2UnionTemplates(int sumCount, int showIndex)
        {
            return GetUnionTemplates(DB2_fillStr, sumCount, showIndex);
        }
        // 获得informix的每列是数字或者字符的穷举
        public static List<String> GetInformixUnionTemplates(int sumCount, int showIndex)
        {
            return GetUnionTemplates(Infomix_fillStr, sumCount, showIndex);
        }

        // 获得数据库的每列是数字或者字符的穷举
        private static List<String> GetUnionTemplates(String[] fillStr,int sumCount, int showIndex)
        {
            List < string > list= new List<String>();
            if (sumCount == 1)
            {
                list.Add("{data}");
               
            }
            else {
                int n = sumCount - 1;
                String[] codes = new String[2 << (n - 1)];
                CreateGrayCode(fillStr,codes, n);
                foreach(string code in codes)
                {
                    string cp = InsertShowTemplate(code, showIndex);
                    list.Add(cp);
                    //插入,显示列
                }
            }
            return list;
        }

        private static string InsertShowTemplate(string temlate,int showIndex) {
            List<String> list = new List<String>(temlate.Split(','));
            list.Insert(showIndex,"{data}");
            return String.Join(",", list);

        }

        private static void CreateGrayCode(String[] fillStr, String[] codes, int n)
        {
            if (n == 1)
            {
                codes[0] = fillStr[0];
                codes[1] = fillStr[1];
            }
            else
            {
                CreateGrayCode(fillStr,codes, n - 1);
                int len = 2 << (n - 1);
                int half = len >> 1;
                for (int i = len - 1, j = 0; i >= 0; i--)
                {
                    if (i < half)
                    {
                        codes[i] = fillStr[0] + "," + codes[--j];
                    }
                    else
                    {
                        codes[i] = fillStr[1] + "," + codes[j++];
                    }
                }
            }
        }


        public static int GetMax(List<int> nums) {
            if (nums.Count > 0) {
                nums.Sort();
                return nums[nums.Count-1];
            }
            
           
            return 0;
        }

        public static int GetMaxSecondByMillisecond(int longMillisecond)
        {
            double c = longMillisecond / (double)1000;
            return (int)(Math.Ceiling(c));
        }


        public static string GetUnionStartStrByBoolSleep(string payload)
        {
            String[] sstr ={"and","or"};
            int index = 0;
            foreach (string str in sstr) {
                index=payload.ToLower().IndexOf(str, StringComparison.Ordinal);
                if (index != -1)
                {
                    return payload.Substring(0, index+str.Length);
                }
                else {
                    break;
                }
            }
            
            return "";
        }










        /// <summary>
        /// JSON请求体位置注入：按点路径（支持 arr[0] 下标）替换标量值，保持其余结构不变
        /// </summary>
        //JSON写回使用宽松转义：< > & ' 等字符保持原文（注入标记<Encode>/<EncodeRaw>与payload引号不能被\uXXXX转义）







        
    }


}
