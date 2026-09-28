using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace SuperSQLInjectionV2.Tools
{
    class StringTools
    {

        public static bool CheckIsIP(string ipStr) {
            return Regex.IsMatch(ipStr, @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}");
        }

        public static bool CheckIsDomain(string ipStr)
        {
            return Regex.IsMatch(ipStr, "[\\w\\-\\.]{1,100}[a-zA-Z]{1,8}");
        }

        public static bool IsNumber(string ipStr)
        {
            return Regex.IsMatch(ipStr, @"[\d]{1,5}");
        }
        
        public static bool CheckIsDomainOrIP(string str)
        {
            return (CheckIsDomain(str)|| CheckIsIP(str));
        }
    }
}
