using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Models
{
    internal class ConstData
    {
        /// <summary>当前软件版本（语义化版本，更新检测以此作为当前版本上报）</summary>
        public const string AppVersion = "2.0.0";

        public const string StartPoint = "<Encode>";
        public const string EndPoint = "</Encode>";
        public const string InjectStr = "$sql$";

        /// <summary>动态规则标记定界符（起止同一标记）：&lt;DRule&gt;标记名:占位值&lt;DRule&gt;</summary>
        public const string DRuleStart = "<DRule>";
        public const string DRuleEnd = "<DRule>";

        public const string TruePayload = " 1=1";
        public const string FalsePayload = " 1=2";

        /// <summary>跳过参数列表文件：注入检测时命中参数名（不区分大小写）直接跳过，用于静态/Token类参数降噪</summary>
        public const string JumpkeyPath = "config/injection/jumpkey.txt";



        public static List<int> ErrorHttpCode = new List<int>{501, 503,403, 502, 404,400, 401, 0};

      

        public static string GetEncodingPoint(string selectedText) {
        
            return $"{StartPoint}{selectedText}{EndPoint}";
       }

        /// <summary>动态规则标记：有占位值（选区数据）时为 &lt;DRule&gt;标记名:占位值&lt;DRule&gt;，无占位值（光标处空标记）为 &lt;DRule&gt;标记名&lt;DRule&gt;；
        /// 标记名为空时留空（运行时取第一条启用的动态值规则）。占位值仅用于人读与剥离还原，发包时整块被动态值替换</summary>
        public static string GetDRulePoint(string selectedText, string? tagName)
        {
            if (string.IsNullOrEmpty(selectedText))
            {
                return $"{DRuleStart}{tagName}{DRuleEnd}";
            }
            return $"{DRuleStart}{tagName}:{selectedText}{DRuleEnd}";
        }


        public static Dictionary<string, string> JumpkeyList = new Dictionary<string, string>();
        public static string GetInjectPoint()
        {
            return InjectStr;
        }


        public static string GetParamAndEncode(string data)
        {
            if (string.IsNullOrEmpty(data)) {
                return StartPoint + InjectStr + EndPoint;
            }
            return StartPoint+data+EndPoint;
        }
    }
}
