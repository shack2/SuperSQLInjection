using System.Collections.Generic;

namespace SuperSQLInjectionV2.Models.Detect
{
    /// <summary>
    /// boundaries.xml 的 boundary 定义（注入点前后缀边界）
    /// </summary>
    public class PayloadBoundary
    {
        public int Level { get; set; }
        public List<int> Clause { get; set; } = new List<int>();
        public List<int> Where { get; set; } = new List<int>();
        /// <summary>
        /// 参数值类型：1=未转义数字 2=单引号字符串 3=LIKE单引号 4=双引号字符串 5=LIKE双引号 6=标识符 7=块注释 8=其他引号形式
        /// </summary>
        public int Ptype { get; set; }
        public string Prefix { get; set; } = "";
        public string Suffix { get; set; } = "";
    }

    /// <summary>
    /// payloads/*.xml 的 test 定义（单个检测用例）
    /// </summary>
    public class PayloadTest
    {
        public string Title { get; set; } = "";
        /// <summary>来源XML文件名（不含目录，如 boolean_blind.xml；命中次数统计定位用）</summary>
        public string FileName { get; set; } = "";
        /// <summary>
        /// 技术类型：1=布尔盲注 2=报错 3=内联查询 4=堆叠查询 5=时间盲注 6=Union查询
        /// </summary>
        public int SType { get; set; }
        public int Level { get; set; }
        public int Risk { get; set; }
        public List<int> Clause { get; set; } = new List<int>();
        public List<int> Where { get; set; } = new List<int>();
        public string Vector { get; set; } = "";
        public string RequestPayload { get; set; } = "";
        public string RequestComment { get; set; } = "";
        public string RequestChar { get; set; } = "";
        public string RequestColumns { get; set; } = "";
        /// <summary>
        /// 布尔/内联型：假条件payload（与真条件对比）
        /// </summary>
        public string ResponseComparison { get; set; } = "";
        /// <summary>
        /// 报错型：响应中正则提取标记
        /// </summary>
        public string ResponseGrep { get; set; } = "";
        /// <summary>
        /// 时间/堆叠型：延时时间占位
        /// </summary>
        public string ResponseTime { get; set; } = "";
        /// <summary>
        /// 适用数据库（空=通用），如 MySQL、Microsoft SQL Server
        /// </summary>
        public string Dbms { get; set; } = "";
        /// <summary>
        /// 排除的数据库
        /// </summary>
        public string DbmsExclude { get; set; } = "";
    }
}
