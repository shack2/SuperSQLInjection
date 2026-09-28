using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Models
{
    public class InjectPoint
    {


        public bool IsInject { get; set; } = false;

        public string UnionStartPayLoad { get; set; } = "";


        public string TestPayload { get; set; } = "";
        public bool Revers { get; set; } =false;

        public int ShowColumnIndex { get; set; } = 1;

        public int SumColumnCount { get; set; } = 1;

        public string RequestTxt { get; set; } = "";

        public string PName { get; set; } = "";

        public string PValue { get; set; } = "";

        /// <summary>注入位置（Query/BodyForm/Cookie/Header/BodyJson），默认Query兼容旧记录</summary>
        public ParamPlace Place { get; set; } = ParamPlace.Query;

        /// <summary>Place=Header时的头名称（如User-Agent/Referer）</summary>
        public string HeaderName { get; set; } = "";

        public InjectType InjectType { get; set; }= InjectType.UnKnow;

        public DBType DBType { get; set; } = DBType.UnKnow;
        public BoolInjectType BoolInjectType { get; set; }= BoolInjectType.KeyWord;
        public string CheckValue { get; set; } = "";

        /// <summary>where语义：1=ORIGINAL原值后追加；2=NEGATIVE负值替换；3=REPLACE参数整体替换（取数按vector模板注入）</summary>
        public int Where { get; set; } = 1;

        /// <summary>检出用例的vector模板（where=3参数替换点取数复用，[INFERENCE]/[QUERY]为取数槽位）</summary>
        public string VectorTemplate { get; set; } = "";

        /// <summary>注入参数原始值（where=3替换点记录原值，供vector中[ORIGVALUE]渲染）</summary>
        public string OrigValue { get; set; } = "";

        /// <summary>检测期自动适配的tamper名（如between：'>'被过滤时验证有效后记录，取数恢复记录时自动启用对应tamper）</summary>
        public string AutoTamper { get; set; } = "";

        /// <summary>检测期真值页HTTP状态码（防脏数据校验：取数探测出现TrueCode/FalseCode之外的意外码时探测作废重发）</summary>
        public int TrueCode { get; set; } = 0;

        /// <summary>检测期假值页HTTP状态码（与TrueCode构成合法状态码集合；0=未记录不做校验）</summary>
        public int FalseCode { get; set; } = 0;

        /// <summary>检出payload的boundary前缀（结构化双轨：供注入记录展示上下文类型，如 ' 型 / " 型 / 括号嵌套）</summary>
        public string Prefix { get; set; } = "";

        /// <summary>检出payload的boundary后缀（与Prefix配对记录）</summary>
        public string Suffix { get; set; } = "";

        /// <summary>Place=Uri时的路径段序号（非空段0基，恢复记录重烘焙定位用；-1=非URI注入）</summary>
        public int UriIndex { get; set; } = -1;

        /// <summary>检出boundary的SQL子句上下文（逗号分隔clause id：0=任意 1=WHERE 2=GROUP BY 3=ORDER BY 4=LIMIT 5=OFFSET 6=INSERT 7=UPDATE）；非0/1时取数"and"胶水可能不适用</summary>
        public string Clause { get; set; } = "";
    }
}
