using System;

namespace SuperSQLInjectionV2.Models
{
    /// <summary>
    /// 注入记录：检测到注入点时自动记录，可随时恢复到当前配置进行利用
    /// </summary>
    public class InjectRecord
    {
        /// <summary>TableView行勾选（工具栏"删除选中"批量操作目标；不参与序列化）</summary>
        [System.Text.Json.Serialization.JsonIgnore]
        public bool RowChecked { get; set; } = false;

        public string Id { get; set; } = Guid.NewGuid().ToString("N");

        /// <summary>
        /// 发现时间
        /// </summary>
        public DateTime Time { get; set; } = DateTime.Now;

        /// <summary>
        /// 目标摘要（host:port）
        /// </summary>
        public string Target { get; set; } = "";

        /// <summary>
        /// 注入参数名
        /// </summary>
        public string PName { get; set; } = "";

        public DBType DBType { get; set; } = DBType.UnKnow;

        /// <summary>识别到的Fork/衍生库名（如MariaDB/TiDB，DBType仍为族宿主库；空=未识别或非fork），随记录持久化</summary>
        public string ForkName { get; set; } = "";

        public InjectType InjectType { get; set; } = InjectType.UnKnow;

        public BoolInjectType BoolInjectType { get; set; } = BoolInjectType.KeyWord;

        /// <summary>
        /// 盲注判断值（关键字/状态码/延时时长）
        /// </summary>
        public string CheckValue { get; set; } = "";

        /// <summary>
        /// 盲注判断取反
        /// </summary>
        public bool Revers { get; set; } = false;

        /// <summary>相似度判定比对基准文本（BoolInjectType=Similarity时有效，高动态页面三档兜底取数oracle）</summary>
        public string SimilarTemplate { get; set; } = "";
        /// <summary>相似度判定投影模式（""=正常模板 / "skeleton"=结构骨架 / "text"=纯文本）</summary>
        public string SimilarMode { get; set; } = "";
        /// <summary>相似度判定阈值：ratio≥该值判真</summary>
        public double SimilarCutoff { get; set; } = 0.95;

        /// <summary>Union总列数（仅Union注入有意义，其余类型记录中无意义）</summary>
        public int SumColumnCount { get; set; } = 1;

        /// <summary>Union显示列下标（仅Union注入有意义）</summary>
        public int ShowColumnIndex { get; set; } = 1;

        /// <summary>列数显示文本：非Union注入不显示无意义的数值</summary>
        [System.Text.Json.Serialization.JsonIgnore]
        public string SumColumnCountText => InjectType == InjectType.Union ? SumColumnCount.ToString (): "-";

        /// <summary>显示位显示文本：非Union注入不显示无意义的数值</summary>
        [System.Text.Json.Serialization.JsonIgnore]
        public string ShowColumnIndexText => InjectType == InjectType.Union ? ShowColumnIndex.ToString (): "-";

        public string UnionStartPayLoad { get; set; } = "";

        /// <summary>
        /// 检测成功时的测试payload
        /// </summary>
        public string TestPayload { get; set; } = "";

        /// <summary>
        /// 带注入标记（$sql$）的完整请求报文
        /// </summary>
        public string RequestTxt { get; set; } = "";

        /// <summary>
        /// 注入标记参数值
        /// </summary>
        public string PValue { get; set; } = "";

        /// <summary>注入位置（Query/BodyForm/Cookie/Header/BodyJson），默认Query兼容旧记录</summary>
        public ParamPlace Place { get; set; } = ParamPlace.Query;

        /// <summary>Place=Header时的头名称</summary>
        public string HeaderName { get; set; } = "";

        /// <summary>where语义：1=ORIGINAL原值后追加；2=NEGATIVE负值替换；3=REPLACE参数整体替换（取数按vector模板注入）</summary>
        public int Where { get; set; } = 1;

        /// <summary>检出用例的vector模板（where=3参数替换点取数复用，[INFERENCE]/[QUERY]为取数槽位）</summary>
        public string VectorTemplate { get; set; } = "";

        /// <summary>注入参数原始值（where=3替换点记录原值，供vector中[ORIGVALUE]渲染）</summary>
        public string OrigValue { get; set; } = "";

        /// <summary>实测报错回显净容量（报错通道取数时探针二分测得并写回；>0时恢复记录免重复探测，分片按实测步长）</summary>
        public int ErrorChunkLen { get; set; } = 0;

        /// <summary>检测期自动适配的tamper名（如between：'>'被过滤时验证有效后记录；恢复记录时自动启用对应tamper）</summary>
        public string AutoTamper { get; set; } = "";

        /// <summary>检测期真值页HTTP状态码（防脏数据校验：取数探测出现TrueCode/FalseCode之外的意外码时探测作废重发）</summary>
        public int TrueCode { get; set; } = 0;

        /// <summary>检测期假值页HTTP状态码（与TrueCode构成合法状态码集合；0=未记录不做校验）</summary>
        public int FalseCode { get; set; } = 0;

        /// <summary>检出payload的boundary前缀（结构化记录注入点上下文类型）</summary>
        public string Prefix { get; set; } = "";

        /// <summary>检出payload的boundary后缀（与Prefix配对记录）</summary>
        public string Suffix { get; set; } = "";

        /// <summary>Place=Uri时的路径段序号（非空段0基，恢复记录重烘焙定位用；-1=非URI注入）</summary>
        public int UriIndex { get; set; } = -1;

        /// <summary>检出boundary的SQL子句上下文（逗号分隔clause id：0=任意 1=WHERE 2=GROUP BY 3=ORDER BY 4=LIMIT 5=OFFSET 6=INSERT 7=UPDATE）；非0/1时取数"and"胶水可能不适用</summary>
        public string Clause { get; set; } = "";

        /// <summary>本注入点的随机回显标记（起始/结束/分隔），防止固定短串与页面自然内容冲突；空=旧记录用模板默认标记</summary>
        public string StartMark { get; set; } = "";
        public string EndMark { get; set; } = "";
        public string SplitMark { get; set; } = "";

        /// <summary>注入上下文描述（由boundary前缀推断：数字型/单引号/双引号/括号嵌套）</summary>
        [System.Text.Json.Serialization.JsonIgnore]
        public string BoundaryDesc
        {
            get
            {
                if (string.IsNullOrEmpty(Prefix)) return "数字型";
                if (Prefix.Contains(')', StringComparison.Ordinal)) return "括号嵌套";
                if (Prefix.Contains('\'', StringComparison.Ordinal)) return "单引号型";
                if (Prefix.Contains('"', StringComparison.Ordinal)) return "双引号型";
                return "数字型";
            }
        }

        /// <summary>注入位置描述（列表展示用）</summary>
        public string PlaceDesc => Place switch
        {
            ParamPlace.Cookie => "Cookie",
            ParamPlace.Header => "HTTP头(" + HeaderName + ")",
            ParamPlace.BodyJson => "JSON体",
            ParamPlace.BodyXml => "XML/SOAP体",
            ParamPlace.BodyMultipart => "Multipart表单",
            ParamPlace.BodyForm => "POST表单",
            ParamPlace.Uri => "URI路径段",
            _ => "GET参数"
        };

        public string TimeStr => Time.ToString("MM-dd HH:mm:ss");

        /// <summary>Fork库显示文本：未识别/非fork显示"-"（列表展示用；DBType始终为族宿主库）</summary>
        [System.Text.Json.Serialization.JsonIgnore]
        public string ForkNameText => string.IsNullOrEmpty(ForkName) ? "-" : ForkName;

        /// <summary>下拉选择器显示文本（目标 · 参数 · 类型 · 数据库(Fork)；数字型为默认上下文不显示后缀，其余上下文附加显示；base64包装参数附加标识）</summary>
        public string DisplayText => TimeStr + "  " + Target + " · " + PName + " · " + InjectTypeDesc + " · " + DBType
            + (string.IsNullOrEmpty(ForkName) ? "" : "(" + ForkName + ")")
            + (BoundaryDesc == "数字型" ? "" : " · " + BoundaryDesc)
            + ("base64encode".Equals(AutoTamper, StringComparison.OrdinalIgnoreCase) ? " · base64" : "");

        public string InjectTypeDesc
        {
            get
            {
                if (InjectType == InjectType.Blind)
                {
                    return "Bool盲注(" + BoolInjectType + ")";
                }
                if (InjectType == InjectType.Time)
                {
                    return "时间盲注";
                }
                if (InjectType == InjectType.Stacked)
                {
                    return "堆叠(取数回退" + BoolInjectType + ")";
                }
                if (InjectType == InjectType.Dns)
                {
                    return "DNS盲注";
                }
                return InjectType.ToString();
            }
        }
    }
}
