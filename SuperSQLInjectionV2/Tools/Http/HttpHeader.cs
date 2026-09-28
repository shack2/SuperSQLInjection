namespace SuperSQLInjectionV2.Tools.Http
{
    /// <summary>
    /// HTTP报文首部字段类
    /// </summary>
    public class HttpHeader
    {
        /// <summary>
        /// 首部字段名
        /// </summary>
        public string Name { get; set; } = "";

        /// <summary>
        /// 首部字段值
        /// </summary>
        public string Value { get; set; } = "";

        public HttpHeader (){ }

        public HttpHeader(string name, string value)
        {
            Name = name;
            Value = value;
        }

        public override string ToString()
        {
            return $"{Name}: {Value}";
        }
    }
}
