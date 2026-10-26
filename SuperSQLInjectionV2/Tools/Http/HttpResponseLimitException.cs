namespace SuperSQLInjectionV2.Tools.Http
{
    /// <summary>响应头、响应体或解压后内容超过配置上限。</summary>
    public sealed class HttpResponseLimitException : IOException
    {
        public HttpResponseLimitException(string message) : base(message) { }
    }
}
