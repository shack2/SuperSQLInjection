using System.ComponentModel;

namespace SuperSQLInjectionV2.Models
{
    /// <summary>
    /// 注入参数位置（注入点位置）：
    /// Query=GET查询串；BodyForm=POST表单；BodyJson=JSON请求体；
    /// Cookie=Cookie键值对（level>=2）；Header=任意命名头如User-Agent/Referer（level>=3）
    /// </summary>
    public enum ParamPlace
    {
        [Description("GET参数")] Query,
        [Description("POST表单")] BodyForm,
        [Description("JSON请求体")] BodyJson,
        [Description("XML/SOAP体")] BodyXml,
        [Description("Multipart表单")] BodyMultipart,
        [Description("Cookie")] Cookie,
        [Description("HTTP头")] Header,
        [Description("URI路径段")] Uri
    }
}
