using SuperSQLInjectionV2.Tools.Http;
using System;

namespace SuperSQLInjectionV2.Models;

public partial class RequestLog
{
    public HttpRequest Request { get; set; }
    public HttpResponse Response { get; set; }
    public RequestLog(HttpRequest request,HttpResponse response)
    {
        Request = request;
        Response = response;
    }
    public string Time { get; set; }= DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
    public string Payload { get; set; } = "";
    public long UseTime { get; set; } = 0;

    /// <summary>本请求使用的代理（ip:port），"直连"=未走代理</summary>
    public string Proxy { get; set; } = "";

    public string index { get; set; } = "";

}