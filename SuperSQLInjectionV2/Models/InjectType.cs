using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Serialization;


namespace SuperSQLInjectionV2.Models;

[JsonConverter(typeof(JsonStringEnumConverter<InjectType>))]
public enum InjectType
{
    UnKnow,
    /// <summary>Bool盲注（按页面内容判定：关键字/正则/状态码/长度等判断方式）</summary>
    Blind,
    /// <summary>时间盲注（独立注入类型，对标业界同类工具 T技术）：payload带延时函数，按响应耗时判定真假，不再作为盲注判断方式</summary>
    Time,
    Error,
    Union,
    /// <summary>堆叠查询（多语句执行）：取数回退注入点自带的时间盲注通道，写操作/命令执行/任意SQL走堆叠直发</summary>
    Stacked,
    /// <summary>DNS盲注（DNS外带取数，对标业界同类工具 --dns-domain）：payload经注入点盲注通道携带执行，
    /// 查询结果hex分段由DB主动发DNS解析带出，在DNSLog平台回收拼接；适用于无回显且时间盲注过慢的场景</summary>
    Dns
}