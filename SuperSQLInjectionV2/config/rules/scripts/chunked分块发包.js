//@name: chunked分块发包(示例)
//@usage: request
//@enable: false
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