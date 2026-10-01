//@name: Unicode宽字符编码
//@usage: payload
//@enable: false
//@description: 全字符→%uXXXX宽字节编码（%XX→%u00XX跳过，非BMP按UTF-16代理对，ASP/ASP.NET）
function tamper(payload){
    if (!payload) { return payload; }
    var out = '', i = 0;
    while (i < payload.length){
        if (payload.charAt(i) === '%' && i < payload.length - 2
            && /[0-9a-fA-F]/.test(payload.charAt(i + 1)) && /[0-9a-fA-F]/.test(payload.charAt(i + 2))){
            out += '%u00' + payload.substr(i + 1, 2); i += 3;
        } else {
            out += '%u' + payload.charCodeAt(i).toString(16).toUpperCase().padStart(4, '0'); i += 1;
        }
    }
    return out;
}