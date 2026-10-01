//@name: Base64编码
//@usage: payload
//@enable: false
//@description: 整段payload Base64编码（UTF-8）
function utf8bin(s){ return unescape(encodeURIComponent(s)); }
function tamper(payload){
    if (!payload) { return payload; }
    var bin = utf8bin(payload);
    var t = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var out = '', i = 0;
    for (; i + 2 < bin.length; i += 3){
        var n = (bin.charCodeAt(i) << 16) | (bin.charCodeAt(i + 1) << 8) | bin.charCodeAt(i + 2);
        out += t.charAt(n >> 18) + t.charAt((n >> 12) & 63) + t.charAt((n >> 6) & 63) + t.charAt(n & 63);
    }
    var rem = bin.length - i;
    if (rem === 1){
        var n1 = bin.charCodeAt(i) << 16;
        out += t.charAt(n1 >> 18) + t.charAt((n1 >> 12) & 63) + '==';
    } else if (rem === 2){
        var n2 = (bin.charCodeAt(i) << 16) | (bin.charCodeAt(i + 1) << 8);
        out += t.charAt(n2 >> 18) + t.charAt((n2 >> 12) & 63) + t.charAt((n2 >> 6) & 63) + '=';
    }
    return out;
}