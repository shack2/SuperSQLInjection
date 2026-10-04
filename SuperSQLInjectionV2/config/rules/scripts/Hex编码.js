//@name: Hex编码
//@usage: payload
//@enable: false
// hex：整段转十六进制串（0x前缀+UTF-8字节，MySQL可直接作字符串字面量）
function tamper(payload){
    var s = unescape(encodeURIComponent(payload)); // UTF-8字节流
    var out = '0x';
    for (var i = 0; i < s.length; i++){
        out += s.charCodeAt(i).toString(16).padStart(2, '0');
    }
    return out;
}