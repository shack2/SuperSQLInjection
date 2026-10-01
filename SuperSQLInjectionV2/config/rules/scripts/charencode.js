//@name: 逐字符URL编码
//@usage: payload
//@enable: false
//@description: 逐字符URL编码（已有%XX序列跳过，字母数字也编码）
function tamper(payload){
    if (!payload) { return payload; }
    var out = '', i = 0;
    while (i < payload.length){
        if (payload.charAt(i) === '%' && i < payload.length - 2
            && /[0-9a-fA-F]/.test(payload.charAt(i + 1)) && /[0-9a-fA-F]/.test(payload.charAt(i + 2))){
            out += payload.substr(i, 3); i += 3;
        } else {
            out += '%' + payload.charCodeAt(i).toString(16).toUpperCase().padStart(2, '0'); i += 1;
        }
    }
    return out;
}