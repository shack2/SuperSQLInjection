//@name: 双重URL编码
//@usage: payload
//@enable: false
//@description: 双重URL编码（%XX→%25XX，其余→%25XX）
function tamper(payload){
    if (!payload) { return payload; }
    var out = '', i = 0;
    while (i < payload.length){
        if (payload.charAt(i) === '%' && i < payload.length - 2
            && /[0-9a-fA-F]/.test(payload.charAt(i + 1)) && /[0-9a-fA-F]/.test(payload.charAt(i + 2))){
            out += '%25' + payload.substr(i + 1, 2); i += 3;
        } else {
            out += '%25' + payload.charCodeAt(i).toString(16).toUpperCase().padStart(2, '0'); i += 1;
        }
    }
    return out;
}