//@name: HTML十六进制实体
//@usage: payload
//@enable: false
//@description: 全部字符→HTML十六进制实体&#xNN;
function tamper(payload){
    if (!payload) { return payload; }
    var out = '';
    for (var i = 0; i < payload.length; i++){ out += '&#x' + payload.charCodeAt(i).toString(16) + ';'; }
    return out;
}