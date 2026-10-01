//@name: HTML十进制实体
//@usage: payload
//@enable: false
//@description: 全部字符→HTML十进制实体&#NN;
function tamper(payload){
    if (!payload) { return payload; }
    var out = '';
    for (var i = 0; i < payload.length; i++){ out += '&#' + payload.charCodeAt(i) + ';'; }
    return out;
}