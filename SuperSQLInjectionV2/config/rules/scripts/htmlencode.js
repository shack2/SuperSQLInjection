//@name: HTML实体编码
//@usage: payload
//@enable: false
//@description: 非字母数字→HTML十进制实体（已有&#NN;先解码再编，幂等）
function tamper(payload){
    if (!payload) { return payload; }
    payload = payload.replace(/&#(\d+);/g, function(m, n){ return String.fromCharCode(parseInt(n, 10)); });
    return payload.replace(/[^\w]/g, function(c){ return '&#' + c.charCodeAt(0) + ';'; });
}