//@name: 追加sp_password
//@usage: payload
//@enable: false
//@description: payload末尾追加sp_password（MSSQL日志脱敏）
function tamper(payload){
    if (!payload) { return ''; }
    return payload + (payload.indexOf('#') < 0 && payload.indexOf('-- ') < 0 ? '-- ' : '') + 'sp_password';
}