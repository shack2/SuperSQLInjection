//@name: 空格转--注释
//@usage: payload
//@enable: false
//@description: 空格→--随机串%0A（引号感知，遇#/-- 截断，MSSQL/SQLite）
function randStr(){
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    var n = 6 + Math.floor(Math.random() * 7), out = '';
    for (var i = 0; i < n; i++){ out += chars.charAt(Math.floor(Math.random() * chars.length)); }
    return out;
}
function tamper(payload){
    if (!payload) { return ''; }
    var retVal = '', quote = false, dquote = false;
    for (var i = 0; i < payload.length; i++){
        var c = payload.charAt(i);
        if (c === "'" && payload.charAt(i - 1) !== '\\'){ quote = !quote; }
        else if (c === '"' && payload.charAt(i - 1) !== '\\'){ dquote = !dquote; }
        if (!quote && !dquote){
            if (/\s/.test(c)){ retVal += '--' + randStr() + '%0A'; }
            else if (c === '#' || payload.substr(i, 3) === '-- '){ retVal += payload.substring(i); break; }
            else { retVal += c; }
        } else { retVal += c; }
    }
    return retVal;
}