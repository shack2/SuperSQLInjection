//@name: 空格转/**_**/
//@usage: payload
//@enable: false
//@description: 空格→注释/**_**/（引号感知）
function tamper(payload){
    if (!payload) { return payload; }
    var retVal = '', quote = false, dquote = false, firstspace = false;
    for (var i = 0; i < payload.length; i++){
        var c = payload.charAt(i);
        if (!firstspace){
            if (/\s/.test(c)){ firstspace = true; retVal += '/**_**/'; continue; }
        } else if (c === "'" && payload.charAt(i - 1) !== '\\'){
            quote = !quote;
        } else if (c === '"' && payload.charAt(i - 1) !== '\\'){
            dquote = !dquote;
        } else if (c === ' ' && !dquote && !quote){
            retVal += '/**_**/'; continue;
        }
        retVal += c;
    }
    return retVal;
}