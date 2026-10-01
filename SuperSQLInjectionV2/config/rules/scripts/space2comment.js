//@name: 空格转注释
//@usage: payload
//@enable: false
//@description: 空格→内联注释/**/（引号感知）
function tamper(payload){
    if (!payload) { return payload; }
    var retVal = '', quote = false, dquote = false, firstspace = false;
    for (var i = 0; i < payload.length; i++){
        var c = payload.charAt(i);
        if (!firstspace){
            if (/\s/.test(c)){ firstspace = true; retVal += '/**/'; continue; }
        } else if (c === "'" && payload.charAt(i - 1) !== '\\'){
            quote = !quote;
        } else if (c === '"' && payload.charAt(i - 1) !== '\\'){
            dquote = !dquote;
        } else if (c === ' ' && !dquote && !quote){
            retVal += '/**/'; continue;
        }
        retVal += c;
    }
    return retVal;
}