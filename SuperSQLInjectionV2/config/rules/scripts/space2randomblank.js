//@name: 空格转随机空白
//@usage: payload
//@enable: false
//@description: 空格→随机空白符%09/%0A/%0C/%0D（引号感知）
function tamper(payload){
    if (!payload) { return payload; }
    var blanks = ['%09', '%0A', '%0C', '%0D'];
    var retVal = '', quote = false, dquote = false, firstspace = false, end = false;
    for (var i = 0; i < payload.length; i++){
        var c = payload.charAt(i);
        if (!firstspace){
            if (/\s/.test(c)){ firstspace = true; retVal += blanks[Math.floor(Math.random() * blanks.length)]; continue; }
        } else if (c === "'" && payload.charAt(i - 1) !== '\\'){ quote = !quote; }
        else if (c === '"' && payload.charAt(i - 1) !== '\\'){ dquote = !dquote; }
            else if (c === ' ' && !dquote && !quote){ retVal += blanks[Math.floor(Math.random() * blanks.length)]; continue; }        retVal += c;
    }
    return retVal;
}