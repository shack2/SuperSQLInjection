//@name: IFNULL转IF-ISNULL
//@usage: payload
//@enable: false
//@description: IFNULL(A,B)→IF(ISNULL(A),B,A)（MySQL/MariaDB，walker）
function tamper(payload){
    if (!payload || payload.indexOf('IFNULL(') < 0) { return payload; }
    while (payload.indexOf('IFNULL(') > -1){
        var index = payload.indexOf('IFNULL(');
        var depth = 1, comma = -1, end = -1, quote = false, dquote = false;
        for (var i = index + 7; i < payload.length; i++){
            var c = payload.charAt(i);
            if (c === "'" && payload.charAt(i - 1) !== '\\'){ quote = !quote; }
            else if (c === '"' && payload.charAt(i - 1) !== '\\'){ dquote = !dquote; }
            if (!quote && !dquote){
                if (depth === 1 && c === ','){ comma = i; }
                else if (depth === 1 && c === ')'){ end = i; break; }
                else if (c === '('){ depth++; }
                else if (c === ')'){ depth--; }
            }
        }
        if (comma > 0 && end > 0){
            var a = payload.substring(index + 7, comma);
            var b = payload.substring(comma + 1, end).replace(/^\s+/, '');
            var newVal;
            newVal = 'IF(ISNULL(' + a + '),' + b + ',' + a + ')';
            payload = payload.substring(0, index) + newVal + payload.substring(end + 1);
        } else { break; }
    }
    return payload;
}