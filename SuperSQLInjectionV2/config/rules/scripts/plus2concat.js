//@name: 加号转CONCAT
//@usage: payload
//@enable: false
//@description: +号字符串拼接→CONCAT(a,b,..)（括号深度0处的+，MSSQL 2012+）
function zeroDepth(s, ch){
    var idx = [], depth = 0;
    for (var i = 0; i < s.length; i++){
        var c = s.charAt(i);
        if (c === '('){ depth++; }
        else if (c === ')'){ depth--; }
        else if (c === ch && depth === 0){ idx.push(i); }
    }
    return idx;
}
function tamper(payload){
    if (!payload) { return payload; }
    var m = /('[^']+'|CHAR\(\d+\))\+.*(?<=\+)('[^']+'|CHAR\(\d+\))/.exec(payload);
    if (!m) { return payload; }
    var part = m[0];
    var parts = [], last = 0;
    var idxs = zeroDepth(part, '+');
    for (var k = 0; k < idxs.length; k++){
        parts.push(part.substring(last, idxs[k])); last = idxs[k];
    }
    parts.push(part.substring(last));
    parts = parts.map(function(p){ return p.replace(/^\+|\+$/g, ''); });
    var replacement = 'CONCAT(' + parts.join(',') + ')';
    return payload.split(part).join(replacement);
}