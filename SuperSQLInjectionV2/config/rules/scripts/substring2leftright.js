//@name: SUBSTRING转LEFT-RIGHT
//@usage: payload
//@enable: false
//@description: PG的SUBSTRING(x FROM a FOR 1)→LEFT/RIGHT组合（绕SUBSTRING过滤）
function tamper(payload){
    if (!payload) { return payload; }
    var m = /SUBSTRING\((.+?)\s+FROM[^)]+(\d+)[^)]+FOR[^)]+1\)/.exec(payload);
    if (!m) { return payload; }
    var pos = parseInt(m[2], 10);
    var rep = pos === 1 ? 'LEFT(' + m[1] + ',1)' : 'LEFT(RIGHT(' + m[1] + ',' + (1 - pos) + '),1)';
    return payload.split(m[0]).join(rep);
}