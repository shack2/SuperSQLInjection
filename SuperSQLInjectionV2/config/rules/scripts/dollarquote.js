//@name: PG美元引用
//@usage: payload
//@enable: false
//@description: 单引号字符串→PG美元引用$$..$$（含$$的字面量不动，PostgreSQL）
function tamper(payload){
    if (!payload) { return payload; }
    return payload.replace(/'([^']*)'/g, function(m, v){ return v.indexOf('$$') < 0 ? '$' + '$' + v + '$' + '$' : m; });
}