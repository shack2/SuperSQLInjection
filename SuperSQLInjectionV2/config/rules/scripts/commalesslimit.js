//@name: LIMIT无逗号
//@usage: payload
//@enable: false
//@description: LIMIT M,N→LIMIT N OFFSET M（MySQL/MariaDB/SQLite）
function tamper(payload){
    if (!payload) { return payload; }
    var m = /LIMIT\s*(\d+),\s*(\d+)/i.exec(payload);
    return m ? payload.split(m[0]).join('LIMIT ' + m[2] + ' OFFSET ' + m[1]) : payload;
}