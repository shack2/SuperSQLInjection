//@name: 库表名拆分
//@usage: payload
//@enable: false
//@description: FROM schema.table→FROM schema 9.e.table（MySQL语法混淆）
function tamper(payload){ return payload ? payload.replace(/( FROM \w+)\.(\w+)/gi, '$1 9.e.$2') : payload; }