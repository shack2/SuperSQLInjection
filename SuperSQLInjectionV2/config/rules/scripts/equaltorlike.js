//@name: 等号转RLIKE
//@usage: payload
//@enable: false
//@description: 等号→RLIKE（避开复合运算符，MySQL）
function tamper(payload){ return payload ? payload.replace(/\s*(?<![<>!=])=(?!=)\s*/g, ' RLIKE ') : payload; }