//@name: 等号转LIKE
//@usage: payload
//@enable: false
//@description: 等号→LIKE（避开<=/>=/!=/==；不适用PostgreSQL）
function tamper(payload){ return payload ? payload.replace(/\s*(?<![<>!=])=(?!=)\s*/g, ' LIKE ') : payload; }