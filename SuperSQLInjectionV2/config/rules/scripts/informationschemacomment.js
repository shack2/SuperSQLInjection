//@name: information_schema插注释
//@usage: payload
//@enable: false
//@description: information_schema后插内联注释（information_schema/**/.TABLES）
function tamper(payload){ return payload ? payload.replace(/(information_schema)\./gi, '$1/**/.') : payload; }