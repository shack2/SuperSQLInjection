//@name: 单引号掩码
//@usage: payload
//@enable: false
//@description: 单引号→UTF-8全角右单引号%EF%BC%87
function tamper(payload){ return payload ? payload.split("'").join('%EF%BC%87') : payload; }