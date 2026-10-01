//@name: 括号前插注释
//@usage: payload
//@enable: false
//@description: 括号前插入内联注释（( → /**/(）
function tamper(payload){ return payload ? payload.replace(/\b(\w+)\(/g, '$1/**/(') : payload; }