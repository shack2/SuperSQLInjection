//@name: 逻辑符转符号
//@usage: payload
//@enable: false
//@description: AND→%26%26，OR→%7C%7C（&&/||的URL编码形态）
function tamper(payload){ return payload ? payload.replace(/\bOR\b/gi, '%7C%7C').replace(/\bAND\b/gi, '%26%26') : payload; }