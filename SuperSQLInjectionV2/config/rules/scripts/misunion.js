//@name: UNION前缀-.1
//@usage: payload
//@enable: false
//@description: UNION前空格→-.1（1-.1UNION，MySQL）
function tamper(payload){ return payload ? payload.replace(/\s+(UNION )/gi, '-.1$1') : payload; }