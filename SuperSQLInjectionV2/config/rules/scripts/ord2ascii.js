//@name: ORD转ASCII
//@usage: payload
//@enable: false
//@description: ORD(→ASCII(（MySQL）
function tamper(payload){ return payload ? payload.replace(/\bORD\(/gi, 'ASCII(') : payload; }