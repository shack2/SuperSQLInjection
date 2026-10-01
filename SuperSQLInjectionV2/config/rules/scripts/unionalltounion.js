//@name: UNION ALL转UNION
//@usage: payload
//@enable: false
//@description: UNION ALL SELECT→UNION SELECT
function tamper(payload){ return payload ? payload.replace(/UNION\s+ALL\s+SELECT/gi, 'UNION SELECT') : payload; }