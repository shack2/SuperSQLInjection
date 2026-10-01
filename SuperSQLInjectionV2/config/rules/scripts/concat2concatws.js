//@name: CONCAT转CONCAT_WS
//@usage: payload
//@enable: false
//@description: CONCAT(a,b)→CONCAT_WS(MID(CHAR(0),0,0),a,b)（MySQL，跳过GROUP_CONCAT）
function tamper(payload){ return payload ? payload.replace(/(?<!GROUP_)CONCAT\(/gi, 'CONCAT_WS(MID(CHAR(0),0,0),') : payload; }