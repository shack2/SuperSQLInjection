//@name: 尾部空字节
//@usage: payload
//@enable: false
//@description: payload末尾追加%00空字节（Access）
function tamper(payload){ return payload ? payload + '%00' : payload; }