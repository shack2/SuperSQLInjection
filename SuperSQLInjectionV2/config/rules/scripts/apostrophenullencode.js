//@name: 单引号NUL编码
//@usage: payload
//@enable: false
//@description: 单引号→%00%27（NUL+单引号）
function tamper(payload){ return payload ? payload.split("'").join('%00%27') : payload; }