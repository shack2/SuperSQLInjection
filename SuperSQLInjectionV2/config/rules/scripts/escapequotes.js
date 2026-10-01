//@name: 引号转义
//@usage: payload
//@enable: false
//@description: 单双引号加反斜杠转义（'→\' "→\"）
function tamper(payload){ return payload ? payload.split("'").join("\\'").split('"').join('\\"') : payload; }