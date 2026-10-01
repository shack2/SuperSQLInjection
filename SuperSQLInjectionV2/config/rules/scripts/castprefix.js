//@name: 数字CAST包裹
//@usage: payload
//@enable: false
//@description: 前导数字包裹cast(N as decimal)（绕CRS 942360锚定规则，MySQL/PG/MSSQL）
function tamper(payload){ return payload ? payload.replace(/^([+-]?\d+)(?![\w.])/, 'cast($1 as decimal)') : payload; }