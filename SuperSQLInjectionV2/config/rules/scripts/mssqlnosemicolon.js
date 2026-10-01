//@name: MSSQL去分号
//@usage: payload
//@enable: false
//@description: 语句分隔分号→空格（T-SQL无需分隔符，MSSQL堆叠绕过；）
function tamper(payload){ return payload ? payload.replace(/;(?=\s*(?:WAITFOR|DECLARE|SET|EXEC(?:UTE)?|SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|BEGIN|IF|WHILE|PRINT|USE|GRANT|REVOKE|BACKUP|RESTORE|RECONFIGURE|SHUTDOWN|WITH)\b)/gi, ' ') : payload; }