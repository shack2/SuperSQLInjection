//@name: IF转CASE
//@usage: payload
//@enable: false
//@description: IF(A,B,C)→CASE WHEN (A) THEN (B) ELSE (C) END（MySQL/MariaDB，平衡括号walker）
function unwrap(expr){
    expr = expr.trim();
    while (expr.length > 1 && expr.charAt(0) === '(' && expr.charAt(expr.length - 1) === ')'){
        var depth = 0, wrapper = true;
        for (var i = 0; i < expr.length; i++){
            var c = expr.charAt(i);
            if (c === '('){ depth++; }
            else if (c === ')'){
                depth--;
                if (depth === 0 && i !== expr.length - 1){ wrapper = false; break; }
            }
        }
        if (!wrapper){ break; }
        expr = expr.substring(1, expr.length - 1).trim();
    }
    return expr;
}
function tamper(payload){
    if (!payload || payload.indexOf('IF(') < 0) { return payload; }
    var MARK = 'PAR';
    payload = payload.split('()').join(MARK);
    while (payload.indexOf('IF(') > -1){
        var index = payload.indexOf('IF(');
        var depth = 1, commas = [], end = -1, quote = false, dquote = false;
        for (var i = index + 3; i < payload.length; i++){
            var c = payload.charAt(i);
            if (c === "'" && payload.charAt(i - 1) !== '\\'){ quote = !quote; }
            else if (c === '"' && payload.charAt(i - 1) !== '\\'){ dquote = !dquote; }
            if (!quote && !dquote){
                if (depth === 1 && c === ','){ commas.push(i); }
                else if (depth === 1 && c === ')'){ end = i; break; }
                else if (c === '('){ depth++; }
                else if (c === ')'){ depth--; }
            }
        }
        if (commas.length === 2 && end > 0){
            var a = unwrap(payload.substring(index + 3, commas[0]));
            var b = unwrap(payload.substring(commas[0] + 1, commas[1]));
            var cc = unwrap(payload.substring(commas[1] + 1, end));
            payload = payload.substring(0, index) + 'CASE WHEN (' + a + ') THEN (' + b + ') ELSE (' + cc + ') END' + payload.substring(end + 1);
        } else { break; }
    }
    return payload.split(MARK).join('()');
}