//@name: ModSecurity零版本注释
//@usage: payload
//@enable: false
//@description: 首空格后整段包裹/*!00000..*/零版本注释（注释尾保留，MySQL/ModSecurity）
function tamper(payload){
    if (!payload) { return payload; }
    var postfix = '';
    var cuts = ['#', '--', '/*'];
    for (var k = 0; k < cuts.length; k++){
        var idx = payload.indexOf(cuts[k]);
        if (idx >= 0){ postfix = payload.substring(idx); payload = payload.substring(0, idx); break; }
    }
    var sp = payload.indexOf(' ');
    if (sp < 0) { return payload; }
    return payload.substring(0, sp) + ' /*!00000' + payload.substring(sp + 1) + '*/' + postfix;
}