//@name: 参数名大小写混淆(示例)
//@usage: request
//@enable: false
// 报文级：参数名大小写混淆（参数名逐字符随机大小写，绕过按参数名精确匹配的参数级WAF）
// PARAM 改为你的注入参数名（不区分大小写匹配）；留空 '' 则混淆所有参数名
var PARAM = '';
function tamper(request){
    return request.replace(/([?&\n])([^&=\s]+)=/g, function(m, pre, name){
        if (PARAM && name.toLowerCase() !== PARAM.toLowerCase()) { return m; }
        var out = '';
        for (var i = 0; i < name.length; i++) {
            var c = name.charAt(i);
            out += Math.random() < 0.5 ? c.toLowerCase() : c.toUpperCase();
        }
        return pre + out + '=';
    });
}