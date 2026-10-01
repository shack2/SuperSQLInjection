//@name: Unicode编码
//@usage: payload
//@enable: false
//@description: 整段字符→%uXXXX（UTF-16宽字符，ASP/IIS场景）
function tamper(payload){
    var out = '';
    for (var i = 0; i < payload.length; i++){
        out += '%u' + payload.charCodeAt(i).toString(16).padStart(4, '0');
    }
    return out;
}