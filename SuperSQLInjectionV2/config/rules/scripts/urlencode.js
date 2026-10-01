//@name: url编码
//@usage: payload
//@enable: false
//@description: 整段URL编码（特殊字符→%XX；启用后抑制Encode块的兜底URL编码）
function tamper(payload){
    var keep = /[a-zA-Z0-9\-._()*'!]/;
    var out = '';
    for (var i = 0; i < payload.length; i++){
        var c = payload.charAt(i);
        out += keep.test(c) ? c : encodeURIComponent(c).toLowerCase();
    }
    return out;
}