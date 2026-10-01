//@name: 百分号前缀
//@usage: payload
//@enable: false
//@description: 每个字符前加%（%XX序列与空格跳过，ASP/IIS宽松解析场景）
function tamper(payload){
    if (!payload) { return payload; }
    var out = '', i = 0;
    while (i < payload.length){
        var c = payload.charAt(i);
        if (c === '%' && i < payload.length - 2
            && /[0-9a-fA-F]/.test(payload.charAt(i + 1)) && /[0-9a-fA-F]/.test(payload.charAt(i + 2))){
            out += payload.substr(i, 3); i += 3;
        } else if (c !== ' '){
            out += '%' + c; i += 1;
        } else { out += c; i += 1; }
    }
    return out;
}