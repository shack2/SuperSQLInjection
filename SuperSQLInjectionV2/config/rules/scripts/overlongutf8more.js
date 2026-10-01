//@name: 超长UTF-8全字符
//@usage: payload
//@enable: false
//@description: 全部字符→超长UTF-8编码（%XX跳过）
function tamper(payload){
    if (!payload) { return payload; }
    var out = '', i = 0;
    function hex2(n){ return n.toString(16).toUpperCase().padStart(2, '0'); }
    while (i < payload.length){
        var c = payload.charAt(i);
        if (c === '%' && i < payload.length - 2
            && /[0-9a-fA-F]/.test(payload.charAt(i + 1)) && /[0-9a-fA-F]/.test(payload.charAt(i + 2))){
            out += payload.substr(i, 3); i += 3; continue;
        }
        var ord = payload.charCodeAt(i);
        if (ord <= 0x7FF){
            out += '%' + hex2(0xc0 + (ord >> 6)) + '%' + hex2(0x80 + (ord & 0x3f));
        } else {
            var bin = unescape(encodeURIComponent(c));
            for (var j = 0; j < bin.length; j++){ out += '%' + hex2(bin.charCodeAt(j)); }
        }
        i += 1;
    }
    return out;
}