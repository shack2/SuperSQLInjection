//@name: 交替大小写
//@usage: payload
//@enable: false
//@description: 关键字字母按位交替大小写（库名.表/@变量/引号字符串/函数调用不处理）
function altCase(key){
    var out = '';
    for (var j = 0; j < key.length; j++){
        out += j % 2 === 0 ? key.charAt(j).toUpperCase() : key.charAt(j).toLowerCase();
    }
    return out;
}
function tamper(oldStr){
    var ret = oldStr;
    try{
        var re = /([a-zA-Z_.]+|@+[a-zA-Z_]+|[a-zA-Z_]\(\)+|'[a-zA-Z_\-]+')/g;
        var m;
        while ((m = re.exec(oldStr)) !== null){
            var keyStr = m[0];
            if (keyStr.indexOf("'") >= 0 || keyStr.indexOf(".") >= 0 || keyStr.indexOf("@") >= 0 || keyStr.indexOf("()") >= 0) { continue; }
            ret = ret.split(keyStr).join(altCase(keyStr));
        }
    } catch(e){}
    return ret.split('0X').join('0x');
}