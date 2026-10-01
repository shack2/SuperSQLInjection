//@name: Oracle q-quote
//@usage: payload
//@enable: false
//@description: 单引号字符串→Oracle q-quote（q'[..]'，自动选首个未出现的定界符）
function tamper(payload){
    if (!payload) { return payload; }
    var delims = [['[', ']'], ['{', '}'], ['(', ')'], ['<', '>'], ['!', '!'], ['|', '|'], ['#', '#']];
    return payload.replace(/'([^']*)'/g, function(m, v){
        for (var k = 0; k < delims.length; k++){
            if (v.indexOf(delims[k][0]) < 0 && v.indexOf(delims[k][1]) < 0){
                return "q'" + delims[k][0] + v + delims[k][1] + "'";
            }
        }
        return m;
    });
}