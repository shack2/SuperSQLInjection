//@name: 比较转BETWEEN
//@usage: payload
//@enable: false
//@description: a>b→a NOT BETWEEN 0 AND b；a=b→a BETWEEN b AND b（避开复合运算符）
function tamper(payload){
    if (!payload) { return payload; }
    var retVal = payload;
    var m = /(\b(AND|OR)\b\s+)(?!.*\b(AND|OR)\b)([^>]+?)\s*(?<![<])>(?!=)\s*([^>]+)\s*$/i.exec(payload);
    if (m){
        retVal = retVal.split(m[0]).join(m[2] + ' ' + m[4] + ' NOT BETWEEN 0 AND ' + m[5]);
    } else {
        retVal = payload.replace(/\s*(?<![<])>(?!=)\s*(\d+|'[^']+'|\w+\(\d+\))/g, ' NOT BETWEEN 0 AND $1');
    }
    if (retVal === payload){
        var m2 = /(\b(AND|OR)\b\s+)(?!.*\b(AND|OR)\b)([^=]+?)\s*(?<![<>!])=(?!=)\s*([\w()]+)\s*/i.exec(payload);
        if (m2){
            retVal = retVal.split(m2[0]).join(m2[2] + ' ' + m2[4] + ' BETWEEN ' + m2[5] + ' AND ' + m2[5]);
        }
    }
    return retVal;
}