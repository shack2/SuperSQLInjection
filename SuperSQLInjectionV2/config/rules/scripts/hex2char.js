//@name: Hex转CHAR拼接
//@usage: payload
//@enable: false
//@description: 0x hex串→CONCAT(CHAR(n),..)（MySQL，应用层大写化场景）
function tamper(payload){
    if (!payload) { return payload; }
    var retVal = payload, re = /\b0x([0-9a-f]+)\b/gi, m;
    while ((m = re.exec(payload)) !== null){
        var hexs = m[1], parts = [];
        for (var i = 0; i + 1 < hexs.length; i += 2){ parts.push('CHAR(' + parseInt(hexs.substr(i, 2), 16) + ')'); }
        retVal = retVal.split(m[0]).join(parts.length > 1 ? 'CONCAT(' + parts.join(',') + ')' : parts[0]);
    }
    return retVal;
}