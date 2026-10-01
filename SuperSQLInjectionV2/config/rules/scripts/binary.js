//@name: binary关键字注入
//@usage: payload
//@enable: false
//@description: NULL/数字/hex字面量前注入binary关键字（MySQL，强制字节序比较）
function tamper(payload){
    if (!payload) { return payload; }
    var retVal = payload;
    retVal = retVal.replace(/\bNULL\b/g, 'binary NULL');
    retVal = retVal.replace(/\b(THEN\s+)(\d+|0x[0-9a-f]+)(\s+ELSE\s+)(\d+|0x[0-9a-f]+)/g, '$1binary $2$3binary $4');
    retVal = retVal.replace(/(\d+\s*[>=]\s*)(\d+)/g, 'binary $1binary $2');
    retVal = retVal.replace(/\b((AND|OR)\s*)(\d+)/g, '$1binary $3');
    retVal = retVal.replace(/([>=]\s*)(\d+)/g, '$1binary $2');
    retVal = retVal.replace(/\b(0x[0-9a-f]+)/g, 'binary $1');
    retVal = retVal.replace(/(\s+binary)+/g, '$1');
    return retVal;
}