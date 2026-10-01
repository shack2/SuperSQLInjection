//@name: MID无逗号
//@usage: payload
//@enable: false
//@description: MID(x,a,b)→MID(x FROM a FOR b)（MySQL逗号被过滤时）
function tamper(payload){
    if (!payload) { return payload; }
    var m = /MID\((.+?)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)/i.exec(payload);
    return m ? payload.split(m[0]).join('MID(' + m[1] + ' FROM ' + m[2] + ' FOR ' + m[3] + ')') : payload;
}