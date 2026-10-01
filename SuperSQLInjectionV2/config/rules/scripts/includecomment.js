//@name: 关键字内联注释
//@usage: payload
//@enable: false
//@description: 标识符包裹MySQL内联执行注释（kw→/*!kw*/，@变量不动）
function tamper(payload){
    return payload.replace(/[a-zA-Z_.(@]{2,50}/g, function(m){
        return m.indexOf('@') >= 0 ? m : '/*!' + m + '*/';
    });
}