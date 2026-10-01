//@name: 随机IP头
//@usage: request
//@enable: false
//@description: 追加X-Forwarded-For等5个随机IP头+Via头（绕基于IP的WAF/限流）
function rip(){ return (1 + Math.floor(Math.random() * 254)) + '.' + Math.floor(Math.random() * 256) + '.' + Math.floor(Math.random() * 256) + '.' + (1 + Math.floor(Math.random() * 254)); }
function tamper(request){
    var heads = 'X-Forwarded-For: ' + rip() + '\r\nX-Client-Ip: ' + rip() + '\r\nX-Real-Ip: ' + rip()
        + '\r\nCF-Connecting-IP: ' + rip() + '\r\nTrue-Client-IP: ' + rip() + '\r\nVia: 1.1 Chrome-Compression-Proxy';
    return request.replace(/\r\n\r\n/, '\r\n' + heads + '\r\n\r\n');
}