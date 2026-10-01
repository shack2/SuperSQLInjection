//@name: X-originating-IP头
//@usage: request
//@enable: false
//@description: 追加X-originating-IP: 127.0.0.1头（绕Varnish防火墙）
function tamper(request){
    if (/^X-originating-IP:/im.test(request)){
        return request.replace(/^X-originating-IP:[^\r\n]*/im, 'X-originating-IP: 127.0.0.1');
    }
    return request.replace(/\r\n\r\n/, '\r\nX-originating-IP: 127.0.0.1\r\n\r\n');
}