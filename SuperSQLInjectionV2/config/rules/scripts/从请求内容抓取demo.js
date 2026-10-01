//@name: 从请求内容抓取demo
//@usage: extract
//@enable: true
// 请求抓取：输入为抓取请求返回的完整HTTP响应报文（响应头+空行+响应体）
// 返回从响应中提取的动态值字符串
function tamper(response){
    // 示例：从响应体中提取 token 字段
    var m = response.match(/token["']?\s*[:=]\s*["']?([0-9a-zA-Z]+)/);
    return m ? m[1] : '';
}