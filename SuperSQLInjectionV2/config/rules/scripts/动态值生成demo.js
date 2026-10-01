//@name: 动态值生成demo
//@usage: generate
//@enable: true
// 自主生成：输入为主请求报文（请求行+请求头+空行+请求体）
// 返回动态值字符串，回填主请求的 <DRule> 标记（API签名/时间戳/随机数等场景）
function tamper(request){
    // 示例1：时间戳动态值
    // return String(Date.now());
    // 示例2：取主请求参数参与计算（如API签名）
    var m = request.match(/[?&]id=([^&\s]+)/);
    var id = m ? m[1] : '';
    return 'sig-' + id + '-' + Date.now();
}