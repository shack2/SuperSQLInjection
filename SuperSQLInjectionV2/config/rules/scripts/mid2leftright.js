//@name: MID转LEFT-RIGHT
//@usage: payload
//@enable: false
//@description: MID/SUBSTRING/SUBSTR(x,a,b)→RIGHT(LEFT(x,a+b-1),b)（绕CRS 942151，MySQL/MariaDB）
function tamper(payload){
    if (!payload) { return payload; }
    return payload.replace(/\b(?:MID|SUBSTRING|SUBSTR)\(\s*((?:[^()]|\([^()]*\))+?)\s*,(\s*)([^,()]+),(\s*)([^,()]+)\)/gi,
        function(m, expr, sp1, pos, sp2, len){
            pos = pos.trim(); len = len.trim();
            var end = /^\d+$/.test(pos) && /^\d+$/.test(len) ? String(parseInt(pos, 10) + parseInt(len, 10) - 1) : pos + '+' + len + '-1';
            return 'RIGHT(LEFT(' + expr + ',' + sp1 + end + '),' + sp2 + len + ')';
        });
}