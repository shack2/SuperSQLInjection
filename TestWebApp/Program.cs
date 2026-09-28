using System.Data.Common;
using System.Net;
using System.Text;
using TestWebApp;

//DB2原生驱动引导：驱动内部用Assembly.CodeBase定位clidriver，路径含'#'会被Uri截断，
//必须把驱动重定向到无'#'的缓存目录加载（详见Db2NativeBootstrap）
TestWebApp.Db2NativeBootstrap.Install();

var builder = WebApplication.CreateBuilder(args);

//端口：--port N / --urls X / 环境变量PORT / 默认5099
int port = 5099;
for (int i = 0; i < args.Length; i++)
{
    if (args[i] == "--port" && i + 1 < args.Length && int.TryParse(args[i + 1], out int p)) port = p;
    if (args[i].StartsWith("--urls="))
    {
        var m = System.Text.RegularExpressions.Regex.Match(args[i], @"(\d+)\s*$");
        if (m.Success) port = int.Parse(m.Groups[1].Value);
    }
}
if (int.TryParse(Environment.GetEnvironmentVariable("PORT"), out int envPort)) port = envPort;
builder.WebHost.UseUrls($"http://0.0.0.0:{port}");
//靶场环境：放宽请求行长度限制（默认8KB），用于验证GET方式UDF库写入等大payload注入场景
builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestLineSize = 1024 * 1024);

var app = builder.Build();
Db.ApplyConfig(app.Configuration);

//首次启动自动初始化sqlite
try { Db.Init(Db.Find("sqlite")); } catch { /* 忽略，状态页会显示 */ }

string Html(string title, string body) => $$"""
<!DOCTYPE html><html><head><meta charset="utf-8"><title>{{title}}</title>
<style>
body{font-family:Consolas,monospace;margin:24px;background:#f7f7f7;color:#222}
h3{border-left:4px solid #36c;padding-left:8px}
table{border-collapse:collapse;background:#fff}
td,th{border:1px solid #ccc;padding:4px 12px}
.err{background:#ffecec;border:1px solid #f00;padding:8px;margin:8px 0;white-space:pre-wrap;color:#a00}
.ok{background:#ecffeC;border:1px solid #0a0;padding:8px;margin:8px 0;white-space:pre-wrap}
.sql{background:#eef;border:1px dashed #66f;padding:6px;margin:6px 0;font-size:13px}
li{margin:4px 0}
input{padding:4px;margin:4px}
</style></head><body>{{body}}</body></html>
""";

string ShowQuery(HttpRequest req, string title, Db.DbEntry e, string sql)
{
    var sb = new StringBuilder();
    sb.Append($"<h3>{title}（{e.Note}）</h3>");
    sb.Append($"<div class=sql>执行SQL：{WebUtility.HtmlEncode(sql)}</div>");
    try
    {
        using DbConnection conn = Db.Open(e);
        using DbCommand cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        using DbDataReader rd = cmd.ExecuteReader();
        int rows = 0;
        sb.Append("<ul>");
        while (rd.Read())
        {
            rows++;
            var cells = new List<string>();
            for (int i = 0; i < rd.FieldCount; i++)
            {
                //BLOB/binary结果（如concat_ws含hex字面量、load_file）按UTF8文本输出，模拟真实Web框架行为
                object v = rd.GetValue(i);
                cells.Add(WebUtility.HtmlEncode(v is byte[] b ? Encoding.UTF8.GetString(b) : v?.ToString() ?? "NULL"));
            }
            //原样反射完整查询串（模拟真实应用的参数回显）
            sb.Append($"<li><a href=\"{req.Path}{req.QueryString}\">{cells[0]}</a> {string.Join(" | ", cells.Skip(1))}</li>");
        }
        sb.Append("</ul>");
        if (rows == 0) sb.Append("<div>查询结果为空</div>");
    }
    catch (Exception ex)
    {
        //错误信息完整输出到页面（供报错注入与数据库指纹识别）
        sb.Append($"<div class=err>{WebUtility.HtmlEncode(ex.Message)}</div>");
    }
    sb.Append($"<p><a href=\"/?db={e.Name}\">返回首页</a></p>");
    return Html(title, sb.ToString());
}

//首页：导航 + 各数据库连通状态
app.MapGet("/ping", () => Results.Text("pong", "text/plain", Encoding.UTF8));

//回显User-Agent（验证随机UA等请求指纹功能，无需数据库）
app.MapGet("/echo-ua", (HttpRequest req) => Results.Text(req.Headers.UserAgent.ToString(), "text/plain", Encoding.UTF8));

//回显查询参数x（验证Token/动态值替换，无需数据库）
app.MapGet("/echo-q", (HttpRequest req) => Results.Text(req.Query["x"].ToString(), "text/plain", Encoding.UTF8));

//回显Accept-Encoding（验证客户端压缩能力声明重写：统一为gzip, deflate, br，P1①）
app.MapGet("/echo-ae", (HttpRequest req) => Results.Text(req.Headers.AcceptEncoding.ToString(), "text/plain", Encoding.UTF8));

//Brotli压缩响应（验证br解码，P1②；客户端Accept-Encoding含br时解码后应为明文）
app.MapGet("/br", (HttpContext ctx) =>
{
    byte[] raw = Encoding.UTF8.GetBytes("BROTLI-OK-超级SQL注入工具V2");
    byte[] zip;
    using (var ms = new MemoryStream())
    {
        using (var brs = new System.IO.Compression.BrotliStream(ms, System.IO.Compression.CompressionLevel.Fastest, true))
        {
            brs.Write(raw, 0, raw.Length);
        }
        zip = ms.ToArray();
    }
    ctx.Response.Headers.ContentEncoding = "br";
    ctx.Response.Headers.ContentType = "text/plain; charset=utf-8";
    return Results.Bytes(zip);
});

//302跳转链（验证FollowRedirect）：/redir1 → /redir2 → /ping
app.MapGet("/redir1", () => Results.Redirect("/redir2"));
app.MapGet("/redir2", () => Results.Redirect("/ping"));

//回显原始请求体（验证chunked分块发包，无需数据库）
app.MapPost("/echo-body", async (HttpRequest req) =>
    Results.Text(await new StreamReader(req.Body).ReadToEndAsync(), "text/plain", Encoding.UTF8));

//CSRF token联动验证：/token-page每次签发新token，/csrf-check校验是否最新签发值（验证每请求刷新token机制）
string lastCsrfToken = "";
app.MapGet("/token-page", () =>
{
    lastCsrfToken = "tok-" + Guid.NewGuid().ToString("N")[..8];
    return Results.Text($"<html><form><input type=\"hidden\" name=\"csrf\" value=\"{lastCsrfToken}\"></form></html>", "text/html", Encoding.UTF8);
});
app.MapGet("/csrf-check", (HttpRequest req) =>
    Results.Text(req.Query["csrf"].ToString() == lastCsrfToken && lastCsrfToken != "" ? "OK" : "FAIL", "text/plain", Encoding.UTF8));

app.MapGet("/", (HttpRequest req) =>
{
    string dbFilter = req.Query["db"];
    var sb = new StringBuilder("<h3>SQL注入多数据库验证靶场</h3>");
    sb.Append("<p>各端点均存在注入，错误信息直接输出到页面，参数原样回显到href（模拟反射）。</p>");
    sb.Append("<table><tr><th>数据库</th><th>状态</th><th>数字型/news</th><th>字符型/users</th><th>搜索型/like</th><th>POST登录</th><th>初始化</th></tr>");
    foreach (Db.DbEntry e in Db.All)
    {
        if (!string.IsNullOrEmpty(dbFilter) && !e.Name.Equals(dbFilter, StringComparison.OrdinalIgnoreCase)) continue;
        string status;
        try
        {
            using DbConnection c = Db.Open(e);
            status = "在线：" + WebUtility.HtmlEncode(c.ServerVersion);
        }
        catch (Exception ex)
        {
            status = "离线：" + WebUtility.HtmlEncode(ex.Message.Split('\n')[0]);
        }
        sb.Append($"<tr><td>{e.Name}</td><td>{status}</td>"
            + $"<td><a href=\"/num?db={e.Name}&id=1\">/num?id=1</a></td>"
            + $"<td><a href=\"/str?db={e.Name}&name=admin\">/str?name=admin</a></td>"
            + $"<td><a href=\"/like?db={e.Name}&kw=数据\">/like?kw=数据</a></td>"
            + $"<td><a href=\"/login?db={e.Name}\">/login</a></td>"
            + $"<td><a href=\"/init?db={e.Name}\">/init</a></td></tr>");
    }
    sb.Append("</table>");
    sb.Append("<p>达梦DM：语法兼容Oracle，可先用sqlite/mysql验证工具链路；KingbaseES直接用pgsql协议连接（上表kingbase行）。</p>");
    return Results.Content(Html("SQLi验证靶场", sb.ToString()), "text/html", Encoding.UTF8);
});

app.MapGet("/init", (HttpRequest req) =>
{
    Db.DbEntry e = Db.Find(req.Query["db"]);
    try
    {
        string log = Db.Init(e);
        return Results.Content(Html("初始化", $"<div class=ok>{WebUtility.HtmlEncode(log)}</div><p><a href=\"/?db={e.Name}\">返回</a></p>"), "text/html", Encoding.UTF8);
    }
    catch (Exception ex)
    {
        return Results.Content(Html("初始化失败", $"<div class=err>{WebUtility.HtmlEncode(ex.ToString())}</div><p><a href=\"/\">返回</a></p>"), "text/html", Encoding.UTF8);
    }
});

//数字型注入：select 4列，供Union/布尔/报错/时间测试
app.MapGet("/num", (HttpRequest req) =>
{
    Db.DbEntry e = Db.Find(req.Query["db"]);
    string id = req.Query["id"];
    string sql = $"select id,title,content,author from news where id={id}";
    return Results.Content(ShowQuery(req, "数字型注入点 /num", e, sql), "text/html", Encoding.UTF8);
});

//截断版数字型注入点 /numt：页面输出超过1200字符即硬截断（正常页面1035字符不受影响，检测照常；
//超长Union/报错数据被截断，验证"起始标记在/结束标记丢失→分片取回"链路）
app.MapGet("/numt", (HttpRequest req) =>
{
    Db.DbEntry e = Db.Find(req.Query["db"]);
    string id = req.Query["id"];
    string sql = $"select id,title,content,author from news where id={id}";
    string html = ShowQuery(req, "数字型注入点(截断) /numt", e, sql);
    if (html.Length > 1600)
    {
        html = html.Substring(0, 1600);
    }
    return Results.Content(html, "text/html", Encoding.UTF8);
});

//WAF过滤'>'的数字型注入点 /wafgt：注入逻辑同/num，但id含'>'时返回405拦截页（安全狗风格）。
//检测探针用'='不受影响可正常检出盲注；'>'二分取数被拦→验证检测期自动适配between tamper链路
app.MapGet("/wafgt", (HttpRequest req) =>
{
    string id = req.Query["id"].ToString();
    if (id.IndexOf('>') != -1)
    {
        string block = "<html><head><title>405</title></head><body><h1>405 Not Allowed</h1>"
            + "<p>您已被网站管理员设置拦截！拦截原因：疑似SQL注入攻击。</p>"
            + "<p>如需解除拦截请联系管理员，详情见 waf.safedog.cn</p></body></html>";
        return Results.Text(block, "text/html", Encoding.UTF8, StatusCodes.Status405MethodNotAllowed);
    }
    Db.DbEntry e = Db.Find(req.Query["db"]);
    string sql = $"select id,title,content,author from news where id={id}";
    return Results.Content(ShowQuery(req, "数字型注入点(WAF过滤&gt;) /wafgt", e, sql), "text/html", Encoding.UTF8);
});

//抖动版数字型注入点 /numflaky：含"case when"的探测请求（盲注取数特征）每第5个返回500错误页，
//模拟WAF/网关间歇性拦截/限流。检测payload（and 1=1式）不含case when不受影响，可正常检出；
//取数探测间歇500→验证防脏数据校验（意外状态码作废重发+逐字符NOT复核）链路
app.MapGet("/numflaky", (HttpRequest req) =>
{
    string id = req.Query["id"].ToString();
    if (id.Contains("case when", StringComparison.OrdinalIgnoreCase)
        && Interlocked.Increment(ref FlakyState.Count) % 5 == 0)
    {
        return Results.Text("<html><head><title>500</title></head><body><h1>500 Internal Server Error</h1><p>upstream temporarily unavailable</p></body></html>",
            "text/html", Encoding.UTF8, StatusCodes.Status500InternalServerError);
    }
    Db.DbEntry e = Db.Find(req.Query["db"]);
    string sql = $"select id,title,content,author from news where id={id}";
    return Results.Content(ShowQuery(req, "数字型注入点(抖动) /numflaky", e, sql), "text/html", Encoding.UTF8);
});

//Cookie注入：track Cookie作为查询条件（验证level>=2 Cookie注入检测）。
//模拟老旧应用手工解析Cookie头（含空格等非法cookie字符也能读到，正是这类写法容易引入注入）
app.MapGet("/cookie", (HttpRequest req) =>
{
    Db.DbEntry e = Db.Find(req.Query["db"]);
    string track = "1";
    string rawCookie = req.Headers.Cookie.ToString();
    foreach (string pair in rawCookie.Split(';', StringSplitOptions.RemoveEmptyEntries))
    {
        int eq = pair.IndexOf('=');
        if (eq > 0 && pair[..eq].Trim() == "track") { track = pair[(eq + 1)..].Trim(); break; }
    }
    string sql = $"select id,title,content,author from news where id={track}";
    return Results.Content(ShowQuery(req, "Cookie注入点 /cookie", e, sql), "text/html", Encoding.UTF8);
});

//HTTP头注入：User-Agent作为字符型查询条件（验证level>=3 头注入检测）
app.MapGet("/ua", (HttpRequest req) =>
{
    Db.DbEntry e = Db.Find(req.Query["db"]);
    string ua = req.Headers.UserAgent.ToString();
    string sql = $"select id,username,password,email from users where username='{ua}'";
    return Results.Content(ShowQuery(req, "HTTP头注入点 /ua", e, sql), "text/html", Encoding.UTF8);
});

//模拟WAF（安全狗风格）：所有响应带 safedog-flow-item Cookie（被动指纹）；
//参数含攻击特征串时返回405+拦截页（含waf.safedog.cn文案，主动指纹+状态码突变）
app.MapGet("/waf", (HttpRequest req) =>
{
    string id = req.Query["id"].ToString();
    string cookie = "safedog-flow-item=9f2c1a; path=/";
    bool attack = id.IndexOf("union", StringComparison.OrdinalIgnoreCase) != -1
        || id.IndexOf("information_schema", StringComparison.OrdinalIgnoreCase) != -1
        || id.IndexOf("../../", StringComparison.OrdinalIgnoreCase) != -1;
    if (attack)
    {
        string block = "<html><head><title>405</title></head><body><h1>405 Not Allowed</h1>"
            + "<p>您已被网站管理员设置拦截！拦截原因：疑似SQL注入攻击。</p>"
            + "<p>如需解除拦截请联系管理员，详情见 waf.safedog.cn</p></body></html>";
        return Results.Text(block, "text/html", Encoding.UTF8, StatusCodes.Status405MethodNotAllowed);
    }
    string page = "<html><body><h3>新闻页</h3><p>id=" + WebUtility.HtmlEncode(id) + " 的正常内容</p></body></html>";
    var res = Results.Content(page, "text/html", Encoding.UTF8);
    req.HttpContext.Response.Headers["Set-Cookie"] = cookie;
    return res;
});

//JSON体注入：POST {"id":1}（验证JSON参数位置注入）
app.MapPost("/json", async (HttpRequest req) =>
{
    Db.DbEntry e = Db.Find(req.Query["db"]);
    string id = "1";
    try
    {
        using var doc = System.Text.Json.JsonDocument.Parse(await new StreamReader(req.Body).ReadToEndAsync());
        id = doc.RootElement.GetProperty("id").ToString();
    }
    catch { }
    string sql = $"select id,title,content,author from news where id={id}";
    return Results.Content(ShowQuery(req, "JSON注入点 /json", e, sql), "text/html", Encoding.UTF8);
});

//Multipart表单注入：POST multipart/form-data 字段id（验证multipart参数位置注入）
app.MapPost("/multipart", async (HttpRequest req) =>
{
    Db.DbEntry e = Db.Find(req.Query["db"]);
    string id = "1";
    try
    {
        //手工解析multipart文本字段（模拟老旧应用直接读原始body的写法，正是这类写法容易引入注入）
        string ct = req.ContentType ?? "";
        var bm = System.Text.RegularExpressions.Regex.Match(ct, "boundary=(?<b>[^;\\s]+)");
        string body = await new StreamReader(req.Body).ReadToEndAsync();
        if (bm.Success)
        {
            var pm = System.Text.RegularExpressions.Regex.Match(body,
                "name=\"id\"[.\\s\\S]*?\\r?\\n\\r?\\n(?<v>[.\\s\\S]*?)\\r?\\n--" + System.Text.RegularExpressions.Regex.Escape(bm.Groups["b"].Value.Trim('"')));
            if (pm.Success) id = pm.Groups["v"].Value;
        }
    }
    catch { }
    string sql = $"select id,title,content,author from news where id={id}";
    return Results.Content(ShowQuery(req, "Multipart注入点 /multipart", e, sql), "text/html", Encoding.UTF8);
});

//字符型注入：单引号闭合
app.MapGet("/str", (HttpRequest req) =>
{
    Db.DbEntry e = Db.Find(req.Query["db"]);
    string name = req.Query["name"];
    string sql = $"select id,username,password,email from users where username='{name}'";
    return Results.Content(ShowQuery(req, "字符型注入点 /str", e, sql), "text/html", Encoding.UTF8);
});

//搜索型注入：like '%kw%'
app.MapGet("/like", (HttpRequest req) =>
{
    Db.DbEntry e = Db.Find(req.Query["db"]);
    string kw = req.Query["kw"];
    string sql = $"select id,title,content,author from news where title like '%{kw}%'";
    return Results.Content(ShowQuery(req, "搜索型注入点 /like", e, sql), "text/html", Encoding.UTF8);
});

//POST登录注入
app.MapGet("/login", (HttpRequest req) =>
{
    string db = req.Query["db"];
    string form = $"""
<h3>POST登录注入点（{db}）</h3>
<form method="post" action="/login?db={db}">
用户名：<input name="username" value="admin"><br>
密码：<input name="password" value="123"><br>
<input type="submit" value="登录">
</form><p><a href="/">返回首页</a></p>
""";
    return Results.Content(Html("登录", form), "text/html", Encoding.UTF8);
});

app.MapPost("/login", async (HttpRequest req) =>
{
    Db.DbEntry e = Db.Find(req.Query["db"]);
    var form = await req.ReadFormAsync();
    string u = form["username"], p = form["password"];
    string sql = $"select count(1) from users where username='{u}' and password='{p}'";
    var sb = new StringBuilder($"<h3>POST登录注入点（{e.Name}）</h3><div class=sql>执行SQL：{WebUtility.HtmlEncode(sql)}</div>");
    try
    {
        using DbConnection conn = Db.Open(e);
        long cnt = Convert.ToInt64(Db.Scalar(conn, sql));
        sb.Append(cnt > 0 ? "<div class=ok>登录成功！</div>" : "<div>登录失败：用户名或密码错误</div>");
    }
    catch (Exception ex)
    {
        sb.Append($"<div class=err>{WebUtility.HtmlEncode(ex.Message)}</div>");
    }
    sb.Append($"<p><a href=\"/login?db={e.Name}\">返回</a></p>");
    return Results.Content(Html("登录结果", sb.ToString()), "text/html", Encoding.UTF8);
});

app.Run();

/// <summary>/numflaky 抖动计数器（静态字段避免闭包ref限制）</summary>
static class FlakyState
{
    public static int Count;
}
