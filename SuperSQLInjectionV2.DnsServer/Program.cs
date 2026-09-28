using SuperSQLInjectionV2.Tools.Dns;
using System.Net;
using System.Text;

// SuperSQLInjectionV2 自建 DNSLog 接收端（服务器部署形态，P2-8）
// 部署到具有公网IP的VPS，域名（如 dns.example.com）NS记录指向本机；
// 主程序侧"DNSLog域名"填该域名，"DNSLog API地址模板"填：
//   http://<vps>:<httpPort>/api/records?token={token}&type=dns&filter={domain}
// 即可复用现有 ceye 格式回收链路（DnsExfilTool 零改动）。
//
// 用法:
//   SuperSQLInjectionV2.DnsServer --domain dns.example.com --port 53 --http 8080 --token SECRET [--answer 127.0.0.1]
// 注意: UDP 53 需要 root（linux: setcap 'cap_net_bind_service=+ep' 或 sudo）；HTTP API 默认仅监听本机回环以外的地址请自行加防火墙。

string domain = "";
int port = 53;
int httpPort = 8080;
string token = "";
string answer = "127.0.0.1";

for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--domain" when i + 1 < args.Length: domain = args[++i]; break;
        case "--port" when i + 1 < args.Length: port = int.Parse(args[++i]); break;
        case "--http" when i + 1 < args.Length: httpPort = int.Parse(args[++i]); break;
        case "--token" when i + 1 < args.Length: token = args[++i]; break;
        case "--answer" when i + 1 < args.Length: answer = args[++i]; break;
        case "--help":
            Console.WriteLine("用法: SuperSQLInjectionV2.DnsServer --domain <区名> [--port 53] [--http 8080] [--token SECRET] [--answer 127.0.0.1]");
            return 0;
    }
}

if (string.IsNullOrWhiteSpace(domain))
{
    Console.WriteLine("错误：必须指定 --domain（权威区名，如 dns.example.com）。--help 查看用法。");
    return 1;
}

var server = new DnsLogServerCore
{
    ZoneDomain = domain,
    AnswerIp = answer,
    Logger = msg => Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {msg}")
};
server.Start(port);

//ceye兼容HTTP查询API（token为空=不校验，仅限内网/防火墙场景）
var listener = new HttpListener();
try
{
    listener.Prefixes.Add($"http://+:{httpPort}/");
    listener.Start();
    Console.WriteLine($"HTTP查询API已启动: http://+:{httpPort}/api/records?token=<token>&filter=<domain>");
}
catch (HttpListenerException)
{
    //Windows非管理员不能绑通配前缀（http.sys urlacl限制），回退本机回环并给出放行命令提示
    listener = new HttpListener();
    listener.Prefixes.Add($"http://127.0.0.1:{httpPort}/");
    listener.Start();
    Console.WriteLine($"HTTP查询API已启动(仅本机): http://127.0.0.1:{httpPort}/api/records?token=<token>&filter=<domain>");
    Console.WriteLine($"提示：需外部访问请以管理员运行，或先执行 netsh http add urlacl url=http://+:{httpPort}/ user=Everyone");
}

var exit = new ManualResetEventSlim(false);
Console.CancelKeyPress += (_, e) => { e.Cancel = true; exit.Set(); };

while (!exit.IsSet)
{
    HttpListenerContext ctx;
    try
    {
        ctx = await listener.GetContextAsync();
    }
    catch { break; }
    _ = Task.Run(() => HandleApi(ctx, server, token));
}

server.Stop();
return 0;

static void HandleApi(HttpListenerContext ctx, DnsLogServerCore server, string token)
{
    try
    {
        var req = ctx.Request;
        var resp = ctx.Response;
        resp.ContentType = "application/json; charset=utf-8";

        string path = req.Url?.AbsolutePath ?? "";
        if (path == "/healthz")
        {
            WriteJson(resp, 200, "{\"ok\":true}");
            return;
        }
        if (!string.IsNullOrEmpty(token) && req.QueryString["token"] != token)
        {
            WriteJson(resp, 403, "{\"errcode\":403,\"errmsg\":\"invalid token\"}");
            return;
        }

        switch (path)
        {
            case "/api/records":
                //ceye格式：{"data":[{"name":"i1.xxxx.domain"}...]}，主程序DnsExfilTool直接解析
                WriteJson(resp, 200, server.ToCeyeJson(req.QueryString["filter"] ?? ""));
                break;
            case "/api/clear":
                server.Clear();
                WriteJson(resp, 200, "{\"ok\":true}");
                break;
            default:
                WriteJson(resp, 404, "{\"errcode\":404,\"errmsg\":\"not found\"}");
                break;
        }
    }
    catch
    {
        try { ctx.Response.StatusCode = 500; ctx.Response.Close(); } catch { }
    }
}

static void WriteJson(HttpListenerResponse resp, int code, string json)
{
    resp.StatusCode = code;
    byte[] data = Encoding.UTF8.GetBytes(json);
    resp.ContentLength64 = data.Length;
    resp.OutputStream.Write(data, 0, data.Length);
    resp.OutputStream.Close();
}
