using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Tools;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SuperSQLInjectionV2.Cmd;

/// <summary>
/// 检测会话持久化与复用（对齐 sqlmap session 机制 + GUI 注入记录恢复）：
/// 同一目标（scheme/host/port）+ 同一报文 + 同一检测参数（level/risk/technique/dbms/smart/exhaustive/tamper）
/// 指纹匹配时直接载入已检出注入点，跳过重复检测进入取数动作；--flush-session 强制重测并覆盖。
/// 文件为 output/&lt;host&gt;_&lt;port&gt;/session.json，AOT 下走源生成序列化（禁反射）。
/// </summary>
public static class SessionStore
{
    /// <summary>会话文件结构（v2 对象格式；v1 裸数组格式字段不全无法安全取数，视为不兼容自动重测覆盖）</summary>
    public sealed class SessionFile
    {
        public string Fingerprint { get; set; } = "";
        public string Url { get; set; } = "";
        public string SavedAt { get; set; } = "";
        public List<InjectPoint> Hits { get; set; } = [];
    }

    /// <summary>会话指纹：目标+报文+检测参数全量哈希（任一变化即失效重测，与sqlmap仅按目标复用相比更保守防误用旧结果）</summary>
    public static string Fingerprint(AppConfig config, CliOptions opt, string requestTxt)
    {
        string material = (config.IsSSL ? "https" : "http") + "://" + config.Host + ":" + config.Port
            + "|lv" + opt.Level + "|rk" + opt.Risk
            + "|tech:" + (opt.Technique ?? "") + "|dbms:" + (opt.Dbms ?? "")
            + "|smart:" + (!opt.NoSmart) + "|exh:" + opt.Exhaustive + "|tamper:" + (opt.Tamper ?? "")
            + "\n" + requestTxt;
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
    }

    /// <summary>保存会话（检测命中后调用；失败仅告警不影响结果）</summary>
    public static void Save(CliOptions opt, AppConfig config, string displayUrl, string requestTxt, List<InjectPoint> hits)
    {
        try
        {
            string file = Path.Combine(OutputDir(opt, config), "session.json");
            var sf = new SessionFile
            {
                Fingerprint = Fingerprint(config, opt, requestTxt),
                Url = displayUrl,
                SavedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                Hits = hits
            };
            File.WriteAllText(file, JsonSerializer.Serialize(sf, CmdJsonCtx.Default.SessionFile));
            Log.Show($"检测会话已保存: {file}");
        }
        catch (Exception e)
        {
            Log.Warning("会话保存失败（不影响结果）: " + e.Message);
        }
    }

    /// <summary>尝试复用会话：文件存在且指纹匹配时载入注入点返回true；旧版格式/指纹不符/损坏均返回false（调用方重新检测）</summary>
    public static bool TryLoad(CliOptions opt, AppConfig config, string requestTxt, out List<InjectPoint> hits)
    {
        hits = [];
        try
        {
            string file = Path.Combine(OutputDir(opt, config), "session.json");
            if (!File.Exists(file))
            {
                return false;
            }
            string txt = File.ReadAllText(file);
            if (txt.TrimStart().StartsWith("[", StringComparison.Ordinal))
            {
                //v1裸数组格式：缺RequestTxt/AutoTamper/Where等取数必需字段，不可安全复用
                Log.Show("发现旧版会话文件（字段不全无法复用），将重新检测并覆盖");
                return false;
            }
            SessionFile? sf = JsonSerializer.Deserialize(txt, CmdJsonCtx.Default.SessionFile);
            if (sf == null || sf.Hits.Count == 0)
            {
                return false;
            }
            if (!string.Equals(sf.Fingerprint, Fingerprint(config, opt, requestTxt), StringComparison.Ordinal))
            {
                Log.Show("历史会话与当前目标/报文/检测参数不一致，重新检测");
                return false;
            }
            hits = sf.Hits;
            return true;
        }
        catch (Exception e)
        {
            Log.Warning("会话读取失败（将重新检测）: " + e.Message);
            return false;
        }
    }

    private static string OutputDir(CliOptions opt, AppConfig config)
    {
        string dir = opt.OutputDir ?? Path.Combine("output", $"{config.Host}_{config.Port}");
        Directory.CreateDirectory(dir);
        return dir;
    }
}

/// <summary>AOT源生成JSON上下文（会话文件序列化，禁反射）</summary>
[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(SessionStore.SessionFile))]
internal partial class CmdJsonCtx : JsonSerializerContext
{
}
