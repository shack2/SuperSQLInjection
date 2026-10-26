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
        public int SchemaVersion { get; set; } = 3;
        public string EngineVersion { get; set; } = "";
        public string Fingerprint { get; set; } = "";
        public string Url { get; set; } = "";
        public string SavedAt { get; set; } = "";
        public List<InjectPoint> Hits { get; set; } = [];
    }

    /// <summary>会话指纹包含目标报文、检测参数、引擎版本以及规则/脚本/用例内容。</summary>
    public static string Fingerprint(AppConfig config, CliOptions opt, string requestTxt)
    {
        string material = TargetFingerprint.ForConfig(config, requestTxt: requestTxt)
            + "|lv" + opt.Level + "|rk" + opt.Risk
            + "|tech:" + (opt.Technique ?? "") + "|dbms:" + (opt.Dbms ?? "")
            + "|smart:" + (!opt.NoSmart) + "|exh:" + opt.Exhaustive + "|tamper:" + (opt.Tamper ?? "")
            + "|engine:" + Program.AppVersion + "|rules:" + RulesFingerprint(opt)
            + "\n" + requestTxt;
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
    }

    private static string RulesFingerprint(CliOptions opt)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        string root = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config");
        foreach (string directory in new[] { opt.RulesDir ?? Path.Combine(root, "rules"), Path.Combine(root, "injection"), Path.Combine(root, "payload") })
        {
            if (!Directory.Exists(directory)) continue;
            foreach (string file in Directory.GetFiles(directory, "*", SearchOption.AllDirectories).OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            {
                hash.AppendData(Encoding.UTF8.GetBytes(Path.GetRelativePath(directory, file)));
                hash.AppendData(File.ReadAllBytes(file));
            }
        }
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    /// <summary>保存会话（检测命中后调用；失败仅告警不影响结果）</summary>
    public static void Save(CliOptions opt, AppConfig config, string displayUrl, string requestTxt, List<InjectPoint> hits)
    {
        try
        {
            string file = Path.Combine(OutputDir(opt, config, requestTxt), "session.json");
            var sf = new SessionFile
            {
                EngineVersion = Program.AppVersion,
                Fingerprint = Fingerprint(config, opt, requestTxt),
                Url = displayUrl,
                SavedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                Hits = hits
            };
            AtomicFile.WriteAllText(file, JsonSerializer.Serialize(sf, CmdJsonCtx.Default.SessionFile));
            Log.Show($"检测会话已保存: {file}");
        }
        catch (Exception e)
        {
            Log.Warning("会话保存失败（不影响结果）: " + e.Message);
        }
    }

    /// <summary>仅复用当前schema且指纹完全匹配的会话；损坏文件保留备份后重测。</summary>
    public static bool TryLoad(CliOptions opt, AppConfig config, string requestTxt, out List<InjectPoint> hits)
    {
        hits = [];
        string file = Path.Combine(OutputDir(opt, config, requestTxt), "session.json");
        try
        {
            if (!File.Exists(file)) return false;
            string txt = File.ReadAllText(file);
            if (txt.TrimStart().StartsWith("[", StringComparison.Ordinal)) return false;
            SessionFile? sf = JsonSerializer.Deserialize(txt, CmdJsonCtx.Default.SessionFile);
            if (sf == null || sf.SchemaVersion != 3 || sf.Hits.Count == 0) return false;
            if (!string.Equals(sf.Fingerprint, Fingerprint(config, opt, requestTxt), StringComparison.Ordinal))
            {
                Log.Show("历史会话与当前目标/报文/规则/检测参数不一致，重新检测");
                return false;
            }
            hits = sf.Hits;
            return true;
        }
        catch (Exception e)
        {
            try { if (File.Exists(file)) File.Copy(file, file + ".corrupt-" + DateTime.Now.ToString("yyyyMMddHHmmss"), true); } catch { }
            Log.Warning("会话读取失败（已保留损坏备份并重新检测）: " + e.Message);
            return false;
        }
    }

    private static string OutputDir(CliOptions opt, AppConfig config, string requestTxt)
    {
        string requestHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(requestTxt)))[..12].ToLowerInvariant();
        string dir = opt.OutputDir ?? Path.Combine("output", $"{config.Host}_{config.Port}", requestHash);
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
