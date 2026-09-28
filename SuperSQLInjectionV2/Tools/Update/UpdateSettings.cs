namespace SuperSQLInjectionV2.Tools.Update;

/// <summary>
/// 更新服务连接配置：唯一事实源为 config/update.ini（随包分发，UI 不提供修改）。
/// 文件缺失时按内置默认值自动写回；键缺失或为空时回落内置默认值。
/// </summary>
public static class UpdateSettings
{
    private const string DefaultServerUrl = "http://soft.shack2.cn/";
    private const string DefaultAppId = "supersqlinjection";
    private const string DefaultChannel = "stable";
    private const string DefaultAuthKey = "13672d9ae9cd29b9972c0ebcee559f3cb06299434f406eefea9e5d75e6684666";

    private static string IniPath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config", "update.ini");

    private static readonly Lazy<Dictionary<string, string>> _values = new(Load, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>更新服务地址（空=不检测）</summary>
    public static string ServerUrl => Get("ServerUrl", DefaultServerUrl);

    /// <summary>应用标识（需与服务端注册一致）</summary>
    public static string AppId => Get("AppId", DefaultAppId);

    /// <summary>更新渠道（stable/beta...）</summary>
    public static string Channel => Get("Channel", DefaultChannel);

    /// <summary>客户端访问 AES Key（64位十六进制，客户端与Key一起分发）</summary>
    public static string AuthKey => Get("AuthKey", DefaultAuthKey);

    private static string Get(string key, string fallback)
    {
        return _values.Value.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v) ? v.Trim() : fallback;
    }

    private static Dictionary<string, string> Load()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (!File.Exists(IniPath))
            {
                WriteDefault();
            }
            else
            {
                foreach (var raw in File.ReadAllLines(IniPath))
                {
                    var line = raw.Trim();
                    if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';'))
                    {
                        continue;
                    }
                    int eq = line.IndexOf('=');
                    if (eq <= 0)
                    {
                        continue;
                    }
                    map[line[..eq].Trim()] = line[(eq + 1)..].Trim();
                }
            }
        }
        catch (Exception e)
        {
            Log.SysLog("读取config/update.ini失败（将使用内置默认更新配置）：" + e.Message);
        }
        return map;
    }

    /// <summary>首次运行写出默认配置，便于部署时直接改文件。</summary>
    private static void WriteDefault()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(IniPath)!);
            File.WriteAllText(IniPath,
                "# SoftUpdate 更新服务连接配置（UI 不提供修改，直接编辑本文件后重启生效）" + Environment.NewLine +
                "# ServerUrl：更新服务地址，留空则关闭更新检测与反馈提交" + Environment.NewLine +
                "ServerUrl=" + DefaultServerUrl + Environment.NewLine +
                "# AppId：应用标识，需与服务端注册一致" + Environment.NewLine +
                "AppId=" + DefaultAppId + Environment.NewLine +
                "# Channel：更新渠道（stable/beta...）" + Environment.NewLine +
                "Channel=" + DefaultChannel + Environment.NewLine +
                "# AuthKey：客户端访问 AES Key（64位十六进制，服务端启动横幅或 GET /api/admin/client-key 获取）" + Environment.NewLine +
                "AuthKey=" + DefaultAuthKey + Environment.NewLine);
        }
        catch (Exception e)
        {
            Log.SysLog("写入默认config/update.ini失败：" + e.Message);
        }
    }
}
