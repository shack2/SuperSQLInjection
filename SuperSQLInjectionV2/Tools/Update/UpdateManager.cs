using System.Net.Http.Json;
using System.Security.Cryptography;

namespace SuperSQLInjectionV2.Tools.Update;

/// <summary>更新客户端配置（移植自 SoftUpdate.Client.Core，裁剪为检查+下载场景）</summary>
public sealed class UpdateManagerOptions
{
    /// <summary>更新服务地址，例如 http://update.example.com:5900</summary>
    public string ServerUrl { get; set; } = "";

    /// <summary>应用标识，需与服务端注册一致。</summary>
    public string AppId { get; set; } = "";

    /// <summary>客户端访问 AES Key（64 位十六进制字符，来自服务端启动横幅或管理接口），用于生成请求令牌。</summary>
    public string ClientAuthKey { get; set; } = "";

    /// <summary>更新渠道（stable / beta / ...）。</summary>
    public string Channel { get; set; } = "stable";

    /// <summary>客户端软件运行目录，更新 zip 包会下载到该目录。</summary>
    public string InstallDir { get; set; } = AppContext.BaseDirectory;

    /// <summary>当前版本记录文件，默认 {InstallDir}/.softupdate/current-version.txt。由宿主程序在完成安装后写入。</summary>
    public string VersionFile { get; set; } = "";

    public void Normalize()
    {
        InstallDir = Path.GetFullPath(InstallDir);
        if (string.IsNullOrWhiteSpace(VersionFile)) VersionFile = Path.Combine(InstallDir, ".softupdate", "current-version.txt");
        ServerUrl = ServerUrl.TrimEnd('/');
    }
}

public enum UpdatePhase
{
    Checking,
    Downloading,
    Verifying,
    Completed
}

public sealed class UpdateProgress(UpdatePhase phase, string? currentFile, long transferredBytes, long totalBytes, int completedFiles, int totalFiles)
{
    public UpdatePhase Phase { get; } = phase;
    public string? CurrentFile { get; } = currentFile;
    public long TransferredBytes { get; } = transferredBytes;
    public long TotalBytes { get; } = totalBytes;
    public int CompletedFiles { get; } = completedFiles;
    public int TotalFiles { get; } = totalFiles;

    public double Percent => TotalBytes > 0 ? TransferredBytes * 100.0 / TotalBytes : 0;
}

/// <summary>
/// 更新管理门面：检查更新 → 下载 zip 更新包到软件运行目录（SHA256 校验）。
/// 更新包的解压与安装由宿主程序自行处理；当前版本号也由宿主程序写入 VersionFile。
/// </summary>
public sealed class UpdateManager : IDisposable
{
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;

    public UpdateManagerOptions Options { get; }

    public UpdateManager(UpdateManagerOptions options, HttpClient? httpClient = null)
    {
        options.Normalize();
        Options = options;
        _http = httpClient ?? new HttpClient { BaseAddress = new Uri(options.ServerUrl) };
        _ownsHttpClient = httpClient is null;
    }

    /// <summary>读取宿主程序记录的版本号（首次安装返回 null）。</summary>
    public async Task<string?> GetInstalledVersionAsync(CancellationToken ct = default)
    {
        if (!File.Exists(Options.VersionFile)) return null;
        var text = await File.ReadAllTextAsync(Options.VersionFile, ct);
        text = text.Trim();
        return text.Length == 0 ? null : text;
    }

    public async Task<CheckUpdateResponse> CheckForUpdatesAsync(string? currentVersion = null, CancellationToken ct = default)
    {
        currentVersion ??= await GetInstalledVersionAsync(ct) ?? "0.0.0";

        var url = $"/api/client/check?appId={Uri.EscapeDataString(Options.AppId)}" +
                  $"&channel={Uri.EscapeDataString(Options.Channel)}" +
                  $"&version={Uri.EscapeDataString(currentVersion)}" +
                  $"&os={Uri.EscapeDataString(UpdateSystemInfo.GetOsType())}" +
                  $"&arch={Uri.EscapeDataString(UpdateSystemInfo.GetArchitecture())}" +
                  $"&osDesc={Uri.EscapeDataString(UpdateSystemInfo.GetOsDescription())}" +
                  $"&screen={Uri.EscapeDataString(UpdateSystemInfo.GetScreenResolution() ?? "")}" +
                  TokenQuery();
        using var response = await _http.GetAsync(url, ct);
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadFromJsonAsync(Source.JsonCtx.WebInfo<CheckUpdateResponse>(), ct);
        return result ?? throw new InvalidOperationException("服务端返回了空的检查结果");
    }

    /// <summary>
    /// 下载 zip 更新包到软件运行目录并校验 SHA256，返回包的完整路径。
    /// 目录中已存在且哈希一致的包会直接复用；新包下载成功后自动清理上一个未处理的更新包。
    /// </summary>
    public async Task<string> DownloadUpdateAsync(UpdateManifest manifest, IProgress<UpdateProgress>? progress = null, CancellationToken ct = default)
    {
        if (manifest.Files.Count != 1)
            throw new InvalidOperationException("更新清单格式无效：应为单个 zip 更新包");
        var entry = manifest.Files[0];
        if (!entry.Path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"更新清单中的文件不是 zip 压缩包: {entry.Path}");

        var targetPath = SafePath.Combine(Options.InstallDir, entry.Path);

        // 上次已下载且校验一致的包直接复用
        if (File.Exists(targetPath) && await HashUtil.MatchesAsync(targetPath, entry, ct))
            return targetPath;

        CleanupPreviousPackage(entry.Path);

        progress?.Report(new UpdateProgress(UpdatePhase.Downloading, entry.Path, 0, entry.Size, 0, 1));

        var tempPath = targetPath + ".part";
        var url = $"/api/client/file?appId={Uri.EscapeDataString(Options.AppId)}" +
                  $"&version={Uri.EscapeDataString(manifest.Version)}" +
                  $"&path={Uri.EscapeDataString(entry.Path)}" +
                  $"&os={Uri.EscapeDataString(UpdateSystemInfo.GetOsType())}" +
                  $"&arch={Uri.EscapeDataString(UpdateSystemInfo.GetArchitecture())}" +
                  TokenQuery();

        long transferred = 0;
        var lastPercent = -1;
        using (var response = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct))
        {
            response.EnsureSuccessStatusCode();
            await using (var remote = await response.Content.ReadAsStreamAsync(ct))
            await using (var local = File.Create(tempPath))
            {
                var buffer = new byte[81920];
                int read;
                while ((read = await remote.ReadAsync(buffer, ct)) > 0)
                {
                    await local.WriteAsync(buffer.AsMemory(0, read), ct);
                    transferred += read;
                    var percent = (int)(transferred * 100 / Math.Max(entry.Size, 1));
                    if (percent != lastPercent)
                    {
                        lastPercent = percent;
                        progress?.Report(new UpdateProgress(UpdatePhase.Downloading, entry.Path, transferred, entry.Size, 0, 1));
                    }
                }
            }
        }

        if (!await HashUtil.MatchesAsync(tempPath, entry, ct))
        {
            TryDelete(tempPath);
            throw new InvalidOperationException($"更新包校验失败（SHA256 不匹配）: {entry.Path}");
        }
        progress?.Report(new UpdateProgress(UpdatePhase.Verifying, null, entry.Size, entry.Size, 1, 1));

        File.Move(tempPath, targetPath, overwrite: true);
        WritePendingMarker(entry.Path);
        return targetPath;
    }

    /// <summary>
    /// 提交意见建议反馈到更新服务（POST /api/client/feedback）。
    /// 联系方式可空；内容服务端限制 4000 字以内。
    /// </summary>
    public async Task SubmitFeedbackAsync(string content, string? contact = null, string? version = null, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(content))
            throw new ArgumentException("反馈内容不能为空", nameof(content));

        version ??= await GetInstalledVersionAsync(ct) ?? "0.0.0";
        var payload = new FeedbackRequest
        {
            AppId = Options.AppId,
            Version = version,
            Content = content.Trim(),
            Contact = string.IsNullOrWhiteSpace(contact) ? null : contact.Trim()
        };
        var url = "/api/client/feedback" + TokenQuery();
        //TokenQuery 以 & 开头（供追加在已有查询串后），feedback 无其他参数，首个参数需用 ?
        url = url.Replace("/feedback&", "/feedback?", StringComparison.Ordinal);
        using var response = await _http.PostAsJsonAsync(url, payload, Source.JsonCtx.WebInfo<FeedbackRequest>(), ct);
        response.EnsureSuccessStatusCode();
    }

    private string PendingMarkerPath
        => Path.Combine(Path.GetDirectoryName(Options.VersionFile)!, "pending-package.txt");

    /// <summary>删除上一个未处理的更新包，避免运行目录堆积 zip。</summary>
    private void CleanupPreviousPackage(string newPackage)
    {
        try
        {
            var marker = PendingMarkerPath;
            if (!File.Exists(marker)) return;
            var previous = File.ReadAllText(marker).Trim();
            if (previous.Length > 0 && previous != newPackage)
                TryDelete(SafePath.Combine(Options.InstallDir, previous));
            TryDelete(marker);
        }
        catch
        {
            // 清理失败不影响下载流程
        }
    }

    private void WritePendingMarker(string package)
    {
        try
        {
            var marker = PendingMarkerPath;
            Directory.CreateDirectory(Path.GetDirectoryName(marker)!);
            File.WriteAllText(marker, package);
        }
        catch
        {
            // 记录失败不影响下载流程
        }
    }

    /// <summary>构造访问令牌查询串（"&amp;token=..."）；未配置 Key 时返回空串。</summary>
    private string TokenQuery()
    {
        var token = ClientToken.Create(Options.ClientAuthKey, Options.AppId);
        return token is null ? "" : $"&token={Uri.EscapeDataString(token)}";
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch { /* 可能被宿主程序占用，下次再清理 */ }
    }

    public void Dispose()
    {
        if (_ownsHttpClient) _http.Dispose();
    }
}

internal static class SafePath
{
    public static string Combine(string root, string relativePath)
    {
        root = Path.GetFullPath(root);
        var normalized = relativePath.Replace('\\', '/').TrimStart('/');
        if (normalized.Length == 0 || normalized.Contains("..", StringComparison.Ordinal))
            throw new InvalidOperationException($"更新清单包含非法相对路径: '{relativePath}'");

        var full = Path.GetFullPath(Path.Combine(root, normalized));
        var comparison = OperatingSystem.IsWindows ()? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (!full.StartsWith(root, comparison))
            throw new InvalidOperationException($"更新清单路径越界: '{relativePath}'");
        return full;
    }
}

internal static class HashUtil
{
    public static async Task<string> Sha256FileAsync(string path, CancellationToken ct = default)
    {
        await using var stream = File.OpenRead(path);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, ct)).ToLowerInvariant();
    }

    public static async Task<bool> MatchesAsync(string path, ManifestFileEntry entry, CancellationToken ct = default)
    {
        return new FileInfo(path).Length == entry.Size &&
               string.Equals(await Sha256FileAsync(path, ct), entry.Sha256, StringComparison.OrdinalIgnoreCase);
    }
}
