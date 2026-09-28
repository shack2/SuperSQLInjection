using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace SuperSQLInjectionV2.Tools.Update;

/// <summary>
/// 采集更新主机环境信息（操作系统类型、屏幕分辨率），供服务端记录更新请求。
/// 移植自 SoftUpdate.Client.Core（改名避免与系统类同名混淆）。
/// </summary>
public static partial class UpdateSystemInfo
{
    /// <summary>操作系统描述，例如 "Microsoft Windows 10.0.19045 (X64)"。</summary>
    public static string GetOsDescription()
        => $"{RuntimeInformation.OSDescription} ({RuntimeInformation.OSArchitecture})";

    /// <summary>操作系统类型（windows/linux/osx），用于匹配平台专属版本。</summary>
    public static string GetOsType()
        => OperatingSystem.IsWindows()? "windows"
         : OperatingSystem.IsLinux()? "linux"
         : OperatingSystem.IsMacOS()? "osx"
         : "unknown";

    /// <summary>处理器架构（x64/arm64/x86/arm），用于匹配平台专属版本。</summary>
    public static string GetArchitecture()
        => RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant();

    /// <summary>主屏幕分辨率，例如 "1920x1080"；无法获取时返回 null。结果会缓存。</summary>
    public static string? GetScreenResolution() => _resolution.Value;

    private static readonly Lazy<string?> _resolution = new Lazy<string?>(GetScreenResolutionCore);

    private static string? GetScreenResolutionCore()
    {
        try
        {
            if (OperatingSystem.IsWindows()) return GetWindowsResolution();
            if (OperatingSystem.IsLinux()) return GetLinuxResolution();
            if (OperatingSystem.IsMacOS()) return GetMacResolution();
        }
        catch
        {
            // 采集失败不影响更新流程
        }
        return null;
    }

    /// <summary>Windows：GetSystemMetrics 取主屏逻辑分辨率。</summary>
    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int nIndex);

    private static string? GetWindowsResolution()
    {
        var width = GetSystemMetrics(0);
        var height = GetSystemMetrics(1);
        return width > 0 && height > 0 ? $"{width}x{height}" : null;
    }

    /// <summary>Linux：解析 xrandr 当前带 * 标记的模式。</summary>
    private static string? GetLinuxResolution()
    {
        var output = RunAndReadOutput("xrandr", "--current");
        if (string.IsNullOrEmpty(output)) return null;
        var match = ScreenModeRegex().Match(output);
        return match.Success ? match.Groups[1].Value : null;
    }

    [GeneratedRegex(@"(\d+x\d+)\s+[\d.]+\*")]
    private static partial Regex ScreenModeRegex();

    /// <summary>macOS：解析 system_profiler 输出的 Resolution 行。</summary>
    private static string? GetMacResolution()
    {
        var output = RunAndReadOutput("system_profiler", "SPDisplaysDataType");
        if (string.IsNullOrEmpty(output)) return null;
        var match = MacResolutionRegex().Match(output);
        return match.Success ? $"{match.Groups[1].Value}x{match.Groups[2].Value}" : null;
    }

    [GeneratedRegex(@"Resolution:\s*(\d+)\s*x\s*(\d+)")]
    private static partial Regex MacResolutionRegex();

    private static string? RunAndReadOutput(string fileName, string arguments)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            RedirectStandardOutput = true,
            UseShellExecute = false
        });
        if (process is null) return null;
        var text = process.StandardOutput.ReadToEnd();
        process.WaitForExit(3000);
        return string.IsNullOrWhiteSpace(text) ? null : text;
    }
}
