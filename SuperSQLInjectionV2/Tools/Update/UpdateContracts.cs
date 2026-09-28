namespace SuperSQLInjectionV2.Tools.Update;

/// <summary>检查更新响应（移植自 SoftUpdate.Contracts）</summary>
public sealed class CheckUpdateResponse
{
    public bool HasUpdate { get; set; }

    public bool Mandatory { get; set; }

    public UpdateManifest? Manifest { get; set; }

    public string? Message { get; set; }
}

/// <summary>更新清单（移植自 SoftUpdate.Contracts）</summary>
public sealed class UpdateManifest
{
    public string AppId { get; set; } = "";

    public string Version { get; set; } = "";

    public string Channel { get; set; } = "stable";

    /// <summary>适用的操作系统类型（windows/linux/osx）；为空表示不限平台。</summary>
    public string? Os { get; set; }

    /// <summary>适用的处理器架构（x86/x64/arm/arm64）；为空表示不限架构。</summary>
    public string? Arch { get; set; }

    public string? Notes { get; set; }

    public bool Mandatory { get; set; }

    /// <summary>低于该版本必须强制更新；为空表示无强制下限。</summary>
    public string? MinCompatibleVersion { get; set; }

    public DateTime PublishedAtUtc { get; set; }

    public List<ManifestFileEntry> Files { get; set; } = [];
}

public sealed class ManifestFileEntry
{
    /// <summary>相对安装目录的路径，统一使用 '/' 分隔。</summary>
    public string Path { get; set; } = "";

    public long Size { get; set; }

    public string Sha256 { get; set; } = "";
}

/// <summary>意见建议反馈提交请求（移植自 SoftUpdate.Contracts.FeedbackRequest）</summary>
public sealed class FeedbackRequest
{
    public string AppId { get; set; } = "";

    public string Version { get; set; } = "";

    public string Content { get; set; } = "";

    public string? Contact { get; set; }
}
