using System;
using System.Collections.Generic;

namespace SuperSQLInjectionV2.Models
{
    /// <summary>单个数据库UDF部署状态，仅属于当前AppConfig会话，不跨目标共享。</summary>
    public sealed class UdfInstallationState
    {
        public string? ReadyTargetKey { get; set; }
        public string? InstalledPath { get; set; }
        public bool IsWindows { get; set; }
        public DateTimeOffset? InstalledAtUtc { get; set; }
        public long BinarySize { get; set; }
        public string Sha256 { get; set; } = "";

        public bool HasArtifacts => ReadyTargetKey != null || InstalledPath != null;

        public void Reset()
        {
            ReadyTargetKey = null;
            InstalledPath = null;
            IsWindows = false;
            InstalledAtUtc = null;
            BinarySize = 0;
            Sha256 = "";
        }
    }

    /// <summary>当前配置会话的UDF生命周期信息；不持久化，避免重启后误认远端仍已安装。</summary>
    public sealed class UdfSessionState
    {
        public UdfInstallationState MySql { get; } = new();
        public UdfInstallationState PostgreSql { get; } = new();

        public string DescribeInstalled(params (string Name, UdfInstallationState State)[] entries)
        {
            var lines = new List<string>();
            foreach ((string name, UdfInstallationState state) in entries)
            {
                if (!state.HasArtifacts) continue;
                lines.Add($"{name}: path={state.InstalledPath ?? "未记录"}, platform={(state.IsWindows ? "Windows" : "Linux/Unix")}, "
                    + $"installedAt={state.InstalledAtUtc?.ToString("O") ?? "未记录"}, size={state.BinarySize}, sha256={state.Sha256}");
            }
            return string.Join(Environment.NewLine, lines);
        }

        public string PendingSummary()
        {
            return DescribeInstalled(("MySQL", MySql), ("PostgreSQL", PostgreSql));
        }
    }
}
