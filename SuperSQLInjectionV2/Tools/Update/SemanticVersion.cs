using System.Globalization;

namespace SuperSQLInjectionV2.Tools.Update;

/// <summary>
/// 语义化版本（支持 1.2.3、1.2.10、2.0.0-beta.1 等形式）。
/// 规则：数值段按数值比较；带预发布号低于不带；预发布标识符数值段小于字母段。
/// 移植自 SoftUpdate.Contracts。
/// </summary>
public sealed class SemanticVersion : IComparable<SemanticVersion>
{
    public int Major { get; }
    public int Minor { get; }
    public int Patch { get; }
    public IReadOnlyList<string> PreRelease { get; }

    private SemanticVersion(int major, int minor, int patch, IReadOnlyList<string> preRelease)
    {
        Major = major;
        Minor = minor;
        Patch = patch;
        PreRelease = preRelease;
    }

    public static bool TryParse(string? text, out SemanticVersion version)
    {
        version = null!;
        if (string.IsNullOrWhiteSpace(text))
            return false;

        var body = text.Trim();
        var preRelease = new List<string>();
        var plusIndex = body.IndexOf('+', StringComparison.Ordinal);
        if (plusIndex >= 0)
            body = body[..plusIndex];

        var dashIndex = body.IndexOf('-', StringComparison.Ordinal);
        if (dashIndex >= 0)
        {
            var pre = body[(dashIndex + 1)..];
            body = body[..dashIndex];
            if (pre.Length == 0)
                return false;
            preRelease.AddRange(pre.Split('.'));
        }

        var parts = body.Split('.');
        if (parts.Length is < 1 or > 4)
            return false;

        var numbers = new int[parts.Length];
        for (var i = 0; i < parts.Length; i++)
        {
            if (!int.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out numbers[i]) || numbers[i] < 0)
                return false;
        }

        version = new SemanticVersion(
            numbers[0],
            parts.Length > 1 ? numbers[1] : 0,
            parts.Length > 2 ? numbers[2] : 0,
            preRelease);
        return true;
    }

    public static SemanticVersion Parse(string text)
        => TryParse(text, out var v) ? v : throw new FormatException($"无法解析版本号: '{text}'");

    public int CompareTo(SemanticVersion? other)
    {
        if (other is null) return 1;

        var cmp = Major.CompareTo(other.Major);
        if (cmp != 0) return cmp;
        cmp = Minor.CompareTo(other.Minor);
        if (cmp != 0) return cmp;
        cmp = Patch.CompareTo(other.Patch);
        if (cmp != 0) return cmp;

        if (PreRelease.Count == 0 && other.PreRelease.Count == 0) return 0;
        if (PreRelease.Count == 0) return 1;               // 正式版 > 预发布版
        if (other.PreRelease.Count == 0) return -1;

        var max = Math.Max(PreRelease.Count, other.PreRelease.Count);
        for (var i = 0; i < max; i++)
        {
            var a = i < PreRelease.Count ? PreRelease[i] : null;
            var b = i < other.PreRelease.Count ? other.PreRelease[i] : null;
            if (a is null) return -1;                       // 标识符少的小
            if (b is null) return 1;

            var aIsNum = int.TryParse(a, NumberStyles.None, CultureInfo.InvariantCulture, out var an);
            var bIsNum = int.TryParse(b, NumberStyles.None, CultureInfo.InvariantCulture, out var bn);

            if (aIsNum && bIsNum)
            {
                cmp = an.CompareTo(bn);
                if (cmp != 0) return cmp;
            }
            else if (aIsNum != bIsNum)
            {
                return aIsNum ? -1 : 1;                     // 数值标识符 < 字母标识符
            }
            else
            {
                cmp = string.CompareOrdinal(a, b);
                if (cmp != 0) return cmp;
            }
        }
        return 0;
    }

    public override string ToString()
    {
        var core = $"{Major}.{Minor}.{Patch}";
        return PreRelease.Count == 0 ? core : $"{core}-{string.Join('.', PreRelease)}";
    }
}
