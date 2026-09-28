using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;

namespace TestWebApp;

/// <summary>
/// IBM.Data.Db2 原生驱动加载引导。
/// 问题：Net.IBM.Data.Db2 的 GetCliDriverPath 用 Assembly.CodeBase + new Uri(...).LocalPath
/// 解析 clidriver 位置；本项目路径含 '#'（F:\MyCoding\c#\...），'#' 被 Uri 当作 fragment
/// 截断，导致探测目录变成 F:\MyCoding，报 SQL1159 reason code 2。
/// 修复：把 IBM.Data.Db2.dll + clidriver 同步到无 '#' 的缓存目录（%TEMP%\db2provider-cache），
/// 通过 AssemblyLoadContext.Resolving 重定向到缓存副本加载（其 CodeBase 不含 '#'，探测即可命中
/// 缓存目录下的 clidriver\bin\db2app64.dll），并用 SetDllDirectory 兜底按名称的 P/Invoke。
/// 配合 csproj 的 RenameDb2Asm 目标：构建后把输出目录的 IBM.Data.Db2.dll 改名为 .dll.x，
/// 使默认程序集探测落空，Resolving 事件才有机会接管。
/// </summary>
internal static class Db2NativeBootstrap
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetDllDirectory(string lpPathName);

    public static void Install()
    {
        string baseDir = AppContext.BaseDirectory;
        string asmSrc = Path.Combine(baseDir, "IBM.Data.Db2.dll.x");
        string cliSrc = Path.Combine(baseDir, "clidriver");
        if (!File.Exists(asmSrc) || !Directory.Exists(cliSrc)) return; //未引用DB2提供程序

        string safeDir = Path.Combine(Path.GetTempPath(), "db2provider-cache");
        string asmDst = Path.Combine(safeDir, "IBM.Data.Db2.dll");
        string cliDst = Path.Combine(safeDir, "clidriver");
        try
        {
            Directory.CreateDirectory(safeDir);
            SyncFile(asmSrc, asmDst);
            SyncDir(cliSrc, cliDst);
        }
        catch
        {
            return; //缓存失败则回退默认行为（报错信息会给出真实路径）
        }

        //按名称 P/Invoke db2app64.dll 的兜底搜索目录
        SetDllDirectory(Path.Combine(cliDst, "bin"));
        AssemblyLoadContext.Default.Resolving += (ctx, name) =>
            string.Equals(name.Name, "IBM.Data.Db2", StringComparison.OrdinalIgnoreCase)
                ? ctx.LoadFromAssemblyPath(asmDst)
                : null;
    }

    private static void SyncFile(string src, string dst)
    {
        if (File.Exists(dst) && File.GetLastWriteTimeUtc(dst) == File.GetLastWriteTimeUtc(src)
            && new FileInfo(dst).Length == new FileInfo(src).Length) return;
        File.Copy(src, dst, true);
        File.SetLastWriteTimeUtc(dst, File.GetLastWriteTimeUtc(src));
    }

    private static void SyncDir(string src, string dst)
    {
        Directory.CreateDirectory(dst);
        foreach (var f in Directory.EnumerateFiles(src))
            SyncFile(f, Path.Combine(dst, Path.GetFileName(f)));
        foreach (var d in Directory.EnumerateDirectories(src))
            SyncDir(d, Path.Combine(dst, Path.GetFileName(d)));
    }
}
