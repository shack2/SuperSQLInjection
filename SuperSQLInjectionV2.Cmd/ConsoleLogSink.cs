using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Tools;

namespace SuperSQLInjectionV2.Cmd;

/// <summary>
/// 控制台日志槽：实现主库 ILogSink 抽象，按级别着色输出到 stdout/stderr。
/// </summary>
public sealed class ConsoleLogSink : ILogSink
{
    private static void Write(string msg, ConsoleColor? color, bool stderr = false)
    {
        var old = Console.ForegroundColor;
        try
        {
            if (color.HasValue) Console.ForegroundColor = color.Value;
            (stderr ? Console.Error : Console.Out).WriteLine($"[{DateTime.Now:HH:mm:ss}] {msg}");
        }
        finally
        {
            Console.ForegroundColor = old;
        }
    }

    public void Show(string msg) => Write(msg, null);
    public void Success(string msg) => Write(msg, ConsoleColor.Green);
    public void Highlight(string msg) => Write(msg, ConsoleColor.Cyan);
    public void Error(string msg) => Write(msg, ConsoleColor.Red, stderr: true);
    public void Warning(string msg) => Write(msg, ConsoleColor.Yellow);
    public void SysLog(string log) => Write(log, ConsoleColor.DarkGray);
    public void SysLog(string log, Tools.LogLevel level)
    {
        var color = level switch
        {
            Tools.LogLevel.Success => ConsoleColor.Green,
            Tools.LogLevel.Error => ConsoleColor.Red,
            Tools.LogLevel.Warn => ConsoleColor.Yellow,
            _ => ConsoleColor.DarkGray
        };
        Write(log, color, stderr: level == Tools.LogLevel.Error);
    }
    public void SetFilter(int filter) { /* 控制台不过滤 */ }
    public void ClearLog (){ /* 控制台不清屏 */ }
}
