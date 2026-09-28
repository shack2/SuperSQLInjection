namespace SuperSQLInjectionV2.Tools
{
    /// <summary>
    /// 日志输出抽象：UI日志/headless控制台共用，逻辑层只依赖本接口，不感知Avalonia与ViewModel
    /// </summary>
    public interface ILogSink
    {
        void Show(string msg);
        void Success(string msg);
        void Highlight(string msg);
        void Error(string msg);
        void Warning(string msg);
        void SysLog(string log);
        void SysLog(string log, LogLevel level);
        void SetFilter(int filter);
        void ClearLog();
    }

    /// <summary>
    /// 全局日志门面：替代原 MainViewViewModel.LogTool 静态后门。
    /// Models/Tools 等逻辑层统一经此输出日志；Sink 由 UI（MainViewViewModel.InitLogTools）
    /// 或 headless 宿主（TestHarness）在启动时注入，未注入时所有调用静默忽略。
    /// </summary>
    public static class Log
    {
        public static ILogSink? Sink { get; set; }

        public static void Show(string msg) => Sink?.Show(msg);

        public static void Success(string msg) => Sink?.Success(msg);

        public static void Highlight(string msg) => Sink?.Highlight(msg);

        public static void Error(string msg) => Sink?.Error(msg);

        public static void Warning(string msg) => Sink?.Warning(msg);

        public static void SysLog(string log) => Sink?.SysLog(log);

        public static void SysLog(string log, LogLevel level) => Sink?.SysLog(log, level);

        public static void SetFilter(int filter) => Sink?.SetFilter(filter);

        public static void ClearLog() => Sink?.ClearLog();
    }
}
