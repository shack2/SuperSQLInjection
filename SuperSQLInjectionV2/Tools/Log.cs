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
    /// 批量任务等并发场景可用 PushScope 在当前异步流内挂接带前缀/降级的临时 Sink（AsyncLocal 隔离，不影响其他任务）。
    /// </summary>
    public static class Log
    {
        public static ILogSink? Sink { get; set; }

        /// <summary>异步流级临时Sink（批量并发任务日志隔离：每个任务自己的前缀/降级策略，随async上下文流动）</summary>
        private static readonly AsyncLocal<ILogSink?> _scopeSink = new AsyncLocal<ILogSink?>();

        private static ILogSink? Current => _scopeSink.Value ?? Sink;

        /// <summary>在当前异步流内挂接临时Sink（using释放后自动还原；子任务经async/await继承同一作用域）</summary>
        public static IDisposable PushScope(ILogSink? sink)
        {
            ILogSink? prev = _scopeSink.Value;
            _scopeSink.Value = sink;
            return new ScopePopper(prev);
        }

        private sealed class ScopePopper : IDisposable
        {
            private ILogSink? _prev;
            public ScopePopper(ILogSink? prev) => _prev = prev;
            public void Dispose()
            {
                _scopeSink.Value = _prev;
                _prev = null;
            }
        }

        public static void Show(string msg) => Current?.Show(msg);

        public static void Success(string msg) => Current?.Success(msg);

        public static void Highlight(string msg) => Current?.Highlight(msg);

        public static void Error(string msg) => Current?.Error(msg);

        public static void Warning(string msg) => Current?.Warning(msg);

        public static void SysLog(string log) => Current?.SysLog(log);

        public static void SysLog(string log, LogLevel level) => Current?.SysLog(log, level);

        public static void SetFilter(int filter) => Current?.SetFilter(filter);

        public static void ClearLog() => Current?.ClearLog();
    }

    /// <summary>
    /// 前缀降级Sink（批量任务用）：所有日志加目标前缀后转发给主Sink的SysLog（带级别），
    /// 不触发通知弹窗（N个目标并发时弹窗会刷屏）；SetFilter/ClearLog 直接透传。
    /// keepChannel=true 时保持原日志通道（Show→Show、Warning→Warning，仅加前缀不降级），
    /// 用于单目标检测日志加URL前缀且保留颜色/通知行为的场景。
    /// </summary>
    public sealed class PrefixLogSink : ILogSink
    {
        private readonly ILogSink? _inner;
        private readonly string _prefix;
        private readonly bool _keepChannel;

        public PrefixLogSink(string prefix, ILogSink? inner, bool keepChannel = false)
        {
            _prefix = prefix;
            _inner = inner;
            _keepChannel = keepChannel;
        }

        public void Show(string msg)
        {
            if (_keepChannel) { _inner?.Show(_prefix + msg); } else { _inner?.SysLog(_prefix + msg, LogLevel.Info); }
        }
        public void Success(string msg)
        {
            if (_keepChannel) { _inner?.Success(_prefix + msg); } else { _inner?.SysLog(_prefix + msg, LogLevel.Success); }
        }
        public void Highlight(string msg)
        {
            if (_keepChannel) { _inner?.Highlight(_prefix + msg); } else { _inner?.SysLog(_prefix + msg, LogLevel.Highlight); }
        }
        public void Error(string msg)
        {
            if (_keepChannel) { _inner?.Error(_prefix + msg); } else { _inner?.SysLog(_prefix + msg, LogLevel.Error); }
        }
        public void Warning(string msg)
        {
            if (_keepChannel) { _inner?.Warning(_prefix + msg); } else { _inner?.SysLog(_prefix + msg, LogLevel.Warn); }
        }
        public void SysLog(string log) => _inner?.SysLog(_prefix + log);
        public void SysLog(string log, LogLevel level) => _inner?.SysLog(_prefix + log, level);
        public void SetFilter(int filter) => _inner?.SetFilter(filter);
        public void ClearLog() { /* 批量任务不允许清空全局日志 */ }
    }
}
