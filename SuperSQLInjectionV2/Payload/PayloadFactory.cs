using SuperSQLInjectionV2.Models;
using System;
using System.Threading;

namespace SuperSQLInjectionV2.Payload
{
    /// <summary>
    /// Payload兼容入口。实际状态保存在PayloadSession；异步作用域解析当前会话，
    /// 未显式进入作用域的旧UI/模板代码使用独立兼容会话。
    /// </summary>
    public static class PayloadFactory
    {
        private static readonly AsyncLocal<PayloadSession?> s_current = new();
        private static readonly PayloadSession s_fallback = new();

        public static PayloadSession Current => s_current.Value ?? s_fallback;
        public static BasePayload BasePayload => Current.Base;
        public static IDbDialect BPTool => Current.Dialect;

        /// <summary>当前fork/衍生库名；仅修改当前异步作用域的会话。</summary>
        public static string ForkName
        {
            get => Current.ForkName;
            set => Current.ForkName = value ?? "";
        }

        /// <summary>初始化当前兼容/作用域会话。</summary>
        public static void Init(DBType dBType)
        {
            Current.Init(dBType);
        }

        /// <summary>初始化指定目标配置自己的会话，不影响其他目标。</summary>
        public static void Init(AppConfig config, DBType dBType)
        {
            config.Payload.Init(dBType, config.DataConfig.SelectedForkName ?? "");
        }

        /// <summary>进入目标会话；异步子任务继承该值，Dispose后恢复外层会话。</summary>
        public static IDisposable Activate(AppConfig config)
        {
            return Activate(config.Payload);
        }

        public static IDisposable Activate(PayloadSession session)
        {
            PayloadSession? previous = s_current.Value;
            s_current.Value = session;
            return new Scope(previous);
        }

        private sealed class Scope : IDisposable
        {
            private readonly PayloadSession? _previous;
            private bool _disposed;
            public Scope(PayloadSession? previous) => _previous = previous;
            public void Dispose()
            {
                if (_disposed) return;
                s_current.Value = _previous;
                _disposed = true;
            }
        }
    }
}
