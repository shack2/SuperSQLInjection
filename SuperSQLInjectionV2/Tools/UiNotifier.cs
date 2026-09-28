using Avalonia.Threading;

namespace SuperSQLInjectionV2.Tools
{
    /// <summary>
    /// UI 更新通知中心：多线程后台任务 → UI 的统一事件通知入口。
    /// 替代散落的 Dispatcher.UIThread.Post 直调，统一处理：
    /// Headless/线程守卫、默认 Background 优先级（取数洪峰不抢输入响应）。
    /// </summary>
    public static class UiNotifier
    {
        /// <summary>单次事件通知：后台线程安全调用，已在UI线程/无UI模式下直接执行</summary>
        public static void Post(Action action, DispatcherPriority? priority = null)
        {
            if (LogTools.Headless || Avalonia.Application.Current == null)
            {
                action();
                return;
            }
            if (Dispatcher.UIThread.CheckAccess())
            {
                action();
                return;
            }
            Dispatcher.UIThread.Post(action, priority ?? DispatcherPriority.Background);
        }
    }
}
