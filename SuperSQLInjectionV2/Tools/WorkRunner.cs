using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Tools
{
    /// <summary>
    /// 轻量并行任务执行器（替代Amib SmartThreadPool）：
    /// 基于BCL原生Parallel.ForEach/For，范围分区+按消费速度枚举（背压），
    /// CancellationToken贯穿——停止时立即停止派发新迭代，配合socket异步取消实现秒级停止。
    /// </summary>
    public static class WorkRunner
    {
        /// <summary>
        /// 火忘任务完成回调（异常兜底）：任务完成后若为Faulted且非用户取消，把异常写日志
        /// （裸 GetAwaiter.OnCompleted 模式下任务异常会被静默丢失），随后执行收尾continuation。
        /// task在注册时捕获，避免回调执行时RunTask属性已指向新任务。
        /// </summary>
        public static void OnCompletedSurfaced(Task task, Action continuation)
        {
            task.GetAwaiter().OnCompleted( ()=>
            {
                try
                {
                    task.GetAwaiter().GetResult();
                }
                catch (OperationCanceledException)
                {
                    //停止按钮触发的取消属正常流程
                }
                catch (Exception ex)
                {
                    Log.SysLog("后台任务异常（原火忘模式会静默丢失）：" + ex);
                }
                continuation();
            });
        }

        private static int _activeCount;

        /// <summary>当前正在执行的任务数（UI运行线程数显示）</summary>
        public static int ActiveCount => Volatile.Read(ref _activeCount);

        private static ParallelOptions CreateOptions(AppConfig config)
        {
            return new ParallelOptions
            {
                MaxDegreeOfParallelism = Math.Max(1, config.ThreadSize),
                CancellationToken = config.RunCts?.Token ?? CancellationToken.None
            };
        }

        private static void Wrap(Action body)
        {
            Interlocked.Increment(ref _activeCount);
            try
            {
                body();
            }
            finally
            {
                Interlocked.Decrement(ref _activeCount);
            }
        }

        /// <summary>
        /// 索引区间并行（盲注逐字符取数等场景）：[fromInclusive, toExclusive)，阻塞至全部完成或取消
        /// </summary>
        public static void Run(int fromInclusive, int toExclusive, AppConfig config, Action<int> body)
        {
            if (toExclusive <= fromInclusive) return;
            Parallel.For(fromInclusive, toExclusive, CreateOptions(config),
                i => Wrap( ()=> body(i)));
        }

        /// <summary>
        /// 集合并行：阻塞至全部完成或取消
        /// </summary>
        public static void Run<T>(IEnumerable<T> items, AppConfig config, Action<T> body)
        {
            Parallel.ForEach(items, CreateOptions(config),
                item => Wrap( ()=> body(item)));
        }

        /// <summary>
        /// 后台并行执行（不阻塞调用方，替代QueueWorkItem无等待场景，如库表列结构异步填充）
        /// </summary>
        public static void FireAndForget<T>(IEnumerable<T> items, AppConfig config, Action<T> body)
        {
            Task.Run( ()=>
            {
                try
                {
                    Run(items, config, body);
                }
                catch (OperationCanceledException)
                {
                    //用户停止，静默结束
                }
                catch (Exception e)
                {
                    Log.SysLog("后台并行任务异常：" + e.Message);
                }
            });
        }

        /// <summary>
        /// 全异步索引区间并行（ForEachAsync）：供异步化后的取数链路使用，
        /// await等待不占用线程，取消令牌贯穿socket读取
        /// </summary>
        public static async Task RunAsync(int fromInclusive, int toExclusive, AppConfig config, Func<int, ValueTask> body)
        {
            if (toExclusive <= fromInclusive) return;
            await Parallel.ForEachAsync(
                System.Linq.Enumerable.Range(fromInclusive, toExclusive - fromInclusive),
                CreateOptions(config),
                async (i, ct) =>
                {
                    Interlocked.Increment(ref _activeCount);
                    try
                    {
                        await body(i);
                    }
                    finally
                    {
                        Interlocked.Decrement(ref _activeCount);
                    }
                });
        }

        /// <summary>
        /// 全异步集合并行（ForEachAsync）
        /// </summary>
        public static async Task RunAsync<T>(IEnumerable<T> items, AppConfig config, Func<T, ValueTask> body)
        {
            await Parallel.ForEachAsync(items, CreateOptions(config),
                async (item, ct) =>
                {
                    Interlocked.Increment(ref _activeCount);
                    try
                    {
                        await body(item);
                    }
                    finally
                    {
                        Interlocked.Decrement(ref _activeCount);
                    }
                });
        }

        /// <summary>
        /// 后台并行执行异步任务（不阻塞调用方）：供异步化后的环境信息批量获取等场景使用。
        /// Parallel.ForEachAsync 本身即异步调度，无需外层 Task.Run 再占一次线程池排队；
        /// 用 OnCompleted 兜底异常（与 OnCompletedSurfaced 同模式，防止火忘任务异常静默丢失）。
        /// </summary>
        public static void FireAndForgetAsync<T>(IEnumerable<T> items, AppConfig config, Func<T, ValueTask> body)
        {
            Task task = RunAsync(items, config, body);
            task.GetAwaiter().OnCompleted( ()=>
            {
                try
                {
                    task.GetAwaiter().GetResult();
                }
                catch (OperationCanceledException)
                {
                    //用户停止，静默结束
                }
                catch (Exception e)
                {
                    Log.SysLog("后台并行任务异常：" + e.Message);
                }
            });
        }
    }
}
