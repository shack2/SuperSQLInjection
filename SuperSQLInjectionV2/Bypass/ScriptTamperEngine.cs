using System;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Threading;
using System.Threading.Tasks;
using SuperSQLInjectionV2.Bypass.QuickJs;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Tools;
using SuperSQLInjectionV2.ViewModels;

namespace SuperSQLInjectionV2.Bypass
{
    /// <summary>
    /// tamper脚本语言（枚举值显式固定：历史配置按数字持久化；1=已删除的Python占位、2=已删除的C#占位，勿复用）
    /// </summary>
    public enum ScriptLang
    {
        [Description("JavaScript")] JavaScript = 0
    }

    /// <summary>
    /// 统一tamper执行视图（P10：ScriptTamperModel动态值脚本与EncodeToolModel编码工具的执行入口收敛）。
    /// 内置项统一按Key（兼容按Name）从EncodeToolRegistry解析C#实现，自定义项走QuickJS池化执行。
    /// </summary>
    public interface ITamperItem
    {
        /// <summary>显示名（内置项兼容键）</summary>
        string Name { get; }
        /// <summary>内置C#实现标识</summary>
        bool Builtin { get; }
        /// <summary>内置注册表键（EncodeToolModel持有；ScriptTamperModel恒null，回落Name匹配）</summary>
        string? Key { get; }
        /// <summary>自定义JS脚本内容</summary>
        string? Code { get; }
    }

    /// <summary>
    /// tamper脚本化引擎（自定义脚本能力）：
    /// 用户脚本约定 function tamper(payload) { ... return x; }，输入Encode块内payload文本，返回变换后的文本。
    /// 运行时：QuickJS（quickjs-ng 2026-06-04，NativeAOT兼容，ES2025全量正则可用）。
    /// 按脚本内容池化执行上下文：同一份脚本复用同一context（加锁串行调用），
    /// 避免每个payload重建引擎（原Jint每次new Engine约1-5ms，池化后单次调用为微秒级）。
    /// </summary>
    public static class ScriptTamperEngine
    {
        /// <summary>单次脚本执行超时（毫秒），由中断回调强制执行（死循环脚本可被真正打断）</summary>
        public static int TimeOutMs { get; set; } = 10000;

        /// <summary>
        /// 池上限：key为脚本全文，脚本每编辑一次产生新key。超出后整体换血（仅丢引用，原生资源由GC终结器回收），
        /// 防脚本编辑弹窗反复"验证执行"导致旧context无限堆积
        /// </summary>
        private const int MaxPoolSize = 32;

        private sealed class PooledContext
        {
            public readonly QuickJsContext Ctx;
            public readonly object Sync = new object();

            public PooledContext(string code)
            {
                Ctx = new QuickJsContext();
                Ctx.Load(code ?? "");
            }
        }

        private static readonly ConcurrentDictionary<string, PooledContext> _pool =
            new ConcurrentDictionary<string, PooledContext>();

        /// <summary>内置编码工具解析（统一注册表EncodeToolRegistry；tamper/编码处理合并后的唯一内置事实源）</summary>
        public static EncodeTool? FindBuiltinScript(string name)
        {
            return EncodeToolRegistry.TryGet(name, out EncodeTool t) ? t : null;
        }

        //======== 统一执行入口（ITamperItem）：ScriptTamperModel/EncodeToolModel共用唯一实现 ========

        public static string Tamper(ITamperItem item, string payload)
        {
            try
            {
                return ExecuteItem(item, payload);
            }
            catch (Exception e)
            {
                Log.SysLog("tamper脚本[" + item.Name + "]执行失败：" + e.Message);
                if (LogTools.Headless)
                {
                    Console.WriteLine("[tamper脚本异常] " + item.Name + ": " + e.Message);
                }
                return payload;
            }
        }

        /// <summary>严格模式执行（编辑弹窗"验证执行"用）：不吞异常，错误直接抛出给调用方展示</summary>
        public static string TamperStrict(ITamperItem item, string payload)
        {
            return ExecuteItem(item, payload);
        }

        /// <summary>
        /// 异步版tamper执行（请求热路径使用）：内置C#委托/QuickJS均为进程内同步执行（微秒~毫秒级），
        /// 无异步IO，保持同步执行直接包装返回
        /// </summary>
        public static Task<string> TamperAsync(ITamperItem item, string payload, CancellationToken ct = default)
        {
            try
            {
                return Task.FromResult(ExecuteItem(item, payload));
            }
            catch (Exception e)
            {
                Log.SysLog("tamper脚本[" + item.Name + "]执行失败：" + e.Message);
                if (LogTools.Headless)
                {
                    Console.WriteLine("[tamper脚本异常] " + item.Name + ": " + e.Message);
                }
                return Task.FromResult(payload);
            }
        }

        /// <summary>统一分发：内置项按Key（兼容旧数据按Name）解析EncodeToolRegistry注册表C#委托（不经过QuickJS），自定义项走QuickJS池化执行</summary>
        private static string ExecuteItem(ITamperItem item, string payload)
        {
            if (item.Builtin)
            {
                string key = !string.IsNullOrEmpty(item.Key) ? item.Key! : item.Name;
                if (EncodeToolRegistry.TryGet(key, out EncodeTool tool))
                {
                    return tool.Impl(payload);
                }
            }
            return Execute(item.Code ?? "", payload);
        }

        private static string Execute(string code, string payload)
        {
            if (_pool.Count > MaxPoolSize)
            {
                _pool.Clear(); // 换血：引用丢弃后由QuickJsContext终结器释放原生runtime
            }
            PooledContext pooled = _pool.GetOrAdd(code ?? "", static c => new PooledContext(c));
            lock (pooled.Sync)
            {
                return pooled.Ctx.Call("tamper", payload, TimeOutMs);
            }
        }
    }
}
