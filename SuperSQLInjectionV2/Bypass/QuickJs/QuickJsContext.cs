using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace SuperSQLInjectionV2.Bypass.QuickJs
{
    /// <summary>
    /// QuickJS 执行上下文安全封装：一个 context 加载一份脚本，串行调用（QuickJS context 非线程安全）。
    /// - 内存上限 16MB、栈上限 1MB（与原 Jint 配置对齐）
    /// - 超时通过 JS_SetInterruptHandler + 截止时间戳实现（AOT 兼容的 UnmanagedCallersOnly 函数指针）
    /// - 约定脚本定义函数（如 function tamper(payload){...}），Call 按名调用
    /// </summary>
    internal sealed class QuickJsContext : IDisposable
    {
        private const ulong MemoryLimit = 16UL * 1024 * 1024;
        private const ulong StackLimit = 1UL * 1024 * 1024;

        private IntPtr _rt;
        private IntPtr _ctx;
        private bool _loaded;

        /// <summary>中断截止时间戳（Environment.TickCount64），pinned long 直接供原生回调读取；long.MaxValue=不设限</summary>
        private readonly long[] _deadline = { long.MaxValue };
        private GCHandle _deadlineHandle;
        private bool _disposed;

        public QuickJsContext()
        {
            _rt = QuickJsNative.JS_NewRuntime();
            if (_rt == IntPtr.Zero)
            {
                throw new InvalidOperationException("QuickJS 创建 Runtime 失败");
            }
            QuickJsNative.JS_SetMemoryLimit(_rt, (UIntPtr)MemoryLimit);
            QuickJsNative.JS_SetMaxStackSize(_rt, (UIntPtr)StackLimit);
            _deadlineHandle = GCHandle.Alloc(_deadline, GCHandleType.Pinned);
            unsafe
            {
                QuickJsNative.JS_SetInterruptHandler(_rt, &InterruptHandler, _deadlineHandle.AddrOfPinnedObject());
            }
            _ctx = QuickJsNative.JS_NewContext(_rt);
            if (_ctx == IntPtr.Zero)
            {
                Dispose();
                throw new InvalidOperationException("QuickJS 创建 Context 失败");
            }
        }

        /// <summary>AOT 兼容中断回调：opaque 为 pinned long（截止时间戳），超时返回1中断脚本</summary>
        [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
        private static unsafe int InterruptHandler(IntPtr rt, IntPtr opaque)
        {
            long deadline = Volatile.Read(ref *(long*)opaque);
            return deadline != long.MaxValue && Environment.TickCount64 > deadline ? 1 : 0;
        }

        /// <summary>编译加载脚本（全局作用域执行，定义函数/变量）。语法错误抛异常。</summary>
        public void Load(string code, string filename = "tamper.js")
        {
            ThrowIfDisposed();
            byte[] codeBytes = ToUtf8ZeroTerminated(code ?? "()");
            byte[] nameBytes = ToUtf8ZeroTerminated(filename);
            BeginDeadline(30000); // 加载阶段也给30秒兜底（防脚本顶层死循环）
            try
            {
                unsafe
                {
                    fixed (byte* pCode = codeBytes)
                    fixed (byte* pName = nameBytes)
                    {
                        JSValue result = QuickJsNative.JS_Eval(_ctx, pCode, (UIntPtr)(codeBytes.Length - 1), pName, 0);
                        if (result.IsException)
                        {
                            throw new QuickJsScriptException("脚本加载失败：" + TakeExceptionMessage());
                        }
                        FreeValue(result);
                    }
                }
                _loaded = true;
            }
            finally
            {
                EndDeadline();
            }
        }

        /// <summary>按名调用脚本内函数，传入单个字符串参数，返回字符串结果。函数不存在/执行异常抛异常。</summary>
        public string Call(string functionName, string payload, int timeoutMs)
        {
            ThrowIfDisposed();
            if (!_loaded)
            {
                throw new QuickJsScriptException("脚本未加载");
            }
            BeginDeadline(timeoutMs);
            try
            {
                return CallCore(functionName, payload);
            }
            finally
            {
                EndDeadline();
            }
        }

        /// <summary>已解析函数句柄缓存（Load后函数固定，免去每次Call的GetGlobalObject+GetPropertyStr两次原生互操作；句柄持有引用计数，Dispose时统一释放）</summary>
        private readonly System.Collections.Generic.Dictionary<string, JSValue> _funcCache = new();

        private string CallCore(string functionName, string payload)
        {
            if (!_funcCache.TryGetValue(functionName, out JSValue func))
            {
                byte[] nameBytes = ToUtf8ZeroTerminated(functionName);
                JSValue global = QuickJsNative.JS_GetGlobalObject(_ctx);
                try
                {
                    unsafe
                    {
                        fixed (byte* pName = nameBytes)
                        {
                            func = QuickJsNative.JS_GetPropertyStr(_ctx, global, pName);
                        }
                    }
                    if (QuickJsNative.JS_IsFunction(_ctx, func) == 0)
                    {
                        FreeValue(func);
                        throw new QuickJsScriptException("脚本中未定义函数 " + functionName + "()");
                    }
                    _funcCache[functionName] = func; // 缓存持有至Dispose
                }
                finally
                {
                    FreeValue(global);
                }
            }
            byte[] payloadBytes = ToUtf8(payload ?? "()");
            JSValue arg = JSValue.Undefined;
            JSValue result = JSValue.Undefined;
            try
            {
                unsafe
                {
                    fixed (byte* pPayload = payloadBytes)
                    {
                        arg = QuickJsNative.JS_NewStringLen(_ctx, pPayload, (UIntPtr)payloadBytes.Length);
                    }
                    JSValue* argv = stackalloc JSValue[1];
                    argv[0] = arg;
                    result = QuickJsNative.JS_Call(_ctx, func, JSValue.Undefined, 1, argv);
                    if (result.IsException)
                    {
                        throw new QuickJsScriptException("执行失败：" + TakeExceptionMessage());
                    }
                    return ValueToString(result);
                }
            }
            finally
            {
                FreeValue(result);
                FreeValue(arg);
            }
        }

        /// <summary>JSValue → 托管字符串（非字符串类型由引擎侧 ToCString 转字符串表示）</summary>
        private string ValueToString(JSValue val)
        {
            IntPtr cstr = QuickJsNative.JS_ToCStringLen2(_ctx, out UIntPtr len, val, 0);
            if (cstr == IntPtr.Zero)
            {
                return "()";
            }
            try
            {
                unsafe
                {
                    return Encoding.UTF8.GetString((byte*)cstr, (int)len);
                }
            }
            finally
            {
                QuickJsNative.JS_FreeCString(_ctx, cstr);
            }
        }

        /// <summary>取出当前异常并转为消息文本（消费异常，避免泄漏）；附带 JS 侧堆栈行号便于定位脚本错误行</summary>
        private string TakeExceptionMessage()
        {
            JSValue ex = QuickJsNative.JS_GetException(_ctx);
            try
            {
                string msg = ValueToString(ex);
                //Error 对象的 stack 为自有数据属性（读取不执行脚本代码）：首行与 msg 重复，取后续 at 行（含行号）
                byte[] nameBytes = ToUtf8ZeroTerminated("stack");
                JSValue stack;
                unsafe
                {
                    fixed (byte* pName = nameBytes)
                    {
                        stack = QuickJsNative.JS_GetPropertyStr(_ctx, ex, pName);
                    }
                }
                try
                {
                    if (stack.HasRefCount) //字符串 tag 带引用计数；无 stack（undefined）时跳过
                    {
                        //QuickJS 的 stack 仅含 at 行（不含消息首行），剔除与消息重复的行后附加
                        string[] lines = ValueToString(stack).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                        string at = string.Join("；", lines.Where(l => l != msg));
                        if (!string.IsNullOrEmpty(at))
                        {
                            msg = msg + "（" + at + "）";
                        }
                    }
                }
                finally
                {
                    FreeValue(stack);
                }
                return msg;
            }
            finally
            {
                FreeValue(ex);
            }
        }

        private void FreeValue(JSValue val)
        {
            // 仅引用计数的值需要释放（string/object 等负 tag）；int/bool/null/undefined/exception/float64 无引用计数
            if (val.HasRefCount)
            {
                QuickJsNative.JS_FreeValue(_ctx, val);
            }
        }

        private void BeginDeadline(int timeoutMs)
        {
            long t = timeoutMs <= 0 ? long.MaxValue : Environment.TickCount64 + timeoutMs;
            Volatile.Write(ref _deadline[0], t);
        }

        private void EndDeadline()
        {
            Volatile.Write(ref _deadline[0], long.MaxValue);
        }

        private static byte[] ToUtf8(string s)
        {
            return Encoding.UTF8.GetBytes(s);
        }

        /// <summary>JS_Eval / JS_GetPropertyStr 要求 C 风格零结尾字符串</summary>
        private static byte[] ToUtf8ZeroTerminated(string s)
        {
            byte[] body = Encoding.UTF8.GetBytes(s);
            byte[] buf = new byte[body.Length + 1];
            Array.Copy(body, buf, body.Length);
            return buf;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(QuickJsContext));
            }
        }

        /// <summary>兜底：上下文池换血时仅丢弃引用不逐一下锁Dispose，原生资源由终结器回收</summary>
        ~QuickJsContext()
        {
            Dispose();
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            GC.SuppressFinalize(this);
            if (_ctx != IntPtr.Zero)
            {
                //先释放缓存的函数句柄（持有引用计数），再释放context
                foreach (System.Collections.Generic.KeyValuePair<string, JSValue> kv in _funcCache)
                {
                    if (kv.Value.HasRefCount)
                    {
                        QuickJsNative.JS_FreeValue(_ctx, kv.Value);
                    }
                }
                _funcCache.Clear();
                QuickJsNative.JS_FreeContext(_ctx);
                _ctx = IntPtr.Zero;
            }
            if (_rt != IntPtr.Zero)
            {
                QuickJsNative.JS_FreeRuntime(_rt);
                _rt = IntPtr.Zero;
            }
            if (_deadlineHandle.IsAllocated)
            {
                _deadlineHandle.Free();
            }
        }
    }

    /// <summary>QuickJS 脚本加载/执行异常（消息含 JS 侧错误文本）</summary>
    internal sealed class QuickJsScriptException : Exception
    {
        public QuickJsScriptException(string message) : base(message) { }
    }
}
