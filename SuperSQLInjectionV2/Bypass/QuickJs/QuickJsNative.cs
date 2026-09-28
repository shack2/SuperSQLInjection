using System.Runtime.InteropServices;

namespace SuperSQLInjectionV2.Bypass.QuickJs
{
    /// <summary>
    /// quickjs-ng v0.17.0 (x64) JSValue：非 NAN_BOXING 布局 { JSValueUnion u; int64_t tag; }，16字节 POD。
    /// Windows x64 ABI 下 16 字节 POD 结构体经隐藏缓冲区返回、按指针传参，.NET P/Invoke 按值传递/返回均兼容。
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct JSValue
    {
        public long U;
        public long Tag;

        public static readonly JSValue Undefined = new JSValue { U = 0, Tag = 3 };
        public static readonly JSValue Null = new JSValue { U = 0, Tag = 2 };

        public const int TagException = 6;

        public readonly bool IsException => Tag == TagException;
        /// <summary>引用计数 tag 为负值（JS_TAG_FIRST=-9 ~ JS_TAG_OBJECT=-1）</summary>
        public readonly bool HasRefCount => Tag is >= -9 and <= -1;
    }

    /// <summary>
    /// libquickjs.dll P/Invoke 薄封装（只映射 tamper/eval 脚本执行所需的最小函数集）。
    /// DLL 由 Native/quickjs-amalgam.c (quickjs-ng v0.17.0) 经 MSVC /MT 静态编译，仅依赖 KERNEL32.dll。
    /// 构建脚本见 TestHarness/build-qjs.bat。
    /// </summary>
    internal static unsafe class QuickJsNative
    {
        private const string Lib = "libquickjs";

        // ---- Runtime ----
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr JS_NewRuntime();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void JS_FreeRuntime(IntPtr rt);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void JS_SetMemoryLimit(IntPtr rt, UIntPtr limit);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void JS_SetMaxStackSize(IntPtr rt, UIntPtr stackSize);

        /// <summary>中断回调：int handler(JSRuntime* rt, void* opaque)，返回非0中断执行（超时控制用）</summary>
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void JS_SetInterruptHandler(IntPtr rt,
            delegate* unmanaged[Cdecl]<IntPtr, IntPtr, int> cb, IntPtr opaque);

        // ---- Context ----
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr JS_NewContext(IntPtr rt);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void JS_FreeContext(IntPtr ctx);

        // ---- Eval / Call ----
        /// <summary>input 必须以 '\0' 结尾（input[input_len] == 0），flags=JS_EVAL_TYPE_GLOBAL(0)</summary>
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern JSValue JS_Eval(IntPtr ctx, byte* input, UIntPtr inputLen,
            byte* filename, int evalFlags);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern JSValue JS_Call(IntPtr ctx, JSValue funcObj, JSValue thisObj,
            int argc, JSValue* argv);

        // ---- 值操作 ----
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern JSValue JS_NewStringLen(IntPtr ctx, byte* str, UIntPtr len);

        /// <summary>cesu8=0 返回标准 UTF-8；返回的指针须 JS_FreeCString 释放</summary>
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr JS_ToCStringLen2(IntPtr ctx, out UIntPtr plen, JSValue val, int cesu8);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void JS_FreeCString(IntPtr ctx, IntPtr ptr);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern JSValue JS_GetException(IntPtr ctx);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern JSValue JS_GetGlobalObject(IntPtr ctx);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern JSValue JS_GetPropertyStr(IntPtr ctx, JSValue thisObj, byte* prop);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int JS_IsFunction(IntPtr ctx, JSValue val);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void JS_FreeValue(IntPtr ctx, JSValue val);
    }
}
