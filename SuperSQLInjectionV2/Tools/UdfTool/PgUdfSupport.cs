using System;
using System.IO;

namespace SuperSQLInjectionV2.Tools.UdfTool
{
    /// <summary>
    /// PostgreSQL UDF（lib_postgresqludf_sys）支持：按目标版本/平台/架构选择配套 UDF 二进制并解密。
    /// 配套库仅提供 8.2 ~ 9.4（9.5+ 建议走 COPY FROM PROGRAM），库文件以 cloak 格式（xor+zlib）
    /// 存放在 config/udf/postgresql/{linux|windows}/{32|64}/{版本}/ 下，运行时解密到内存使用。
    /// </summary>
    public static class PgUdfSupport
    {
        /// <summary>配套的 PG UDF 支持的版本目录</summary>
        public static readonly string[] SupportedVersions = { "8.2", "8.3", "8.4", "9.0", "9.1", "9.2", "9.3", "9.4" };

        public static string BaseDir => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config", "udf", "postgresql");

        public static bool IsAvailable()
        {
            //配套库仅提供 windows/32（8.2~9.0）与 linux 32/64（8.2~9.4），无 windows/64
            return File.Exists(Path.Combine(BaseDir, "linux", "64", "9.1", "lib_postgresqludf_sys.so_"))
                && File.Exists(Path.Combine(BaseDir, "windows", "32", "9.0", "lib_postgresqludf_sys.dll_"));
        }

        /// <summary>
        /// 从 version 返回串解析 PG 主版本号（如 "PostgreSQL 9.1.24 on x86_64-pc-linux-gnu" → "9.1"）。
        /// 返回 null 表示解析失败
        /// </summary>
        public static string? ParseMajorMinor(string versionStr)
        {
            if (string.IsNullOrEmpty(versionStr))
            {
                return null;
            }
            var m = System.Text.RegularExpressions.Regex.Match(versionStr, @"PostgreSQL\s+(\d+)\.(\d+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (!m.Success)
            {
                return null;
            }
            return m.Groups[1].Value + "." + m.Groups[2].Value;
        }

        /// <summary>版本是否有配套 UDF 库（8.2 ~ 9.4）</summary>
        public static bool IsVersionSupported(string? majorMinor)
        {
            return majorMinor != null && Array.IndexOf(SupportedVersions, majorMinor) >= 0;
        }

        /// <summary>
        /// 按目标版本/平台/架构选择 UDF 二进制并解密
        /// </summary>
        /// <param name="versionStr">version 返回串（用于判断 Windows/Linux 与位数）</param>
        /// <param name="majorMinor">主版本号（8.2 ~ 9.4）</param>
        /// <param name="libExt">库文件扩展名（.so/.dll）</param>
        /// <param name="isWindows">目标是否 Windows 平台</param>
        public static byte[] LoadUdfBinary(string versionStr, string majorMinor, out string libExt, out bool isWindows)
        {
            string v = versionStr ?? "";
            isWindows = v.Contains("windows", StringComparison.OrdinalIgnoreCase)
                     || v.Contains("mingw", StringComparison.OrdinalIgnoreCase)
                     || v.Contains("Visual C++", StringComparison.OrdinalIgnoreCase);
            bool is64 = v.Contains("x86_64", StringComparison.OrdinalIgnoreCase)
                     || v.Contains("x64", StringComparison.OrdinalIgnoreCase)
                     || v.Contains("64-bit", StringComparison.OrdinalIgnoreCase)
                     || v.Contains("AMD64", StringComparison.OrdinalIgnoreCase);
            string osDir = isWindows ? "windows" : "linux";
            libExt = isWindows ? ".dll" : ".so";
            string fileName = isWindows ? "lib_postgresqludf_sys.dll_" : "lib_postgresqludf_sys.so_";
            string archDir = is64 ? "64" : "32";
            string path = Path.Combine(BaseDir, osDir, archDir, majorMinor, fileName);
            if (!File.Exists(path) && !isWindows)
            {
                //linux对应架构缺失时回退到64位
                path = Path.Combine(BaseDir, osDir, "64", majorMinor, fileName);
            }
            if (!File.Exists(path))
            {
                //windows仅提供32位库：64位Windows的PG无法加载32位DLL，明确报错而非静默错库
                throw new FileNotFoundException("PG UDF库文件缺失：" + path + (isWindows && is64 ? "（未提供Windows 64位PG UDF库，该目标不可用UDF通道）" : ""));
            }
            return MySqlUdfSupport.Decloak(File.ReadAllBytes(path));
        }
    }
}
