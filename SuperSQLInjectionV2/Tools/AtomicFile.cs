using System.Text;

namespace SuperSQLInjectionV2.Tools
{
    /// <summary>同目录临时文件+落盘+原子替换，避免进程中断留下半个JSON或规则文件。</summary>
    public static class AtomicFile
    {
        public static void WriteAllText(string path, string contents, Encoding? encoding = null)
        {
            string fullPath = Path.GetFullPath(path);
            string? directory = Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
            string temp = fullPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var writer = new StreamWriter(stream, encoding ?? new UTF8Encoding(false)))
                {
                    writer.Write(contents);
                    writer.Flush();
                    stream.Flush(true);
                }
                if (File.Exists(fullPath))
                {
                    try { File.Replace(temp, fullPath, null, true); }
                    catch (PlatformNotSupportedException) { File.Move(temp, fullPath, true); }
                    catch (IOException) { File.Move(temp, fullPath, true); }
                }
                else
                {
                    File.Move(temp, fullPath);
                }
            }
            finally
            {
                if (File.Exists(temp)) File.Delete(temp);
            }
        }
    }
}
