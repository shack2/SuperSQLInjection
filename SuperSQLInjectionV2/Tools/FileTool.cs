using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using SuperSQLInjectionV2.Models;
using Avalonia;
using System.Net;
using SuperSQLInjectionV2.ViewModels;

namespace SuperSQLInjectionV2.Tools
{
    class FileTool
    {
        public static List<string> readFileToList(string path)
        {
            
            List<string> list = new List<string>();
            FileStream? fs_dir = null;
            StreamReader? reader = null;
            try
            {
                fs_dir = new FileStream(AppDomain.CurrentDomain.BaseDirectory + "/" + path, FileMode.Open, FileAccess.Read);

                reader = new StreamReader(fs_dir);

                string? lineStr;

                while ((lineStr = reader.ReadLine()) != null)
                {
                    if (!lineStr.Equals("", StringComparison.Ordinal))
                    {
                       list.Add(lineStr);
                    }
                }
            } catch
            {
                throw;
            }
            finally {
                if (reader != null)
                {
                    reader.Close();
                }
                if (fs_dir != null)
                {
                    fs_dir.Close();
                }
            }
            return list;
        }


        public static Dictionary<string, string> ReadSQLPayload(string path)
        {

            Dictionary<string,string> list = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
            FileStream? fs_dir = null;
            StreamReader? reader = null;
            try
            {
                fs_dir = new FileStream(AppDomain.CurrentDomain.BaseDirectory + "/" + path, FileMode.Open, FileAccess.Read);
                reader = new StreamReader(fs_dir);
                string? lineStr;
                while ((lineStr = reader.ReadLine()) != null)
                {
                    if (!lineStr.Equals("", StringComparison.Ordinal))
                    {
                        //按首个冒号分割，值中允许包含冒号（如informix的sysmaster:sysdual、SQLServer的waitfor delay '0:0:5'）
                        int splitIndex = lineStr.IndexOf(':', StringComparison.Ordinal);
                        if (splitIndex > 0)
                        {
                            list.Add(lineStr.Substring(0, splitIndex), lineStr.Substring(splitIndex + 1));
                        }
                    }
                }
            }
            catch
            {
                throw;
            }
            finally
            {
                if (reader != null)
                {
                    reader.Close();
                }
                if (fs_dir != null)
                {
                    fs_dir.Close();
                }
            }
            return list;
        }

        //读取文件
        public static byte[] readFileToByte(string path,Encoding encode)
        {
            byte[]? buffer = null;
            FileStream? fs_dir = null;
            StreamReader? reader = null;
            try
            {
                fs_dir = new FileStream(path, FileMode.Open, FileAccess.Read);
                BinaryReader br = new BinaryReader(fs_dir, encode);
                int len = (int)fs_dir.Length;

                buffer = new byte[len];

                int size = br.Read(buffer, 0, len);

                reader?.Read();
                
            }
            catch
            {
                throw;
            }
            finally
            {
                if (reader != null)
                {
                    reader.Close();
                }
                if (fs_dir != null)
                {
                    fs_dir.Close();
                }
            }
            return buffer;
            
        }
        public static object c = "";
        public static string error = "";
        /// <summary>日志长驻写入器（按路径缓存，避免每行open/close；AutoFlush保证崩溃不丢日志）</summary>
        private static readonly Dictionary<string, StreamWriter> _logWriters = new Dictionary<string, StreamWriter>(StringComparer.OrdinalIgnoreCase);
        public static void AppendLogToFile(string path,string log)
        {
            //锁住，防止多线程引发错误
            lock (c)
            {
                try
                {
                    if (!_logWriters.TryGetValue(path, out StreamWriter? sw))
                    {
                        //P4-3：确保日志目录存在（防目录缺失/磁盘异常导致整个发包流程崩溃）
                        string fullPath = AppDomain.CurrentDomain.BaseDirectory + "/" + path;
                        string? dir = Path.GetDirectoryName(fullPath);
                        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                        {
                            Directory.CreateDirectory(dir);
                        }
                        sw = new StreamWriter(new FileStream(fullPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite)) { AutoFlush = true };
                        _logWriters[path] = sw;
                    }
                    sw.WriteLine(log);
                }
                catch (Exception e)
                {
                    error = "文件操作发生异常！" + e.Message;
                }
            }

        }
        /// <summary>
        /// 注意：vals为空或null会清空代理
        /// </summary>
        /// <param name="path"></param>
        /// <param name="vals"></param>
        public static void SaveProxyList(string path, Dictionary<string,Proxy>.ValueCollection vals)
        {
     
            FileStream? fs_dir = null;
            StreamWriter? sw = null;
            try
            {
                if (vals != null && vals.Count > 0)
                {
                    fs_dir = new FileStream(path, FileMode.Create, FileAccess.Write);
                    sw = new StreamWriter(fs_dir, Encoding.UTF8);
                    string head = "域名或IP,代理端口,代理类型,代理账号,代理密码,是否可用,用时(毫秒),验证时间(毫秒)";
                    sw.WriteLine(head);
                    foreach (Proxy proxy in vals)
                    {
                        string line = proxy.Host + "," + proxy.Port + "," + proxy.proxyType + "," + proxy.username + "," + proxy.password + "," + proxy.IsOk + "," + proxy.UseTime + "," + proxy.CheckTime;
                        sw.WriteLine(line);
                    }
                }
                else {
                    //如果为空，则删除代理
                    File.Delete(path);
                }
            }
            catch
            {
                throw;
            }
            finally
            {
                if (sw != null)
                {
                    sw.Close();
                }
                if (fs_dir != null)
                {
                    fs_dir.Close();
                }
            }

        }

        public static Dictionary<string,Proxy> ReadProxyList(string path)
        {

            Dictionary<string, Proxy> list = new Dictionary<string, Proxy>();
            FileStream? fs_dir = null;
            StreamReader? reader = null;
            try
            {
                fs_dir = new FileStream(path, FileMode.Open, FileAccess.Read);

                reader = new StreamReader(fs_dir);

                string? lineStr;
                int line = 0;
                while ((lineStr = reader.ReadLine()) != null)
                {
                    line++;
                    if (line == 1) {
                        continue;
                    }
                    
                    if (!lineStr.Equals("", StringComparison.Ordinal))
                    {
                        string[] strs = lineStr.Split(',');
                        if (strs.Length == 2)
                        {
                            Proxy proxy = new Proxy();
                            proxy.Host = strs[0];
                            proxy.Port = MyTools.ConvertToInt(strs[1]);
                            list.Add(proxy.Host.ToString ()+ proxy.Port, proxy);
                        }
                        else if (strs.Length == 3)
                        {
                            Proxy proxy = new Proxy();
                            proxy.Host = strs[0];
                            proxy.Port = MyTools.ConvertToInt(strs[1]);
                            proxy.proxyType = strs[2];
                            list.Add(proxy.Host.ToString ()+ proxy.Port, proxy);
                        }
                        else if (strs.Length == 5)
                        {
                                Proxy proxy = new Proxy();
                                proxy.Host = strs[0];
                            proxy.Port = MyTools.ConvertToInt(strs[1]);
                                proxy.proxyType = strs[2];
                                proxy.username = strs[3];
                                proxy.password = strs[4];
                                list.Add(proxy.Host.ToString ()+ proxy.Port, proxy);
                        }
                        else if (strs.Length == 8)
                        {
                            Proxy proxy = new Proxy();
                            proxy.Host = strs[0];
                            proxy.Port = MyTools.ConvertToInt(strs[1]);
                            proxy.proxyType = strs[2];
                            proxy.username = strs[3];
                            proxy.password = strs[4];
                            proxy.IsOk = bool.Parse(strs[5]);
                            proxy.UseTime = MyTools.ConvertToInt(strs[6]);
                            proxy.CheckTime = strs[7];
                            list.Add(proxy.Host.ToString ()+ proxy.Port, proxy);
                        }
                    }
                   
                }
            }
            catch (Exception e)
            {
               Log.SysLog("ReadProxyList：" + e.Message);
            }
            finally
            {
                if (reader != null)
                {
                    reader.Close();
                }
                if (fs_dir != null)
                {
                    fs_dir.Close();
                }
            }
            return list;
        }


    }
}
