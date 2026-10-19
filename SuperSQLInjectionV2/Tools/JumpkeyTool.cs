using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using SuperSQLInjectionV2.Models;

namespace SuperSQLInjectionV2.Tools
{
    /// <summary>
    /// 跳过参数列表（jumpkey.txt）加载/保存。
    /// 注入检测时命中参数名（不区分大小写）直接跳过，用于静态参数/Token/视图状态类参数降噪。
    /// 界面列表与检测字典共用本工具，保证 UI 管理与检测链路数据一致。
    /// </summary>
    public static class JumpkeyTool
    {
        public static string FilePath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, ConstData.JumpkeyPath);

        /// <summary>从 jumpkey.txt 加载参数名列表：去空白、去注释（#开头）、不区分大小写去重</summary>
        public static List<string> Load()
        {
            List<string> items = new List<string>();
            string file = FilePath;
            if (!File.Exists(file))
            {
                return items;
            }
            foreach (string line in File.ReadAllLines(file))
            {
                string key = line.Trim();
                if (key.Length == 0 || key.StartsWith('#') || items.Contains(key, StringComparer.OrdinalIgnoreCase))
                {
                    continue;
                }
                items.Add(key);
            }
            return items;
        }

        /// <summary>保存参数名列表到 jumpkey.txt（自动建目录）</summary>
        public static void Save(IEnumerable<string> items)
        {
            string file = FilePath;
            Directory.CreateDirectory(Path.GetDirectoryName(file)!);
            File.WriteAllLines(file, items);
        }

        /// <summary>列表转检测用字典（不区分大小写）</summary>
        public static Dictionary<string, string> ToDict(IEnumerable<string> items)
        {
            Dictionary<string, string> dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string key in items)
            {
                dict[key] = key;
            }
            return dict;
        }

        /// <summary>从 jumpkey.txt 加载并刷新检测用字典（无UI入口共用，如CMD启动；检测引擎经 ConstData.JumpkeyList 读取），返回加载项数</summary>
        public static int LoadIntoDetectDict()
        {
            List<string> items = Load();
            ConstData.JumpkeyList = ToDict(items);
            return items.Count;
        }
    }
}
