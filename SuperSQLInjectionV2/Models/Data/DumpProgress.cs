using SuperSQLInjectionV2.Source;
using SuperSQLInjectionV2.Tools;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;

namespace SuperSQLInjectionV2.Models.Data
{
    /// <summary>
    /// dump 任务级断点续传（dump 进度持久化）：
    /// 以 注入点+库+表+列+where+通道 为任务键，记录"下一待读行索引"，中断/停止后重跑同任务从断点续传。
    /// 跨进程持久化到 config/sessions/dump_progress.json；写盘按1s节流（Union批量模式行推进快，逐行盲注每次写也无压力）。
    /// 与盲注单值断点（blind_progress.json，payload级前缀续取）互补：一个管"读到哪一行"，一个管"当前行读到哪字符"。
    /// </summary>
    public static class DumpProgress
    {
        private static readonly ConcurrentDictionary<string, int> _progress = new ConcurrentDictionary<string, int>();
        private static readonly object _ioLock = new object();
        private static long _lastSaveTicks;
        private static bool _dirty;

        private static string FilePath => Path.Combine("config", "sessions", "dump_progress.json");

        static DumpProgress()
        {
            try
            {
                if (File.Exists(FilePath))
                {
                    var dic = JsonSerializer.Deserialize(File.ReadAllText(FilePath), JsonCtx.CompactInfo<Dictionary<string, int>>());
                    if (dic != null)
                    {
                        foreach (var kv in dic)
                        {
                            _progress[kv.Key] = kv.Value;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Log.SysLog("dump断点加载异常：" + e.Message);
            }
        }

        /// <summary>任务键：注入点+库类型+通道+库表列+where（同任务不同通道进度互不污染）</summary>
        public static string BuildKey(AppConfig config, string channel, string db, string table, IEnumerable<string> cols, string where)
        {
            string colStr = string.Join(",", cols ?? Enumerable.Empty<string>());
            return string.Join("|",
                config.Host + ":" + config.Port,
                config.DataConfig?.SelectedDBType.ToString ()?? "",
                channel, db ?? "", table ?? "", colStr, where ?? "");
        }

        /// <summary>查询断点：返回下一待读行索引（0基），无断点返回 -1</summary>
        public static int GetResumeIndex(string key)
        {
            return _progress.TryGetValue(key, out int next) ? next : -1;
        }

        /// <summary>记录进度（nextIndex=下一待读行索引）。写盘节流1s，进程内立即生效</summary>
        public static void Save(string key, int nextIndex)
        {
            _progress[key] = nextIndex;
            _dirty = true;
            long now = DateTime.UtcNow.Ticks;
            if (now - Interlocked.Read(ref _lastSaveTicks) > TimeSpan.TicksPerSecond)
            {
                Persist();
            }
        }

        /// <summary>任务完成/用户放弃续传：清除断点并立即落盘</summary>
        public static void Complete(string key)
        {
            if (_progress.TryRemove(key, out _))
            {
                Persist();
            }
        }

        /// <summary>进程退出前兜底落盘（主窗口关闭时调用）</summary>
        public static void Flush()
        {
            if (_dirty)
            {
                Persist();
            }
        }

        private static void Persist()
        {
            lock (_ioLock)
            {
                try
                {
                    Interlocked.Exchange(ref _lastSaveTicks, DateTime.UtcNow.Ticks);
                    Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
                    File.WriteAllText(FilePath, JsonSerializer.Serialize(new Dictionary<string, int>(_progress), JsonCtx.CompactInfo<Dictionary<string, int>>()));
                    _dirty = false;
                }
                catch (Exception e)
                {
                    Log.SysLog("dump断点保存异常：" + e.Message);
                }
            }
        }
    }
}
