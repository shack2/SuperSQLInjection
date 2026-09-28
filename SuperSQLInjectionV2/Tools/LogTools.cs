using Avalonia.Controls;
using Avalonia.Controls.Notifications;
using Avalonia.Media;
using Avalonia.Threading;
using AvaloniaEdit;
using AvaloniaEdit.Document;
using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Ursa.Controls;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace SuperSQLInjectionV2.Tools
{
    public class LogTools : ILogSink
    {
        /// <summary>
        /// 无UI（控制台/测试）模式：日志直接输出到控制台与文件，跳过Dispatcher
        /// </summary>
        public static bool Headless { get; set; } = false;

        /// <summary>日志文档最大字符数，超出后从头部裁剪（防止长时间运行内存膨胀）</summary>
        private const int MaxLogChars = 200000;

        public required Ursa.Controls.WindowNotificationManager? NotificationManager { get; set; }

        /// <summary>日志显示编辑器（只读AvaloniaEdit，支持逐行着色+任意选择复制）</summary>
        public required TextEditor TxtLog { get; set; }

        public required AppConfig? AppConfig { get; set; }

        /// <summary>行级着色器（TxtLog赋值后由InitLogTools挂到TextArea.TextView）</summary>
        public LogLineColorizer Colorizer { get; } = new LogLineColorizer();

        /// <summary>日志条目缓冲（供级别过滤重渲染），上限5000条超出后丢弃最旧</summary>
        private readonly List<(string Text, LogLevel Level)> _entries = new List<(string, LogLevel)>();
        private const int MaxEntries = 5000;

        /// <summary>日志级别过滤：0全部 1信息(含高亮) 2成功 3警告/错误</summary>
        public int LevelFilter { get; private set; } = 0;

        /// <summary>设置日志级别过滤并重渲染日志区</summary>
        public void SetFilter(int filter)
        {
            if (filter == LevelFilter)
            {
                return;
            }
            LevelFilter = filter;
            if (Headless)
            {
                return;
            }
            Dispatcher.UIThread.Post((Action)ReRender, DispatcherPriority.Normal);
        }

        private static bool PassesFilter(LogLevel level, int filter)
        {
            return filter switch
            {
                1 => level is LogLevel.Info or LogLevel.Highlight,
                2 => level is LogLevel.Success,
                3 => level is LogLevel.Warn or LogLevel.Error,
                _ => true
            };
        }

        public void Show(string msg)
        {
            if (Headless)
            {
                Console.WriteLine("[INFO] " + msg);
                SysLog(msg, LogLevel.Info);
                return;
            }
            // 检查当前线程状态
            if (!Dispatcher.UIThread.CheckAccess())
            {
                Dispatcher.UIThread.Post( ()=>
                {
                    NotificationManager?.Show(msg);

                }, DispatcherPriority.Normal); // 可设置优先级
            }
            else
            {
                NotificationManager?.Show(msg);
            }
            SysLog(msg, LogLevel.Info);
        }

        /// <summary>成功日志（绿色）：注入命中、取数成功等</summary>
        public void Success(string msg)
        {
            if (Headless)
            {
                Console.WriteLine("[OK] " + msg);
                SysLog(msg, LogLevel.Success);
                return;
            }
            SysLog(msg, LogLevel.Success);
        }

        /// <summary>高亮日志（蓝色）：检测开始/完成等关键节点</summary>
        public void Highlight(string msg)
        {
            if (Headless)
            {
                Console.WriteLine("[*] " + msg);
                SysLog(msg, LogLevel.Highlight);
                return;
            }
            SysLog(msg, LogLevel.Highlight);
        }

        public void Error(string msg)
        {
            if (Headless)
            {
                Console.WriteLine("[ERROR] " + msg);
                SysLog(msg, LogLevel.Error);
                return;
            }
            if (!Dispatcher.UIThread.CheckAccess())
            {
                Dispatcher.UIThread.Post( ()=>
                {
                    NotificationManager?.Show(msg, NotificationType.Error);

                }, DispatcherPriority.Normal); // 可设置优先级
            }
            else
            {
                NotificationManager?.Show(msg, NotificationType.Error);
            }
            SysLog(msg, LogLevel.Error);
        }


        public void Warning(string msg)
        {
            if (Headless)
            {
                Console.WriteLine("[WARN] " + msg);
                SysLog(msg, LogLevel.Warn);
                return;
            }
            if (!Dispatcher.UIThread.CheckAccess())
            {
                Dispatcher.UIThread.Post( ()=>
                {
                    NotificationManager?.Show(msg,NotificationType.Warning);

                }, DispatcherPriority.Normal); // 可设置优先级
            }
            else
            {
                NotificationManager?.Show(msg, NotificationType.Warning);
            }
            SysLog(msg, LogLevel.Warn);
        }

        public void SysLog(string log)
        {
            SysLog(log, LogLevel.Info);
        }

        /// <summary>日志批量派发缓冲：高频日志先入队，100ms窗口合并为一次UI派发（盲注高并发时UI队列不逐条堆积）</summary>
        private readonly List<(string Log, LogLevel Level)> _pending = new List<(string, LogLevel)>();
        private readonly object _pendingLock = new object();
        private bool _flushScheduled = false;

        /// <summary>
        /// 写系统日志：UI模式追加到只读编辑器并按级别着色，同时写日志文件
        /// </summary>
        public void SysLog(string log, LogLevel level)
        {
            if (Headless)
            {
                if (AppConfig != null)
                {
                    if (AppConfig.TxtLog.Length > 65535)
                    {
                        AppConfig.TxtLog = "";
                    }
                    AppConfig.TxtLog = AppConfig.TxtLog + DateTime.Now.ToString("[yyyy-MM-dd HH:mm:ss] ") + log + "\r\n";
                }
                FileTool.AppendLogToFile("logs/" + DateTime.Now.ToString("yyyy-MM-dd") + ".log.txt", log + "----" + DateTime.Now);
                return;
            }
            lock (_pendingLock)
            {
                _pending.Add((log, level));
                if (!_flushScheduled)
                {
                    _flushScheduled = true;
                    Dispatcher.UIThread.Post(async  ()=>
                    {
                        //100ms攒批窗口：一批日志一次UI回合追加完，滚动只触发一次
                        //注意不能ConfigureAwait(false)：必须回到UI上下文执行FlushPending，否则跨线程访问TxtLog.Document崩溃
                        await Task.Delay(100);
                        FlushPending();
                    }, DispatcherPriority.Background);
                }
            }
            FileTool.AppendLogToFile("logs/" + DateTime.Now.ToString("yyyy-MM-dd") + ".log.txt", log + "----" + DateTime.Now);
        }

        /// <summary>把攒批缓冲一次性追加到编辑器（UI线程执行）</summary>
        private void FlushPending()
        {
            //兜底防线：任何路径误入非UI线程时重投回UI线程，杜绝跨线程访问TxtLog.Document
            if (!Dispatcher.UIThread.CheckAccess())
            {
                Dispatcher.UIThread.Post(FlushPending, DispatcherPriority.Background);
                return;
            }
            List<(string Log, LogLevel Level)> batch;
            lock (_pendingLock)
            {
                batch = new List<(string, LogLevel Level)>(_pending);
                _pending.Clear();
                _flushScheduled = false;
            }
            foreach ((string log, LogLevel level) in batch)
            {
                AppendToEditor(log, level, false);
            }
            if (batch.Count > 0)
            {
                ScrollLogToEnd();
            }
        }

        /// <summary>
        /// 追加日志：加时间前缀后入缓冲，通过当前过滤则增量追加到编辑器并记录行级别（必须在UI线程调用）
        /// </summary>
        private void AppendToEditor(string log, LogLevel level, bool scrollToEnd = true)
        {
            //每条日志首行前加当前时间（含年月日），多行内容仅首行带时间戳
            string stamped = DateTime.Now.ToString("[yyyy-MM-dd HH:mm:ss] ") + (log ?? "");
            _entries.Add((stamped, level));
            if (_entries.Count > MaxEntries)
            {
                //缓冲超限：滞回裁剪到MaxEntries-1000（避免饱和后每条日志都触发一次裁剪）；
                //无过滤时按被删条目的行数增量裁剪文档，有级别过滤时才整体重渲染（U2：消除周期性大卡顿）
                int removeCount = _entries.Count - (MaxEntries - 1000);
                List<(string Text, LogLevel Level)> removed = _entries.GetRange(0, removeCount);
                _entries.RemoveRange(0, removeCount);
                if (LevelFilter == 0)
                {
                    TrimDocByEntries(removed);
                }
                else
                {
                    ReRender();
                    return;
                }
            }
            if (!PassesFilter(level, LevelFilter))
            {
                return;
            }
            AppendLineToDoc(stamped, level, scrollToEnd);
        }

        /// <summary>按被丢弃的日志条目增量删除文档头部对应行（条目占行数=换行数+1）</summary>
        private void TrimDocByEntries(List<(string Text, LogLevel Level)> removed)
        {
            TextDocument doc = TxtLog.Document;
            int removeLines = 0;
            foreach ((string text, _) in removed)
            {
                removeLines += text.Split('\n').Length;
            }
            int removedLines = 0;
            while (removedLines < removeLines && doc.LineCount > 1)
            {
                DocumentLine first = doc.GetLineByNumber(1);
                doc.Remove(0, first.TotalLength);
                removedLines++;
            }
            Colorizer.RemoveFirstLines(removedLines);
        }

        /// <summary>
        /// 单条日志追加到文档并着色（必须在UI线程调用）
        /// </summary>
        private void AppendLineToDoc(string log, LogLevel level, bool scrollToEnd)
        {
            TextDocument doc = TxtLog.Document;
            //超长裁剪：从头部删行直到低于阈值一半
            if (doc.TextLength > MaxLogChars)
            {
                int removed = 0;
                while (doc.TextLength > MaxLogChars / 2 && doc.LineCount > 1)
                {
                    DocumentLine first = doc.GetLineByNumber(1);
                    doc.Remove(0, first.TotalLength);
                    removed++;
                }
                Colorizer.RemoveFirstLines(removed);
            }
            //追加前最后一行恒为空行（每次追加都以\r\n结尾），新内容从该行开始
            int startLineIndex = doc.LineCount - 1;
            string appendText = log + "\r\n";
            doc.Insert(doc.TextLength, appendText);
            int newLineCount = appendText.Split('\n').Length - 1; //追加文本中的换行数=占用的行数
            for (int i = 0; i < newLineCount; i++)
            {
                Colorizer.SetLineLevel(startLineIndex + i, level);
            }
            if (scrollToEnd)
            {
                ScrollLogToEnd();
            }
        }

        /// <summary>
        /// 滚动到日志末尾：把最后内容钉在视口底部。
        /// ScrollToEnd会滚过文档末尾（最后一行顶到视口顶部、下方大片空白，看起来像没日志），
        /// 改为按最大合法偏移滚动；Background优先级派发，等布局完成后ExtentHeight才是追加后的值
        /// </summary>
        private void ScrollLogToEnd()
        {
            Dispatcher.UIThread.Post( ()=>
            {
                double max = TxtLog.ExtentHeight - TxtLog.ViewportHeight;
                TxtLog.ScrollToVerticalOffset(max > 0 ? max : 0);
            }, DispatcherPriority.Background);
        }

        /// <summary>
        /// 按当前过滤级别整体重渲染日志区（必须在UI线程调用）
        /// </summary>
        private void ReRender()
        {
            TxtLog.Document.Text = "";
            Colorizer.Clear();
            foreach ((string text, LogLevel level) in _entries)
            {
                if (PassesFilter(level, LevelFilter))
                {
                    AppendLineToDoc(text, level, false);
                }
            }
            ScrollLogToEnd();
        }

        /// <summary>
        /// 清空日志显示（同步清理级别记录与缓冲）
        /// </summary>
        public void ClearLog()
        {
            if (Headless)
            {
                _entries.Clear();
                if (AppConfig != null) AppConfig.TxtLog = "";
                return;
            }
            //_entries只在UI线程读写（FlushPending/ReRender），清理也必须派发到UI线程，防止与重渲染竞争
            Dispatcher.UIThread.Post((Action)( ()=>
            {
                _entries.Clear();
                TxtLog.Document.Text = "";
                Colorizer.Clear();
            }), DispatcherPriority.Normal);
        }
    }
}
