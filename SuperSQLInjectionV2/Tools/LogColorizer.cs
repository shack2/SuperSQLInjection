using Avalonia.Media;
using AvaloniaEdit.Document;
using AvaloniaEdit.Rendering;
using System;
using System.Collections.Generic;

namespace SuperSQLInjectionV2.Tools
{
    /// <summary>
    /// 日志级别（决定行颜色）
    /// </summary>
    public enum LogLevel
    {
        Info,       //默认前景色
        Success,    //绿色：注入命中/取数成功等
        Warn,       //琥珀色：警告
        Error,      //红色：错误/异常
        Highlight   //蓝色：关键节点（检测开始/完成、注入点确认等）
    }

    /// <summary>
    /// 日志行级着色器：按行号记录日志级别，AvaloniaEdit渲染时逐行着色。
    /// 日志编辑器为只读、仅追加/头部裁剪，行号映射稳定。
    /// </summary>
    public class LogLineColorizer : DocumentColorizingTransformer
    {
        private readonly List<LogLevel> _lineLevels = new List<LogLevel>();

        private static readonly IBrush SuccessBrush = new SolidColorBrush(Color.Parse("#3FB950"));
        private static readonly IBrush WarnBrush = new SolidColorBrush(Color.Parse("#D29922"));
        private static readonly IBrush ErrorBrush = new SolidColorBrush(Color.Parse("#F85149"));
        private static readonly IBrush HighlightBrush = new SolidColorBrush(Color.Parse("#58A6F5"));

        /// <summary>
        /// 设置指定行（0起始索引）的日志级别，行索引越界时自动按Info补齐
        /// </summary>
        public void SetLineLevel(int lineIndex, LogLevel level)
        {
            while (_lineLevels.Count <= lineIndex)
            {
                _lineLevels.Add(LogLevel.Info);
            }
            _lineLevels[lineIndex] = level;
        }

        /// <summary>
        /// 头部裁剪后同步移除前count行的级别记录
        /// </summary>
        public void RemoveFirstLines(int count)
        {
            if (count <= 0) return;
            if (count >= _lineLevels.Count)
            {
                _lineLevels.Clear();
                return;
            }
            _lineLevels.RemoveRange(0, count);
        }

        public void Clear()
        {
            _lineLevels.Clear();
        }

        /// <summary>
        /// 查询指定行（0起始索引）的级别，供自检验证
        /// </summary>
        public LogLevel GetLineLevel(int lineIndex)
        {
            return lineIndex >= 0 && lineIndex < _lineLevels.Count ? _lineLevels[lineIndex] : LogLevel.Info;
        }

        protected override void ColorizeLine(DocumentLine line)
        {
            int idx = line.LineNumber - 1;
            if (idx < 0 || idx >= _lineLevels.Count) return;
            IBrush? brush = _lineLevels[idx] switch
            {
                LogLevel.Success => SuccessBrush,
                LogLevel.Warn => WarnBrush,
                LogLevel.Error => ErrorBrush,
                LogLevel.Highlight => HighlightBrush,
                _ => null
            };
            if (brush == null) return;
            //着色范围含行尾，保证空行/整行背景一致
            ChangeLinePart(line.Offset, line.EndOffset, element =>
            {
                element.TextRunProperties.SetForegroundBrush(brush);
            });
        }
    }
}
