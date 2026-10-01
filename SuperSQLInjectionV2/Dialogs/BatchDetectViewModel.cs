using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Irihi.Avalonia.Shared.Contracts;
using SuperSQLInjectionV2.Models.Detect;
using SuperSQLInjectionV2.Tools;
using SuperSQLInjectionV2.Tools.Inject;
using SuperSQLInjectionV2.Models;
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SuperSQLInjectionV2.Dialogs;

/// <summary>批量检测结果行</summary>
public partial class BatchRow : ObservableObject
{
    public int Index { get; init; }
    public string Url { get; init; } = "";

    [ObservableProperty] private string _status = "排队";
    [ObservableProperty] private int _hitCount;
    [ObservableProperty] private string _typeSummary = "";
    [ObservableProperty] private string _dbSummary = "";
    [ObservableProperty] private string _elapsedText = "";
    [ObservableProperty] private string _message = "";
}

/// <summary>
/// 批量注入检测弹窗：导入一批URL，多线程逐目标调用多技术检测引擎；
/// 命中点经回调写入主界面注入记录（UI线程执行），检测日志带[T序号]前缀进主日志。
/// 检测配置（Level/Risk/线程内并发/tamper/代理等）与当前界面配置一致。
/// </summary>
public partial class BatchDetectViewModel : ObservableObject, IDialogContext
{
    private readonly AppConfig _template;
    private readonly Action<InjectPoint, string, int> _onHit;
    private readonly Func<Task<string?>>? _openFilePicker;
    private CancellationTokenSource? _cts;

    public BatchDetectViewModel(AppConfig template, Action<InjectPoint, string, int> onHit, Func<Task<string?>>? openFilePicker)
    {
        _template = template;
        _onHit = onHit;
        _openFilePicker = openFilePicker;
    }

    /// <summary>URL列表（一行一个，支持缺省scheme，默认补http://）</summary>
    [ObservableProperty] private string _urlsText = "";

    /// <summary>并行检测的目标数（1-20）</summary>
    [ObservableProperty] private int _threadCount = 4;

    [ObservableProperty] private string _progressText = "导入URL后开始检测";
    [ObservableProperty] private bool _isRunning;

    public ObservableCollection<BatchRow> Rows { get; } = new();

    public event EventHandler<object?>? RequestClose;

    [RelayCommand]
    private async Task ImportUrls()
    {
        if (_openFilePicker == null)
        {
            return;
        }
        string? file = await _openFilePicker();
        if (string.IsNullOrEmpty(file) || !File.Exists(file))
        {
            return;
        }
        try
        {
            string txt = await File.ReadAllTextAsync(file);
            UrlsText = string.IsNullOrWhiteSpace(UrlsText) ? txt.Trim() : UrlsText.TrimEnd() + "\n" + txt.Trim();
        }
        catch (Exception e)
        {
            Log.Warning("读取URL文件失败：" + e.Message);
        }
    }

    [RelayCommand]
    private void ClearUrls()
    {
        if (IsRunning)
        {
            return;
        }
        UrlsText = "";
        Rows.Clear();
        ProgressText = "导入URL后开始检测";
    }

    [RelayCommand]
    private async Task Start()
    {
        if (IsRunning)
        {
            return;
        }
        var urls = (UrlsText ?? "").Split('\n')
            .Select(l => l.Trim().TrimEnd('\r'))
            .Where(l => l.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (urls.Count == 0)
        {
            Log.Warning("大侠，请先粘贴或导入要检测的URL（一行一个）！");
            return;
        }
        Rows.Clear();
        for (int i = 0; i < urls.Count; i++)
        {
            Rows.Add(new BatchRow { Index = i + 1, Url = urls[i] });
        }
        IsRunning = true;
        _cts = new CancellationTokenSource();
        int total = Rows.Count, done = 0, hitTotal = 0;
        ProgressText = "0/" + total + " 检测中……";
        Log.Highlight("批量检测开始：共 " + total + " 个目标，并行度 " + Math.Min(ThreadCount, total) + "（检测配置与当前界面一致）");

        int next = -1;
        int workers = Math.Max(1, Math.Min(ThreadCount, total));
        var tasks = Enumerable.Range(0, workers).Select(async _ =>
        {
            while (true)
            {
                int i = Interlocked.Increment(ref next);
                if (i >= total || _cts.IsCancellationRequested)
                {
                    break;
                }
                BatchRow row = Rows[i];
                await Dispatcher.UIThread.InvokeAsync(() => row.Status = "检测中");
                BatchTargetResult result = await BatchDetectEngine.DetectOne(_template, row.Url, "T" + row.Index, _cts.Token);
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    foreach ((InjectPoint inp, string host, int port) in result.Hits)
                    {
                        _onHit(inp, host, port);
                    }
                    row.HitCount = result.Hits.Count;
                    row.TypeSummary = result.TypeSummary;
                    row.DbSummary = result.DbSummary;
                    row.ElapsedText = result.Elapsed.TotalSeconds.ToString("F1") + "s";
                    row.Message = result.Error;
                    row.Status = result.Error == "已停止" ? "已停止"
                        : result.Error.Length > 0 ? "失败"
                        : result.Hits.Count > 0 ? "命中" : "完成";
                    int d = Interlocked.Increment(ref done);
                    Interlocked.Add(ref hitTotal, result.Hits.Count);
                    ProgressText = d + "/" + total + " 完成，命中 " + hitTotal + " 个注入点";
                });
            }
        }).ToList();
        try
        {
            await Task.WhenAll(tasks);
        }
        catch (Exception e)
        {
            Log.Error("批量检测异常：" + e.Message);
        }
        IsRunning = false;
        bool stopped = _cts.IsCancellationRequested;
        ProgressText += stopped ? "（已停止）" : "（全部完成）";
        if (stopped)
        {
            Log.Show("批量检测已停止：" + ProgressText);
        }
        else
        {
            Log.Highlight("批量检测完成：" + ProgressText + "——命中点已全部写入注入记录，可选择注入点恢复配置后取数！");
        }
    }

    [RelayCommand]
    private void Stop()
    {
        _cts?.Cancel();
    }

    [RelayCommand]
    public void Close()
    {
        _cts?.Cancel();
        RequestClose?.Invoke(this, null);
    }
}
