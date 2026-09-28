using Avalonia;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using System.ComponentModel;

namespace SuperSQLInjectionV2.ViewModels;

public class ViewModelBase : ObservableObject
{

    // 例如使用 Dispatcher 的实现
    protected override void OnPropertyChanged(PropertyChangedEventArgs e)
    {
        //无Avalonia应用实例（控制台/测试环境）：直接触发，Dispatcher.Invoke会因无UI消息循环永久阻塞
        if (Avalonia.Application.Current == null || Dispatcher.UIThread.CheckAccess())
        {
            // 当前已在 UI 线程（或无UI环境），直接触发
            base.OnPropertyChanged(e);
        }
        else
        {
            // 当前不在 UI 线程，异步派发到 UI 线程执行。
            // 不用Invoke：后台线程同步等待UI线程，一旦UI线程繁忙/阻塞即死锁（检测卡死根因之一）
            Dispatcher.UIThread.Post( ()=> base.OnPropertyChanged(e));
        }
    }
}