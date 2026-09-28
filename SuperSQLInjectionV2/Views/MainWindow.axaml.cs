using Avalonia.Controls.Notifications;
using System.Threading.Tasks;
using Ursa.Controls;
using WindowNotificationManager = Ursa.Controls.WindowNotificationManager;

namespace SuperSQLInjectionV2.Views;

public partial class MainWindow : UrsaWindow
{
    public WindowNotificationManager? NotificationManager { get; set; }

    public MainWindow()
    {
        InitializeComponent();
        NotificationManager = new WindowNotificationManager(this) { MaxItems = 3, Position = NotificationPosition.BottomRight };
    }

    protected override async Task<bool> CanClose()
    {
        var result = await OverlayMessageBox.ShowAsync("Are you sure you want to exit?\n您确定要退出吗？", "Exit", button: MessageBoxButton.YesNo);
        if (result == MessageBoxResult.Yes)
        {
            //dump断点节流写盘的兜底落盘（退出不丢最后1s内的进度）
            SuperSQLInjectionV2.Models.Data.DumpProgress.Flush();
        }
        return result == MessageBoxResult.Yes;
    }
}