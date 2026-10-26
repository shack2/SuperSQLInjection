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
        Title = "超级SQL注入工具V2 v" + Models.ConstData.AppVersion;
        NotificationManager = new WindowNotificationManager(this) { MaxItems = 3, Position = NotificationPosition.BottomRight };
    }

    protected override async Task<bool> CanClose()
    {
        string prompt = "Are you sure you want to exit?\n您确定要退出吗？";
        if (DataContext is ViewModels.MainViewViewModel vm)
        {
            string pending = vm.AppConfig.UdfSession.PendingSummary();
            if (!string.IsNullOrEmpty(pending))
            {
                prompt += "\n\n警告：本次会话安装过UDF，退出不会自动清理，目标可能仍残留函数和库文件：\n" + pending
                    + "\n如不再需要，请先取消退出并执行UDF痕迹清理。";
            }
        }
        var result = await OverlayMessageBox.ShowAsync(prompt, "Exit", button: MessageBoxButton.YesNo);
        if (result == MessageBoxResult.Yes)
        {
            //dump断点节流写盘的兜底落盘（退出不丢最后1s内的进度）
            SuperSQLInjectionV2.Models.Data.DumpProgress.Flush();
        }
        return result == MessageBoxResult.Yes;
    }
}