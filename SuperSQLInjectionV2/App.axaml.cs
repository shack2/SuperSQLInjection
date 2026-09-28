using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using SuperSQLInjectionV2.ViewModels;
using SuperSQLInjectionV2.Views;

namespace SuperSQLInjectionV2;

public partial class App : Application
{

    private MainViewViewModel mainView=new MainViewViewModel();
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
        System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow = new MainWindow
            {
                DataContext = mainView
            };
            desktop.Exit += Desktop_Exit;
        }
        else if (ApplicationLifetime is ISingleViewApplicationLifetime singleView)
        {
            singleView.MainView = new SingleView
            {
                DataContext = mainView,
            };
        }
       
        base.OnFrameworkInitializationCompleted();
    }

    private void Desktop_Exit(object? sender, ControlledApplicationLifetimeExitEventArgs e)
    {
        mainView.SavaConfig();
    }

   
}