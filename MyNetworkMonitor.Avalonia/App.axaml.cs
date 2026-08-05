using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using MyNetworkMonitor.Avalonia.Views;

namespace MyNetworkMonitor.Avalonia;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            // TEMPORAER waehrend der Migration: es wird jeweils die aktuell
            // portierte Form als Startfenster gezeigt. Am Ende uebernimmt das
            // portierte MainWindow die Navigation zu den Dialogen.
            desktop.MainWindow = new EnterpriseMessageView();
        }

        base.OnFrameworkInitializationCompleted();
    }
}
