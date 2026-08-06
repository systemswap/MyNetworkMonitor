using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using MyNetworkMonitor.Avalonia.Platform.Linux;
#if WINDOWS
using MyNetworkMonitor.Platform.Windows;
#endif
using MyNetworkMonitor.Avalonia.Views;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Avalonia;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        // Plattform-Implementierungen fuer die neutrale Scan-Engine in Core.
        // Wichtig: unter Windows muessen die Windows-Provider registriert werden -
        // mit den Linux-Providern schlagen ARP-Request und Routing dort fehl.
#if WINDOWS
        PlatformServices.RegisterArp(new WindowsArpProvider());
        PlatformServices.RegisterRouting(new WindowsRoutingProvider());
        PlatformServices.RegisterRegistry(new WindowsRegistryReader());
        PlatformServices.RegisterEnterprise(new WindowsEnterpriseEnvironment());
        PlatformServices.RegisterWifi(new ScanningMethod_WiFi());
#else
        PlatformServices.RegisterArp(new LinuxArpProvider());
        PlatformServices.RegisterRouting(new LinuxRoutingProvider());
        PlatformServices.RegisterRegistry(new LinuxRegistryReader());
        PlatformServices.RegisterEnterprise(new LinuxEnterpriseEnvironment());
        PlatformServices.RegisterWifi(new LinuxWifiProvider());
#endif

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            // TEMPORAER waehrend der Migration: es wird jeweils die aktuell
            // portierte Form als Startfenster gezeigt. Am Ende uebernimmt das
            // portierte MainWindow die Navigation zu den Dialogen.
            desktop.MainWindow = new MainWindowView();
        }

        base.OnFrameworkInitializationCompleted();
    }
}
