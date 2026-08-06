using System;
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
            desktop.MainWindow = CreateStartWindow(desktop);
        }

        base.OnFrameworkInitializationCompleted();
    }

    /// <summary>
    /// Im Firmennetz steht der Lizenzhinweis vor dem Hauptfenster: erst ein Klick
    /// auf OK gibt es frei, jeder andere Weg (X, Alt+F4) beendet die Anwendung.
    ///
    /// WPF erreicht das mit ShowDialog() im Konstruktor des MainWindow, wo das
    /// Hauptfenster noch nicht existiert. In Avalonia gibt es diesen Moment nicht
    /// - ein modaler Dialog braucht ein Besitzerfenster. Deshalb ist der Hinweis
    /// hier selbst das Startfenster und erzeugt das Hauptfenster erst, wenn er
    /// bestaetigt wurde.
    /// </summary>
    private static global::Avalonia.Controls.Window CreateStartWindow(IClassicDesktopStyleApplicationLifetime desktop)
    {
        bool isCompanyNetwork;

        try
        {
            isCompanyNetwork = PlatformServices.EnterpriseOrNull?.IsCompanyNetwork() == true;
        }
        catch (Exception)
        {
            // Eine fehlgeschlagene Erkennung darf den Start nie verhindern
            isCompanyNetwork = false;
        }

        if (!isCompanyNetwork) return new MainWindowView();

        var notice = new EnterpriseMessageView();

        notice.Accepted += () =>
        {
            var mainWindow = new MainWindowView();

            // MainWindow umhaengen, damit spaetere Dialoge das richtige
            // Besitzerfenster finden (AvaloniaDialogService liest es aus).
            desktop.MainWindow = mainWindow;
            mainWindow.Show();
        };

        return notice;
    }
}
