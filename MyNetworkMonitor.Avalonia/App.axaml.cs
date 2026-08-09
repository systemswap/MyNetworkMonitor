using System;
using System.Linq;
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
        PlatformServices.RegisterNeighbors(new WindowsNeighborProvider());
#else
        PlatformServices.RegisterArp(new LinuxArpProvider());
        PlatformServices.RegisterRouting(new LinuxRoutingProvider());
        PlatformServices.RegisterRegistry(new LinuxRegistryReader());
        PlatformServices.RegisterEnterprise(new LinuxEnterpriseEnvironment());
        PlatformServices.RegisterWifi(new LinuxWifiProvider());
        PlatformServices.RegisterNeighbors(new LinuxNeighborProvider());
#endif

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            // Ab jetzt startet die neue Oberflaeche. Die bisherige bleibt
            // vollstaendig erhalten und laesst sich mit --classic oeffnen -
            // sie haelt noch die Ansichten, die im neuen Fenster erst
            // Platzhalter sind: Topologie, Portsammlungen, Dienstdefinitionen,
            // Namenszuordnung und die Verwaltung der IP-Gruppen.
            UseClassicShell = desktop.Args?.Any(a =>
                string.Equals(a, "--classic", StringComparison.OrdinalIgnoreCase)) == true;

            desktop.MainWindow = CreateStartWindow(desktop);
        }

        base.OnFrameworkInitializationCompleted();
    }

    /// <summary>Die bisherige Oberflaeche wurde ueber --classic angefordert.</summary>
    private static bool UseClassicShell { get; set; }

    private static global::Avalonia.Controls.Window CreateMainWindow() =>
        UseClassicShell ? new MainWindowView() : new ShellView();

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

        if (!isCompanyNetwork) return CreateMainWindow();

        var notice = new EnterpriseMessageView();

        notice.Accepted += () =>
        {
            // Der try ist hier kein Zierrat. Schlaegt das Erzeugen des
            // Hauptfensters fehl, wird es nie gezeigt - der Hinweis schliesst
            // sich trotzdem, es bleibt kein Fenster offen, und die
            // Standardregel (OnLastWindowClose) beendet die Anwendung. Fuer den
            // Nutzer sieht das aus, als beende ein Klick auf OK das Programm,
            // und zwar ohne jede Meldung.
            try
            {
                var mainWindow = CreateMainWindow();

                // MainWindow umhaengen, damit spaetere Dialoge das richtige
                // Besitzerfenster finden (AvaloniaDialogService liest es aus).
                desktop.MainWindow = mainWindow;
                mainWindow.Show();
            }
            catch (Exception ex)
            {
                ShowStartupFailure(desktop, ex);
            }
        };

        return notice;
    }

    /// <summary>
    /// Zeigt, woran der Start gescheitert ist - in einem eigenen Fenster, weil
    /// es zu diesem Zeitpunkt kein anderes mehr gibt.
    /// <para>
    /// Ohne dieses Fenster verschwindet die Anwendung wortlos, und der Fehler
    /// ist nur noch auf der Konsole zu sehen - die beim Doppelklick niemand
    /// offen hat. Der Text ist markierbar, damit er sich weiterreichen laesst.
    /// </para>
    /// </summary>
    private static void ShowStartupFailure(IClassicDesktopStyleApplicationLifetime desktop, Exception error)
    {
        var window = new global::Avalonia.Controls.Window
        {
            Title = "MyNetworkMonitor could not start",
            Width = 720,
            Height = 420,
            WindowStartupLocation = global::Avalonia.Controls.WindowStartupLocation.CenterScreen,
            Content = new global::Avalonia.Controls.ScrollViewer
            {
                Padding = new global::Avalonia.Thickness(16),
                Content = new global::Avalonia.Controls.SelectableTextBlock
                {
                    FontFamily = new global::Avalonia.Media.FontFamily("Consolas, Menlo, monospace"),
                    FontSize = 12,
                    TextWrapping = global::Avalonia.Media.TextWrapping.Wrap,
                    Text = "The main window could not be opened.\n\n" + error
                }
            }
        };

        desktop.MainWindow = window;
        window.Show();
    }
}
