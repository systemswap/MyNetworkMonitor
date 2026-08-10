using Avalonia;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using MyNetworkMonitor.Core.SatelliteLink;
using MyNetworkMonitor.Core.Services;
#if WINDOWS
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using MyNetworkMonitor.Platform.Windows;
#endif

namespace MyNetworkMonitor.Avalonia;

class Program
{
    /// <summary>
    /// Absturzprotokoll neben den Einstellungen. Ohne das laesst sich ein
    /// Fehler in einem Scan-Callback nicht diagnostizieren - die App wuerde
    /// kommentarlos beendet.
    /// </summary>
    private static readonly string CrashLog = Path.Combine(Path.GetTempPath(), "MyNetworkMonitor_crash.log");

    // Initialization code. Don't use any Avalonia, third-party APIs or any
    // SynchronizationContext-reliant code before AppMain is called: things aren't initialized
    // yet and stuff might break.
    [STAThread]
    public static void Main(string[] args)
    {
        AppDomain.CurrentDomain.UnhandledException += (_, e) => Log("UnhandledException", e.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, e) => Log("UnobservedTaskException", e.Exception);

        try
        {
            // Muss vor allem anderen stehen: davon haengt ab, wo Schluessel,
            // Listen und Einstellungen liegen.
            ApplyStateFolder(args);

            // Die drei Betriebsarten ohne Fenster stehen vor Avalonia: der
            // Dienst hat keine Oberflaeche, und die beiden Einrichtungslaeufe
            // sind nach einer Sekunde wieder vorbei. Wuerde erst Avalonia
            // hochfahren, blitzte bei jedem davon ein Fenster auf.
            if (HandledWithoutWindow(args)) return;

            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception ex)
        {
            Log("Main", ex);
            throw;
        }
    }

    /// <summary>
    /// Faengt die Aufrufe ab, die ohne Oberflaeche auskommen. Gibt zurueck, ob
    /// einer davon zutraf - dann ist die Arbeit schon getan.
    /// </summary>
    private static bool HandledWithoutWindow(string[] args)
    {
#if WINDOWS
        if (HasArgument(args, WindowsServiceControl.InstallArgument))
        {
            Environment.ExitCode = RunServiceSetup(install: true);
            return true;
        }

        if (HasArgument(args, WindowsServiceControl.UninstallArgument))
        {
            Environment.ExitCode = RunServiceSetup(install: false);
            return true;
        }

        if (HasArgument(args, WindowsServiceControl.SatelliteArgument))
        {
            RunAsService(args);
            return true;
        }
#endif
        return false;
    }

    private static bool HasArgument(string[] args, string name) =>
        args?.Any(a => string.Equals(a, name, StringComparison.OrdinalIgnoreCase)) == true;

    /// <summary>
    /// Wertet <c>--state &lt;Ordner&gt;</c> aus: diese Instanz legt Schluessel,
    /// Listen und Einstellungen dort ab statt an den ueblichen Orten.
    /// <para>
    /// Gedacht zum Ausprobieren auf einem einzigen Rechner - Hauptscanner in
    /// der einen Instanz, Satellit in der anderen. Ohne das teilten sich beide
    /// denselben Schluessel und damit denselben Fingerabdruck: die Freigabe
    /// waere eine Freigabe fuer sich selbst, und beide schrieben abwechselnd
    /// dieselben Dateien leer.
    /// </para>
    /// </summary>
    private static void ApplyStateFolder(string[] args)
    {
        if (args is null) return;

        for (int i = 0; i < args.Length - 1; i++)
        {
            if (!string.Equals(args[i], "--state", StringComparison.OrdinalIgnoreCase)) continue;

            AppPaths.UseOwnState(args[i + 1]);
            return;
        }
    }

#if WINDOWS
    /// <summary>
    /// Der erhoeht gestartete Durchlauf: richtet den Dienst ein oder entfernt
    /// ihn und beendet sich sofort wieder. Der Rueckgabewert ist das, was der
    /// aufrufende Durchlauf auswertet.
    /// </summary>
    private static int RunServiceSetup(bool install)
    {
        try
        {
            WindowsServiceControl control = new();

            ServiceChangeResult result = install
                ? control.InstallElevated(Environment.ProcessPath ?? string.Empty)
                : control.UninstallElevated();

            // In das Protokoll, weil dieser Durchlauf keine Oberflaeche hat:
            // der aufrufende sieht nur den Rueckgabewert und verweist fuer die
            // Einzelheiten hierher.
            Note($"Service {(install ? "setup" : "removal")}: {result.Message}");

            return result.Success ? 0 : 1;
        }
        catch (Exception ex)
        {
            Log("ServiceSetup", ex);
            return 1;
        }
    }

    /// <summary>
    /// Laeuft als Windows-Dienst: verbindet sich zu allen eingetragenen
    /// Hauptscannern und wartet auf Auftraege, bis die Dienstverwaltung ihn
    /// anhaelt.
    /// </summary>
    private static void RunAsService(string[] args)
    {
        SatelliteRuntime? runtime = null;

        try
        {
            PlatformRegistration.RegisterAll();

            runtime = new SatelliteRuntime(OwnVersion(), Path.Combine(AppPaths.MachineFolder, "services.xml"));

            // Ohne args: der Aufbau liest sonst die Befehlszeile als
            // Konfiguration, und "--satellite" ohne Wert ist fuer ihn kein
            // gueltiges Paar - der Dienst startete gar nicht erst.
            HostApplicationBuilder builder = Host.CreateApplicationBuilder();

            builder.Services.AddWindowsService(options =>
                options.ServiceName = WindowsServiceControl.ServiceName);

            IHost host = builder.Build();

            // Vor dem Lauf, damit die Verbindungen stehen, sobald die
            // Dienstverwaltung "gestartet" meldet. Der Aufruf kehrt sofort
            // zurueck - das Verbinden selbst laeuft im Hintergrund.
            runtime.Start();

            host.Run();
        }
        catch (Exception ex)
        {
            runtime?.Log($"The service stopped with an error: {ex}");
            Log("Service", ex);
        }
        finally
        {
            runtime?.Stop();
        }
    }

    private static string OwnVersion() =>
        System.Reflection.Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? string.Empty;
#endif

    /// <summary>Eine Zeile ins Protokoll, ohne dass etwas schiefging.</summary>
    private static void Note(string text)
    {
        try
        {
            File.AppendAllText(CrashLog, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {text}{Environment.NewLine}");
        }
        catch (Exception)
        {
            // Protokollieren darf nie selbst zum Problem werden
        }
    }

    private static void Log(string source, Exception? exception)
    {
        try
        {
            File.AppendAllText(CrashLog, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {source}: {exception}{Environment.NewLine}{Environment.NewLine}");
        }
        catch (Exception)
        {
            // Protokollieren darf nie selbst zum Problem werden
        }
    }

    // Avalonia configuration, don't remove; also used by visual designer.
    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
#if DEBUG
            .WithDeveloperTools()
#endif
            .WithInterFont()
            .LogToTrace();
}
