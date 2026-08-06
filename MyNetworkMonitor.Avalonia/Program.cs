using Avalonia;
using System;
using System.IO;
using System.Threading.Tasks;

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
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception ex)
        {
            Log("Main", ex);
            throw;
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
