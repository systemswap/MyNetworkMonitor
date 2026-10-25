// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
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
    /// Crash log in the temporary folder. Without it, an error in a scan
    /// callback cannot be diagnosed: the application would exit without a word.
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
            // Must come before everything else: it determines where keys,
            // lists and settings are stored.
            ApplyStateFolder(args);

            // The three modes without a window come before Avalonia: the
            // service has no user interface, and the two setup runs end after
            // a second. If Avalonia started first, each of them would flash a
            // window.
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
    /// Handles the invocations that need no user interface.
    /// </summary>
    /// <returns>True if one of them applied; the work is then already done.</returns>
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
    /// Evaluates <c>--state &lt;folder&gt;</c>: this instance stores keys,
    /// lists and settings there instead of in the usual locations.
    /// <para>
    /// Intended for trying things out on a single machine: main scanner in one
    /// instance, satellite in the other. Without it, both would share the same
    /// key and therefore the same fingerprint: an approval would approve
    /// itself, and both would overwrite the same files in turn.
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
    /// The elevated run: installs or removes the service and exits right away.
    /// </summary>
    /// <param name="install">True to install, false to remove.</param>
    /// <returns>The exit code the calling process evaluates: 0 on success, 1 on failure.</returns>
    private static int RunServiceSetup(bool install)
    {
        try
        {
            WindowsServiceControl control = new();

            ServiceChangeResult result = install
                ? control.InstallElevated(Environment.ProcessPath ?? string.Empty)
                : control.UninstallElevated();

            // Written to the log because this run has no user interface: the
            // calling process only sees the exit code and refers to the log
            // for details.
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
    /// Runs as a Windows service: connects to all configured main scanners and
    /// waits for jobs until the Service Control Manager stops it.
    /// </summary>
    private static void RunAsService(string[] args)
    {
        SatelliteRuntime? runtime = null;

        try
        {
            PlatformRegistration.RegisterAll();

            runtime = new SatelliteRuntime(OwnVersion(), Path.Combine(AppPaths.MachineFolder, "services.xml"));

            // Without args: the builder would otherwise read the command line as
            // configuration, and "--satellite" without a value is not a valid
            // pair for it; the service would not start at all.
            HostApplicationBuilder builder = Host.CreateApplicationBuilder();

            builder.Services.AddWindowsService(options =>
                options.ServiceName = WindowsServiceControl.ServiceName);

            IHost host = builder.Build();

            // Before Run, so that the connections are up as soon as the Service
            // Control Manager reports "started". The call returns immediately;
            // connecting runs in the background.
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

    /// <summary>Writes an informational line to the log.</summary>
    private static void Note(string text)
    {
        try
        {
            File.AppendAllText(CrashLog, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {text}{Environment.NewLine}");
        }
        catch (Exception)
        {
            // Logging must never become a problem of its own.
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
            // Logging must never become a problem of its own.
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
