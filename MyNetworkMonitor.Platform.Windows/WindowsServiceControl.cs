using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.ServiceProcess;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Platform.Windows
{
    /// <summary>
    /// Richtet den Satellitendienst unter Windows ein - ueber <c>sc.exe</c>,
    /// mit einer Rueckfrage des Betriebssystems, wenn die Rechte fehlen.
    /// <para>
    /// Warum <c>sc.exe</c> und nicht die API: Anlegen und Entfernen sind zwei
    /// Aufrufe, die genau einmal je Anlage vorkommen. Der Rueckgabewert des
    /// Programms genuegt als Auskunft, und es ist nichts zu uebersetzen - im
    /// Gegensatz zur Ausgabe von <c>sc query</c>, die auf einem deutschen
    /// Windows deutsch ist. Fuer den <em>Zustand</em> wird darum
    /// <see cref="ServiceController"/> benutzt, der liefert Zahlen statt Text.
    /// </para>
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class WindowsServiceControl : IServiceControl
    {
        /// <summary>Der Name, unter dem der Dienst eingetragen wird.</summary>
        public const string ServiceName = "MyNetworkMonitorSatellite";

        /// <summary>Der Name, den die Dienstverwaltung anzeigt.</summary>
        public const string DisplayName = "MyNetworkMonitor Satellite";

        /// <summary>Das Argument, mit dem sich die Anwendung erhoeht selbst einrichtet.</summary>
        public const string InstallArgument = "--install-service";

        /// <summary>Das Gegenstueck zum Einrichten.</summary>
        public const string UninstallArgument = "--uninstall-service";

        /// <summary>Das Argument, mit dem der Dienst die Anwendung startet.</summary>
        public const string SatelliteArgument = "--satellite";

        public bool IsSupported => true;

        public bool IsElevated
        {
            get
            {
                try
                {
                    using WindowsIdentity identity = WindowsIdentity.GetCurrent();
                    return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
                }
                catch (Exception)
                {
                    return false;
                }
            }
        }

        // ------------------------------------------------------------ Zustand

        public ServiceStatus Read()
        {
            try
            {
                using ServiceController controller = new(ServiceName);

                // Der Zugriff auf Status wirft, wenn es den Dienst nicht gibt -
                // das ist der einzige verlaessliche Weg, ihn zu erkennen.
                ServiceControllerStatus status = controller.Status;

                bool running = status is ServiceControllerStatus.Running
                                      or ServiceControllerStatus.StartPending
                                      or ServiceControllerStatus.ContinuePending;

                bool auto = controller.StartType == ServiceStartMode.Automatic;

                return new ServiceStatus(
                    running ? ServiceState.Running : ServiceState.Stopped,
                    running
                        ? auto
                            ? "The service is running and starts with the system."
                            : "The service is running, but it does not start with the system."
                        : "The service is set up but not running.",
                    auto);
            }
            catch (InvalidOperationException)
            {
                // Nicht eingetragen - der Normalfall vor der Einrichtung.
                return new ServiceStatus(
                    ServiceState.NotInstalled,
                    "No service set up. This machine is a satellite only while this window is open.",
                    false);
            }
            catch (Exception ex)
            {
                return new ServiceStatus(ServiceState.Unknown, $"The service state could not be read: {ex.Message}", false);
            }
        }

        // --------------------------------------------------- Einrichten

        public ServiceChangeResult Install(string executablePath)
        {
            if (string.IsNullOrWhiteSpace(executablePath) || !File.Exists(executablePath))
            {
                return new ServiceChangeResult(false, $"The application was not found at \"{executablePath}\".");
            }

            if (!IsElevated) return Elevate(executablePath, InstallArgument, "set up");

            return InstallElevated(executablePath);
        }

        /// <summary>
        /// Legt den Dienst tatsaechlich an. Nur mit erhoehten Rechten
        /// aufzurufen - oeffentlich, weil der erhoeht gestartete Durchlauf der
        /// Anwendung genau hier hereinkommt.
        /// </summary>
        public ServiceChangeResult InstallElevated(string executablePath)
        {
            // Ein vorhandener Eintrag wird ersetzt statt danebengelegt: sonst
            // zeigte der alte womoeglich auf eine Anwendung, die nicht mehr da
            // ist, und niemand saehe den Unterschied.
            if (Read().IsInstalled) RemoveService();

            (int code, string output) = Run("sc.exe",
                "create", ServiceName,
                "binPath=", $"\"{executablePath}\" {SatelliteArgument}",
                "start=", "auto",
                "DisplayName=", DisplayName);

            if (code != 0)
            {
                return new ServiceChangeResult(false, $"The service could not be created: {output.Trim()}");
            }

            // Beschreibung und Wiederanlauf sind Beiwerk - schlaegt eines fehl,
            // laeuft der Dienst trotzdem, und eine Fehlermeldung darueber waere
            // nur verwirrend.
            Run("sc.exe", "description", ServiceName,
                "Scans the local network segment on behalf of a MyNetworkMonitor main scanner.");

            // Nach einem Absturz nach einer Minute erneut versuchen, dreimal,
            // und der Zaehler faellt taeglich zurueck. Ein Satellit steht in
            // einem Schaltschrank - niemand sieht dort nach.
            Run("sc.exe", "failure", ServiceName,
                "reset=", "86400",
                "actions=", "restart/60000/restart/60000/restart/60000");

            GrantUsersAccessToDataFolder();

            ServiceChangeResult started = StartElevated();

            return started.Success
                ? new ServiceChangeResult(true, "The service is set up, running, and starts with the system.")
                : new ServiceChangeResult(true, $"The service is set up, but it did not start: {started.Message}");
        }

        public ServiceChangeResult Uninstall()
        {
            if (!Read().IsInstalled) return new ServiceChangeResult(true, "No service was set up.");

            if (!IsElevated)
            {
                return Elevate(Environment.ProcessPath ?? string.Empty, UninstallArgument, "removed");
            }

            return UninstallElevated();
        }

        /// <summary>Entfernt den Dienst. Nur mit erhoehten Rechten aufzurufen.</summary>
        public ServiceChangeResult UninstallElevated()
        {
            (int code, string output) = RemoveService();

            return code == 0
                ? new ServiceChangeResult(true, "The service was removed.")
                : new ServiceChangeResult(false, $"The service could not be removed: {output.Trim()}");
        }

        private (int Code, string Output) RemoveService()
        {
            StopElevated();
            return Run("sc.exe", "delete", ServiceName);
        }

        // ------------------------------------------------------ Starten/Halten

        public ServiceChangeResult Start()
        {
            if (!Read().IsInstalled) return new ServiceChangeResult(false, "No service is set up.");
            if (!IsElevated) return new ServiceChangeResult(false, "Starting the service needs administrator rights.");

            return StartElevated();
        }

        private ServiceChangeResult StartElevated()
        {
            try
            {
                using ServiceController controller = new(ServiceName);

                if (controller.Status == ServiceControllerStatus.Running)
                {
                    return new ServiceChangeResult(true, "The service is already running.");
                }

                controller.Start();
                controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));

                return new ServiceChangeResult(true, "The service is running.");
            }
            catch (Exception ex)
            {
                return new ServiceChangeResult(false, ex.Message);
            }
        }

        public ServiceChangeResult Stop()
        {
            if (!Read().IsRunning) return new ServiceChangeResult(true, "The service is not running.");
            if (!IsElevated) return new ServiceChangeResult(false, "Stopping the service needs administrator rights.");

            return StopElevated();
        }

        private ServiceChangeResult StopElevated()
        {
            try
            {
                using ServiceController controller = new(ServiceName);

                if (controller.Status == ServiceControllerStatus.Stopped)
                {
                    return new ServiceChangeResult(true, "The service is not running.");
                }

                controller.Stop();
                controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));

                return new ServiceChangeResult(true, "The service was stopped.");
            }
            catch (Exception ex)
            {
                return new ServiceChangeResult(false, ex.Message);
            }
        }

        // --------------------------------------------------------- Werkzeug

        /// <summary>
        /// Startet die Anwendung erhoeht neu, damit sie den Eingriff selbst
        /// vornimmt, und wartet ab, wie es ausging.
        /// </summary>
        private static ServiceChangeResult Elevate(string executablePath, string argument, string what)
        {
            try
            {
                ProcessStartInfo info = new()
                {
                    FileName = executablePath,
                    UseShellExecute = true,
                    Verb = "runas"
                };

                info.ArgumentList.Add(argument);

                using Process? process = Process.Start(info);
                if (process is null) return new ServiceChangeResult(false, "The elevated run could not be started.");

                process.WaitForExit(120_000);

                return process.HasExited && process.ExitCode == 0
                    ? new ServiceChangeResult(true, $"The service was {what}.")
                    : new ServiceChangeResult(false, $"The service could not be {what} - see the log next to the settings.");
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                // ERROR_CANCELLED - der Nutzer hat die Rueckfrage weggeklickt.
                // Das ist kein Fehler, sondern eine Entscheidung.
                return new ServiceChangeResult(false, "Cancelled - the service needs administrator rights.");
            }
            catch (Exception ex)
            {
                return new ServiceChangeResult(false, ex.Message);
            }
        }

        /// <summary>
        /// Gibt den maschinenweiten Datenordner fuer normale Benutzer frei.
        /// <para>
        /// Noetig, weil beide Seiten hineinschreiben: der Dienst als
        /// LocalSystem und die Oberflaeche als angemeldeter Nutzer. Legt der
        /// Dienst den Ordner zuerst an, duerfte der Nutzer sonst nur lesen und
        /// koennte seine Hostliste nicht mehr speichern.
        /// </para>
        /// </summary>
        private static void GrantUsersAccessToDataFolder()
        {
            try
            {
                string folder = AppPaths.EnsureMachineFolder();

                // Ueber die bekannte Kennung und nicht ueber den Namen
                // "Users" - der heisst auf einem deutschen Windows
                // "Benutzer", und icacls nimmt beides, aber die Kennung
                // stimmt ueberall.
                SecurityIdentifier users = new(WellKnownSidType.BuiltinUsersSid, null);

                Run("icacls.exe", folder, "/grant", $"*{users.Value}:(OI)(CI)M", "/T");
            }
            catch (Exception)
            {
                // Klappt es nicht, faellt es beim Speichern auf - dort gibt es
                // eine Meldung. Die Einrichtung daran scheitern zu lassen waere
                // unverhaeltnismaessig.
            }
        }

        private static (int Code, string Output) Run(string fileName, params string[] arguments)
        {
            try
            {
                ProcessStartInfo info = new()
                {
                    FileName = fileName,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                foreach (string argument in arguments) info.ArgumentList.Add(argument);

                using Process? process = Process.Start(info);
                if (process is null) return (-1, $"{fileName} could not be started.");

                string output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
                process.WaitForExit(60_000);

                return (process.HasExited ? process.ExitCode : -1, output);
            }
            catch (Exception ex)
            {
                return (-1, ex.Message);
            }
        }
    }
}
