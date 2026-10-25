// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.ServiceProcess;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Platform.Windows
{
    /// <summary>
    /// Sets up the satellite service on Windows with <c>sc.exe</c>, with an
    /// elevation prompt of the operating system when rights are missing.
    /// <para>
    /// Why <c>sc.exe</c> and not the API: creating and removing are two calls
    /// that happen once per installation. The exit code of the program is
    /// sufficient information and needs no parsing, unlike the output of
    /// <c>sc query</c>, which is localized. For the <em>state</em>,
    /// <see cref="ServiceController"/> is used instead; it returns numbers
    /// rather than text.
    /// </para>
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class WindowsServiceControl : IServiceControl
    {
        /// <summary>The name under which the service is registered.</summary>
        public const string ServiceName = "MyNetworkMonitorSatellite";

        /// <summary>The name the Services console shows.</summary>
        public const string DisplayName = "MyNetworkMonitor Satellite";

        /// <summary>The argument with which the elevated application installs the service itself.</summary>
        public const string InstallArgument = "--install-service";

        /// <summary>The counterpart of <see cref="InstallArgument"/>: removes the service.</summary>
        public const string UninstallArgument = "--uninstall-service";

        /// <summary>The argument with which the service starts the application.</summary>
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

        // -------------------------------------------------------------- State

        public ServiceStatus Read()
        {
            try
            {
                using ServiceController controller = new(ServiceName);

                // Reading Status throws when the service does not exist; that is
                // the only reliable way to detect it.
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
                // Not registered: the normal case before setup.
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

        // -------------------------------------------------------------- Setup

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
        /// Actually creates the service. Must be called with elevated rights;
        /// public because the elevated run of the application enters here.
        /// </summary>
        /// <param name="executablePath">Path of the application the service starts.</param>
        /// <returns>Whether setup succeeded, with a message to display.</returns>
        public ServiceChangeResult InstallElevated(string executablePath)
        {
            // An existing entry is replaced rather than kept alongside: it might
            // point to an application that no longer exists, and nobody would
            // notice the difference.
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

            // Description and restart policy are secondary: if either fails,
            // the service still runs, and an error message about it would only
            // confuse.
            Run("sc.exe", "description", ServiceName,
                "Scans the local network segment on behalf of a MyNetworkMonitor main scanner.");

            // After a crash, retries after one minute, three times; the counter
            // resets daily. A satellite sits in a network cabinet where nobody
            // checks on it.
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

        /// <summary>Removes the service. Must be called with elevated rights.</summary>
        /// <returns>Whether removal succeeded, with a message to display.</returns>
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

        // ------------------------------------------------------- Start/Stop

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

        // ------------------------------------------------------------ Helpers

        /// <summary>
        /// Restarts the application elevated so that it performs the change
        /// itself, and waits for the outcome.
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
                // ERROR_CANCELLED: the elevation prompt was dismissed.
                // That is not an error but a decision.
                return new ServiceChangeResult(false, "Cancelled - the service needs administrator rights.");
            }
            catch (Exception ex)
            {
                return new ServiceChangeResult(false, ex.Message);
            }
        }

        /// <summary>
        /// Grants normal users write access to the machine-wide data folder.
        /// <para>
        /// Required because both sides write to it: the service as LocalSystem
        /// and the user interface as the logged-on account. If the service
        /// creates the folder first, the user interface could otherwise only
        /// read and could no longer save its host list.
        /// </para>
        /// </summary>
        private static void GrantUsersAccessToDataFolder()
        {
            try
            {
                string folder = AppPaths.EnsureMachineFolder();

                // Uses the well-known SID rather than the name "Users": the
                // name is localized (e.g. "Benutzer" on German Windows); icacls
                // accepts both, but the SID is valid everywhere.
                SecurityIdentifier users = new(WellKnownSidType.BuiltinUsersSid, null);

                Run("icacls.exe", folder, "/grant", $"*{users.Value}:(OI)(CI)M", "/T");
            }
            catch (Exception)
            {
                // If this fails, it shows when saving, which reports an error.
                // Failing the whole setup because of it would be
                // disproportionate.
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
