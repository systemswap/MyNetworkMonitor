using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Models;
using MyNetworkMonitor.Core.Scanning.Engine;
using MyNetworkMonitor.Core.ServiceLink;
using MyNetworkMonitor.Core.Services;
using MyNetworkMonitor.Core.ViewModels;

namespace MyNetworkMonitor.Core.SatelliteLink
{
    /// <summary>
    /// The satellite without a window: what the service runs.
    /// <para>
    /// It builds the same machinery as the user interface (engine, device
    /// store, <see cref="ShellViewModel"/>) and uses its job execution. This is
    /// deliberate: a separate scanning path would be a second truth, and a
    /// finding on the satellite would come about differently from the same
    /// finding produced by hand. Only the display is missing.
    /// </para>
    /// <para>
    /// See SATELLIT.md, section 9.
    /// </para>
    /// </summary>
    public sealed class SatelliteRuntime : IDisposable
    {
        private readonly string _appVersion;
        private readonly string _serviceXmlPath;
        private readonly string _logPath;

        private ShellViewModel? _shell;

        /// <summary>Creates the runtime; nothing starts before <see cref="Start"/>.</summary>
        /// <param name="appVersion">The own version, as the peer should see it.</param>
        /// <param name="serviceXmlPath">Path of the service definitions for service detection.</param>
        public SatelliteRuntime(string appVersion, string serviceXmlPath)
        {
            _appVersion = appVersion ?? string.Empty;
            _serviceXmlPath = serviceXmlPath ?? string.Empty;
            _logPath = Path.Combine(AppPaths.MachineFolder, "satellite.log");
        }

        /// <summary>Builds everything and connects to all main scanners.</summary>
        public void Start()
        {
            AppPaths.EnsureMachineFolder();

            // No user or machine name in the log (logs contain no personal data).
            // See docs/FEHLERGEDAECHTNIS.md, No. 13.
            Log($"Satellite starting, version {_appVersion}.");

            DeviceStore store = new();
            ScanEngine engine = ScanEngineFactory.Create(_serviceXmlPath);

            _shell = new ShellViewModel(engine, store);

            SatelliteEditorViewModel satellites = _shell.SatelliteEditor;

            satellites.SetAppVersion(_appVersion);

            // The service has no Documents folder to import settings from;
            // the empty path skips the import.
            satellites.Load(string.Empty);

            foreach (MainScanner host in satellites.Hosts)
            {
                host.PropertyChanged += (_, e) =>
                {
                    if (e.PropertyName == nameof(MainScanner.Status)) Log($"{host.Host}: {host.Status}");
                };
            }

            // The control pipe first, and always: especially when no main
            // scanner is configured yet, the window needs to see why nothing
            // happens. Opened only after the check below, the service would be
            // silent exactly when querying it matters most.
            StartControlPipe(satellites);

            if (satellites.Hosts.Count == 0)
            {
                Log("No main scanners configured yet. Add them in the window under Satellites - the service picks them up on request, without a restart.");
                return;
            }

            satellites.ConnectAllHosts();

            Log($"Connecting to {satellites.Hosts.Count(h => h.Enabled)} main scanner(s).");
        }

        /// <summary>
        /// Opens the control pipe through which the user interface watches.
        /// <para>
        /// Without it the service would be a black box: it works, but nobody
        /// sees for whom and how far; the only source would be the log.
        /// </para>
        /// </summary>
        private void StartControlPipe(SatelliteEditorViewModel satellites)
        {
            _pipe = new ServiceControlServer(
                () => new ServiceSnapshot
                {
                    OwnName = satellites.OwnName,
                    Version = _appVersion,
                    JobHost = satellites.LocalJobHost,
                    JobId = satellites.LocalJobId,
                    JobPercent = satellites.LocalJobPercent,
                    JobCurrent = satellites.LocalJobCurrent,
                    JobDone = satellites.LocalJobDone,
                    JobPending = satellites.LocalJobPending,
                    Hosts = [.. satellites.Hosts.Select(h => new ServiceHostState
                    {
                        Display = h.Display,
                        IsConnected = h.IsConnected,
                        IsApproved = h.IsApproved,
                        Status = h.Status
                    })]
                },
                command =>
                {
                    switch (command)
                    {
                        case ServiceMessageType.StopJob:
                            satellites.StopLocalJobCommand.Execute(null);
                            Log("Stop requested from the window.");
                            return "Stop sent to the running job.";

                        case ServiceMessageType.Reconnect:
                            satellites.Load(string.Empty);
                            satellites.ConnectAllHosts();
                            Log("Host list reloaded and reconnected, on request from the window.");
                            return $"Reloaded - connecting to {satellites.Hosts.Count(h => h.Enabled)} main scanner(s).";

                        default:
                            return $"Unknown request \"{command}\".";
                    }
                });

            _pipe.Failed += (_, text) => Log(text);
            _pipe.Start();

            Log("Control pipe open - the window can watch this service.");
        }

        private ServiceControlServer? _pipe;

        /// <summary>Closes the control pipe and all connections.</summary>
        public void Stop()
        {
            _pipe?.Stop();
            _shell?.SatelliteEditor.DisconnectAllHosts();
            Log("Satellite stopped.");
        }

        /// <summary>
        /// Writes a line to the log next to the data. A service has no console
        /// that anyone reads; without a file, every error would be invisible.
        /// </summary>
        /// <param name="text">The line to write, without personal data.</param>
        public void Log(string text)
        {
            try
            {
                File.AppendAllText(_logPath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {text}{Environment.NewLine}");
            }
            catch (Exception)
            {
                // Logging must never become a problem of its own.
            }
        }

        /// <summary>Same as <see cref="Stop"/>.</summary>
        public void Dispose() => Stop();
    }
}
