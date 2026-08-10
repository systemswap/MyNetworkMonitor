using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Models;
using MyNetworkMonitor.Core.Scanning.Engine;
using MyNetworkMonitor.Core.ServiceLink;
using MyNetworkMonitor.Core.Services;
using MyNetworkMonitor.Core.ViewModels;

namespace MyNetworkMonitor.Core.SatelliteLink
{
    /// <summary>
    /// Der Satellit ohne Fenster - das, was der Dienst ausfuehrt.
    /// <para>
    /// Er baut dieselbe Maschinerie auf wie die Oberflaeche (Engine, Bestand,
    /// <see cref="ShellViewModel"/>) und benutzt deren Auftragsausfuehrung. Das
    /// ist Absicht: ein zweiter, eigener Weg zum Scannen waere eine zweite
    /// Wirklichkeit, und ein Befund am Satelliten kaeme anders zustande als
    /// derselbe Befund von Hand. Was fehlt, ist nur die Anzeige.
    /// </para>
    /// <para>
    /// Siehe SATELLIT.md, Abschnitt 9.
    /// </para>
    /// </summary>
    public sealed class SatelliteRuntime : IDisposable
    {
        private readonly string _appVersion;
        private readonly string _serviceXmlPath;
        private readonly string _logPath;

        private ShellViewModel? _shell;

        /// <param name="appVersion">Die eigene Version, wie die Gegenstelle sie sehen soll.</param>
        /// <param name="serviceXmlPath">Die Dienstdefinitionen fuer die Diensterkennung.</param>
        public SatelliteRuntime(string appVersion, string serviceXmlPath)
        {
            _appVersion = appVersion ?? string.Empty;
            _serviceXmlPath = serviceXmlPath ?? string.Empty;
            _logPath = Path.Combine(AppPaths.MachineFolder, "satellite.log");
        }

        /// <summary>Baut alles auf und verbindet sich zu allen Empfaengern.</summary>
        public void Start()
        {
            AppPaths.EnsureMachineFolder();

            Log($"Satellite starting, version {_appVersion}, as {Environment.UserName} on {Environment.MachineName}.");

            DeviceStore store = new();
            ScanEngine engine = ScanEngineFactory.Create(_serviceXmlPath);

            _shell = new ShellViewModel(engine, store);

            SatelliteEditorViewModel satellites = _shell.SatelliteEditor;

            satellites.SetAppVersion(_appVersion);

            // Der Dienst hat kein Dokumente-Verzeichnis, aus dem etwas zu
            // uebernehmen waere - der leere Pfad ueberspringt die Uebernahme.
            satellites.Load(string.Empty);

            foreach (MainScanner host in satellites.Hosts)
            {
                host.PropertyChanged += (_, e) =>
                {
                    if (e.PropertyName == nameof(MainScanner.Status)) Log($"{host.Host}: {host.Status}");
                };
            }

            // Die Steuerpipe zuerst, und in jedem Fall: gerade wenn noch kein
            // Empfaenger eingetragen ist, will das Fenster nachsehen koennen,
            // warum nichts passiert. Ginge sie erst nach der Pruefung unten
            // auf, waere der Dienst genau dann stumm, wenn man ihn am
            // dringendsten befragen moechte.
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
        /// Macht die Steuerpipe auf, ueber die die Oberflaeche zusieht.
        /// <para>
        /// Ohne sie waere der Dienst eine Blackbox: er arbeitet, aber niemand
        /// sieht fuer wen und wie weit - man muesste im Protokoll nachlesen.
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

        /// <summary>Legt alle Verbindungen ab.</summary>
        public void Stop()
        {
            _pipe?.Stop();
            _shell?.SatelliteEditor.DisconnectAllHosts();
            Log("Satellite stopped.");
        }

        /// <summary>
        /// Schreibt eine Zeile in das Protokoll neben den Daten. Ein Dienst hat
        /// keine Konsole, an der jemand mitliest - ohne Datei waere jeder
        /// Fehler unsichtbar.
        /// </summary>
        public void Log(string text)
        {
            try
            {
                File.AppendAllText(_logPath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {text}{Environment.NewLine}");
            }
            catch (Exception)
            {
                // Protokollieren darf nie selbst zum Problem werden.
            }
        }

        public void Dispose() => Stop();
    }
}
