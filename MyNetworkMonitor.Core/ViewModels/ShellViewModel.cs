using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Scanning.Engine;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>Die Abschnitte der Navigationsleiste.</summary>
    public enum ShellSection
    {
        Devices,
        Network,
        Findings,
        Topology,
        Scopes,
        Ports,
        Services,
        Names,
        Settings
    }

    /// <summary>
    /// Ein Umfang im Kommandobalken: eine benannte Zusammenstellung von
    /// Verfahren. Deckt den haeufigsten Fall mit einem Klick ab, statt jedes
    /// Mal Kaestchen zu setzen.
    /// </summary>
    public sealed class ScanProfile
    {
        public required string Name { get; init; }
        public required string Description { get; init; }

        /// <summary>Leer bei "Angepasst" - dann bleibt die Auswahl, wie sie ist.</summary>
        public IReadOnlyList<string> MethodIds { get; init; } = [];

        public bool IsCustom => MethodIds.Count == 0;
    }

    /// <summary>
    /// Der Kommandobalken samt allem, was daran haengt: Bereichsauswahl,
    /// Umfang, Verfahren-Schublade, Start und Abbruch, Fortschritt und
    /// Statuszeile.
    /// <para>
    /// Loest die Scan-Steuerung aus dem Hauptfenster ab, wo sie bisher als
    /// Code-Behind lag. Plattformneutral - WPF wie Avalonia binden dagegen.
    /// </para>
    /// </summary>
    public partial class ShellViewModel : ObservableObject
    {
        private readonly ScanEngine _engine;
        private readonly DeviceStore _store;

        public ShellViewModel(ScanEngine engine, DeviceStore store)
        {
            _engine = engine ?? throw new ArgumentNullException(nameof(engine));
            _store = store ?? throw new ArgumentNullException(nameof(store));

            Devices = new DeviceListViewModel(store);

            foreach (IScanMethod method in _engine.Methods)
            {
                Methods.Add(new ScanMethodChoice { Method = method });
            }

            _engine.ProgressChanged += OnProgress;
            _engine.MethodFinished += OnMethodFinished;

            ApplyProfile(Profiles[1]); // Standard
        }

        public DeviceListViewModel Devices { get; }

        public ObservableCollection<ScanScope> Scopes { get; } = [];

        public ObservableCollection<ScanMethodChoice> Methods { get; } = [];

        /// <summary>Was die Engine zuletzt uebersprungen hat - fuer die Statuszeile.</summary>
        public ObservableCollection<ScanMethodOutcome> LastSkipped { get; } = [];

        public ScanSettings Settings { get; } = new();

        [ObservableProperty] private ShellSection _section = ShellSection.Devices;

        [ObservableProperty] private bool _isDrawerOpen;

        // ---------------------------------------------------------- Umfaenge

        public IReadOnlyList<ScanProfile> Profiles { get; } =
        [
            new ScanProfile
            {
                Name = "Schnell",
                Description = "Nur finden - wer ist da?",
                MethodIds = ["ping", "arp.request", "arp.cache"]
            },
            new ScanProfile
            {
                Name = "Standard",
                Description = "Finden und bestimmen, mit den ueblichen Diensten",
                MethodIds =
                [
                    "ping", "arp.request", "arp.cache", "ssdp", "mdns",
                    "dns.lookup", "dns.reverse", "snmp", "ports.tcp"
                ]
            },
            new ScanProfile
            {
                Name = "Gruendlich",
                Description = "Alles, was verfuegbar ist - dauert entsprechend",
                MethodIds =
                [
                    "ping", "arp.request", "arp.cache", "ssdp", "mdns",
                    "dns.lookup", "dns.reverse", "netbios", "snmp", "onvif",
                    "ports.tcp", "ports.udp", "smb.version", "services"
                ]
            },
            new ScanProfile
            {
                Name = "Angepasst",
                Description = "Die Auswahl in der Schublade gilt"
            }
        ];

        [ObservableProperty] private ScanProfile? _selectedProfile;

        /// <summary>
        /// Setzt die Verfahrensauswahl auf den Umfang. "Angepasst" laesst sie
        /// unberuehrt - sonst wuerde das Umschalten die eigene Auswahl loeschen.
        /// </summary>
        public void ApplyProfile(ScanProfile profile)
        {
            ArgumentNullException.ThrowIfNull(profile);
            SelectedProfile = profile;

            if (profile.IsCustom) return;

            foreach (ScanMethodChoice choice in Methods)
            {
                choice.IsSelected = choice.IsEnabled && profile.MethodIds.Contains(choice.Id);
            }

            OnPropertyChanged(nameof(SelectedMethodCount));
            OnPropertyChanged(nameof(CanStart));
        }

        // ------------------------------------------------------- Bereiche

        public IEnumerable<ScanScope> SelectedScopes => Scopes.Where(s => s.IsSelected);

        public int SelectedScopeCount => SelectedScopes.Count();

        public int SelectedMethodCount => Methods.Count(m => m.IsSelected);

        /// <summary>
        /// Zaehler und Schaetzung werden gemeinsam berechnet, weil beide
        /// dieselbe Aufloesung der Bereiche brauchen. Wird bei jeder Aenderung
        /// der Auswahl neu bestimmt, darum ohne Aufzaehlung der Adressen.
        /// </summary>
        private (long Count, bool IsEstimate) CountTargets()
        {
            long total = 0;
            bool estimate = false;

            foreach (ScopeRuntime runtime in _lastRuntimes)
            {
                total += ScopeRuntimeFactory.CountTargets(runtime, out bool est);
                if (est) estimate = true;
            }

            return (total, estimate);
        }

        private List<ScopeRuntime> _lastRuntimes = [];

        /// <summary>Summe der Ziele ueber alle gewaehlten Bereiche.</summary>
        public long TargetCount => CountTargets().Count;

        /// <summary>Mindestens ein Bereich liefert nur eine Schaetzung.</summary>
        public bool TargetCountIsEstimate => CountTargets().IsEstimate;

        /// <summary>
        /// Grobe Dauerschaetzung fuer den Kommandobalken. Bewusst einfach
        /// gehalten - sie soll die Groessenordnung zeigen, damit niemand
        /// versehentlich einen Lauf ueber Stunden anstoesst.
        /// </summary>
        public TimeSpan EstimatedDuration
        {
            get
            {
                long targets = TargetCount;
                if (targets == 0) return TimeSpan.Zero;

                int methods = Math.Max(1, Methods.Count(m => m.IsSelected && !m.IsPassive));

                // Erfahrungswert: rund 40 Ziele je Sekunde und Verfahren,
                // weil parallel gearbeitet wird.
                double seconds = targets * methods / 40.0;
                return TimeSpan.FromSeconds(Math.Max(1, seconds));
            }
        }

        public bool CanStart => !IsRunning && SelectedScopeCount > 0 && SelectedMethodCount > 0;

        /// <summary>
        /// Nach jeder Aenderung an der Bereichsauswahl aufrufen: bestimmt die
        /// Verfuegbarkeit aller Verfahren neu und aktualisiert die Zaehler.
        /// </summary>
        public void RefreshAvailability()
        {
            _lastRuntimes = ScopeRuntimeFactory.Build([.. SelectedScopes]);

            ScanContext probe = BuildProbeContext();

            foreach (ScanMethodChoice choice in Methods)
            {
                choice.Availability = choice.Method.CheckAvailability(probe);
            }

            OnPropertyChanged(nameof(SelectedScopeCount));
            OnPropertyChanged(nameof(SelectedMethodCount));
            OnPropertyChanged(nameof(TargetCount));
            OnPropertyChanged(nameof(TargetCountIsEstimate));
            OnPropertyChanged(nameof(EstimatedDuration));
            OnPropertyChanged(nameof(CanStart));
            OnPropertyChanged(nameof(ScopeSummary));
        }

        /// <summary>Kurztext der Bereichsauswahl fuer den Kommandobalken.</summary>
        public string ScopeSummary
        {
            get
            {
                int count = SelectedScopeCount;
                if (count == 0) return "Kein Bereich";

                string targets = TargetCountIsEstimate ? $"ca. {TargetCount}" : TargetCount.ToString();

                return count == 1
                    ? $"{SelectedScopes.First().GroupDescription} · {targets} Ziele"
                    : $"{count} Bereiche · {targets} Ziele";
            }
        }

        // --------------------------------------------------------- Fortschritt

        [ObservableProperty] private bool _isRunning;
        [ObservableProperty] private string _currentMethodName = string.Empty;
        [ObservableProperty] private int _progressCurrent;
        [ObservableProperty] private int _progressTotal;
        [ObservableProperty] private int _progressResponded;
        [ObservableProperty] private string _statusText = "Bereit.";

        public double ProgressFraction =>
            ProgressTotal <= 0 ? 0 : Math.Clamp((double)ProgressCurrent / ProgressTotal, 0, 1);

        private void OnProgress(ScanProgress progress)
        {
            CurrentMethodName = progress.MethodName;
            ProgressCurrent = progress.Current;
            ProgressTotal = progress.Total;
            ProgressResponded = progress.Responded;
            OnPropertyChanged(nameof(ProgressFraction));
        }

        private void OnMethodFinished(ScanMethodOutcome outcome)
        {
            if (outcome.State != ScanMethodState.Available || outcome.Error is not null)
            {
                LastSkipped.Add(outcome);
            }
        }

        // -------------------------------------------------------------- Start

        [RelayCommand]
        private async Task StartAsync()
        {
            if (!CanStart) return;

            IsRunning = true;
            OnPropertyChanged(nameof(CanStart));
            LastSkipped.Clear();
            StatusText = "Scan laeuft...";

            List<ScanScope> scopes = [.. SelectedScopes];
            List<string> methods = [.. Methods.Where(m => m.IsSelected).Select(m => m.Id)];

            try
            {
                // Waehrend des Laufs die Neuberechnung der Liste aussetzen -
                // sonst wird sie bei jeder einzelnen Meldung neu sortiert.
                using (Devices.SuspendRefresh())
                {
                    ScanRunResult result = await _engine.RunAsync(scopes, methods, Settings, _store);
                    StatusText = Describe(result);
                }
            }
            catch (Exception ex)
            {
                StatusText = $"Scan fehlgeschlagen: {ex.Message}";
            }
            finally
            {
                IsRunning = false;
                CurrentMethodName = string.Empty;
                ProgressCurrent = ProgressTotal = 0;
                OnPropertyChanged(nameof(ProgressFraction));
                OnPropertyChanged(nameof(CanStart));
            }
        }

        [RelayCommand]
        private void Stop()
        {
            _engine.Stop();
            StatusText = "Wird abgebrochen...";
        }

        [RelayCommand]
        private void ClearResults()
        {
            _store.Clear();
            Devices.Refresh();
            StatusText = "Tabelle geleert.";
        }

        /// <summary>
        /// Fasst den Lauf in einem Satz zusammen. Uebersprungene Verfahren
        /// werden genannt, nicht verschwiegen - sonst wundert man sich, warum
        /// Ergebnisse fehlen.
        /// </summary>
        private string Describe(ScanRunResult result)
        {
            if (result.WasCancelled)
            {
                return $"Abgebrochen nach {result.Duration.TotalSeconds:F0} s. " +
                       $"{_store.Devices.Count} Geraete bis dahin gefunden.";
            }

            string summary =
                $"{_store.Devices.Count} Geraete in {result.Duration.TotalSeconds:F0} s " +
                $"({result.TargetCount} Ziele).";

            int skipped = result.Skipped.Count();
            if (skipped > 0) summary += $" {skipped} Verfahren uebersprungen.";

            int failed = result.Failed.Count();
            if (failed > 0) summary += $" {failed} fehlgeschlagen.";

            return summary;
        }

        /// <summary>
        /// Ein Kontext ohne Ziele, nur zur Verfuegbarkeitspruefung. Die
        /// Bereiche stehen darin vollstaendig - daran haengt die
        /// IPv6-Beurteilung -, die Zielaufzaehlung waere hier aber
        /// verschwendet, weil sie bei jedem Haken neu liefe.
        /// </summary>
        private ScanContext BuildProbeContext()
        {
            // Ein einzelnes Ziel je Bereich genuegt, damit die Verfahren die
            // vorhandenen Adressfamilien erkennen.
            List<ScanTargetEntry> sample = [];
            List<ScopeRuntime> runtimes = _lastRuntimes;

            foreach (ScopeRuntime runtime in runtimes)
            {
                sample.AddRange(ScopeRuntimeFactory.SampleTargets(runtime));
            }

            return new ScanContext
            {
                Scopes = runtimes,
                Targets = sample,
                Settings = Settings,
                Store = _store,
                Report = _ => { },
                ReportProgress = (_, _, _) => { }
            };
        }
    }
}
