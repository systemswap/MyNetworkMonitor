using System.Collections.ObjectModel;
using System.ComponentModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Persistence;
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
            ScopeEditor = new ScopeEditorViewModel(Scopes);
            PortEditor = new PortEditorViewModel(Settings);
            ServiceEditor = new ServiceEditorViewModel();
            NetworkView = new NetworkViewModel();

            // Ein Haken im Kommandobalken und eine Aenderung in der Verwaltung
            // treffen dieselbe Liste - die Zaehler muessen in beiden Faellen neu.
            ScopeEditor.SelectionChanged += RefreshAvailability;

            foreach (IScanMethod method in _engine.Methods)
            {
                Methods.Add(new ScanMethodChoice { Method = method });
            }

            _engine.ProgressChanged += OnProgress;
            _engine.MethodFinished += OnMethodFinished;

            ApplyProfile(Profiles[1]); // Standard
        }

        public DeviceListViewModel Devices { get; }

        /// <summary>Die Verwaltung der Bereiche - arbeitet auf <see cref="Scopes"/>.</summary>
        public ScopeEditorViewModel ScopeEditor { get; }

        /// <summary>Die Portsammlung. Traegt ihre Auswahl in <see cref="Settings"/> ein.</summary>
        public PortEditorViewModel PortEditor { get; }

        /// <summary>Welcher Dienst auf welchen Ports gesucht wird.</summary>
        public ServiceEditorViewModel ServiceEditor { get; }

        /// <summary>Die Adapter dieses Rechners samt ihrer Namensserver.</summary>
        public NetworkViewModel NetworkView { get; }

        public ObservableCollection<ScanScope> Scopes { get; } = [];

        public ObservableCollection<ScanMethodChoice> Methods { get; } = [];

        /// <summary>
        /// Die Verfahren, die sich auf die bekannten Geraete beschraenken
        /// lassen. Wer keine Zielliste hat, steht hier nicht - ein Kaestchen
        /// ohne Wirkung waere schlimmer als keines.
        /// </summary>
        public IEnumerable<ScanMethodChoice> RestrictableMethods =>
            Methods.Where(m => m.CanRestrictToKnown);

        /// <summary>Was die Engine zuletzt uebersprungen hat - fuer die Statuszeile.</summary>
        public ObservableCollection<ScanMethodOutcome> LastSkipped { get; } = [];

        public ScanSettings Settings { get; } = new();

        // ------------------------------------------------------ Einstellungen

        private UserSettings? _userSettings;

        /// <summary>Wo die Einstellungsdateien liegen - fuer die Anzeige und den Ordnerknopf.</summary>
        [ObservableProperty] private string _settingsFolder = string.Empty;

        /// <summary>Wo die Anwendung selbst liegt.</summary>
        public string ApplicationFolder => AppContext.BaseDirectory;

        /// <summary>
        /// Bindet die Einstellungen an die Ablage: liest den gespeicherten
        /// Stand und schreibt jede Aenderung sofort zurueck.
        /// <para>
        /// Sofort statt beim Schliessen, weil die Anwendung auch abstuerzen
        /// oder abgeschossen werden kann - ein Schieberegler, den man dreimal
        /// nachstellt, weil er sich nichts merkt, ist aergerlicher als ein
        /// Dateizugriff je Klick auf eine Datei mit sechs Zeilen.
        /// </para>
        /// </summary>
        public void AttachSettings(string settingsFolder)
        {
            SettingsFolder = settingsFolder;
            _userSettings = new UserSettings(settingsFolder);

            Settings.PortTimeoutMs = _userSettings.GetInt("PortTimeoutMs", Settings.PortTimeoutMs);
            Settings.ScanAllPorts = _userSettings.GetBool("ScanAllPorts", Settings.ScanAllPorts);
            Settings.OnlyKnownTargets = _userSettings.GetBool("OnlyKnownTargets", Settings.OnlyKnownTargets);
            Settings.ClearArpCacheFirst = _userSettings.GetBool("ClearArpCacheFirst", Settings.ClearArpCacheFirst);
            Settings.OverrideDnsServer = _userSettings.GetString("OverrideDnsServer");
            Settings.UseOnlineTopologyLibrary =
                _userSettings.GetBool("UseOnlineTopologyLibrary", Settings.UseOnlineTopologyLibrary);

            SaveLastScanResult = _userSettings.GetBool("SaveLastScanResult", true);

            // Welche Verfahren nur die bekannten Geraete abfragen sollen. Als
            // eine Zeile gespeichert - eine Einstellung je Verfahren waere
            // dieselbe Angabe, nur unuebersichtlicher.
            foreach (string id in (_userSettings.GetString("OnlyKnownTargetsFor") ?? string.Empty)
                         .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                Settings.OnlyKnownTargetsFor.Add(id);
            }

            foreach (ScanMethodChoice method in Methods)
            {
                method.OnlyKnownTargets = Settings.OnlyKnownTargetsFor.Contains(method.Id);
                method.PropertyChanged += OnMethodRestrictionChanged;
            }

            if (SaveLastScanResult) LoadLastScanResult();

            Settings.PropertyChanged += (_, e) =>
            {
                switch (e.PropertyName)
                {
                    case nameof(ScanSettings.PortTimeoutMs):
                        _userSettings.SetInt("PortTimeoutMs", Settings.PortTimeoutMs);
                        break;
                    case nameof(ScanSettings.ScanAllPorts):
                        _userSettings.SetBool("ScanAllPorts", Settings.ScanAllPorts);
                        RefreshAvailability(); // schaltet "TCP-Ports" frei bzw. sperrt es
                        break;
                    case nameof(ScanSettings.OnlyKnownTargets):
                        _userSettings.SetBool("OnlyKnownTargets", Settings.OnlyKnownTargets);
                        break;
                    case nameof(ScanSettings.ClearArpCacheFirst):
                        _userSettings.SetBool("ClearArpCacheFirst", Settings.ClearArpCacheFirst);
                        break;
                    case nameof(ScanSettings.OverrideDnsServer):
                        _userSettings.SetString("OverrideDnsServer", Settings.OverrideDnsServer);
                        break;
                    case nameof(ScanSettings.UseOnlineTopologyLibrary):
                        _userSettings.SetBool("UseOnlineTopologyLibrary", Settings.UseOnlineTopologyLibrary);
                        break;
                }
            };
        }

        /// <summary>
        /// Den Bestand beim Beenden sichern und beim Start wieder laden.
        /// </summary>
        [ObservableProperty] private bool _saveLastScanResult = true;

        partial void OnSaveLastScanResultChanged(bool value) =>
            _userSettings?.SetBool("SaveLastScanResult", value);

        /// <summary>Wo der letzte Bestand liegt.</summary>
        public string LastScanResultPath =>
            Path.Combine(SettingsFolder ?? string.Empty, DeviceStoreFile.DefaultFileName);

        /// <summary>
        /// Traegt die Beschraenkung eines Verfahrens in die Einstellungen ein.
        /// Die Menge ist die Wahrheit; die Kaestchen sind nur ihre Anzeige.
        /// </summary>
        private void OnMethodRestrictionChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName != nameof(ScanMethodChoice.OnlyKnownTargets)) return;
            if (sender is not ScanMethodChoice choice) return;

            if (choice.OnlyKnownTargets) Settings.OnlyKnownTargetsFor.Add(choice.Id);
            else Settings.OnlyKnownTargetsFor.Remove(choice.Id);

            _userSettings?.SetString("OnlyKnownTargetsFor", string.Join(",", Settings.OnlyKnownTargetsFor));
        }

        /// <summary>
        /// Liest den zuletzt gesicherten Bestand. Ohne Datei bleibt es bei der
        /// leeren Liste - das ist kein Fehler, sondern der erste Start.
        /// </summary>
        public void LoadLastScanResult()
        {
            if (string.IsNullOrEmpty(SettingsFolder)) return;

            int count = DeviceStoreFile.Load(_store, LastScanResultPath);
            if (count == 0) return;

            Devices.Refresh();
            StatusText = $"{count} devices from the last scan. Nothing has been checked yet.";
        }

        /// <summary>
        /// Sichert den Bestand. Wird beim Schliessen des Fensters gerufen -
        /// ein Fehler darf das Beenden nicht aufhalten, darum meldet die
        /// Methode nur, ob es geklappt hat.
        /// </summary>
        public bool SaveLastScanResultNow()
        {
            if (!SaveLastScanResult || string.IsNullOrEmpty(SettingsFolder)) return false;

            return DeviceStoreFile.Save(_store, LastScanResultPath);
        }

        [ObservableProperty] private ShellSection _section = ShellSection.Devices;

        [ObservableProperty] private bool _isDrawerOpen;

        // ---------------------------------------------------------- Umfaenge

        public IReadOnlyList<ScanProfile> Profiles { get; } =
        [
            new ScanProfile
            {
                Name = "Quick",
                Description = "Discovery only - who is there?",
                MethodIds = ["ping", "arp.request", "arp.cache"]
            },
            new ScanProfile
            {
                Name = "Standard",
                Description = "Discover and identify, with the usual services",
                MethodIds =
                [
                    "ping", "arp.request", "arp.cache", "ssdp", "mdns",
                    "dns.lookup", "dns.reverse", "snmp", "ports.tcp"
                ]
            },
            new ScanProfile
            {
                Name = "Thorough",
                Description = "Everything available - takes accordingly long",
                MethodIds =
                [
                    "ping", "arp.request", "arp.cache", "ssdp", "mdns",
                    "dns.lookup", "dns.reverse", "netbios", "snmp", "onvif",
                    "ports.tcp", "ports.udp", "smb.version", "services"
                ]
            },
            new ScanProfile
            {
                Name = "Custom",
                Description = "Whatever is ticked in the drawer"
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

        /// <summary>
        /// Von Hand eingetragene Ziele. Damit laesst sich etwas nachsehen, ohne
        /// erst einen Bereich anzulegen - der haeufigste Grund, die Verwaltung
        /// ueberhaupt zu oeffnen. Wirkt zusaetzlich zu den angehakten
        /// Bereichen; ist keiner angehakt, ist das hier die ganze Auswahl.
        /// </summary>
        [ObservableProperty] private string _customTargets = string.Empty;

        /// <summary>Der aus <see cref="CustomTargets"/> gelesene Bereich, falls gueltig.</summary>
        public ScanScope? CustomScope { get; private set; }

        /// <summary>Was an der Eingabe nicht stimmt - leer, wenn sie taugt.</summary>
        [ObservableProperty] private string _customTargetsProblem = string.Empty;

        partial void OnCustomTargetsChanged(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                CustomScope = null;
                CustomTargetsProblem = string.Empty;
            }
            else if (ScanScope.TryParseCustom(value, out ScanScope? parsed, out string? problem))
            {
                CustomScope = parsed;
                CustomTargetsProblem = string.Empty;
            }
            else
            {
                CustomScope = null;
                CustomTargetsProblem = problem ?? "Entry not understood.";
            }

            RefreshAvailability();
        }

        public IEnumerable<ScanScope> SelectedScopes
        {
            get
            {
                foreach (ScanScope scope in Scopes.Where(s => s.IsSelected)) yield return scope;
                if (CustomScope is not null) yield return CustomScope;
            }
        }

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
                if (count == 0) return "No range selected";

                string targets = TargetCountIsEstimate ? $"~{TargetCount}" : TargetCount.ToString();

                return count == 1
                    ? $"{SelectedScopes.First().GroupDescription} · {targets} targets"
                    : $"{count} ranges · {targets} targets";
            }
        }

        // --------------------------------------------------------- Fortschritt

        [ObservableProperty] private bool _isRunning;
        [ObservableProperty] private string _currentMethodName = string.Empty;
        [ObservableProperty] private int _progressCurrent;
        [ObservableProperty] private int _progressTotal;
        [ObservableProperty] private int _progressResponded;
        [ObservableProperty] private string _statusText = "Ready.";

        public double ProgressFraction =>
            ProgressTotal <= 0 ? 0 : Math.Clamp((double)ProgressCurrent / ProgressTotal, 0, 1);

        // ------------------------------------------------- Ablauf des Laufs

        /// <summary>
        /// Die Verfahren dieses Laufs in Ausfuehrungsfolge und was aus jedem
        /// geworden ist. Daraus entsteht die Anzeige "fertig: Ping, ARP -
        /// offen: SMB, Dienste, SNMP": ein Lauf besteht aus mehreren
        /// Verfahren, und ohne diese Liste sieht man nur das gerade laufende
        /// und weiss nicht, wie viel noch kommt.
        /// </summary>
        private readonly List<string> _planned = [];
        private readonly List<string> _done = [];

        /// <summary>Die abgeschlossenen Verfahren, in der Reihenfolge ihres Endes.</summary>
        public string CompletedScansText => _done.Count == 0 ? "-" : string.Join(", ", _done);

        /// <summary>Was noch aussteht - das laufende Verfahren zuerst.</summary>
        public string PendingScansText
        {
            get
            {
                List<string> open = [.. _planned.Where(name => !_done.Contains(name))];
                return open.Count == 0 ? "-" : string.Join(", ", open);
            }
        }

        /// <summary>Die Zeile hat nur waehrend und nach einem Lauf etwas zu sagen.</summary>
        public bool HasScanPlan => _planned.Count > 0;

        private void NotifyPlanChanged()
        {
            OnPropertyChanged(nameof(CompletedScansText));
            OnPropertyChanged(nameof(PendingScansText));
            OnPropertyChanged(nameof(HasScanPlan));
        }

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

            if (!_done.Contains(outcome.MethodName)) _done.Add(outcome.MethodName);
            NotifyPlanChanged();
        }

        // -------------------------------------------------------------- Start

        [RelayCommand]
        private async Task StartAsync()
        {
            if (!CanStart) return;

            IsRunning = true;
            OnPropertyChanged(nameof(CanStart));
            LastSkipped.Clear();
            StatusText = "Scan running...";

            List<ScanScope> scopes = [.. SelectedScopes];
            List<ScanMethodChoice> chosen = [.. Methods.Where(m => m.IsSelected)];
            List<string> methods = [.. chosen.Select(m => m.Id)];

            // Der Ablaufplan steht vor dem Start fest - die Statuszeile kann
            // damit von Anfang an sagen, was noch kommt.
            _planned.Clear();
            _done.Clear();
            _planned.AddRange(chosen.Select(m => m.DisplayName));
            NotifyPlanChanged();

            try
            {
                // Waehrend des Laufs sammelt die Liste die Meldungen und zieht
                // in kurzen Abstaenden nach - die Tabelle fuellt sich also,
                // waehrend gescannt wird, statt erst am Ende auf einen Schlag.
                using (Devices.BeginLiveUpdates())
                {
                    ScanRunResult result = await _engine.RunAsync(scopes, methods, Settings, _store);
                    StatusText = Describe(result);
                }
            }
            catch (Exception ex)
            {
                StatusText = $"Scan failed: {ex.Message}";
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
            StatusText = "Cancelling...";
        }

        [RelayCommand]
        private void ClearResults()
        {
            _store.Clear();
            Devices.Refresh();

            _planned.Clear();
            _done.Clear();
            NotifyPlanChanged();

            StatusText = "Table cleared.";
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
                return $"Cancelled after {result.Duration.TotalSeconds:F0} s. " +
                       $"{_store.Devices.Count} devices found so far.";
            }

            string summary =
                $"{_store.Devices.Count} devices in {result.Duration.TotalSeconds:F0} s " +
                $"({result.TargetCount} targets).";

            int skipped = result.Skipped.Count();
            if (skipped > 0) summary += $" {skipped} method(s) skipped.";

            int failed = result.Failed.Count();
            if (failed > 0) summary += $" {failed} failed.";

            // Der Befund gehoert an den Anfang des Satzes, nicht ans Ende: er
            // ist der Grund, aus dem man ueberhaupt gescannt hat.
            if (result.ConflictCount > 0)
            {
                summary = $"{result.ConflictCount} device(s) with duplicate addresses or names. " + summary;
            }

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
