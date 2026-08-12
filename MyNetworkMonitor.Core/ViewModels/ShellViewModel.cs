using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;
using MyNetworkMonitor.Core.Persistence;
using MyNetworkMonitor.Core.Models;
using MyNetworkMonitor.Core.SatelliteLink;
using MyNetworkMonitor.Core.Scanning.Engine;
using MyNetworkMonitor.Core.Services;

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
        Satellites,
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

        /// <summary>
        /// Die laufende Portsuche, solange eine laeuft.
        /// <para>
        /// Sie laeuft <b>nicht</b> ueber die Engine, sondern als eigene
        /// Modulinstanz - <c>_engine.Stop()</c> erreicht sie darum nicht. Ohne
        /// diesen Verweis liesse sich eine Suche ueber 65 536 Ports gar nicht
        /// abbrechen: der Knopf meldete "Cancelling...", und der Lauf ginge
        /// weiter, bis er von allein fertig war.
        /// </para>
        /// </summary>
        private ScanningMethod_Services? _portSearch;

        /// <summary>
        /// Der Oberflaechen-Thread, festgehalten beim Erzeugen.
        /// <para>
        /// Seit der Lauf auf einem Hintergrund-Thread stattfindet, treffen die
        /// Fortschrittsmeldungen von dort ein. Sie schreiben gebundene
        /// Eigenschaften - das darf nur von hier aus geschehen, sonst wirft
        /// Avalonia beim ersten Zeichnen.
        /// </para>
        /// </summary>
        private readonly SynchronizationContext? _uiContext = SynchronizationContext.Current;

        /// <summary>
        /// Fuehrt die Aktion auf dem Oberflaechen-Thread aus. Ohne erfassten
        /// Kontext - etwa in Tests - unmittelbar.
        /// </summary>
        private void OnUi(Action action)
        {
            if (_uiContext is null) action();
            else _uiContext.Post(_ => action(), null);
        }

        /// <summary>
        /// Die laufende Portsuche wurde abgebrochen.
        /// <para>
        /// Noetig, weil das Modul nach dem Abbruch ganz normal zurueckkehrt -
        /// mit einem leeren Ergebnis. Ohne diese Unterscheidung meldete der
        /// Abbruch "wurde auf keinem Port gefunden", und das ist eine Aussage
        /// ueber das Geraet, die gar nicht geprueft wurde.
        /// </para>
        /// </summary>
        private bool _portSearchStopped;

        public ShellViewModel(ScanEngine engine, DeviceStore store)
        {
            _engine = engine ?? throw new ArgumentNullException(nameof(engine));
            _store = store ?? throw new ArgumentNullException(nameof(store));

            Devices = new DeviceListViewModel(store);
            ScopeEditor = new ScopeEditorViewModel(Scopes);
            PortEditor = new PortEditorViewModel(Settings);
            ServiceEditor = new ServiceEditorViewModel();
            SatelliteEditor = new SatelliteEditorViewModel
            {
                // Als Satellit: einen hereinkommenden Auftrag ausfuehren.
                JobRunner = RunJobAsync
            };

            // Womit ein neu angemeldeter Satellit startet. Nur beim Anlegen -
            // danach fuehrt er seinen Umfang selbst, und Aenderungen hier
            // wirken sich ausdruecklich nicht mehr auf ihn aus.
            SatelliteEditor.ScanScopeDefaults = () =>
                (Settings.OnlyKnownTargets,
                 [.. Settings.OnlyKnownTargetsFor],
                 Settings.CrossCheckOnlyKnownTargets);

            // Als Hauptscanner: ein Ergebnis eines Satelliten einmischen.
            SatelliteEditor.ResultArrived += (_, e) =>
                MergeSatelliteResult(e.SatelliteName, e.DevicesJson, e.Partial);

            // Die Satellitenansicht zeigt zu jedem Satelliten, welche Bereiche
            // auf ihn zeigen. Die Bereiche gehoeren hierher, nicht dorthin -
            // darum wird die Liste von hier aus nachgefuehrt.
            SatelliteEditor.PropertyChanged += (_, e) =>
            {
                if (e.PropertyName == nameof(SatelliteEditorViewModel.Selected)) RefreshRangesOfSatellite();
            };

            // ... und ebenso, wenn sich an den Bereichen selbst etwas aendert.
            //
            // Vorher wurde die Liste nur beim Wechsel der Auswahl gefuellt:
            // wer einem Bereich drueben "Scanned by" zuwies und zurueckkam,
            // sah die alte Liste und musste die Anwendung neu starten, damit
            // sie stimmt. Beobachtet und genau so gemeldet.
            Scopes.CollectionChanged += (_, e) =>
            {
                foreach (ScanScope s in e.OldItems?.OfType<ScanScope>() ?? [])
                {
                    s.PropertyChanged -= OnScopeChangedForSatellite;
                }

                // Beim Leeren nennt die Sammlung keine alten Eintraege. Darum
                // wird nach jeder Aenderung ueber den ganzen Bestand gegangen
                // und erst ab-, dann angemeldet: doppelt angemeldet hiesse,
                // die Liste bei jeder Eingabe zweimal zu bauen.
                foreach (ScanScope s in Scopes)
                {
                    s.PropertyChanged -= OnScopeChangedForSatellite;
                    s.PropertyChanged += OnScopeChangedForSatellite;
                }

                RefreshRangesOfSatellite();
            };
            NetworkView = new NetworkViewModel();
            FindingsView = new FindingsViewModel(store);

            // Ein Haken im Kommandobalken und eine Aenderung in der Verwaltung
            // treffen dieselbe Liste - die Zaehler muessen in beiden Faellen neu.
            ScopeEditor.SelectionChanged += RefreshAvailability;
            PortEditor.PortsChanged += RefreshAvailability;

            foreach (IScanMethod method in _engine.Methods)
            {
                Methods.Add(new ScanMethodChoice { Method = method });
            }

            // Erst hier, nicht oben bei den uebrigen Zuweisungen an die
            // Satellitenverwaltung: die Verfahrensliste entsteht in der
            // Schleife darueber. Vorher gesetzt bliebe die Umfangsauswahl je
            // Satellit leer - nur der Gesamthaken waere zu sehen.
            //
            // Verfahren, die lauschen statt zu fragen - SSDP, mDNS,
            // ARP-Tabelle -, haben keine Zielliste und stehen darum nicht drin.
            SatelliteEditor.RestrictableMethods =
                [.. Methods.Where(m => m.CanRestrictToKnown)
                           .Select(m => (m.Id, m.Method.DisplayName))];

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

        /// <summary>
        /// Die Satelliten - Instanzen, die in anderen Segmenten scannen. Ihre
        /// Namen speisen die Auswahl "Scanned by" in der Bereichsmaske.
        /// Siehe SATELLIT.md.
        /// </summary>
        public SatelliteEditorViewModel SatelliteEditor { get; }

        /// <summary>Die Adapter dieses Rechners samt ihrer Namensserver.</summary>
        public NetworkViewModel NetworkView { get; }

        /// <summary>Alle Befunde an einer Stelle.</summary>
        public FindingsViewModel FindingsView { get; }

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

        // ------------------------------------------------- Voreinstellungen

        /// <summary>
        /// Welche Verfahren beim ersten Start nur die bereits gefundenen
        /// Geraete abfragen.
        /// <para>
        /// Alles, was eine Zielliste abarbeitet und nichts Neues entdeckt: die
        /// beiden Namensdienste, NetBIOS, ONVIF, die Portscans, die
        /// SMB-Version und die Diensterkennung. Ueber einen ganzen Bereich
        /// gefragt, laufen deren Anfragen fast alle in Adressen, an denen
        /// niemand ist - das kostet die meiste Zeit eines Laufs, ohne je ein
        /// Geraet zu finden, das nicht schon Ping oder ARP gemeldet haetten.
        /// </para>
        /// <para>
        /// Nicht in der Liste stehen die Verfahren, die ueberhaupt erst
        /// Geraete auftun - Ping und ARP-Anfrage -, denn beschraenkt fänden
        /// sie nur, was schon dasteht. SSDP, mDNS und die ARP-Tabelle haben
        /// gar keine Zielliste und tauchen darum nirgends auf.
        /// </para>
        /// </summary>
        private static readonly string[] DefaultOnlyKnownTargetsFor =
        [
            "dns.reverse", "dns.lookup", "netbios", "onvif",
            "ports.tcp", "ports.udp", "smb.version", "services"
        ];

        /// <summary>
        /// Die Dienste, die in der Tabelle von Haus aus zu einem "+n"
        /// zusammengefasst werden.
        /// <para>
        /// Es sind die, die auf jedem zweiten Geraet stehen und darum nichts
        /// unterscheiden - Namens- und Adressdienste, dazu die
        /// Fernwartungswerkzeuge, die im Unternehmensnetz ohnehin ueberall
        /// ausgerollt sind. Sie einzeln zu zeigen fuellt die Spalte, ohne dass
        /// man daran ein Geraet vom naechsten unterscheiden koennte.
        /// </para>
        /// </summary>
        private static readonly string[] DefaultGroupedServices =
        [
            "DHCP", "DNS_TCP", "DNS_UDP", "NetBIOS",
            "RustdeskServer", "TeamViewer", "UltraVNC"
        ];

        /// <summary>
        /// Packt Eintraege aus, die aus einer aelteren Fassung stammen.
        /// <para>
        /// Bevor es <see cref="UserSettings.SetStrings"/> gab, hat die
        /// Verfahrensliste ihre Schluessel selbst zusammengefuegt - mit Komma,
        /// wo die Ablage einen senkrechten Strich erwartet. So ein Eintrag
        /// steht bis heute in gewachsenen Dateien und enthaelt die ganze Liste
        /// in einem Feld. Er richtet keinen Schaden an, weil kein Verfahren so
        /// heisst; er wird nur nie wieder los, solange ihn niemand aufloest.
        /// </para>
        /// <para>
        /// Zerlegt statt weggeworfen: die Schluessel darin sind gueltig, und
        /// bei jemandem, dessen Auswahl <em>nur</em> aus so einem Eintrag
        /// besteht, waere Wegwerfen der Verlust seiner Einstellung.
        /// Unbekanntes bleibt unangetastet - es koennte zu einem Verfahren
        /// gehoeren, das erst spaeter dazukommt.
        /// </para>
        /// </summary>
        private static IEnumerable<string> ExpandLegacyIds(IEnumerable<string> ids) =>
            ids.SelectMany(id => id.Split(',', StringSplitOptions.RemoveEmptyEntries
                                             | StringSplitOptions.TrimEntries))
               .Where(id => id.Length > 0);

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

            // Die Gemeinschaftskennung leer zu speichern waere ein Fussangel:
            // SNMP fragt dann ohne Kennung und bekommt nirgends eine Antwort.
            string community = _userSettings.GetString("SnmpCommunity");
            if (!string.IsNullOrWhiteSpace(community)) Settings.SnmpCommunity = community;
            Settings.OnlyKnownTargets = _userSettings.GetBool("OnlyKnownTargets", Settings.OnlyKnownTargets);
            Settings.ClearArpCacheFirst = _userSettings.GetBool("ClearArpCacheFirst", Settings.ClearArpCacheFirst);
            Settings.CrossCheckDnsServers =
                _userSettings.GetBool("CrossCheckDnsServers", Settings.CrossCheckDnsServers);
            Settings.CrossCheckOnlyKnownTargets =
                _userSettings.GetBool("CrossCheckOnlyKnownTargets", Settings.CrossCheckOnlyKnownTargets);
            Settings.OverrideDnsServer = _userSettings.GetString("OverrideDnsServer");
            Settings.ReverseLookupConcurrency =
                _userSettings.GetInt("ReverseLookupConcurrency", Settings.ReverseLookupConcurrency);

            Settings.SatelliteListenEnabled =
                _userSettings.GetBool("SatelliteListenEnabled", Settings.SatelliteListenEnabled);
            Settings.SatelliteListenPort =
                _userSettings.GetInt("SatelliteListenPort", Settings.SatelliteListenPort);
            Settings.SatelliteModeEnabled =
                _userSettings.GetBool("SatelliteModeEnabled", Settings.SatelliteModeEnabled);
            Settings.MainScannerHost = _userSettings.GetString("MainScannerHost");
            Settings.MainScannerPort =
                _userSettings.GetInt("MainScannerPort", Settings.MainScannerPort);
            Settings.AllowCancelFromAnyReceiver =
                _userSettings.GetBool("AllowCancelFromAnyReceiver", Settings.AllowCancelFromAnyReceiver);

            SatelliteEditor.AllowCancelFromAnyReceiver = Settings.AllowCancelFromAnyReceiver;
            Settings.UseOnlineTopologyLibrary =
                _userSettings.GetBool("UseOnlineTopologyLibrary", Settings.UseOnlineTopologyLibrary);

            SaveLastScanResult = _userSettings.GetBool("SaveLastScanResult", true);

            // Welche Dienste in der Tabelle zu einem "+n" zusammengefasst
            // werden. Voreingestellt an, mit der Auswahl aus
            // <see cref="DefaultGroupedServices"/>.
            ServiceDisplay.GroupSelected = _userSettings.GetBool("GroupServices", true);

            // Nach dem Schluessel gefragt, nicht nach dem Wert: wer die
            // Gruppierung leerraeumt, hat das entschieden, und die
            // Voreinstellung darf sie ihm nicht bei jedem Start
            // zurueckschreiben.
            IReadOnlyList<string> grouped = _userSettings.Contains("GroupedServices")
                ? _userSettings.GetStrings("GroupedServices")
                : DefaultGroupedServices;

            foreach (string name in grouped)
            {
                ServiceDisplay.Grouped.Add(name);
            }

            // Offene Ports ohne erkannten Dienst ("TCP 8080", "UDP 53", ...)
            // sind der Fall, der die Spalte am haeufigsten sprengt - darum
            // eigene Schalter, voreingestellt an, statt sie ueber die
            // namentliche Liste einzeln abwaehlen zu muessen.
            ServiceDisplay.GroupTcpPorts = _userSettings.GetBool("GroupTcpPorts", true);
            ServiceDisplay.GroupUdpPorts = _userSettings.GetBool("GroupUdpPorts", true);

            OnPropertyChanged(nameof(GroupServices));
            BuildGroupableServices();

            // Welche Verfahren nur die bekannten Geraete abfragen sollen.
            //
            // Beim ersten Start die beiden Namensdienste vorbelegen. Die
            // bisherige Anwendung hat ihre Liste aus der Ergebnistabelle
            // gebaut, also aus den gefundenen Geraeten; ueber einen ganzen
            // Bereich gefragt, laufen die meisten Anfragen in Adressen ohne
            // Eintrag - das kostet nur Zeit und belastet den Namensserver.
            //
            // Gefragt wird nach dem Schluessel, nicht nach dem Wert: eine
            // leere Auswahl ist eine Entscheidung und darf nicht bei jedem
            // Start ueberschrieben werden.
            if (!_userSettings.Contains("OnlyKnownTargetsFor"))
            {
                _userSettings.SetStrings("OnlyKnownTargetsFor", DefaultOnlyKnownTargetsFor);
            }

            IReadOnlyList<string> stored = _userSettings.GetStrings("OnlyKnownTargetsFor");

            foreach (string id in ExpandLegacyIds(stored))
            {
                Settings.OnlyKnownTargetsFor.Add(id);
            }

            // Hat das Auspacken etwas veraendert, den bereinigten Stand
            // zurueckschreiben - sonst schleppt die Datei den Altbestand
            // weiter mit, auch wenn ihn niemand mehr liest.
            if (Settings.OnlyKnownTargetsFor.Count != stored.Count
                || !stored.All(Settings.OnlyKnownTargetsFor.Contains))
            {
                _userSettings.SetStrings("OnlyKnownTargetsFor", Settings.OnlyKnownTargetsFor);
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
                    case nameof(ScanSettings.SnmpCommunity):
                        _userSettings.SetString("SnmpCommunity", Settings.SnmpCommunity);
                        break;
                    case nameof(ScanSettings.OnlyKnownTargets):
                        _userSettings.SetBool("OnlyKnownTargets", Settings.OnlyKnownTargets);
                        break;
                    case nameof(ScanSettings.ClearArpCacheFirst):
                        _userSettings.SetBool("ClearArpCacheFirst", Settings.ClearArpCacheFirst);
                        break;
                    case nameof(ScanSettings.CrossCheckDnsServers):
                        _userSettings.SetBool("CrossCheckDnsServers", Settings.CrossCheckDnsServers);
                        break;
                    case nameof(ScanSettings.CrossCheckOnlyKnownTargets):
                        _userSettings.SetBool("CrossCheckOnlyKnownTargets",
                                              Settings.CrossCheckOnlyKnownTargets);
                        break;
                    case nameof(ScanSettings.OverrideDnsServer):
                        _userSettings.SetString("OverrideDnsServer", Settings.OverrideDnsServer);
                        break;
                    case nameof(ScanSettings.ReverseLookupConcurrency):
                        _userSettings.SetInt("ReverseLookupConcurrency", Settings.ReverseLookupConcurrency);
                        break;
                    case nameof(ScanSettings.SatelliteListenEnabled):
                        _userSettings.SetBool("SatelliteListenEnabled", Settings.SatelliteListenEnabled);
                        break;
                    case nameof(ScanSettings.SatelliteListenPort):
                        _userSettings.SetInt("SatelliteListenPort", Settings.SatelliteListenPort);
                        break;
                    case nameof(ScanSettings.SatelliteModeEnabled):
                        _userSettings.SetBool("SatelliteModeEnabled", Settings.SatelliteModeEnabled);
                        break;
                    case nameof(ScanSettings.MainScannerHost):
                        _userSettings.SetString("MainScannerHost", Settings.MainScannerHost);
                        break;
                    case nameof(ScanSettings.MainScannerPort):
                        _userSettings.SetInt("MainScannerPort", Settings.MainScannerPort);
                        break;
                    case nameof(ScanSettings.AllowCancelFromAnyReceiver):
                        _userSettings.SetBool("AllowCancelFromAnyReceiver", Settings.AllowCancelFromAnyReceiver);

                        // Sofort wirksam, nicht erst beim naechsten Start: die
                        // Einstellung soll greifen, waehrend gerade etwas haengt.
                        SatelliteEditor.AllowCancelFromAnyReceiver = Settings.AllowCancelFromAnyReceiver;
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
            if (sender is not ScanMethodChoice choice) return;

            // Der Quervergleich haengt am DNS-Scan: ohne ihn gibt es keine
            // Namen, ueber die sich die Server uneinig sein koennten. Sein
            // Kaestchen muss darum mitbekommen, wenn eines der beiden
            // DNS-Verfahren an- oder abgewaehlt wird.
            if (e.PropertyName == nameof(ScanMethodChoice.IsSelected))
            {
                if (IsDnsMethod(choice.Id)) OnPropertyChanged(nameof(CanCrossCheckDns));

                // Alles, was an der Verfahrensauswahl haengt, muss bei *jedem*
                // Kaestchen nachziehen.
                //
                // Vorher meldete sich nur der Quervergleich, und auch der nur
                // bei den beiden DNS-Verfahren. Die Zahl am Knopf "Methods"
                // wurde ausschliesslich beim Wechsel des Umfangs und bei einer
                // Aenderung an den Bereichen neu berechnet - dazwischen stand
                // sie auf dem Stand des zuletzt gewaehlten Umfangs, waehrend
                // die Haken laengst andere waren.
                OnPropertyChanged(nameof(SelectedMethodCount));
                OnPropertyChanged(nameof(EstimatedDuration));
                OnPropertyChanged(nameof(CanStart));
                return;
            }

            if (e.PropertyName != nameof(ScanMethodChoice.OnlyKnownTargets)) return;

            if (choice.OnlyKnownTargets) Settings.OnlyKnownTargetsFor.Add(choice.Id);
            else Settings.OnlyKnownTargetsFor.Remove(choice.Id);

            _userSettings?.SetStrings("OnlyKnownTargetsFor", Settings.OnlyKnownTargetsFor);
        }

        private static bool IsDnsMethod(string id) =>
            id is "dns.lookup" or "dns.reverse";

        /// <summary>
        /// Der DNS-Quervergleich ist waehlbar. Es ist keine eigene Methode,
        /// sondern eine Unterfunktion des Namensscans - ohne ihn liefe sie
        /// ins Leere, und ein Kaestchen, das nichts bewirkt, ist schlimmer als
        /// eines, das erkennbar gesperrt ist.
        /// </summary>
        public bool CanCrossCheckDns =>
            Methods.Any(m => m.IsEffective && IsDnsMethod(m.Id));

        /// <summary>
        /// Liest den zuletzt gesicherten Bestand. Ohne Datei bleibt es bei der
        /// leeren Liste - das ist kein Fehler, sondern der erste Start.
        /// </summary>
        public void LoadLastScanResult()
        {
            if (string.IsNullOrEmpty(SettingsFolder)) return;

            int count = DeviceStoreFile.Load(_store, LastScanResultPath, out string? error);

            if (error is not null)
            {
                // Nicht ueberschreiben, was sich nicht lesen liess - sonst ist
                // beim naechsten Schliessen auch die Datei weg.
                _loadFailed = true;
                StatusText = $"The last scan result could not be read, it stays untouched: {error}";
                return;
            }

            if (count == 0) return;

            // Die Doppelbelegungen stehen nicht in der Datei, und das mit
            // Absicht: gespeicherte Befunde waeren eine zweite Wahrheit neben
            // den Daten und muessten eigens wieder aufgeraeumt werden, wenn der
            // Fehler behoben ist. Aus dem geladenen Bestand neu abgeleitet
            // stimmen sie von selbst - sie sind nach dem Start wieder da und
            // fallen weg, sobald ein Scan sie nicht mehr hergibt.
            int conflicts;

            lock (_store.SyncRoot)
            {
                conflicts = DuplicateDetector.Analyze(_store.Devices);
            }

            Devices.Refresh();
            FindingsView.Refresh();

            StatusText = conflicts == 0
                ? $"{count} devices from the last scan. Nothing has been rechecked yet."
                : $"{count} devices from the last scan, {conflicts} of them with a finding. " +
                  "Nothing has been rechecked yet.";
        }

        /// <summary>Der letzte Bestand liess sich nicht lesen.</summary>
        private bool _loadFailed;

        // ------------------------------------------------- Dienste in der Spalte

        /// <summary>
        /// Die ausgewaehlten Dienste in der Tabelle zu einem "+n"
        /// zusammenfassen, statt alle einzeln zu zeigen.
        /// </summary>
        public bool GroupServices
        {
            get => ServiceDisplay.GroupSelected;
            set
            {
                if (ServiceDisplay.GroupSelected == value) return;

                ServiceDisplay.GroupSelected = value;
                _userSettings?.SetBool("GroupServices", value);

                OnPropertyChanged();
                ServiceDisplay.NotifyChanged();
            }
        }


        // ------------------------------------------------- MAC-Herstellerliste

        /// <summary>Waehrend des Herunterladens gesperrt, damit kein zweiter Versuch nebenher laeuft.</summary>
        [ObservableProperty] private bool _isUpdatingMacVendors;

        /// <summary>
        /// Baut die MAC-Herstellerliste aus Wiresharks manuf-Datei neu auf - siehe
        /// <see cref="MacVendorUpdater"/> dazu, warum das mehr Treffer liefert als
        /// die mitgelieferte Liste (die kennt nur die klassischen 24-Bit-Bloecke).
        /// </summary>
        [RelayCommand]
        private async Task UpdateMacVendorsAsync()
        {
            if (IsUpdatingMacVendors) return;

            IsUpdatingMacVendors = true;
            StatusText = "Downloading the current MAC vendor list from Wireshark...";

            try
            {
                string targetPath = Path.Combine(AppContext.BaseDirectory, "MacVendors", "mac_vendors.csv");
                MacVendorUpdateResult result = await MacVendorUpdater.UpdateAsync(targetPath);

                StatusText = result.Success
                    ? $"MAC vendor list updated: {result.EntryCount:N0} entries (MA-L, MA-M and MA-S). " +
                      "Takes effect on the next scan."
                    : $"MAC vendor update failed: {result.Error}";
            }
            finally
            {
                IsUpdatingMacVendors = false;
            }
        }

        /// <summary>
        /// Alle Dienste, die sich zusammenfassen lassen - mit ihrem Haken.
        /// Gespeist aus den Dienstdefinitionen und den Verfahren mit eigenem
        /// Modul, damit die Liste auch ohne vorherigen Scan vollstaendig ist.
        /// </summary>
        public ObservableCollection<GroupableService> GroupableServices { get; } = [];

        /// <summary>
        /// Dieselben Dienste, nach ihrer Rubrik gebuendelt - so wie sie in den
        /// Definitionen stehen. Eine Liste aus dreissig Namen am Stueck laesst
        /// sich nicht ueberfliegen; nach Rubriken sortiert findet man den
        /// gesuchten Dienst dort, wo man ihn vermutet.
        /// </summary>
        public ObservableCollection<GroupableServiceGroup> GroupableServiceGroups { get; } = [];

        /// <summary>
        /// Dieselben Rubriken, auf zwei Spalten verteilt.
        /// <para>
        /// Die Aufteilung passiert hier und nicht im Layout, weil ein
        /// Gitter mit gleich hohen Zellen sich an der groessten Rubrik
        /// ausrichtet - zwischen einer Rubrik mit zwei Eintraegen und der
        /// naechsten klafft dann eine Luecke von der Hoehe der laengsten.
        /// Zwei Spalten, die jede fuer sich untereinander wachsen, haben das
        /// Problem nicht und stellen sich von selbst neu ein, wenn Dienste
        /// dazukommen.
        /// </para>
        /// </summary>
        public ObservableCollection<GroupableServiceGroup> GroupableServicesLeft { get; } = [];

        public ObservableCollection<GroupableServiceGroup> GroupableServicesRight { get; } = [];

        /// <summary>
        /// Verteilt die Rubriken so auf zwei Spalten, dass beide etwa gleich
        /// hoch werden. Gezaehlt wird in Zeilen: je Dienst eine, dazu eine fuer
        /// die Ueberschrift.
        /// </summary>
        private void SpreadOverTwoColumns()
        {
            GroupableServicesLeft.Clear();
            GroupableServicesRight.Clear();

            int left = 0;
            int right = 0;

            foreach (GroupableServiceGroup group in GroupableServiceGroups)
            {
                int height = group.Services.Count + 1;

                // Immer in die derzeit kuerzere Spalte - so bleibt der
                // Unterschied hoechstens eine Rubrik gross, egal wie viele
                // spaeter dazukommen.
                if (left <= right)
                {
                    GroupableServicesLeft.Add(group);
                    left += height;
                }
                else
                {
                    GroupableServicesRight.Add(group);
                    right += height;
                }
            }
        }

        /// <summary>
        /// Wohin die vier Verfahren mit eigenem Modul gehoeren. Sie stehen
        /// nicht in den Dienstdefinitionen, sind aber Dienste wie die anderen -
        /// ohne Zuordnung landeten sie in einer Sammelrubrik, in der niemand
        /// sucht.
        /// </summary>
        private static readonly Dictionary<string, string> ModuleServiceGroups = new(StringComparer.OrdinalIgnoreCase)
        {
            ["SMB"] = "🗂️ Dateidienste",
            ["ONVIF"] = "📷 Kameras",
            ["NetBIOS"] = "🌍 Netzwerk-Dienste",
            ["SNMP"] = "🌍 Netzwerk-Dienste"
        };

        private const string UngroupedServices = "· Ohne Rubrik";

        /// <summary>
        /// Baut die Auswahlliste neu. Muss nach dem Laden der
        /// Dienstdefinitionen laufen - vorher kennt der Editor nur die vier
        /// Verfahren mit eigenem Modul.
        /// </summary>
        public void BuildGroupableServices()
        {
            GroupableServices.Clear();
            GroupableServiceGroups.Clear();

            // Name und Rubrik zusammenfuehren: aus den Definitionen, was dort
            // steht, fuer die vier Modulverfahren die feste Zuordnung.
            Dictionary<string, string> groupOf = new(StringComparer.OrdinalIgnoreCase);

            foreach (ServiceEntry service in ServiceEditor.All.Where(s => !string.IsNullOrWhiteSpace(s.Name)))
            {
                groupOf[service.Name] = string.IsNullOrWhiteSpace(service.Group)
                    ? UngroupedServices
                    : service.Group;
            }

            foreach (KeyValuePair<string, string> module in ModuleServiceGroups)
            {
                groupOf.TryAdd(module.Key, module.Value);
            }

            foreach (IGrouping<string, KeyValuePair<string, string>> group in groupOf
                         .GroupBy(pair => pair.Value)
                         .OrderBy(g => g.Key, StringComparer.CurrentCulture))
            {
                GroupableServiceGroup bucket = new() { Name = group.Key };

                foreach (string name in group.Select(p => p.Key).OrderBy(n => n, StringComparer.CurrentCulture))
                {
                    GroupableService entry = new()
                    {
                        Name = name,
                        IsGrouped = ServiceDisplay.Grouped.Contains(name)
                    };

                    entry.PropertyChanged += OnGroupableServiceChanged;

                    bucket.Services.Add(entry);
                    GroupableServices.Add(entry);
                }

                GroupableServiceGroups.Add(bucket);
            }

            // Offene Ports ohne erkannten Dienst treffen keinen einzelnen
            // Namen - "TCP 8080", "TCP 8081", "TCP 8443" ... sind alle
            // verschieden. Eigene Rubrik, eigene Schalter (siehe
            // GroupableService.OnChanged), aber optisch dieselbe Zeile wie
            // jeder andere Dienst.
            GroupableServiceGroup openPorts = new() { Name = "🔌 Open Ports" };

            openPorts.Services.Add(OpenPortsEntry("TCP Ports",
                ServiceDisplay.GroupTcpPorts,
                value => { ServiceDisplay.GroupTcpPorts = value; _userSettings?.SetBool("GroupTcpPorts", value); }));

            openPorts.Services.Add(OpenPortsEntry("UDP Ports",
                ServiceDisplay.GroupUdpPorts,
                value => { ServiceDisplay.GroupUdpPorts = value; _userSettings?.SetBool("GroupUdpPorts", value); }));

            foreach (GroupableService entry in openPorts.Services) GroupableServices.Add(entry);
            GroupableServiceGroups.Add(openPorts);

            SpreadOverTwoColumns();
        }

        private GroupableService OpenPortsEntry(string name, bool initial, Action<bool> apply)
        {
            GroupableService entry = new()
            {
                Name = name,
                IsGrouped = initial,
                OnChanged = value =>
                {
                    apply(value);
                    ServiceDisplay.NotifyChanged();
                }
            };

            entry.PropertyChanged += OnGroupableServiceChanged;
            return entry;
        }

        private void OnGroupableServiceChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName != nameof(GroupableService.IsGrouped)) return;
            if (sender is not GroupableService entry) return;

            if (entry.OnChanged is not null)
            {
                entry.OnChanged(entry.IsGrouped);
                return;
            }

            if (entry.IsGrouped) ServiceDisplay.Grouped.Add(entry.Name);
            else ServiceDisplay.Grouped.Remove(entry.Name);

            // Gespeichert wird immer die ganze Menge, nicht die einzelne
            // Aenderung. Damit traegt es von selbst, wenn Dienste dazukommen
            // oder wegfallen - es gibt nichts, was man dabei vergessen
            // koennte.
            _userSettings?.SetStrings("GroupedServices", ServiceDisplay.Grouped);

            ServiceDisplay.NotifyChanged();
        }

        /// <summary>
        /// Sichert den Bestand. Wird beim Schliessen des Fensters gerufen -
        /// ein Fehler darf das Beenden nicht aufhalten, darum meldet die
        /// Methode nur, ob es geklappt hat.
        /// </summary>
        public bool SaveLastScanResultNow()
        {
            if (!SaveLastScanResult || string.IsNullOrEmpty(SettingsFolder)) return false;

            // Was sich beim Start nicht lesen liess, wird auch nicht
            // ueberschrieben. Sonst kostet ein einzelner Lesefehler den
            // gesamten gespeicherten Bestand.
            if (_loadFailed) return false;

            return DeviceStoreFile.Save(_store, LastScanResultPath);
        }

        [ObservableProperty] private ShellSection _section = ShellSection.Devices;

        [ObservableProperty] private bool _isDrawerOpen;

        // ---------------------------------------------------------- Umfaenge

        // Die ARP-Tabelle ist in keinem Umfang dabei, obwohl sie nichts kostet:
        // sie liefert den Zwischenspeicher des eigenen Rechners und damit
        // Geraete, die im Lauf gar nicht befragt wurden - teils laengst
        // abgeschaltete. Beilaeufig mitgenommen sieht das Ergebnis nach mehr
        // aus, als tatsaechlich geprueft wurde. Wer sie will, hakt sie an.
        //
        // Dasselbe gilt fuer den DNS-Quervergleich, siehe ApplyProfile.
        public IReadOnlyList<ScanProfile> Profiles { get; } =
        [
            new ScanProfile
            {
                Name = "Quick",
                Description = "Discovery only - who is there?",
                MethodIds = ["ping", "arp.request", "dns.reverse", "dns.lookup"]
            },
            new ScanProfile
            {
                Name = "Standard",
                Description = "Discover and identify, with the usual services",
                MethodIds =
                [
                    "ping", "arp.request", "dns.reverse", "dns.lookup",
                    "snmp", "ssdp", "smb.version", "onvif"
                ]
            },
            new ScanProfile
            {
                Name = "Thorough",
                Description = "Everything available - takes accordingly long",
                MethodIds =
                [
                    "ping", "arp.request", "dns.reverse", "dns.lookup",
                    "netbios", "mdns",
                    "snmp", "ssdp", "smb.version", "wsdiscovery", "onvif",
                    "services", "web.identity", "switch.ports"
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
                // Ohne Ruecksicht auf die Verfuegbarkeit: das Profil sagt, was
                // gewuenscht ist. Was davon gerade laufen kann, entscheidet
                // IsEffective - und sobald es wieder kann, ist es von selbst
                // wieder dabei.
                choice.IsSelected = profile.MethodIds.Contains(choice.Id);
            }

            // Kein Umfang schaltet den DNS-Quervergleich ein. Er fragt jede
            // Adresse bei jedem Server einzeln und in beide Richtungen - das
            // ist nichts, was man beilaeufig mit einem Umfang mitnimmt, und
            // wer es will, hakt es selbst an.
            Settings.CrossCheckDnsServers = false;

            OnPropertyChanged(nameof(SelectedMethodCount));
            OnPropertyChanged(nameof(CanCrossCheckDns));
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

        /// <summary>
        /// Ein Adapter zur Auswahl fuer die eigene Eingabe. Der erste Eintrag
        /// traegt eine leere Kennung und bedeutet "den nehmen, ueber den das
        /// Betriebssystem ohnehin routen wuerde".
        /// </summary>
        public sealed class AdapterChoice
        {
            public required string Id { get; init; }
            public required string Display { get; init; }
            public override string ToString() => Display;
        }

        /// <summary>
        /// Die Adapter, ueber die eine eigene Eingabe gescannt werden kann.
        /// <para>
        /// Noetig, weil ein einzelnes Ziel keinen Bereich hat, aus dem sich der
        /// Adapter ableiten liesse. Ohne angehakten Bereich fiel bisher alles
        /// auf den Standardadapter zurueck - was falsch ist, sobald der Rechner
        /// in mehreren Netzen haengt und das Ziel im anderen steht.
        /// </para>
        /// </summary>
        public ObservableCollection<AdapterChoice> CustomTargetAdapters { get; } = [];

        [ObservableProperty] private AdapterChoice? _selectedCustomAdapter;

        partial void OnSelectedCustomAdapterChanged(AdapterChoice? value)
        {
            if (CustomScope is not null) CustomScope.InterfaceId = value?.Id ?? string.Empty;

            RefreshAvailability();
        }

        /// <summary>Liest die Adapterliste fuer die eigene Eingabe neu.</summary>
        public void RefreshCustomTargetAdapters()
        {
            string? keep = SelectedCustomAdapter?.Id;

            CustomTargetAdapters.Clear();
            CustomTargetAdapters.Add(new AdapterChoice { Id = string.Empty, Display = "automatic" });

            foreach (NetworkInterface nic in SafeInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;

                string addresses = string.Join(", ", SafeIpv4(nic));
                if (addresses.Length == 0) continue;

                CustomTargetAdapters.Add(new AdapterChoice
                {
                    Id = nic.Id,
                    Display = $"{nic.Name}  ·  {addresses}"
                });
            }

            SelectedCustomAdapter =
                CustomTargetAdapters.FirstOrDefault(a => a.Id == keep) ?? CustomTargetAdapters[0];

            static NetworkInterface[] SafeInterfaces()
            {
                try { return NetworkInterface.GetAllNetworkInterfaces(); }
                catch (NetworkInformationException) { return []; }
            }

            static IEnumerable<string> SafeIpv4(NetworkInterface nic)
            {
                List<string> result = [];

                try
                {
                    foreach (UnicastIPAddressInformation u in nic.GetIPProperties().UnicastAddresses)
                    {
                        if (u.Address.AddressFamily == AddressFamily.InterNetwork) result.Add(u.Address.ToString());
                    }
                }
                catch (NetworkInformationException) { }

                return result;
            }
        }

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

                // Die Adapterwahl gilt auch fuer eine neu getippte Eingabe -
                // sonst muesste man sie nach jeder Aenderung erneut treffen.
                if (CustomScope is not null)
                {
                    CustomScope.InterfaceId = SelectedCustomAdapter?.Id ?? string.Empty;
                }

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

        /// <summary>
        /// Wie viele Verfahren ein Lauf jetzt tatsaechlich ausfuehren wuerde -
        /// angehakt <em>und</em> lauffaehig.
        /// </summary>
        public int SelectedMethodCount => Methods.Count(m => m.IsEffective);

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

                int methods = Math.Max(1, Methods.Count(m => m.IsEffective && !m.IsPassive));

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

            EnsureLocalInterfaceSelected();

            ScanContext probe = BuildProbeContext();

            foreach (ScanMethodChoice choice in Methods)
            {
                choice.Availability = choice.Method.CheckAvailability(probe);
            }

            OnPropertyChanged(nameof(SelectedScopeCount));
            OnPropertyChanged(nameof(SelectedMethodCount));
            OnPropertyChanged(nameof(CanCrossCheckDns));
            OnPropertyChanged(nameof(TargetCount));
            OnPropertyChanged(nameof(TargetCountIsEstimate));
            OnPropertyChanged(nameof(EstimatedDuration));
            OnPropertyChanged(nameof(CanStart));
            OnPropertyChanged(nameof(ScopeSummary));
        }

        /// <summary>
        /// Sorgt dafuer, dass eine lokale Netzwerkkarte eingetragen ist.
        /// <para>
        /// Verfahren, die einen Lauscher aufsetzen statt Ziele abzufragen -
        /// SSDP, ONVIF, der DHCP-Mitschnitt - binden ihn an
        /// <c>SupportMethods.SelectedNetworkInterfaceInfos.IPv4</c>. In der
        /// bisherigen Oberflaeche kam der Wert aus einer Auswahlliste; die gibt
        /// es hier nicht, und so blieb er leer. SSDP war damit dauerhaft
        /// gesperrt, ohne dass man haette sehen koennen, warum.
        /// </para>
        /// <para>
        /// Genommen wird die Karte des ersten gewaehlten Bereichs - dort soll
        /// gescannt werden, also gehoert der Lauscher dorthin. Ohne Bereich die
        /// erste betriebsbereite Karte mit Gateway.
        /// </para>
        /// </summary>
        private void EnsureLocalInterfaceSelected()
        {
            NetworkInterface? nic = _lastRuntimes
                .Select(r => r.Interface)
                .FirstOrDefault(i => i is not null);

            nic ??= NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(i =>
                    i.OperationalStatus == OperationalStatus.Up &&
                    i.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) &&
                    i.GetIPProperties().GatewayAddresses.Any(g => g.Address?.AddressFamily == AddressFamily.InterNetwork));

            if (nic is null) return;

            IPAddress? address = nic.GetIPProperties().UnicastAddresses
                .FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork)?.Address;

            if (address is null) return;

            SupportMethods.SelectedNetworkInterfaceInfos.Name = nic.Name;
            SupportMethods.SelectedNetworkInterfaceInfos.IPv4 = address;
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

        /// <summary>
        /// Fortschritt eines Verfahrens. Kommt aus dem Scan-Thread und wird
        /// darum hinuebergereicht, bevor irgendetwas Gebundenes geschrieben wird.
        /// </summary>
        private void OnProgress(ScanProgress progress) => OnUi(() => ApplyProgress(progress));

        private void ApplyProgress(ScanProgress progress)
        {
            CurrentMethodName = progress.MethodName;
            ProgressCurrent = progress.Current;
            ProgressTotal = progress.Total;
            ProgressResponded = progress.Responded;
            OnPropertyChanged(nameof(ProgressFraction));

            // Zusaetzlich am Verfahren selbst festhalten. Der Kommandobalken
            // zeigt nur das laufende; die Zahlen der schon gelaufenen sind
            // aber genau das, was man am Ende vergleichen will - welches
            // Verfahren hat wie viel gebracht.
            ScanMethodChoice? choice = Methods.FirstOrDefault(m =>
                string.Equals(m.Id, progress.MethodId, StringComparison.OrdinalIgnoreCase));

            if (choice is null) return;

            choice.Sent = progress.Current;
            choice.Responded = progress.Responded;
            choice.Total = progress.Total;
            choice.HasProgress = true;
        }

        /// <summary>
        /// Ein Verfahren ist fertig. Schreibt in <see cref="LastSkipped"/>, eine
        /// gebundene Sammlung - also ebenfalls nur vom Oberflaechen-Thread aus.
        /// </summary>
        private void OnMethodFinished(ScanMethodOutcome outcome) => OnUi(() =>
        {
            if (outcome.State != ScanMethodState.Available || outcome.Error is not null)
            {
                LastSkipped.Add(outcome);
            }

            if (!_done.Contains(outcome.MethodName)) _done.Add(outcome.MethodName);
            NotifyPlanChanged();
        });

        // -------------------------------------------------------------- Start

        [RelayCommand]
        private async Task StartAsync()
        {
            if (!CanStart) return;

            await RunAsync([.. SelectedScopes]);
        }

        /// <summary>
        /// Scannt nur die markierten Geraete noch einmal - mit denselben
        /// Verfahren, die im Kommandobalken gewaehlt sind.
        /// <para>
        /// Der Weg dahin ist eine Zielliste als eigener Bereich: ein Geraet
        /// steht mit allen seinen Adressen darin, v4 wie v6, damit der Lauf
        /// beide Seiten auffrischt. Bereichsangaben wie Domain, Namensserver
        /// und Gateway kommen aus dem Bereich, aus dem das Geraet stammt -
        /// sonst liefe der zweite Blick unter anderen Bedingungen als der
        /// erste und die Ergebnisse waeren nicht vergleichbar.
        /// </para>
        /// </summary>
        [RelayCommand]
        private async Task RescanSelectedAsync()
        {
            if (IsRunning || SelectedMethodCount == 0) return;

            List<ScanScope> scopes = BuildRescanScopes(Devices.ActionTargets);

            if (scopes.Count == 0)
            {
                StatusText = "Nothing selected to rescan.";
                return;
            }

            await RunAsync(scopes);
        }

        /// <summary>
        /// Baut je Herkunftsbereich eine Zielliste. Die Aufteilung ist noetig,
        /// weil Domain und Namensserver am Bereich haengen: zwei Geraete aus
        /// verschiedenen Bereichen in einer Liste bekaemen die Angaben des
        /// einen und der andere ginge leer aus.
        /// </summary>
        private List<ScanScope> BuildRescanScopes(IReadOnlyList<Device> devices)
        {
            Dictionary<string, List<string>> byGroup = [];

            foreach (Device device in devices)
            {
                List<string> addresses = [.. device.Ipv4Addresses.Select(a => a.Info.Canonical)];

                // Von den IPv6-Adressen genuegt die beste. Ein Geraet traegt
                // regulaer mehrere, die meisten davon kurzlebig - sie alle
                // abzufragen kostet Zeit und bringt denselben Befund.
                if (device.BestIpv6Address is { } v6) addresses.Add(v6.Info.Canonical);

                if (addresses.Count == 0) continue;

                if (!byGroup.TryGetValue(device.GroupDescription, out List<string>? list))
                {
                    byGroup[device.GroupDescription] = list = [];
                }

                foreach (string address in addresses.Where(a => !list.Contains(a)))
                {
                    list.Add(address);
                }
            }

            List<ScanScope> scopes = [];

            foreach ((string group, List<string> addresses) in byGroup)
            {
                ScanScope? origin = Scopes.FirstOrDefault(s =>
                    string.Equals(s.GroupDescription, group, StringComparison.OrdinalIgnoreCase));

                scopes.Add(new ScanScope
                {
                    Kind = ScanScopeKind.TargetList,
                    IsSelected = true,
                    GroupDescription = string.IsNullOrWhiteSpace(group) ? "Rescan" : group,
                    DeviceDescription = origin?.DeviceDescription ?? string.Empty,
                    Domain = origin?.Domain ?? string.Empty,
                    DnsServers = origin?.DnsServers ?? string.Empty,
                    GatewayIP = origin?.GatewayIP ?? string.Empty,
                    // Der Nachschlag erbt den Satelliten des Bereichs: sonst
                    // liefe er von hier aus und damit ohne ARP, waehrend der
                    // Bereich selbst aus dem Segment heraus gescannt wird.
                    ScannedBy = origin?.ScannedBy ?? string.Empty,
                    Targets = [.. addresses]
                });
            }

            return scopes;
        }

        /// <summary>
        /// Der eigentliche Lauf. Gemeinsam fuer den vollen Scan und das
        /// erneute Pruefen einzelner Geraete - beide unterscheiden sich nur in
        /// den Bereichen, alles Uebrige davor und danach ist dasselbe.
        /// </summary>
        // ------------------------------------------------- Satellitenbetrieb

        /// <summary>
        /// Verteilt die Bereiche, die einem Satelliten gehoeren, an ihre
        /// Satelliten - <b>ein</b> Auftrag je Satellit mit allen seinen
        /// Bereichen, damit nichts doppelt gescannt wird (SATELLIT.md,
        /// Abschnitt 3).
        /// </summary>
        private async Task DispatchToSatellitesAsync(List<ScanScope> remote)
        {
            List<string> scanning = [];
            List<string> missing = [];

            foreach (IGrouping<string, ScanScope> group in
                     remote.GroupBy(s => s.ScannedBy, StringComparer.OrdinalIgnoreCase))
            {
                // Zugeordnet wird ueber die Kennung, nicht ueber den Namen: der
                // Name ist aenderbar, und eine Umbenennung darf keine
                // Zuordnung zerreissen.
                Satellite? satellite = SatelliteEditor.ById(group.Key);

                if (satellite is null || !satellite.IsConnected || !satellite.Approved)
                {
                    // Nicht erreichbar heisst "nicht gescannt" und nicht
                    // stillschweigend oertlich gescannt - sonst stuenden im
                    // Ergebnis Zahlen, die anders zustande kamen als
                    // angenommen.
                    missing.Add(satellite?.Name ?? SatelliteEditor.DisplayNameOf(group.Key));
                    continue;
                }

                string jobText = JobRequest.Format(
                    [.. group],
                    Methods.Where(m => m.IsEffective).Select(m => m.Method.Id),
                    Settings.TcpPorts,
                    Settings.UdpPorts,
                    Settings.PortTimeoutMs,

                    // "Nur abfragen, was schon dasteht" kommt jetzt vom
                    // Satelliten und nicht mehr aus den Haupteinstellungen:
                    // was sich einzuschraenken lohnt, haengt an seinem Segment.
                    // Ein Bereich voller offline-Adressen kostet bei der
                    // Diensterkennung jedes Mal das volle Zeitlimit je Port -
                    // an einem anderen Standort kann genau das falsch sein.
                    satellite.EffectiveOnlyKnownFor(
                        Methods.Where(m => m.CanRestrictToKnown).Select(m => m.Id)),

                    satellite.CrossCheckOnlyKnownTargets);

                if (await SatelliteEditor.SendJobAsync(satellite, jobText, CancellationToken.None))
                {
                    scanning.Add(satellite.Name);
                }
                else
                {
                    // In die Meldung gehoert der Name, nicht die Kennung.
                    missing.Add(satellite.Name);
                }
            }

            SatelliteScanNote = Describe(scanning, missing);
        }

        /// <summary>
        /// Ein Satz fuer die Statuszeile darueber, was gerade bei den
        /// Satelliten laeuft. Leer, wenn keiner beteiligt ist.
        /// <para>
        /// Steht als eigene Eigenschaft und nicht nur als einmalig gesetzter
        /// Text, weil der oertliche Lauf die Statuszeile waehrenddessen
        /// weiterschreibt: ohne diesen Merker waere der Hinweis nach dem ersten
        /// Verfahren wieder weg, obwohl der Satellit noch arbeitet.
        /// </para>
        /// </summary>
        public string SatelliteScanNote { get; private set; } = string.Empty;

        /// <summary>Was uebersprungen oder ersatzweise oertlich gescannt wurde.</summary>
        private string _skippedNote = string.Empty;

        /// <summary>
        /// Setzt die Statuszeile aus dem eigentlichen Befund und dem, was es
        /// ueber die Satelliten zu sagen gibt - an einer Stelle, damit die
        /// Hinweise nicht an drei Orten getrennt zusammengebaut werden.
        /// </summary>
        private string WithSatelliteNotes(string main) =>
            string.Join("  ·  ", new[] { main, SatelliteScanNote, _skippedNote }
                .Where(t => !string.IsNullOrWhiteSpace(t)));

        /// <summary>
        /// Rueckfragen an den Nutzer. Setzt die Ansicht.
        /// <para>
        /// Ohne gesetzten Dienst - im Dienstbetrieb und in Tests - wird nicht
        /// gefragt, und die Antwort gilt als "nein". Das ist die sichere Seite:
        /// lieber ein Bereich nicht gescannt als einer mit falschen Zahlen, und
        /// vor einem Dienst sitzt niemand, der antworten koennte.
        /// </para>
        /// </summary>
        public IDialogService? Dialogs { get; set; }

        /// <summary>
        /// Ist dieser Satellit gerade ansprechbar - verbunden und freigegeben?
        /// <para>
        /// Gesucht wird ueber die Kennung, denn genau die steht in
        /// <c>ScanScope.ScannedBy</c>. Vorher wurde hier gegen den
        /// <em>Namen</em> verglichen: das traf nie zu, jeder Bereich galt als
        /// "Satellit nicht verbunden", und der Lauf fragte, ob er stattdessen
        /// von hier scannen soll - obwohl der Satellit verbunden dastand.
        /// </para>
        /// </summary>
        /// <summary>
        /// Gehoert der Bereich einem Satelliten, den es wirklich gibt?
        /// <para>
        /// Leer heisst "von diesem Rechner aus" - und ein Wert, zu dem kein
        /// Satellit mehr existiert, ebenso. Das ist der Fall aus alten
        /// Staenden: in der Auswahl steht dann nichts, weil der Wert zu keinem
        /// Eintrag passt. Zaehlte er trotzdem als Satellitenbereich, meldete
        /// der Lauf einen "(unknown satellite)", der nicht verbunden sei -
        /// eine Rueckfrage zu einem Satelliten, den niemand je eingerichtet
        /// hat. Was die Auswahl leer zeigt, wird auch so behandelt.
        /// </para>
        /// </summary>
        private bool IsAssignedToSatellite(ScanScope scope) =>
            scope.IsScannedRemotely && SatelliteEditor.ById(scope.ScannedBy) is not null;

        private bool IsSatelliteReady(string id)
        {
            Satellite? satellite = SatelliteEditor.ById(id);
            return satellite is not null && satellite.IsConnected && satellite.Approved;
        }

        /// <summary>
        /// Fragt nach, was mit Bereichen geschehen soll, deren Satellit nicht
        /// erreichbar ist.
        /// <para>
        /// Gefragt wird, statt still zu entscheiden: von hier aus gescannt
        /// kommt ein anderes Ergebnis heraus - kein ARP, alles ueber den
        /// Router, laengere Laufzeiten. Das kann im Einzelfall trotzdem
        /// gewuenscht sein, aber es ist eine Entscheidung und keine
        /// Nebenwirkung. Darum steht der Unterschied auch im Text.
        /// </para>
        /// </summary>
        private async Task<bool> AskToScanLocallyAsync(List<ScanScope> orphaned)
        {
            if (Dialogs is null) return false;

            // Im Bereich steht die Kennung; in einer Meldung will die niemand
            // lesen - dort gehoert der Name hin.
            List<string> names = [.. orphaned
                .Select(s => SatelliteEditor.DisplayNameOf(s.ScannedBy))
                .Where(n => !string.IsNullOrWhiteSpace(n))
                .Distinct(StringComparer.OrdinalIgnoreCase)];

            string who = names.Count == 1
                ? $"Satellite \"{names[0]}\" is not connected."
                : $"{names.Count} satellites are not connected ({string.Join(", ", names)}).";

            string ranges = string.Join(Environment.NewLine,
                orphaned.Select(s => $"   {s.GroupDescription}   {s.FirstIP} - {s.LastIP}"));

            string message =
                $"{who}{Environment.NewLine}{Environment.NewLine}" +
                $"Scan these ranges from this machine instead?{Environment.NewLine}{Environment.NewLine}" +
                $"{ranges}{Environment.NewLine}{Environment.NewLine}" +
                "Note that the result will not be the same. From here there is no ARP - it does not cross a router - " +
                "everything goes the long way through the router, and response times are longer. Devices that only " +
                $"answer to ARP will be missing.{Environment.NewLine}{Environment.NewLine}" +
                "No means these ranges are left out of this run.";

            return await Dialogs.ConfirmAsync(message, "Satellite not connected");
        }

        /// <summary>
        /// Warnt vor einem Lauf, der nichts finden kann, und fragt, ob er
        /// trotzdem starten soll.
        /// <para>
        /// Der Fall: jedes gewaehlte Verfahren ist auf "nur Geraete, die schon
        /// in der Tabelle stehen" beschraenkt, und es steht keines darin. Die
        /// Kuerzung auf bekannte Ziele laesst dann nichts uebrig, jedes
        /// Verfahren laeuft ueber eine leere Liste, und am Ende steht ein
        /// Ergebnis von null Geraeten - ohne Fehler, denn aus Sicht der
        /// Verfahren ist genau das richtig.
        /// </para>
        /// <para>
        /// Ein Satellit ist davon staerker betroffen als diese Anlage: sein
        /// Auftrag laeuft gegen einen frisch angelegten, <em>leeren</em>
        /// Bestand, nicht gegen die Tabelle des Hauptscanners. Was hier steht,
        /// kennt er nicht. Bei ihm genuegt also die Beschraenkung allein, damit
        /// nichts herauskommt.
        /// </para>
        /// <para>
        /// Kein Grund zur Warnung ist ein Verfahren, das selbst sucht: eines
        /// ohne Zielliste (Rundruf wie SSDP oder mDNS) oder eines, das nicht
        /// beschraenkt ist. Das fuellt die Tabelle, und die beschraenkten
        /// danach haben etwas zu fragen - genau dafuer ist die Abstufung da.
        /// </para>
        /// </summary>
        private async Task<bool> ConfirmRunWithoutTargetsAsync(
            List<ScanScope> local, List<ScanScope> remote)
        {
            List<ScanMethodChoice> chosen = [.. Methods.Where(m => m.IsEffective)];

            if (chosen.Count == 0) return true;

            IReadOnlyList<string> restrictable =
                [.. chosen.Where(m => m.CanRestrictToKnown).Select(m => m.Id)];

            // Findet unter den gewaehlten Verfahren eines von selbst Geraete?
            bool NothingDiscovers(Func<string, bool> isRestricted) =>
                chosen.All(m => m.CanRestrictToKnown && isRestricted(m.Id));

            List<string> affected = [];

            if (local.Count > 0 && NothingDiscovers(Settings.IsRestrictedToKnown))
            {
                bool tableIsEmpty;
                lock (_store.SyncRoot) tableIsEmpty = _store.Devices.Count == 0;

                if (tableIsEmpty) affected.Add("this machine (the table is still empty)");
            }

            foreach (IGrouping<string, ScanScope> group in
                     remote.GroupBy(s => s.ScannedBy, StringComparer.OrdinalIgnoreCase))
            {
                Satellite? satellite = SatelliteEditor.ById(group.Key);
                if (satellite is null) continue;

                HashSet<string> restricted =
                    new(satellite.EffectiveOnlyKnownFor(restrictable), StringComparer.OrdinalIgnoreCase);

                if (NothingDiscovers(restricted.Contains))
                {
                    affected.Add($"satellite \"{satellite.Name}\" (it starts every job with an empty table)");
                }
            }

            if (affected.Count == 0) return true;

            // Ohne Dialogdienst - im Dienstbetrieb und in Tests - wird nicht
            // gefragt und auch nicht abgebrochen: der Lauf verhaelt sich dann
            // wie bisher. Anders als bei einem nicht erreichbaren Satelliten
            // steht hier kein falsches Ergebnis zu befuerchten, sondern nur ein
            // leeres.
            if (Dialogs is null) return true;

            string who = string.Join(Environment.NewLine, affected.Select(a => $"   {a}"));
            string methods = string.Join(", ", chosen.Select(m => m.DisplayName));

            string message =
                $"Every selected method is limited to devices that are already in the table, " +
                $"and there are none to work from:{Environment.NewLine}{Environment.NewLine}" +
                $"{who}{Environment.NewLine}{Environment.NewLine}" +
                $"Selected: {methods}{Environment.NewLine}{Environment.NewLine}" +
                $"Methods like Services or TCP ports do not look for devices - they ask the ones " +
                $"already found. Without a device to ask, this run reports nothing." +
                $"{Environment.NewLine}{Environment.NewLine}" +
                $"Add a method that finds devices by itself - Ping or ARP request - or switch off " +
                $"\"only devices in table\" for the methods you picked. For a satellite that setting " +
                $"is per satellite, under \"Scan scope for this satellite\"." +
                $"{Environment.NewLine}{Environment.NewLine}" +
                $"Start anyway?";

            return await Dialogs.ConfirmAsync(message, "This scan would find nothing");
        }

        private static string Describe(List<string> scanning, List<string> missing)
        {
            List<string> parts = [];

            if (scanning.Count == 1) parts.Add($"Satellite \"{scanning[0]}\" is scanning");
            else if (scanning.Count > 1) parts.Add($"{scanning.Count} satellites are scanning ({string.Join(", ", scanning)})");

            if (missing.Count == 1) parts.Add($"\"{missing[0]}\" is not connected - its ranges were not scanned");
            else if (missing.Count > 1) parts.Add($"{missing.Count} satellites are not connected - their ranges were not scanned");

            return string.Join(" · ", parts);
        }

        /// <summary>
        /// Fuehrt einen Auftragstext aus - die Seite des Satelliten. Laeuft
        /// gegen einen <em>eigenen</em> Bestand: zurueckgeschickt wird, was
        /// dieser Auftrag gefunden hat, nicht der ganze Bestand des
        /// Satellitenrechners.
        /// </summary>
        public async Task<string> RunJobAsync(
            string jobText, IProgress<ProgressPayload> progress, CancellationToken token)
        {
            JobRequest job = JobRequest.Parse(jobText);

            if (!job.IsValid) throw new InvalidOperationException(job.Problem ?? "The job could not be read.");

            ScanSettings settings = new()
            {
                PortTimeoutMs = job.TimeoutMs ?? Settings.PortTimeoutMs,
                SnmpCommunity = Settings.SnmpCommunity
            };

            settings.TcpPorts.AddRange(job.TcpPorts.Count > 0 ? job.TcpPorts : Settings.TcpPorts);
            settings.UdpPorts.AddRange(job.UdpPorts.Count > 0 ? job.UdpPorts : Settings.UdpPorts);

            // Die Beschraenkung kommt aus dem Auftrag, nicht aus den eigenen
            // Einstellungen: es zaehlt, was der Hauptscanner angehakt hat, und
            // nicht, was jemand am Satelliten einmal eingestellt hat.
            foreach (string id in job.OnlyKnownFor) settings.OnlyKnownTargetsFor.Add(id);

            // Ebenso der Quervergleich: nennt der Auftrag ihn nicht, bleibt es
            // bei der Vorgabe dieser Anlage.
            settings.CrossCheckOnlyKnownTargets =
                job.CrossCheckOnlyKnown ?? Settings.CrossCheckOnlyKnownTargets;

            List<IScanMethod> methods = job.MethodIds.Count > 0
                ? [.. _engine.Methods.Where(m => job.MethodIds.Contains(m.Id, StringComparer.OrdinalIgnoreCase))]
                : [.. Methods.Where(m => m.IsEffective).Select(m => m.Method)];

            DeviceStore jobStore = new();

            // Fortschritt: derselbe Stand, den die oertliche Anzeige zeigt -
            // laufendes Verfahren, sein Anteil und seine drei Zahlen.
            //
            // Frueher wurde nur bei *fertigem* Verfahren gemeldet, und die
            // Prozentzahl war der Anteil fertiger Verfahren. Bei drei
            // Verfahren hiess das: 0, dann lange nichts, dann 33. Waehrend
            // eines langen Verfahrens war von aussen nicht zu unterscheiden,
            // ob der Satellit arbeitet oder haengt.
            int done = 0;
            List<string> completed = [];

            // Der letzte bekannte Stand, aus dem jede Meldung gebaut wird.
            ScanProgress? latest = null;
            DateTimeOffset lastSent = DateTimeOffset.MinValue;
            string lastMethod = string.Empty;
            Lock progressSync = new();

            ProgressPayload BuildPayload()
            {
                ScanProgress? p = latest;

                return new ProgressPayload
                {
                    // Der Stand des laufenden Verfahrens - "Ping 40 %".
                    Percent = p is null || p.Total <= 0
                        ? 0
                        : (int)Math.Clamp((double)p.Current / p.Total * 100, 0, 100),
                    Current = p?.MethodName ?? string.Empty,
                    Step = done + 1,
                    Steps = methods.Count,
                    Sent = p?.Current ?? 0,
                    Answered = p?.Responded ?? 0,
                    Total = p?.Total ?? 0,
                    // Wie oertlich: ein Strich statt einer leeren Zeile - sonst
                    // sieht "noch nichts fertig" aus wie "Anzeige kaputt".
                    Done = completed.Count == 0 ? "-" : string.Join(", ", completed),
                    Pending = Listed(methods.Select(m => m.DisplayName).Where(n => !completed.Contains(n)))
                };

                static string Listed(IEnumerable<string> names)
                {
                    string text = string.Join(", ", names);
                    return text.Length == 0 ? "-" : text;
                }
            }

            // Gemeldet wird bei Aenderung, aber hoechstens alle zwei Sekunden -
            // und spaetestens alle zehn, auch wenn sich nichts geruehrt hat.
            //
            // Ungebremst waere es eine Meldung je geprueftem Ziel: bei 254
            // Zielen und einem Dutzend Verfahren Tausende von Nachrichten,
            // nur damit ein Balken zappelt. Ganz ohne Untergrenze stuende die
            // Anzeige dagegen still, sobald ein Verfahren lange in
            // Zeitueberschreitungen laeuft - und genau dann will man sehen,
            // dass die Verbindung noch steht.
            TimeSpan minGap = TimeSpan.FromSeconds(2);
            TimeSpan heartbeat = TimeSpan.FromSeconds(10);

            void SendProgress(bool force)
            {
                ProgressPayload payload;

                lock (progressSync)
                {
                    // Vor der ersten Meldung der Engine gibt es nichts zu
                    // berichten. Der Taktgeber wuerde sonst das "starting"
                    // durch eine leere Zeile ersetzen.
                    if (latest is null) return;

                    DateTimeOffset now = DateTimeOffset.UtcNow;

                    if (!force && now - lastSent < minGap) return;

                    lastSent = now;
                    payload = BuildPayload();
                }

                progress.Report(payload);
            }

            void OnEngineProgress(ScanProgress p)
            {
                bool methodChanged;

                lock (progressSync)
                {
                    latest = p;
                    methodChanged = !string.Equals(p.MethodName, lastMethod, StringComparison.Ordinal);
                    if (methodChanged) lastMethod = p.MethodName;
                }

                // Ein Verfahrenswechsel geht sofort raus: darauf wartet man,
                // und zwei Sekunden spaeter waere die Zahl daneben schon eine
                // andere.
                SendProgress(methodChanged);
            }

            void OnFinished(ScanMethodOutcome outcome)
            {
                lock (progressSync)
                {
                    done++;
                    completed.Add(outcome.MethodName);
                }

                SendProgress(true);
            }

            _engine.MethodFinished += OnFinished;
            _engine.ProgressChanged += OnEngineProgress;

            // Der Taktgeber fuer den Fall, dass sich nichts aendert.
            using CancellationTokenSource beatStop = CancellationTokenSource.CreateLinkedTokenSource(token);

            Task beat = Task.Run(async () =>
            {
                try
                {
                    using PeriodicTimer timer = new(heartbeat);
                    while (await timer.WaitForNextTickAsync(beatStop.Token))
                    {
                        SendProgress(true);
                    }
                }
                catch (OperationCanceledException) { }
            }, CancellationToken.None);

            // Der Abbruch muss die Engine anhalten, nicht nur das Warten
            // beenden. Ohne das liefe der Scan nach einem Stopp weiter, waehrend
            // oben schon "abgebrochen" gemeldet wird - genau so, wie es der
            // oertliche Stopp-Knopf mit _engine.Stop() macht.
            using CancellationTokenRegistration stopOnCancel = token.Register(() => _engine.Stop());

            try
            {
                progress.Report(new ProgressPayload
                {
                    Percent = 0,
                    Current = "starting",
                    Step = 1,
                    Steps = methods.Count,
                    Pending = string.Join(", ", methods.Select(m => m.DisplayName))
                });

                await Task.Run(
                    () => _engine.RunAsync(job.Scopes, [.. methods.Select(m => m.Id)], settings, jobStore),
                    token);
            }
            catch (OperationCanceledException)
            {
                // Abbruch wirft den Fund nicht weg: was bis dahin gefunden
                // wurde, geht zurueck an den Auftraggeber.
                //
                // Frueher wurde hier nichts geliefert, damit ein halbes
                // Ergebnis nicht wie ein vollstaendiges aussieht. Der Einwand
                // bleibt richtig - nur ist die Antwort darauf, das Ergebnis zu
                // kennzeichnen, und nicht, die Arbeit wegzuwerfen. Der
                // Auftraggeber markiert es als abgebrochen (siehe
                // MessageType.Result, Feld Partial).
            }
            finally
            {
                _engine.MethodFinished -= OnFinished;
                _engine.ProgressChanged -= OnEngineProgress;

                beatStop.Cancel();
                try { await beat; } catch (OperationCanceledException) { }
            }

            progress.Report(new ProgressPayload
            {
                Percent = 100,
                Step = methods.Count,
                Steps = methods.Count,
                Done = string.Join(", ", completed)
            });

            return DeviceStoreFile.ToJson(jobStore);
        }

        /// <summary>
        /// Traegt nach, welche Bereiche auf den gerade gewaehlten Satelliten
        /// zeigen - fuer die Anzeige in der Satellitenverwaltung.
        /// </summary>
        /// <summary>
        /// Ein Bereich hat sich geaendert. Nur die Felder, die in der Liste
        /// stehen, loesen ein Neubauen aus - <c>IsSelected</c> etwa aendert
        /// sich bei jedem Haken im Kommandobalken und haette die Liste sonst
        /// dauernd neu gebaut.
        /// </summary>
        private void OnScopeChangedForSatellite(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName is nameof(ScanScope.ScannedBy)
                               or nameof(ScanScope.GroupDescription)
                               or nameof(ScanScope.DeviceDescription)
                               or nameof(ScanScope.Kind)
                               or nameof(ScanScope.FirstIP)
                               or nameof(ScanScope.LastIP)
                               or nameof(ScanScope.Prefix)
                               or nameof(ScanScope.PrefixLength))
            {
                RefreshRangesOfSatellite();
            }
        }

        /// <summary>
        /// Schreibt Bereiche, die noch auf den <em>Namen</em> eines Satelliten
        /// zeigen, einmalig auf dessen Kennung um.
        /// <para>
        /// Wird beim Laden aufgerufen. Findet sich kein Satellit des Namens,
        /// wird der Wert geleert: der Bereich laeuft dann von diesem Rechner
        /// aus. Ein Wert, der zu keinem Eintrag passt, laesst die Auswahl in
        /// der Maske leer stehen - und was dort leer steht, muss auch leer
        /// bedeuten, sonst fragt der Lauf nach einem Satelliten, der in der
        /// Maske gar nicht auftaucht.
        /// </para>
        /// </summary>
        public void MigrateScannedByToIds()
        {
            int changed = 0;

            foreach (ScanScope scope in Scopes)
            {
                if (string.IsNullOrWhiteSpace(scope.ScannedBy)) continue;

                string id = SatelliteEditor.ResolveToId(scope.ScannedBy);

                if (!string.Equals(id, scope.ScannedBy, StringComparison.Ordinal))
                {
                    scope.ScannedBy = id;
                    changed++;
                }
            }

            if (changed > 0) ScopeEditor.Save();
        }

        public void RefreshRangesOfSatellite()
        {
            SatelliteEditor.RangesOfSelected.Clear();

            string? id = SatelliteEditor.Selected?.Id;
            if (string.IsNullOrWhiteSpace(id)) return;

            foreach (ScanScope scope in Scopes.Where(s =>
                         string.Equals(s.ScannedBy, id, StringComparison.OrdinalIgnoreCase)))
            {
                string where = scope.Kind switch
                {
                    ScanScopeKind.IPv4Range => $"{scope.FirstIP} - {scope.LastIP}",
                    ScanScopeKind.IPv6Prefix => $"{scope.Prefix}/{scope.PrefixLength}",
                    _ => scope.DeviceDescription
                };

                SatelliteEditor.RangesOfSelected.Add($"{scope.GroupDescription}   {where}");
            }
        }

        /// <summary>Mischt ein Ergebnis ein, das ein Satellit geschickt hat.</summary>
        public void MergeSatelliteResult(string satelliteName, string devicesJson, bool partial = false)
        {
            try
            {
                List<Device> devices = DeviceStoreFile.FromJson(devicesJson);
                int taken = _store.MergeFrom(devices);

                // Beim Abbruch steht dabei, dass der Lauf nicht durch war.
                // Die Geraete sind echt - aber die Abwesenheit eines Geraets
                // sagt hier nichts, und genau das muss an der Meldung haengen.
                StatusText = partial
                    ? $"\"{satelliteName}\" was stopped - {taken} device(s) found so far (range not fully scanned)."
                    : $"\"{satelliteName}\" reported {taken} device(s).";

                lock (_store.SyncRoot)
                {
                    DuplicateDetector.Analyze(_store.Devices);
                }

                FindingsView.Refresh();
            }
            catch (Exception ex)
            {
                StatusText = $"The result from \"{satelliteName}\" could not be read: {ex.Message}";
            }
        }

        private async Task RunAsync(List<ScanScope> scopes)
        {
            // Ganz am Anfang, noch vor "Scan running..." und dem Ablaufplan:
            // kann dieser Lauf ueberhaupt etwas finden? Sind alle gewaehlten
            // Verfahren auf bekannte Geraete beschraenkt und es gibt keine,
            // laeuft er ins Leere - siehe die Erklaerung an der Pruefung.
            // Weiter unten gefragt, staende waehrend der Rueckfrage schon
            // "Scan running..." in der Zeile, obwohl noch nichts laeuft.
            if (!await ConfirmRunWithoutTargetsAsync(
                    [.. scopes.Where(s => !s.IsScannedRemotely)],
                    [.. scopes.Where(s => s.IsScannedRemotely)]))
            {
                StatusText = "Scan cancelled - nothing would have been scanned.";
                return;
            }

            IsRunning = true;
            OnPropertyChanged(nameof(CanStart));
            LastSkipped.Clear();
            StatusText = "Scan running...";

            // Sonst stehen an den nicht gewaehlten Verfahren noch die Zahlen
            // des vorherigen Laufs, als haetten sie gerade gearbeitet.
            foreach (ScanMethodChoice method in Methods) method.ResetProgress();

            List<ScanMethodChoice> chosen = [.. Methods.Where(m => m.IsEffective)];
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
                    // Task.Run ist hier kein Beiwerk, sondern der Grund, warum
                    // sich die Tabelle waehrend des Laufs ueberhaupt fuellt.
                    //
                    // Kein Modul der Kette benutzt ConfigureAwait(false). Wird
                    // die Engine vom Oberflaechen-Thread aus abgewartet, kehrt
                    // damit *jede* Fortsetzung dorthin zurueck: bei 254 Zielen
                    // sind das die Wartezeiten aller Proben, die Auswertung
                    // jeder Antwort und die gesamte Zuordnung im Speicher - alles
                    // auf dem einen Thread, der nebenher zeichnen soll. Die
                    // Tabelle zieht dann zwar alle 400 ms nach, kommt aber gegen
                    // die Flut nicht an und wirkt, als fuelle sie sich erst am
                    // Schluss.
                    //
                    // Task.Run startet ohne Synchronisierungskontext; die
                    // Fortsetzungen laufen damit im Thread-Pool, und der
                    // Oberflaechen-Thread hat nur noch das Zeichnen zu tun.
                    // Bereiche, die ein Satellit uebernimmt, werden hier
                    // abgespalten und dorthin geschickt. Sie oertlich
                    // mitzuscannen waere schlechter als gar nicht: ohne ARP,
                    // ueber den Router, mit anderen Laufzeiten - und der
                    // Bereich waere doppelt gescannt.
                    List<ScanScope> remote = [.. scopes.Where(IsAssignedToSatellite)];
                    List<ScanScope> local = [.. scopes.Where(s => !IsAssignedToSatellite(s))];

                    SatelliteScanNote = string.Empty;
                    _skippedNote = string.Empty;

                    if (remote.Count > 0)
                    {
                        // Zuerst die, deren Satellit gar nicht da ist. Sie
                        // stillschweigend zu ueberspringen war die bisherige
                        // Regel; jetzt entscheidet der Nutzer, ob sie
                        // ersatzweise von hier laufen sollen.
                        List<ScanScope> orphaned = [.. remote.Where(s => !IsSatelliteReady(s.ScannedBy))];

                        if (orphaned.Count > 0)
                        {
                            remote = [.. remote.Except(orphaned)];

                            if (await AskToScanLocallyAsync(orphaned))
                            {
                                local.AddRange(orphaned);
                                _skippedNote = orphaned.Count == 1
                                    ? "1 range whose satellite is offline was scanned from here"
                                    : $"{orphaned.Count} ranges whose satellites are offline were scanned from here";
                            }
                            else
                            {
                                _skippedNote = orphaned.Count == 1
                                    ? "1 range was left out - its satellite is not connected"
                                    : $"{orphaned.Count} ranges were left out - their satellites are not connected";
                            }
                        }
                    }

                    if (remote.Count > 0)
                    {
                        await DispatchToSatellitesAsync(remote);

                        // Sofort sichtbar machen: der Satellit arbeitet ab
                        // jetzt, und bei einem reinen Satellitenlauf ist das
                        // die einzige Meldung, die es zu sehen gibt.
                        if (SatelliteScanNote.Length > 0) StatusText = WithSatelliteNotes(string.Empty);
                    }

                    if (local.Count == 0)
                    {
                        // Die Engine gar nicht erst anwerfen, wenn hier nichts
                        // zu tun ist.
                        //
                        // Ohne diese Sperre liefe sie mit einer leeren
                        // Bereichsliste - und die Rundruf-Verfahren (SSDP,
                        // mDNS, WS-Discovery) fragen nicht nach Zielen,
                        // sondern schicken ihr Paket an alle auf den oertlichen
                        // Adaptern. Sie faenden also Geraete *hier*, obwohl
                        // jeder gewaehlte Bereich einem Satelliten gehoert.
                        // Genau das darf nicht passieren: ein Bereich laeuft
                        // entweder oertlich oder ueber einen Satelliten
                        // (SATELLIT.md, Abschnitt 3).
                        StatusText = WithSatelliteNotes("Nothing runs from this machine");

                        // Der Ablaufplan gehoert zum *oertlichen* Lauf - und
                        // der findet hier nicht statt. Bliebe er stehen,
                        // zeigte die Zeile "done: -" und saemtliche Verfahren
                        // als ausstehend, und zwar bis zum Sankt-Nimmerleins-
                        // Tag: es laeuft ja nichts, was sie abarbeiten
                        // koennte. Genau daneben stuende "Nothing runs from
                        // this machine". Wo der Satellit arbeitet, steht in
                        // seiner eigenen Anzeige.
                        _planned.Clear();
                        _done.Clear();
                        NotifyPlanChanged();
                    }
                    else
                    {
                        ScanRunResult result = await Task.Run(() =>
                            _engine.RunAsync(local, methods, Settings, _store));

                        // Ab hier wieder auf dem Oberflaechen-Thread. Erst jetzt die
                        // Doppelbelegungen bestimmen: die Auswertung schreibt
                        // gebundene Eigenschaften am Geraet, und sie will den
                        // vollstaendigen Bestand sehen - waehrend des Laufs waere
                        // jeder Befund vorlaeufig.
                        lock (_store.SyncRoot)
                        {
                            result.ConflictCount = DuplicateDetector.Analyze(_store.Devices);
                        }

                        // Der oertliche Lauf ist durch - der Satellit meist
                        // noch nicht. Sein Hinweis bleibt darum hinten dran
                        // stehen, sonst sieht der Lauf beendet aus, waehrend
                        // ein Teil der Bereiche noch gescannt wird.
                        StatusText = WithSatelliteNotes(Describe(result));

                        // Der Quervergleich haengt am Ergebnis des Laufs und
                        // laeuft darum danach, nicht als eigenes Verfahren mittendrin.
                        //
                        // Ueber "local" und nicht ueber alle Bereiche: die
                        // Namensserver eines Satellitenbereichs stehen in
                        // dessen Segment. Von hier aus befragt, laufen sie ins
                        // Leere oder - schlimmer - antwortet ein gleichnamiger
                        // Server hier, und der Vergleich meldete eine
                        // Abweichung, die es gar nicht gibt.
                        if (Settings.CrossCheckDnsServers && !result.WasCancelled)
                        {
                            await CrossCheckDnsAsync(local);
                        }
                    }

                    // Die Regeln laufen von selbst, sobald der Lauf durch ist -
                    // ein Befund, den man erst durch einen Klick sichtbar
                    // machen muss, wird nicht gefunden.
                    FindingsView.Refresh();
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

        // ------------------------------------------------- DNS-Quervergleich

        /// <summary>
        /// Prueft nach einem Lauf jede aufgeloeste Adresse gegen jeden bekannten
        /// Namensserver einzeln. Die Server kommen aus den Bereichen, die
        /// gerade gescannt wurden - sonst pruefte man gegen andere Server als
        /// die, mit denen der Lauf gearbeitet hat.
        /// </summary>
        private async Task CrossCheckDnsAsync(List<ScanScope> scopes)
        {
            List<string> servers = [.. scopes
                .SelectMany(s => s.DnsServers.Split([',', ';', '\r', '\n'],
                    StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                .Distinct(StringComparer.OrdinalIgnoreCase)];

            List<Device> devices;

            lock (_store.SyncRoot)
            {
                // Nur Geraete mit Namen: wo nie ein Name im Spiel war, gibt es
                // auch nichts, worueber die Server sich uneinig sein koennten.
                devices = [.. _store.Devices.Where(d => d.PrimaryAddress is not null
                                                     && (d.WasLookedUp || d.HostName.Length > 0)
                                                     && (!Settings.CrossCheckOnlyKnownTargets || d.IsOnline))];
            }

            if (devices.Count == 0) return;

            StatusText = $"Comparing {devices.Count} addresses across the DNS servers...";

            int mismatches = 0;

            foreach (Device device in devices)
            {
                string? address = device.PrimaryAddress?.Info.Canonical;
                if (string.IsNullOrWhiteSpace(address)) continue;

                try
                {
                    DnsCrossCheckResult check = await DnsCrossCheck.RunAsync(address, servers);

                    device.DnsCrossCheck = check;
                    if (check.HasMismatch) mismatches++;
                }
                catch (Exception)
                {
                    // Ein Geraet, das sich nicht pruefen laesst, darf den
                    // Vergleich der uebrigen nicht beenden.
                }
            }

            StatusText = mismatches == 0
                ? StatusText + " All DNS servers agree."
                : StatusText + $" {mismatches} address(es) are answered differently - see Findings.";
        }

        /// <summary>
        /// Derselbe Vergleich fuer die markierten Zeilen, aus dem Kontextmenue.
        /// Das Werkzeug fuer den Einzelfall: man hat ein Geraet im Verdacht und
        /// will wissen, ob alle Server dasselbe dazu sagen.
        /// </summary>
        [RelayCommand]
        private async Task ResolveAcrossDnsServersAsync()
        {
            IReadOnlyList<Device> targets = Devices.ActionTargets;

            if (targets.Count == 0)
            {
                StatusText = "Select a device first.";
                return;
            }

            List<string> servers = [.. Scopes
                .SelectMany(s => s.DnsServers.Split([',', ';', '\r', '\n'],
                    StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                .Distinct(StringComparer.OrdinalIgnoreCase)];

            StatusText = $"Resolving {targets.Count} address(es) across the DNS servers...";

            int mismatches = 0;

            foreach (Device device in targets)
            {
                string? address = device.PrimaryAddress?.Info.Canonical;
                if (string.IsNullOrWhiteSpace(address)) continue;

                try
                {
                    DnsCrossCheckResult check = await DnsCrossCheck.RunAsync(address, servers);

                    device.DnsCrossCheck = check;
                    if (check.HasMismatch) mismatches++;

                    // Auch ins Detailpanel, nicht nur in die Befunde: wer
                    // gezielt ein Geraet prueft, will die Antworten aller
                    // Server nebeneinander sehen - auch die uebereinstimmenden.
                    device.Details["DNS servers"] = check.Report;
                    device.NotifyDisplayChanged();
                }
                catch (Exception ex)
                {
                    StatusText = $"DNS comparison failed: {ex.Message}";
                    return;
                }
            }

            FindingsView.Refresh();

            StatusText = mismatches == 0
                ? "All DNS servers agree. The answers are in the detail panel."
                : $"{mismatches} of {targets.Count} address(es) are answered differently - see Findings.";
        }

        /// <summary>
        /// Sucht einen einzelnen Dienst ueber den gesamten Portbereich.
        /// <para>
        /// Der Fall, fuer den es das gibt: ein Dienst laeuft, aber nicht auf
        /// seinem ueblichen Port, und der regulaere Scan sieht ihn darum nie.
        /// Alle 65 536 Ports dauern - darum je Aufruf ein Geraet und ein
        /// Dienst, statt es beilaeufig im grossen Lauf mitzuschleppen.
        /// </para>
        /// </summary>
        [RelayCommand]
        private async Task FindServicePortAsync(ServiceType service)
        {
            if (IsRunning)
            {
                StatusText = "A scan is already running.";
                return;
            }

            Device? device = Devices.ActionTargets.FirstOrDefault();
            string? address = device?.PrimaryAddress?.Info.Canonical;

            if (device is null || string.IsNullOrWhiteSpace(address))
            {
                StatusText = "Select a device with an address first.";
                return;
            }

            IsRunning = true;
            OnPropertyChanged(nameof(CanStart));

            // Dieselbe Dienstdatei wie der regulaere Dienstscan - sonst suchte
            // die Portsuche nach einem anderen Dienst als der, den man in der
            // Dienstverwaltung eingestellt hat.
            ScanningMethod_Services scanner = new(
                Path.Combine(SettingsFolder ?? string.Empty, "services.xml"));

            // Ab hier ist die Suche fuer den Stop-Knopf erreichbar.
            _portSearch = scanner;
            _portSearchStopped = false;

            // Auch hier ueber den Oberflaechen-Thread: die Suche laeuft im
            // Thread-Pool, und der Fortschrittsbalken ist gebunden.
            void OnProgress(int current, int responded, int total) => OnUi(() =>
            {
                ProgressCurrent = current;
                ProgressTotal = total;
                OnPropertyChanged(nameof(ProgressFraction));
            });

            try
            {
                CurrentMethodName = $"{service} on {address}, all ports";
                StatusText = $"Searching all 65536 ports of {device.DisplayName} for {service}...";

                scanner.FindServicePortProgressUpdated += OnProgress;

                // Wie beim grossen Lauf in den Thread-Pool: 65 536 Proben mit
                // ihren Fortsetzungen auf dem Oberflaechen-Thread legen das
                // Fenster lahm - bis hin zum Stop-Knopf, der dann nicht mehr
                // rechtzeitig drankommt.
                IPToScan found = await Task.Run(() => scanner.FindServicePortAsync(
                    new IPToScan { IPorHostname = address }, service));

                // Offen oder antwortend zaehlt. "Filtered" heisst, dass eine
                // Firewall dazwischensteht - das ist kein Fund des Dienstes.
                List<int> ports = [.. found.Services.Services
                    .Where(s => s.Service == service)
                    .SelectMany(s => s.Ports)
                    .Where(p => p.Status is PortStatus.Open or PortStatus.IsRunning)
                    .SelectMany(p => p.Ports)
                    .Distinct()
                    .Order()];

                if (ports.Count == 0)
                {
                    // Ein Abbruch ist kein Befund: bis wohin gesucht wurde,
                    // weiss der Nutzer, alles dahinter ist ungeprueft.
                    StatusText = _portSearchStopped
                        ? $"Port search for {service} on {device.DisplayName} was cancelled."
                        : $"{service} was not found on any port of {device.DisplayName}.";
                    return;
                }

                // Der eigentliche Fund gehoert in die Dienstliste des Geraets -
                // dorthin, wo auch der regulaere Dienstscan seine Treffer
                // ablegt. Vorher stand er nur in der Statuszeile und in einer
                // Detailzeile: die Spalte "Running services", der Dienstfilter
                // und die Portzaehlung wussten nichts davon, und beim naechsten
                // Speichern war die Suche ueber 65 536 Ports verloren.
                MergeFoundPorts(device, service, found);

                // Der Vermerk bleibt zusaetzlich stehen: er haelt fest, dass
                // dieser Port aus der Suche ueber den ganzen Bereich stammt und
                // nicht aus der regulaeren Portauswahl.
                device.Details[$"{service} port search"] =
                    $"found on port {string.Join(", ", ports)}";
                device.NotifyDisplayChanged();

                // Die Dienstauswahl und die Facettenzaehlung werden aus dem
                // Bestand aufgebaut - ohne diesen Anstoss taucht ein Dienst,
                // den es bisher nirgends gab, im Filter nicht auf.
                Devices.Refresh();

                StatusText = $"{service} answers on port {string.Join(", ", ports)} " +
                             $"of {device.DisplayName}.";
            }
            catch (Exception ex)
            {
                StatusText = $"Port search failed: {ex.Message}";
            }
            finally
            {
                scanner.FindServicePortProgressUpdated -= OnProgress;
                _portSearch = null;

                IsRunning = false;
                CurrentMethodName = string.Empty;
                ProgressCurrent = ProgressTotal = 0;
                OnPropertyChanged(nameof(ProgressFraction));
                OnPropertyChanged(nameof(CanStart));
            }
        }

        /// <summary>
        /// Traegt die Funde der Portsuche in die Dienstliste des Geraets ein.
        /// <para>
        /// Bewusst ueber <c>Observe</c> und nicht durch direktes Anhaengen an
        /// <c>device.Services</c>: die Zusammenfuehrung im Speicher entscheidet
        /// nach Dienst <b>und</b> Ports, ob ein Befund neu ist oder einen
        /// bestehenden ergaenzt. Wer daran vorbei einfuegt, bekommt denselben
        /// Dienst zweimal in der Liste, sobald die Suche wiederholt wird.
        /// </para>
        /// <para>
        /// Uebernommen wird nur, was geantwortet hat. "Filtered" oder "keine
        /// Antwort" ueber 65 536 Ports waere kein Befund, sondern das Protokoll
        /// eines Versuchs - und wuerde die Dienstliste zumuellen.
        /// </para>
        /// </summary>
        private void MergeFoundPorts(Device device, ServiceType service, IPToScan found)
        {
            IpAddressInfo? address = device.PrimaryAddress?.Info;
            if (address is null) return;

            List<DeviceServiceResult> results = [];

            foreach (ServiceScanData.ServiceResult entry in found.Services.Services
                         .Where(s => s.Service == service))
            {
                foreach (ServiceScanData.PortResult port in entry.Ports)
                {
                    if (port.Status is not (PortStatus.Open or PortStatus.IsRunning)) continue;
                    if (port.Ports is not { Count: > 0 }) continue;

                    DeviceServiceResult result = new()
                    {
                        ServiceName = service.ToString(),
                        Category = ServiceCategories.Of(service),
                        Ports = [.. port.Ports],
                        PortLog = string.IsNullOrWhiteSpace(port.PortLog) ? null : port.PortLog
                    };

                    if (address.Family == IpFamily.IPv6) result.StatusIPv6 = port.Status;
                    else result.StatusIPv4 = port.Status;

                    results.Add(result);
                }
            }

            if (results.Count == 0) return;

            _store.Observe(new DeviceObservation
            {
                Source = "Port search",
                Address = address,
                IsResponding = true,
                Services = results
            });
        }

        /// <summary>
        /// Die Dienste, die die Portsuche anbietet - dieselbe Aufzaehlung, die
        /// auch der Dienstscan kennt.
        /// </summary>
        public static IReadOnlyList<ServiceType> AllServiceTypes { get; } =
            [.. Enum.GetValues<ServiceType>()];

        /// <summary>
        /// Bricht ab, was gerade laeuft - den Scan der Engine <b>und</b> eine
        /// Portsuche daneben. Die beiden sind getrennte Laeufe; der Knopf ist
        /// fuer den Nutzer trotzdem derselbe.
        /// </summary>
        [RelayCommand]
        private void Stop()
        {
            _engine.Stop();

            if (_portSearch is not null)
            {
                _portSearchStopped = true;
                _portSearch.StopScan();
            }

            // Satelliten bleiben hier aussen vor: ihr Auftrag wird einzeln in
            // der Satellitenverwaltung gestoppt. Ein Knopf, der alle Segmente
            // auf einmal abraeumt, waere zu grob - meist will man genau den
            // einen freibekommen, der haengt.
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
