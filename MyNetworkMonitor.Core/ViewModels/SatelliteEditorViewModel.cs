using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MyNetworkMonitor.Core.Models;
using MyNetworkMonitor.Core.Persistence;
using MyNetworkMonitor.Core.SatelliteLink;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>
    /// Die Verwaltung der Satelliten: Liste links, Maske rechts - dasselbe
    /// Muster wie bei den Bereichen.
    /// <para>
    /// Der Entwurf steht in SATELLIT.md. Solange der Satellitenbetrieb nicht
    /// gebaut ist, legt man Eintraege von Hand an: Name vergeben, Bereiche
    /// darauf zeigen lassen, fertig. Sobald sich ein Satellit meldet, traegt
    /// er Fingerabdruck, Version und Herkunft selbst nach und wartet auf die
    /// Freigabe.
    /// </para>
    /// </summary>
    public partial class SatelliteEditorViewModel : ObservableObject
    {
        private string _filePath = string.Empty;
        private bool _loading;

        /// <summary>Alle Satelliten - die Liste, an der auch die Bereichsmaske haengt.</summary>
        public ObservableCollection<Satellite> All { get; } = [];

        [ObservableProperty] private Satellite? _selected;

        [ObservableProperty] private string _status = string.Empty;

        /// <summary>
        /// Die Namen fuer die Auswahl in der Bereichsmaske, mit einem leeren
        /// Eintrag voran - der bedeutet "von diesem Rechner aus".
        /// </summary>
        public ObservableCollection<string> NamesForPicker { get; } = [string.Empty];

        /// <summary>Meldet sich, wenn ein Name hinzukam, wegfiel oder sich aenderte.</summary>
        public event Action? NamesChanged;

        public SatelliteEditorViewModel()
        {
            All.CollectionChanged += (_, e) =>
            {
                foreach (Satellite s in e.OldItems?.OfType<Satellite>() ?? [])
                {
                    s.PropertyChanged -= OnSatelliteEdited;
                }
                foreach (Satellite s in e.NewItems?.OfType<Satellite>() ?? [])
                {
                    s.PropertyChanged += OnSatelliteEdited;
                }

                RefreshNames();
                Save();
            };
        }

        private void OnSatelliteEdited(object? sender, PropertyChangedEventArgs e)
        {
            // IsConnected wird nicht gespeichert und soll darum auch nicht
            // jedes Mal eine Schreibrunde ausloesen.
            if (e.PropertyName == nameof(Satellite.IsConnected)) return;

            if (e.PropertyName == nameof(Satellite.Name)) RefreshNames();

            Save();
        }

        private void RefreshNames()
        {
            NamesForPicker.Clear();
            NamesForPicker.Add(string.Empty);

            foreach (string name in All.Select(s => s.Name)
                                       .Where(n => !string.IsNullOrWhiteSpace(n))
                                       .Distinct(StringComparer.OrdinalIgnoreCase)
                                       .OrderBy(n => n, StringComparer.OrdinalIgnoreCase))
            {
                NamesForPicker.Add(name);
            }

            NamesChanged?.Invoke();
        }

        // ------------------------------------------------------------- Laden

        public void Load(string settingsFolder)
        {
            _filePath = Path.Combine(settingsFolder, SatelliteFile.DefaultFileName);
            _loading = true;

            try
            {
                All.Clear();
                foreach (Satellite s in SatelliteFile.Load(_filePath)) All.Add(s);

                Status = All.Count == 0
                    ? "No satellites yet."
                    : $"{All.Count} satellite(s) loaded.";
            }
            finally
            {
                _loading = false;
                RefreshNames();
            }
        }

        // --------------------------------------------------------- Speichern

        public void Save()
        {
            if (_loading || string.IsNullOrEmpty(_filePath)) return;

            try
            {
                SatelliteFile.Save(All, _filePath);
            }
            catch (Exception ex)
            {
                Status = $"Satellites could not be saved: {ex.Message}";
            }
        }

        // ------------------------------------------------ Betrieb: Lauscher

        /// <summary>Name der Firewall-Regel, die diese Anwendung sich selbst anlegt.</summary>
        public const string FirewallRuleName = "MyNetworkMonitor - satellites (inbound)";

        private SatelliteListener? _listener;
        private SatelliteClient? _client;
        private X509Certificate2? _certificate;
        private string _appVersion = string.Empty;

        /// <summary>
        /// Wie eine Aktion auf den Oberflaechen-Thread kommt. Die Ereignisse
        /// von Lauscher und Verbinder treffen auf Hintergrund-Threads ein, und
        /// die Liste haengt an der Anzeige. Die Ansicht setzt das auf ihren
        /// Dispatcher; ohne Zuweisung laeuft es geradeaus, was fuer Tests
        /// genau richtig ist.
        /// </summary>
        public Action<Action> Post { get; set; } = action => action();

        [ObservableProperty] private bool _isListening;
        [ObservableProperty] private string _linkStatus = "Not listening.";
        [ObservableProperty] private string _ownFingerprint = string.Empty;

        /// <summary>Der eigene Schluessel - entsteht beim ersten Zugriff.</summary>
        private X509Certificate2 Certificate(string settingsFolder)
        {
            _certificate ??= SatelliteIdentity.GetOrCreate(settingsFolder, Environment.MachineName);
            OwnFingerprint = SatelliteIdentity.ForDisplay(SatelliteIdentity.Fingerprint(_certificate));
            return _certificate;
        }

        /// <summary>
        /// Faengt an, auf Satelliten zu horchen. Freigegeben ist, wessen
        /// Fingerabdruck in der Liste steht und angehakt ist.
        /// </summary>
        public void StartListening(string settingsFolder, int port, string appVersion)
        {
            StopListening();

            _appVersion = appVersion ?? string.Empty;

            try
            {
                _listener = new SatelliteListener(
                    Certificate(settingsFolder),
                    fingerprint => All.Any(s => s.Approved &&
                        string.Equals(s.Fingerprint, fingerprint, StringComparison.OrdinalIgnoreCase)),
                    _appVersion);
            }
            catch (Exception ex)
            {
                LinkStatus = $"Could not prepare the key: {ex.Message}";
                return;
            }

            _listener.Announced += (_, e) => Post(() =>
                Announce(e.Name, e.Fingerprint, e.AppVersion, e.Os, e.RemoteAddress));

            _listener.Disconnected += (_, fingerprint) => Post(() =>
            {
                Satellite? gone = All.FirstOrDefault(s =>
                    string.Equals(s.Fingerprint, fingerprint, StringComparison.OrdinalIgnoreCase));

                if (gone is not null) gone.IsConnected = false;
            });

            _listener.Failed += (_, text) => Post(() => LinkStatus = text);

            _listener.Start(port);

            IsListening = _listener.IsListening;
            LinkStatus = IsListening
                ? $"Listening on port {port}. Satellites can connect."
                : $"Could not listen on port {port}.";
        }

        public void StopListening()
        {
            _listener?.Stop();
            _listener = null;

            foreach (Satellite s in All) s.IsConnected = false;

            IsListening = false;
            LinkStatus = "Not listening.";
        }

        // ----------------------------------------------- Betrieb: Satellit

        [ObservableProperty] private string _clientStatus = "Not connected.";
        [ObservableProperty] private bool _isConnectedAsSatellite;

        /// <summary>
        /// Verbindet diese Instanz als Satellit zu einem Hauptscanner. Der
        /// Verbindungsversuch laeuft weiter, bis er abgebrochen wird - siehe
        /// SATELLIT.md, Abschnitt 1.
        /// </summary>
        public void ConnectAsSatellite(string settingsFolder, string host, int port, string appVersion, string ownName)
        {
            DisconnectAsSatellite();

            if (string.IsNullOrWhiteSpace(host))
            {
                ClientStatus = "No main scanner set - enter a host name or an address first.";
                return;
            }

            try
            {
                _client = new SatelliteClient(Certificate(settingsFolder), ownName, appVersion);
            }
            catch (Exception ex)
            {
                ClientStatus = $"Could not prepare the key: {ex.Message}";
                return;
            }

            _client.StateChanged += (_, s) => Post(() =>
            {
                ClientStatus = s.Text;
                IsConnectedAsSatellite = s.State == SatelliteLinkState.Connected;
            });

            _client.Start(host, port);
        }

        public void DisconnectAsSatellite()
        {
            _client?.Stop();
            _client = null;

            IsConnectedAsSatellite = false;
            ClientStatus = "Not connected.";
        }

        // ------------------------------------------------------- Firewall

        /// <summary>
        /// Eingehend erlaubte Ports, wie die oertliche Firewall sie meldet -
        /// als Hilfe bei der Portwahl, nicht als Einschraenkung.
        /// </summary>
        public ObservableCollection<string> AllowedInboundPorts { get; } = [];

        [ObservableProperty] private bool _canCreateFirewallRule;
        [ObservableProperty] private string _firewallStatus = string.Empty;

        /// <summary>
        /// Liest die Firewall neu.
        /// <para>
        /// Ohne erhoehte Rechte werden nur Ports gezeigt, die an <em>kein</em>
        /// Programm gebunden sind - nur die lassen sich ohne neue Regel
        /// benutzen. Eine Regel, die einer anderen Anwendung gehoert, nuetzt
        /// dieser hier nichts, und sie aufzufuehren waere eine falsche
        /// Verheissung.
        /// </para>
        /// </summary>
        public void RefreshFirewall()
        {
            AllowedInboundPorts.Clear();

            IFirewallInspector firewall = PlatformServices.Firewall;
            CanCreateFirewallRule = firewall.CanCreateRule;

            if (!firewall.IsSupported)
            {
                FirewallStatus = "The firewall cannot be read on this platform - pick a port and try it.";
                return;
            }

            IReadOnlyList<AllowedInboundPort> all = firewall.ReadAllowedInbound();

            IEnumerable<AllowedInboundPort> usable = CanCreateFirewallRule
                ? all
                : all.Where(p => p.AnyProgram);

            foreach (AllowedInboundPort p in usable)
            {
                AllowedInboundPorts.Add(
                    $"{p.Protocol} {p.Ports}{(p.AnyProgram ? string.Empty : "  (only for " + p.RuleName + ")")}");
            }

            FirewallStatus = AllowedInboundPorts.Count == 0
                ? CanCreateFirewallRule
                    ? "No inbound port is open yet. Pick one and create the rule."
                    : "No inbound port is open that any application may use. Ask for a rule, or run as administrator to create one."
                : CanCreateFirewallRule
                    ? $"{AllowedInboundPorts.Count} inbound port(s) allowed. You may also create your own rule."
                    : $"{AllowedInboundPorts.Count} inbound port(s) are open for any application - one of these works without a new rule.";
        }

        /// <summary>Legt die eigene Regel fuer den angegebenen Port an.</summary>
        public void CreateFirewallRule(int port)
        {
            FirewallChangeResult result = PlatformServices.Firewall.AllowInboundTcp(port, FirewallRuleName);
            FirewallStatus = result.Message;

            if (result.Success) RefreshFirewall();
        }

        /// <summary>Entfernt die eigene Regel wieder.</summary>
        public void RemoveFirewallRule()
        {
            FirewallChangeResult result = PlatformServices.Firewall.RemoveRule(FirewallRuleName);
            FirewallStatus = result.Message;

            if (result.Success) RefreshFirewall();
        }

        // ----------------------------------------------------------- Befehle

        /// <summary>
        /// Nimmt einen Satelliten auf, der sich gerade gemeldet hat, oder
        /// bringt einen bekannten auf den neuesten Stand.
        /// <para>
        /// Es gibt bewusst kein Anlegen von Hand: der Satellit nennt seinen
        /// Namen selbst, sobald er sich verbindet. Ein hier eingetippter Name
        /// waere eine Behauptung, die beim ersten Verbinden ohnehin
        /// ueberschrieben wuerde.
        /// </para>
        /// <para>
        /// Wiedererkannt wird am Fingerabdruck, nicht am Namen - benennt sich
        /// ein Satellit um, bleibt es derselbe Eintrag samt Freigabe. Nur wenn
        /// der Fingerabdruck neu ist, entsteht ein neuer Eintrag, und der
        /// wartet auf Freigabe.
        /// </para>
        /// </summary>
        public Satellite Announce(string name, string fingerprint, string version, string os, string remoteAddress)
        {
            Satellite? known = All.FirstOrDefault(s =>
                !string.IsNullOrWhiteSpace(fingerprint) &&
                string.Equals(s.Fingerprint, fingerprint, StringComparison.OrdinalIgnoreCase));

            if (known is null)
            {
                known = new Satellite { Fingerprint = fingerprint, Approved = false };
                All.Add(known);
                Status = $"\"{name}\" has announced itself and is waiting for approval.";
            }

            known.Name = string.IsNullOrWhiteSpace(name) ? known.Name : name;
            known.Version = version;
            known.Os = os;
            known.RemoteAddress = remoteAddress;
            known.LastSeen = DateTimeOffset.Now;
            known.IsConnected = true;

            Save();
            return known;
        }

        [RelayCommand]
        private void Delete()
        {
            if (Selected is null) return;

            string gone = Selected.Name;
            All.Remove(Selected);
            Selected = All.FirstOrDefault();

            // Die Bereiche zeigen jetzt womoeglich auf einen Namen, den es
            // nicht mehr gibt. Aufgeraeumt wird das nicht hier, sondern beim
            // Lauf: ein unbekannter Name gilt als "nicht verbunden", und der
            // Bereich wird uebersprungen statt stillschweigend oertlich
            // gescannt (SATELLIT.md, Abschnitt 3).
            Status = $"\"{gone}\" removed. Ranges still pointing at it will be reported as not scanned.";
        }

        /// <summary>
        /// Nimmt die Freigabe zurueck. Der Satellit darf sich weiter melden,
        /// bekommt aber keine Auftraege mehr, bis er erneut freigegeben wird.
        /// </summary>
        [RelayCommand]
        private void Revoke()
        {
            if (Selected is null) return;

            Selected.Approved = false;
            Status = $"Approval for \"{Selected.Name}\" withdrawn.";
        }

        /// <summary>Gibt den ausgewaehlten Satelliten frei - der eine Klick aus SATELLIT.md.</summary>
        [RelayCommand]
        private void Approve()
        {
            if (Selected is null) return;

            Selected.Approved = true;
            Status = $"\"{Selected.Name}\" approved.";
        }

    }
}
