using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MyNetworkMonitor.Core.Models;
using MyNetworkMonitor.Core.Network;
using MyNetworkMonitor.Core.Persistence;
using MyNetworkMonitor.Core.SatelliteLink;
using MyNetworkMonitor.Core.ServiceLink;
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
        private string _hostsPath = string.Empty;
        private bool _loading;

        /// <summary>
        /// Ob in dieser Instanz ueberhaupt etwas an den Listen geaendert wurde.
        /// <para>
        /// Beide Dateien liegen maschinenweit, und auf einem Rechner koennen
        /// zwei Instanzen laufen - der Hauptscanner hat keine Empfaenger, der
        /// Satellit keine Satelliten. Ohne diese Merker schriebe jede von
        /// beiden der anderen ihre Liste leer, sobald sie sich schliesst.
        /// Beobachtet als <c>mainScanners.json</c> mit dem Inhalt <c>[]</c>,
        /// woraufhin der Dienst keinen Hauptscanner mehr fand.
        /// </para>
        /// </summary>
        private bool _satellitesChanged;

        private bool _hostsChanged;

        /// <summary>
        /// Wo Schluessel, Satellitenliste und Hostliste liegen - maschinenweit,
        /// damit der Dienst dieselben Dateien liest wie die Oberflaeche.
        /// </summary>
        private static string StateFolder => AppPaths.MachineFolder;

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

        /// <summary>
        /// Die Hauptscanner, zu denen sich <em>diese</em> Anlage hinausverbindet
        /// - Laptop, Server, was es sonst noch gibt. Zu allen gleichzeitig,
        /// jede Verbindung fuer sich (SATELLIT.md, Abschnitt 1).
        /// </summary>
        public ObservableCollection<MainScanner> Hosts { get; } = [];

        [ObservableProperty] private MainScanner? _selectedHost;

        public SatelliteEditorViewModel()
        {
            Hosts.CollectionChanged += (_, e) =>
            {
                foreach (MainScanner h in e.OldItems?.OfType<MainScanner>() ?? [])
                {
                    h.PropertyChanged -= OnHostEdited;
                }
                foreach (MainScanner h in e.NewItems?.OfType<MainScanner>() ?? [])
                {
                    h.PropertyChanged += OnHostEdited;
                }

                if (!_loading) _hostsChanged = true;

                SaveHosts();
            };

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

                if (!_loading) _satellitesChanged = true;

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

            _satellitesChanged = true;
            Save();
        }

        /// <summary>
        /// Ein Empfaenger wurde bearbeitet. Der laufende Zustand loest kein
        /// Schreiben aus - sonst schriebe jede Statuszeile die Datei neu.
        /// </summary>
        private void OnHostEdited(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName is nameof(MainScanner.IsConnected)
                               or nameof(MainScanner.IsApproved)
                               or nameof(MainScanner.IsActive)
                               or nameof(MainScanner.Status)
                               or nameof(MainScanner.Display)
                               or nameof(MainScanner.TargetHost))
            {
                return;
            }

            _hostsChanged = true;
            SaveHosts();
        }

        /// <summary>Schreibt die Hostliste.</summary>
        public void SaveHosts()
        {
            if (_loading || string.IsNullOrEmpty(_hostsPath) || !_hostsChanged) return;

            try
            {
                MainScannerFile.Save(Hosts, _hostsPath);
            }
            catch (Exception ex)
            {
                ClientStatus = $"The list of main scanners could not be saved: {ex.Message}";
            }
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

        /// <summary>
        /// Laedt Satellitenliste und Hostliste.
        /// </summary>
        /// <param name="userSettingsFolder">
        /// Der bisherige Ort der Einstellungen. Wird nur noch gebraucht, um
        /// einen vorhandenen Schluessel samt Freigaben in den maschinenweiten
        /// Ordner zu uebernehmen - danach liest und schreibt alles dort.
        /// </param>
        public void Load(string userSettingsFolder)
        {
            // Erst auflegen, dann neu lesen. Die Liste wird gleich ersetzt;
            // was noch an einem alten Eintrag haengt, haette danach keinen
            // Eintrag mehr, liefe aber weiter.
            DisconnectAllHosts();

            AppPaths.MigrateSatelliteState(userSettingsFolder);

            _filePath = Path.Combine(StateFolder, SatelliteFile.DefaultFileName);
            _hostsPath = Path.Combine(StateFolder, MainScannerFile.DefaultFileName);
            _loading = true;

            try
            {
                All.Clear();
                foreach (Satellite s in SatelliteFile.Load(_filePath)) All.Add(s);

                Hosts.Clear();
                foreach (MainScanner h in MainScannerFile.Load(_hostsPath)) Hosts.Add(h);

                SelectedHost ??= Hosts.FirstOrDefault();

                LoadOwnName();
                RefreshHostInfo();

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
            if (_loading || string.IsNullOrEmpty(_filePath) || !_satellitesChanged) return;

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

        /// <summary>
        /// Der eigene Schluessel - entsteht beim ersten Zugriff, maschinenweit
        /// abgelegt, damit Dienst und Oberflaeche dieselbe Kennung tragen.
        /// </summary>
        private X509Certificate2 Certificate()
        {
            _certificate ??= SatelliteIdentity.GetOrCreate(
                AppPaths.EnsureMachineFolder(), Environment.MachineName);

            OwnFingerprint = SatelliteIdentity.ForDisplay(SatelliteIdentity.Fingerprint(_certificate));
            return _certificate;
        }

        /// <summary>
        /// Faengt an, auf Satelliten zu horchen. Freigegeben ist, wessen
        /// Fingerabdruck in der Liste steht und angehakt ist.
        /// </summary>
        public void StartListening(int port, string appVersion)
        {
            StopListening();

            _appVersion = appVersion ?? string.Empty;

            try
            {
                _listener = new SatelliteListener(
                    Certificate(),
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

            _listener.ProgressReported += (_, e) => Post(() =>
            {
                Satellite? s = ByFingerprint(e.Fingerprint);
                if (s is null) return;

                s.ProgressPercent = e.Progress.Percent;
                s.ProgressCurrent = e.Progress.Current;
                s.ProgressDone = e.Progress.Done;
                s.ProgressPending = e.Progress.Pending;
            });

            _listener.ResultReceived += (_, e) => Post(() =>
            {
                Satellite? s = ByFingerprint(e.Fingerprint);
                if (s is not null)
                {
                    s.JobId = string.Empty;
                    s.ProgressPercent = 100;
                    s.ProgressCurrent = string.Empty;
                }

                ResultArrived?.Invoke(this, (s?.Name ?? "satellite", e.Devices));
            });

            _listener.JobEnded += (_, e) => Post(() =>
            {
                Satellite? s = ByFingerprint(e.Fingerprint);
                if (s is not null)
                {
                    s.JobId = string.Empty;
                    s.ProgressCurrent = string.Empty;
                }

                LinkStatus = e.Text;
            });

            _listener.Start(port);

            IsListening = _listener.IsListening;
            LinkStatus = IsListening
                ? $"Listening on port {port}. Satellites can connect."
                : $"Could not listen on port {port}.";
        }

        /// <summary>
        /// Ein Satellit hat ein Ergebnis geliefert: sein Name und der Bestand
        /// als JSON. Wer es einmischt, entscheidet die Anwendung.
        /// </summary>
        public event EventHandler<(string SatelliteName, string DevicesJson)>? ResultArrived;

        private Satellite? ByFingerprint(string fingerprint) =>
            All.FirstOrDefault(s => string.Equals(s.Fingerprint, fingerprint, StringComparison.OrdinalIgnoreCase));

        /// <summary>
        /// Schickt einen Auftrag an einen Satelliten, sofern er verbunden und
        /// freigegeben ist. Gibt zurueck, ob er angenommen wurde.
        /// </summary>
        public async Task<bool> SendJobAsync(Satellite satellite, string jobText, CancellationToken token)
        {
            ArgumentNullException.ThrowIfNull(satellite);

            if (_listener is null || !satellite.IsConnected || !satellite.Approved) return false;

            try
            {
                string? jobId = await _listener.SendJobAsync(satellite.Fingerprint, jobText, token);
                if (jobId is null) return false;

                Post(() =>
                {
                    satellite.JobId = jobId;
                    satellite.ProgressPercent = 0;
                    satellite.ProgressCurrent = "starting";
                });

                return true;
            }
            catch (Exception ex)
            {
                Post(() => LinkStatus = $"Job for \"{satellite.Name}\" could not be sent: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Ob ein Satellit, den diese Instanz betreibt, sich auch von einem
        /// anderen Hauptscanner abbrechen laesst. Wird an die
        /// Auftragsverwaltung durchgereicht.
        /// </summary>
        public bool AllowCancelFromAnyReceiver
        {
            get => _jobs.AllowCancelFromAnyReceiver;
            set => _jobs.AllowCancelFromAnyReceiver = value;
        }

        /// <summary>
        /// Die Auftragsverwaltung dieser Instanz als Satellit - gemeinsam
        /// ueber alle Empfaenger, siehe <see cref="SatelliteJobHost"/>.
        /// </summary>
        private readonly SatelliteJobHost _jobs = new();

        /// <summary>
        /// Bricht den laufenden Auftrag <b>eines</b> Satelliten ab.
        /// <para>
        /// Einzeln und nicht fuer alle: haengt einer, will man genau den
        /// freibekommen und nicht die uebrigen Segmente mit abraeumen.
        /// </para>
        /// </summary>
        [RelayCommand]
        private async Task StopJob()
        {
            Satellite? satellite = Selected;

            if (_listener is null || satellite is null) return;

            if (!satellite.IsBusy)
            {
                Status = $"\"{satellite.Name}\" is not running a job.";
                return;
            }

            try
            {
                // Ohne Auftragskennung: falls etwas haengt und die Kennung hier
                // nicht mehr stimmt, soll der Stopp trotzdem greifen.
                await _listener.CancelAsync(satellite.Fingerprint, null, CancellationToken.None);
                Status = $"Stop sent to \"{satellite.Name}\".";
            }
            catch (Exception ex)
            {
                Status = $"Stop for \"{satellite.Name}\" failed: {ex.Message}";
            }
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
        /// Fuehrt einen Auftragstext aus und liefert den Bestand als JSON.
        /// Wird von aussen gesetzt - der Transport soll die Scan-Engine nicht
        /// kennen.
        /// </summary>
        public Func<string, IProgress<ProgressPayload>, CancellationToken, Task<string>>? JobRunner { get; set; }

        /// <summary>
        /// Die laufenden Verbindungen, eine je Empfaenger.
        /// <para>
        /// Eine je Eintrag und nicht eine gemeinsame: faellt der Laptop aus,
        /// soll der Server davon nichts merken, und jede Verbindung hat ihren
        /// eigenen gemerkten Fingerabdruck, ihren eigenen Zustand und ihr
        /// eigenes Wiederverbinden.
        /// </para>
        /// </summary>
        private readonly Dictionary<MainScanner, SatelliteClient> _clients = [];

        /// <summary>Wie viele Empfaenger gerade verbunden sind.</summary>
        public int ConnectedHostCount => Hosts.Count(h => h.IsConnected);

        /// <summary>
        /// Nimmt einen Empfaenger auf. Mehr als der Name ist nicht noetig - der
        /// Port bleibt auf der Vorgabe, bis jemand ihn aendert.
        /// </summary>
        [RelayCommand]
        private void AddHost()
        {
            MainScanner host = new() { Host = string.Empty, Port = 27411 };

            Hosts.Add(host);
            SelectedHost = host;

            ClientStatus = "Enter the name or address of the main scanner, then press Connect.";
        }

        /// <summary>Entfernt einen Empfaenger und legt seine Verbindung ab.</summary>
        [RelayCommand]
        private void RemoveHost()
        {
            if (SelectedHost is null) return;

            MainScanner gone = SelectedHost;

            DisconnectHost(gone);
            Hosts.Remove(gone);

            SelectedHost = Hosts.FirstOrDefault();
            ClientStatus = $"\"{gone.Host}\" removed.";
        }

        /// <summary>Verbindet den ausgewaehlten Empfaenger.</summary>
        [RelayCommand]
        private void ConnectHost()
        {
            if (SelectedHost is not null) ConnectTo(SelectedHost);
        }

        /// <summary>Trennt den ausgewaehlten Empfaenger.</summary>
        [RelayCommand]
        private void DisconnectHost()
        {
            if (SelectedHost is not null) DisconnectHost(SelectedHost);
        }

        /// <summary>
        /// Verbindet alle angehakten Empfaenger. Der Weg beim Start und der
        /// Knopf fuer "alles wieder ansprechen".
        /// </summary>
        [RelayCommand]
        public void ConnectAllHosts()
        {
            foreach (MainScanner host in Hosts.Where(h => h.Enabled && !string.IsNullOrWhiteSpace(h.Host)))
            {
                ConnectTo(host);
            }
        }

        /// <summary>
        /// Verbindet diese Anlage als Satellit zu einem Hauptscanner. Der
        /// Verbindungsversuch laeuft weiter, bis er abgebrochen wird - siehe
        /// SATELLIT.md, Abschnitt 1.
        /// </summary>
        public void ConnectTo(MainScanner host)
        {
            ArgumentNullException.ThrowIfNull(host);

            DisconnectHost(host);

            if (string.IsNullOrWhiteSpace(host.Host))
            {
                host.Status = "No name or address given.";
                ClientStatus = host.Status;
                return;
            }

            SatelliteClient client;

            try
            {
                client = new SatelliteClient(Certificate(), OwnName, _appVersion)
                {
                    // Ueber den Umweg, damit die Anzeige weiss, fuer welchen
                    // Empfaenger gerade gearbeitet wird.
                    JobRunner = (text, progress, token) =>
                        RunJobForHostAsync(host, text, progress, token),

                    Jobs = _jobs,

                    // Der gemerkte Fingerabdruck kommt aus der Datei. Ohne ihn
                    // vertraute der Satellit nach jedem Neustart wieder blind
                    // dem ersten, der antwortet.
                    PinnedFingerprint = host.PinnedFingerprint
                };
            }
            catch (Exception ex)
            {
                host.Status = $"Could not prepare the key: {ex.Message}";
                ClientStatus = host.Status;
                return;
            }

            client.StateChanged += (_, s) => Post(() =>
            {
                host.Status = s.Text;
                host.IsConnected = s.State is SatelliteLinkState.Connected or SatelliteLinkState.WaitingForApproval;
                host.IsApproved = s.State == SatelliteLinkState.Connected;
                host.IsActive = s.State != SatelliteLinkState.Idle;

                OnPropertyChanged(nameof(ConnectedHostCount));

                // Die Sammelzeile zeigt den Empfaenger, von dem zuletzt etwas
                // kam - bei einem einzigen ist das genau seiner, bei mehreren
                // die letzte Regung.
                ClientStatus = $"{host.Host}: {s.Text}";
                IsConnectedAsSatellite = Hosts.Any(h => h.IsApproved);
            });

            client.FingerprintPinned += (_, fingerprint) => Post(() =>
            {
                host.PinnedFingerprint = fingerprint;
                SaveHosts();
            });

            _clients[host] = client;
            host.IsActive = true;

            // Nicht host.Host: ist eine Domaene eingetragen und der Name kurz,
            // wird erst beides zusammen aufloesbar.
            client.Start(host.TargetHost, host.Port);
        }

        /// <summary>Legt die Verbindung zu einem Empfaenger ab.</summary>
        public void DisconnectHost(MainScanner host)
        {
            ArgumentNullException.ThrowIfNull(host);

            if (_clients.Remove(host, out SatelliteClient? client)) client.Stop();

            host.IsConnected = false;
            host.IsApproved = false;
            host.IsActive = false;
            host.Status = "Not connected.";

            OnPropertyChanged(nameof(ConnectedHostCount));
            IsConnectedAsSatellite = Hosts.Any(h => h.IsApproved);
        }

        /// <summary>Legt alle Verbindungen ab.</summary>
        public void DisconnectAllHosts()
        {
            // Ueber die Verbindungen selbst und nicht ueber die sichtbare
            // Liste: nach einem Neuladen kann es Verbindungen geben, deren
            // Eintrag es nicht mehr gibt. Genau die blieben sonst haengen und
            // klopften weiter an - beobachtet, nachdem der Dienst seine
            // Hostliste neu einlas: der geloeschte Empfaenger meldete sich
            // danach immer noch.
            foreach (MainScanner host in _clients.Keys.ToList()) DisconnectHost(host);

            foreach (MainScanner host in Hosts.ToList()) DisconnectHost(host);

            IsConnectedAsSatellite = false;
            ClientStatus = "Not connected.";
        }

        /// <summary>
        /// Der Name, unter dem sich diese Anlage bei den Hauptscannern meldet.
        /// Vorgabe ist der Rechnername - er ist da, er ist eindeutig, und
        /// niemand muss ihn tippen.
        /// <para>
        /// Aenderbar, weil der Rechnername nicht immer taugt: zwei Anlagen
        /// koennen gleich heissen, und im Bereich steht unter "Scanned by"
        /// dieser Name, nicht der Fingerabdruck. Wer ihn aendert, muss die
        /// Bereiche druebem nachziehen - darum steht der Hinweis daneben.
        /// </para>
        /// </summary>
        [ObservableProperty] private string _ownName = Environment.MachineName;

        /// <summary>
        /// Wo der geaenderte Eigenname liegt - maschinenweit, neben Schluessel
        /// und Hostliste.
        /// <para>
        /// Muss der Dienst mitlesen koennen: er meldet sich sonst weiter unter
        /// dem Rechnernamen, waehrend das Fenster den geaenderten anzeigt, und
        /// am Hauptscanner staende der Satellit zweimal.
        /// </para>
        /// </summary>
        public const string OwnNameFileName = "satelliteName.txt";

        private string _ownNamePath = string.Empty;

        partial void OnOwnNameChanged(string value)
        {
            if (_loading) return;

            SaveOwnName();
        }

        private void LoadOwnName()
        {
            _ownNamePath = Path.Combine(StateFolder, OwnNameFileName);

            try
            {
                if (!File.Exists(_ownNamePath)) return;

                string stored = File.ReadAllText(_ownNamePath).Trim();

                // Ein leerer Inhalt heisst "nie etwas eingetragen", nicht
                // "namenlos": ohne Namen faende kein Bereich diesen Satelliten.
                if (stored.Length > 0) OwnName = stored;
            }
            catch (Exception)
            {
                // Der Rechnername bleibt stehen - dafuer ist er die Vorgabe.
            }
        }

        private void SaveOwnName()
        {
            if (string.IsNullOrEmpty(_ownNamePath)) return;

            try
            {
                AppPaths.EnsureMachineFolder();

                File.WriteAllText(_ownNamePath, OwnName?.Trim() ?? string.Empty);
            }
            catch (Exception ex)
            {
                ClientStatus = $"The name could not be saved: {ex.Message}";
            }
        }

        /// <summary>Setzt den Namen auf den Rechnernamen zurueck.</summary>
        [RelayCommand]
        private void ResetOwnName() => OwnName = Environment.MachineName;

        // ------------------------------------------- Was diese Anlage ist

        /// <summary>Der Rechnername, wie das Betriebssystem ihn fuehrt.</summary>
        [ObservableProperty] private string _hostName = Environment.MachineName;

        /// <summary>Die Domaene dieses Rechners, oder ein Strich.</summary>
        [ObservableProperty] private string _hostDomain = "-";

        /// <summary>Die IPv4-Adressen der aktiven Adapter, durch Komma getrennt.</summary>
        [ObservableProperty] private string _hostIpv4 = "-";

        /// <summary>Die IPv6-Adressen der aktiven Adapter, durch Komma getrennt.</summary>
        [ObservableProperty] private string _hostIpv6 = "-";

        /// <summary>
        /// Liest, unter welchem Namen und welchen Adressen diese Anlage
        /// erreichbar ist.
        /// <para>
        /// Steht auf der Hauptscanner-Seite, weil genau das die Angaben sind,
        /// die man drueben am Satelliten in seine Empfaengerliste eintragen
        /// muss. Sie hier abzulesen erspart den Weg ueber ipconfig auf einem
        /// Rechner, an dem man vielleicht gar nicht sitzt.
        /// </para>
        /// </summary>
        public void RefreshHostInfo()
        {
            HostName = Environment.MachineName;

            string domain;
            try
            {
                domain = System.Net.NetworkInformation.IPGlobalProperties
                    .GetIPGlobalProperties().DomainName ?? string.Empty;
            }
            catch (Exception)
            {
                domain = string.Empty;
            }

            HostDomain = domain.Length == 0 ? "-" : domain;

            List<AdapterInfo> adapters = [];
            try
            {
                adapters = NetworkAdapters.Read(includeDown: false);
            }
            catch (Exception)
            {
                // Ohne Adapterliste bleiben die Striche stehen.
            }

            // Nur was ein Satellit auch ansprechen kann: Loopback und die
            // link-lokalen Adressen fuehrten hier bloss in die Irre, weil sie
            // aus einem anderen Segment nie erreichbar sind.
            string ipv4 = string.Join(", ", adapters
                .SelectMany(a => a.Ipv4Addresses)
                .Where(ip => !ip.StartsWith("127.", StringComparison.Ordinal)
                          && !ip.StartsWith("169.254.", StringComparison.Ordinal))
                .Distinct(StringComparer.OrdinalIgnoreCase));

            string ipv6 = string.Join(", ", adapters
                .SelectMany(a => a.Ipv6Addresses)
                .Where(ip => !ip.StartsWith("fe80", StringComparison.OrdinalIgnoreCase)
                          && ip != "::1")
                .Distinct(StringComparer.OrdinalIgnoreCase));

            HostIpv4 = ipv4.Length == 0 ? "-" : ipv4;
            HostIpv6 = ipv6.Length == 0 ? "-" : ipv6;
        }

        /// <summary>Setzt die eigene Version fuer die Begruessung.</summary>
        public void SetAppVersion(string appVersion) => _appVersion = appVersion ?? string.Empty;

        // ------------------------------- Der Auftrag, der hier gerade laeuft

        /// <summary>
        /// Von welchem Hauptscanner der Auftrag kommt, der auf dieser Anlage
        /// gerade laeuft. Leer, wenn keiner laeuft.
        /// <para>
        /// Wichtig, sobald mehrere Empfaenger eingetragen sind: der Satellit
        /// nimmt nur einen Auftrag zur Zeit an, und wer davorsitzt, soll sehen,
        /// fuer wen gerade gearbeitet wird - sonst wirkt ein <c>Busy</c> am
        /// anderen Ende unerklaerlich.
        /// </para>
        /// </summary>
        [ObservableProperty] private string _localJobHost = string.Empty;

        [ObservableProperty] private string _localJobId = string.Empty;

        [ObservableProperty] private int _localJobPercent;

        [ObservableProperty] private string _localJobCurrent = string.Empty;

        [ObservableProperty] private string _localJobDone = string.Empty;

        [ObservableProperty] private string _localJobPending = string.Empty;

        /// <summary>Auf dieser Anlage laeuft gerade ein Auftrag von aussen.</summary>
        public bool IsRunningLocalJob => !string.IsNullOrEmpty(LocalJobId);

        partial void OnLocalJobIdChanged(string value) => OnPropertyChanged(nameof(IsRunningLocalJob));

        /// <summary>
        /// Fuehrt einen Auftrag aus und haelt dabei fest, fuer wen.
        /// <para>
        /// Der Umweg um <see cref="JobRunner"/> herum dient allein der Anzeige:
        /// der Transport reicht den Auftragstext durch und weiss nichts von
        /// einer Oberflaeche, und die Scan-Engine weiss nicht, wer gefragt hat.
        /// Beides trifft sich nur hier.
        /// </para>
        /// </summary>
        private async Task<string> RunJobForHostAsync(
            MainScanner host, string jobText, IProgress<ProgressPayload> progress, CancellationToken token)
        {
            if (JobRunner is null) throw new InvalidOperationException("No scan engine is attached.");

            Post(() =>
            {
                LocalJobHost = host.Display;
                LocalJobId = _jobs.CurrentJobId ?? "running";
                LocalJobPercent = 0;
                LocalJobCurrent = "starting";
                LocalJobDone = string.Empty;
                LocalJobPending = string.Empty;
            });

            // Der Fortschritt geht weiter an den Auftraggeber und zusaetzlich
            // in die eigene Anzeige.
            Progress<ProgressPayload> mirrored = new(p =>
            {
                progress.Report(p);

                Post(() =>
                {
                    LocalJobPercent = p.Percent;
                    LocalJobCurrent = p.Current;
                    LocalJobDone = p.Done;
                    LocalJobPending = p.Pending;
                });
            });

            try
            {
                return await JobRunner(jobText, mirrored, token);
            }
            finally
            {
                Post(() =>
                {
                    LocalJobId = string.Empty;
                    LocalJobHost = string.Empty;
                    LocalJobCurrent = string.Empty;
                    LocalJobPercent = 0;
                });
            }
        }

        /// <summary>
        /// Haelt den Auftrag an, der auf dieser Anlage laeuft - unabhaengig
        /// davon, wer ihn gegeben hat. Wer davorsitzt, darf ihn immer stoppen.
        /// </summary>
        [RelayCommand]
        private async Task StopLocalJob()
        {
            // Laeuft der Auftrag im Dienst, hilft die eigene Auftragsverwaltung
            // nicht weiter - der Stopp muss dorthin, wo der Auftrag laeuft.
            if (IsShowingService)
            {
                ClientStatus = await ServiceControlClient.SendCommandAsync(
                    ServiceMessageType.StopJob, CancellationToken.None);
                return;
            }

            ClientStatus = _jobs.CancelCurrent()
                ? "Stopping the running job..."
                : "No job is running on this machine.";
        }

        // ------------------------- Die Bereiche, die auf einen Satelliten zeigen

        /// <summary>
        /// Die Bereiche, die dem ausgewaehlten Satelliten zugewiesen sind - als
        /// fertige Zeilen fuer die Anzeige.
        /// <para>
        /// Damit man am Satelliten sieht, wofuer er zustaendig ist, ohne in die
        /// Bereichsverwaltung wechseln zu muessen. Gefuellt wird von aussen:
        /// die Bereiche gehoeren dem Fenster, nicht dieser Verwaltung.
        /// </para>
        /// </summary>
        public ObservableCollection<string> RangesOfSelected { get; } = [];

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

            _satellitesChanged = true;
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
        private async Task Approve()
        {
            if (Selected is null) return;

            Selected.Approved = true;
            Status = $"\"{Selected.Name}\" approved.";
            // Er haengt in aller Regel schon in der Leitung und wartet. Ihm das
            // zu sagen kostet eine Nachricht und erspart ihm, bis zum naechsten
            // Verbindungsaufbau falsch dazustehen.
            if (_listener is not null && Selected.IsConnected)
            {
                try
                {
                    await _listener.NotifyApprovedAsync(Selected.Fingerprint, CancellationToken.None);
                }
                catch (Exception)
                {
                    // Die Freigabe gilt trotzdem - sie steht in der Liste. Er
                    // erfaehrt es dann beim naechsten Verbinden.
                }
            }
        }

        // ------------------------------------------------------------- Dienst

        /// <summary>
        /// Ob auf dieser Anlage ein Satellitendienst eingerichtet ist und
        /// laeuft.
        /// <para>
        /// Wichtig fuer die Oberflaeche: laeuft der Dienst, verbindet sie sich
        /// <b>nicht</b> selbst. Sonst haengten zwei Verbindungen mit demselben
        /// Schluessel am selben Hauptscanner, und der verwirft die aeltere -
        /// die beiden wuerden sich abwechselnd gegenseitig hinauswerfen.
        /// </para>
        /// </summary>
        [ObservableProperty] private bool _isServiceRunning;

        [ObservableProperty] private bool _isServiceInstalled;

        // Nicht "ServiceStatus": so heisst der Typ, den ServiceControl.Read()
        // liefert, und beides im selben Geltungsbereich verdeckt sich.
        [ObservableProperty] private string _serviceStatusText = string.Empty;

        /// <summary>Ob sich auf dieser Plattform ueberhaupt ein Dienst einrichten laesst.</summary>
        public bool IsServiceSupported => PlatformServices.ServiceControl.IsSupported;

        /// <summary>
        /// Die Oberflaeche darf selbst verbinden - naemlich dann, wenn kein
        /// Dienst die Arbeit schon macht.
        /// </summary>
        public bool CanConnectFromWindow => !IsServiceRunning;

        partial void OnIsServiceRunningChanged(bool value) => OnPropertyChanged(nameof(CanConnectFromWindow));

        /// <summary>Liest den Zustand des Dienstes neu.</summary>
        [RelayCommand]
        public void RefreshService()
        {
            ServiceStatus status = PlatformServices.ServiceControl.Read();

            IsServiceRunning = status.IsRunning;
            IsServiceInstalled = status.IsInstalled;
            ServiceStatusText = status.Message;

            // Laeuft der Dienst, gehoert ihm die Verbindung. Was das Fenster
            // etwa noch offen haelt, wird abgelegt.
            if (IsServiceRunning && _clients.Count > 0) DisconnectAllHosts();

            if (IsServiceRunning) WatchService();
            else StopWatchingService();
        }

        // -------------------------------------------- Zusehen beim Dienst

        private ServiceControlClient? _watcher;

        /// <summary>
        /// Die Anzeige stammt gerade vom Dienst und nicht von diesem Fenster.
        /// <para>
        /// Wichtig fuer den Nutzer: er sieht dieselben Felder, aber sie
        /// beschreiben einen anderen Prozess. Ohne diesen Hinweis wirkte ein
        /// laufender Auftrag so, als haette das Fenster ihn angenommen.
        /// </para>
        /// </summary>
        [ObservableProperty] private bool _isShowingService;

        /// <summary>Der Dienst laeuft, antwortet aber nicht auf der Steuerpipe.</summary>
        [ObservableProperty] private bool _serviceUnreachable;

        /// <summary>Faengt an, dem Dienst zuzusehen.</summary>
        private void WatchService()
        {
            if (_watcher is not null) return;

            _watcher = new ServiceControlClient();

            _watcher.ReachableChanged += (_, reachable) => Post(() =>
            {
                IsShowingService = reachable;
                ServiceUnreachable = !reachable;

                if (!reachable) return;

                // Solange der Dienst antwortet, gehoeren die Anzeigefelder ihm.
                ClientStatus = "Showing the service.";
            });

            _watcher.SnapshotReceived += (_, snapshot) => Post(() => Apply(snapshot));
            _watcher.Start();
        }

        private void StopWatchingService()
        {
            _watcher?.Stop();
            _watcher = null;

            IsShowingService = false;
            ServiceUnreachable = false;
        }

        /// <summary>
        /// Uebernimmt eine Momentaufnahme des Dienstes in dieselben
        /// Eigenschaften, die sonst dieses Fenster fuellt.
        /// <para>
        /// Absichtlich dieselben: die Ansicht soll nicht zweimal gebaut werden,
        /// einmal fuer "ich selbst" und einmal fuer "der Dienst". Was sie
        /// zeigt, ist in beiden Faellen dasselbe - nur die Quelle
        /// unterscheidet sich, und die steht im Hinweis darueber.
        /// </para>
        /// </summary>
        private void Apply(ServiceSnapshot snapshot)
        {
            OwnName = string.IsNullOrWhiteSpace(snapshot.OwnName) ? OwnName : snapshot.OwnName;

            LocalJobHost = snapshot.JobHost;
            LocalJobId = snapshot.JobId;
            LocalJobPercent = snapshot.JobPercent;
            LocalJobCurrent = snapshot.JobCurrent;
            LocalJobDone = snapshot.JobDone;
            LocalJobPending = snapshot.JobPending;

            // Die Empfaenger stehen in derselben Datei, die der Dienst liest -
            // die Liste stimmt also schon. Nachgetragen wird nur, wie es ihnen
            // dort geht.
            foreach (ServiceHostState state in snapshot.Hosts)
            {
                MainScanner? host = Hosts.FirstOrDefault(h =>
                    string.Equals(h.Display, state.Display, StringComparison.OrdinalIgnoreCase));

                if (host is null) continue;

                host.IsConnected = state.IsConnected;
                host.IsApproved = state.IsApproved;
                host.Status = state.Status;
            }

            OnPropertyChanged(nameof(ConnectedHostCount));
        }

        /// <summary>
        /// Traegt dem Dienst auf, die Hostliste neu zu lesen und neu zu
        /// verbinden - der Weg, eine Aenderung wirksam zu machen, ohne ihn
        /// anzuhalten.
        /// </summary>
        [RelayCommand]
        private async Task ApplyToService()
        {
            SaveHosts();

            ServiceStatusText = await ServiceControlClient.SendCommandAsync(
                ServiceMessageType.Reconnect, CancellationToken.None);
        }

        /// <summary>
        /// Richtet den Dienst ein. Fehlen die Rechte, startet sich die
        /// Anwendung dafuer erhoeht neu - der Nutzer sieht eine Rueckfrage des
        /// Betriebssystems.
        /// </summary>
        [RelayCommand]
        private void InstallService()
        {
            // Die Hostliste muss stehen, bevor der Dienst startet: er liest sie
            // beim Hochlaufen und verbindet sich danach nicht mehr neu, nur
            // weil hier jemand tippt.
            SaveHosts();

            string path = Environment.ProcessPath ?? string.Empty;
            ServiceChangeResult result = PlatformServices.ServiceControl.Install(path);

            ServiceStatusText = result.Message;
            RefreshService();
        }

        /// <summary>Entfernt den Dienst wieder.</summary>
        [RelayCommand]
        private void UninstallService()
        {
            ServiceChangeResult result = PlatformServices.ServiceControl.Uninstall();

            ServiceStatusText = result.Message;
            RefreshService();
        }

        /// <summary>Haelt den Dienst an, ohne ihn zu entfernen.</summary>
        [RelayCommand]
        private void StopService()
        {
            ServiceChangeResult result = PlatformServices.ServiceControl.Stop();

            ServiceStatusText = result.Message;
            RefreshService();
        }

        /// <summary>Startet den eingerichteten Dienst wieder.</summary>
        [RelayCommand]
        private void StartService()
        {
            ServiceChangeResult result = PlatformServices.ServiceControl.Start();

            ServiceStatusText = result.Message;
            RefreshService();
        }
    }
}
