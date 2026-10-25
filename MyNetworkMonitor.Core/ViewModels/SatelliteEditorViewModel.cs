// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
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
    /// Management of the satellites: list on the left, form on the right, the
    /// same pattern as for the scopes.
    /// <para>
    /// The design is described in SATELLIT.md. Entries are created when a
    /// satellite connects: it reports its name, fingerprint, version and
    /// origin itself and waits for approval.
    /// </para>
    /// </summary>
    public partial class SatelliteEditorViewModel : ObservableObject
    {
        private string _filePath = string.Empty;
        private string _hostsPath = string.Empty;
        private bool _loading;

        /// <summary>
        /// Whether this instance has changed anything in the lists at all.
        /// <para>
        /// Both files are machine-wide, and two instances can run on one
        /// computer: the main scanner has no receivers, the satellite has no
        /// satellites. Without these flags each of them would overwrite the
        /// other's list with an empty one when it closes; the symptom is a
        /// <c>mainScanners.json</c> containing <c>[]</c>, after which the
        /// service finds no main scanner.
        /// </para>
        /// </summary>
        private bool _satellitesChanged;

        private bool _hostsChanged;

        /// <summary>
        /// Where key, satellite list and host list are stored: machine-wide, so
        /// the service reads the same files as the UI.
        /// </summary>
        private static string StateFolder => AppPaths.MachineFolder;

        /// <summary>All satellites; the scope form binds to the same list.</summary>
        public ObservableCollection<Satellite> All { get; } = [];

        /// <summary>The satellite shown in the form.</summary>
        [ObservableProperty] private Satellite? _selected;

        /// <summary>The status line text of the satellite list.</summary>
        [ObservableProperty] private string _status = string.Empty;

        /// <summary>
        /// An entry of the "Scanned by satellite" selection in the scope form.
        /// <para>
        /// Name and network are displayed; only the identifier is stored. The
        /// separation is necessary because a satellite can change its own name:
        /// if the scope stored the name, the assignment would break after a
        /// rename, silently, and the scope would no longer be scanned.
        /// </para>
        /// </summary>
        public sealed class SatelliteChoice
        {
            /// <summary>The identifier stored in the scope. Empty means "from this machine".</summary>
            public required string Id { get; init; }

            /// <summary>The text shown in the selection: name and network.</summary>
            public required string Display { get; init; }

            /// <summary>All networks of the satellite, for the tooltip.</summary>
            public string Networks { get; init; } = string.Empty;

            public override string ToString() => Display;
        }

        /// <summary>
        /// The selection for the scope form, led by an empty entry that means
        /// "from this machine".
        /// </summary>
        public ObservableCollection<SatelliteChoice> SatellitesForPicker { get; } =
            [new SatelliteChoice { Id = string.Empty, Display = "(this machine)" }];

        /// <summary>Raised when an entry was added, removed or changed.</summary>
        public event Action? NamesChanged;

        /// <summary>
        /// The display name for an identifier, for messages and lists. An
        /// unknown identifier means the satellite was deleted.
        /// </summary>
        /// <param name="id">The satellite identifier.</param>
        /// <returns>The name; empty for a blank identifier, "(unknown satellite)" if none matches.</returns>
        public string DisplayNameOf(string? id)
        {
            if (string.IsNullOrWhiteSpace(id)) return string.Empty;

            Satellite? s = ById(id);
            return s?.Name ?? "(unknown satellite)";
        }

        /// <summary>The satellite with the given identifier, or <c>null</c>.</summary>
        /// <param name="id">The satellite identifier (case-insensitive).</param>
        public Satellite? ById(string? id) =>
            string.IsNullOrWhiteSpace(id)
                ? null
                : All.FirstOrDefault(s => string.Equals(s.Id, id, StringComparison.OrdinalIgnoreCase));

        /// <summary>
        /// Translates a value that still holds a name into the identifier of
        /// the satellite with that name.
        /// <para>
        /// For saved scopes in the older format, where <c>ScannedBy</c> holds
        /// the satellite name. If neither identifier nor name matches an
        /// existing satellite, the result is empty and the scope runs from this
        /// machine. Keeping the value would show nothing in the selection while
        /// the run still asks for a satellite that does not exist.
        /// </para>
        /// </summary>
        /// <param name="scannedBy">The stored <c>ScannedBy</c> value: identifier or name.</param>
        /// <returns>The satellite identifier, or an empty string.</returns>
        public string ResolveToId(string? scannedBy)
        {
            if (string.IsNullOrWhiteSpace(scannedBy)) return string.Empty;

            // Already an identifier: nothing to do.
            if (All.Any(s => string.Equals(s.Id, scannedBy, StringComparison.OrdinalIgnoreCase)))
            {
                return scannedBy;
            }

            Satellite? byName = All.FirstOrDefault(s =>
                string.Equals(s.Name, scannedBy, StringComparison.OrdinalIgnoreCase));

            return byName?.Id ?? string.Empty;
        }

        /// <summary>
        /// The main scanners <em>this</em> installation connects out to
        /// (laptop, server, or others). All at the same time, each connection
        /// independent (SATELLIT.md, section 1).
        /// </summary>
        public ObservableCollection<MainScanner> Hosts { get; } = [];

        /// <summary>The main scanner shown in the form.</summary>
        [ObservableProperty] private MainScanner? _selectedHost;

        /// <summary>
        /// Keeps the age display of running jobs up to date.
        /// <para>
        /// Without this tick "12s ago" would freeze as soon as no more reports
        /// arrive, yet that very case (a satellite that is connected but silent)
        /// is meant to be recognisable by the growing number. Five seconds are
        /// enough; the value is coarse anyway.
        /// </para>
        /// </summary>
        private readonly System.Timers.Timer _ageTicker = new(5000) { AutoReset = true };

        /// <summary>Creates the view model and starts the age ticker.</summary>
        public SatelliteEditorViewModel()
        {
            _ageTicker.Elapsed += (_, _) => Post(() =>
            {
                foreach (Satellite s in All.Where(s => s.IsBusy)) s.RefreshProgressAge();
            });
            _ageTicker.Start();

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

                // Select the first entry right away. Otherwise the right-hand
                // side stays empty although a satellite is in the list, and
                // nothing indicates that a row has to be clicked first.
                Selected ??= All.FirstOrDefault();

                RefreshNames();
                Save();
            };
        }

        private void OnSatelliteEdited(object? sender, PropertyChangedEventArgs e)
        {
            // IsConnected is not saved and therefore must not trigger a write.
            if (e.PropertyName == nameof(Satellite.IsConnected)) return;

            if (e.PropertyName is nameof(Satellite.Name)
                               or nameof(Satellite.SiteNetwork)
                               or nameof(Satellite.SiteNetworks))
            {
                RefreshNames();
            }

            _satellitesChanged = true;
            Save();
        }

        /// <summary>
        /// A receiver was edited. Runtime state does not trigger a write;
        /// otherwise every status line would rewrite the file.
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

        /// <summary>Writes the host list if this instance changed it.</summary>
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
            SatellitesForPicker.Clear();
            SatellitesForPicker.Add(new SatelliteChoice { Id = string.Empty, Display = "(this machine)" });

            foreach (Satellite s in All.Where(s => !string.IsNullOrWhiteSpace(s.Name))
                                       .OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase))
            {
                SatellitesForPicker.Add(new SatelliteChoice
                {
                    Id = s.Id,
                    Display = s.PickerText,

                    // Only the main network is shown in the row. A satellite
                    // often has several adapters (Hyper-V, WSL, VPN), and
                    // listing all of them makes the row unreadable. The rest
                    // is in the tooltip.
                    Networks = string.IsNullOrWhiteSpace(s.SiteNetworks)
                        ? string.Empty
                        : $"{s.Name}\nNetworks: {s.SiteNetworks}"
                });
            }

            NamesChanged?.Invoke();
        }

        // ------------------------------------------------------------ Loading

        /// <summary>
        /// Loads the satellite list and the host list.
        /// </summary>
        /// <param name="userSettingsFolder">
        /// The per-user settings folder. Only used to migrate an existing key
        /// and its approvals to the machine-wide folder; all reads and writes
        /// go there afterwards.
        /// </param>
        public void Load(string userSettingsFolder)
        {
            // Disconnect first, then reload. The list is about to be replaced;
            // a connection attached to an old entry would lose its entry but
            // keep running.
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

        // ------------------------------------------------------------- Saving

        /// <summary>Writes the satellite list if this instance changed it.</summary>
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

        // ------------------------------------------------ Operation: listener

        /// <summary>Name of the firewall rule this application creates for itself.</summary>
        public const string FirewallRuleName = "MyNetworkMonitor - satellites (inbound)";

        private SatelliteListener? _listener;
        private X509Certificate2? _certificate;
        private string _appVersion = string.Empty;

        /// <summary>
        /// How an action reaches the UI thread. Listener and connector events
        /// arrive on background threads, and the list is bound to the display.
        /// The view sets this to its dispatcher; if unset, the action runs
        /// directly, which suits tests.
        /// </summary>
        public Action<Action> Post { get; set; } = action => action();

        /// <summary>The listener for satellites is running.</summary>
        [ObservableProperty] private bool _isListening;
        /// <summary>Status text of the listener.</summary>
        [ObservableProperty] private string _linkStatus = "Not listening.";
        /// <summary>The own certificate fingerprint, formatted for display.</summary>
        [ObservableProperty] private string _ownFingerprint = string.Empty;

        /// <summary>
        /// The own key: created on first access and stored machine-wide so the
        /// service and the UI carry the same identity.
        /// </summary>
        private X509Certificate2 Certificate()
        {
            _certificate ??= SatelliteIdentity.GetOrCreate(
                AppPaths.EnsureMachineFolder(), Environment.MachineName);

            OwnFingerprint = SatelliteIdentity.ForDisplay(SatelliteIdentity.Fingerprint(_certificate));
            return _certificate;
        }

        /// <summary>
        /// Starts listening for satellites. A satellite is admitted if its
        /// fingerprint is in the list and approved.
        /// </summary>
        /// <param name="port">The TCP port to listen on.</param>
        /// <param name="appVersion">The application version reported to connecting satellites.</param>
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
                Announce(e.Name, e.Fingerprint, e.AppVersion, e.Os, e.RemoteAddress, e.Site));

            _listener.Disconnected += (_, fingerprint) => Post(() =>
            {
                Satellite? gone = All.FirstOrDefault(s =>
                    string.Equals(s.Fingerprint, fingerprint, StringComparison.OrdinalIgnoreCase));

                if (gone is null) return;

                gone.IsConnected = false;

                // Losing the connection also loses the job: the result would
                // come back over exactly this session. If the job stayed, the
                // display would keep showing the state at the moment of the
                // drop: a progress bar that never moves again and a row
                // claiming "running" while nobody is there.
                if (gone.IsBusy)
                {
                    gone.JobId = string.Empty;
                    gone.ProgressCurrent = string.Empty;
                    gone.ProgressPercent = 0;
                    ClearCounts(gone);
                }
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
                s.ProgressStep = e.Progress.Step;
                s.ProgressSteps = e.Progress.Steps;
                s.ProgressSent = e.Progress.Sent;
                s.ProgressAnswered = e.Progress.Answered;
                s.ProgressTotal = e.Progress.Total;

                // The timestamp is set here, not on the satellite: its clock
                // may differ, and the question is "when did *this* side last
                // hear something" anyway.
                s.ProgressAt = DateTimeOffset.UtcNow;
            });

            _listener.ResultReceived += (_, e) => Post(() =>
            {
                Satellite? s = ByFingerprint(e.Fingerprint);
                if (s is not null)
                {
                    s.JobId = string.Empty;
                    s.ProgressPercent = 100;
                    s.ProgressCurrent = string.Empty;
                    ClearCounts(s);
                }

                ResultArrived?.Invoke(this, (s?.Name ?? "satellite", e.Devices, e.Partial));
            });

            _listener.JobEnded += (_, e) => Post(() =>
            {
                Satellite? s = ByFingerprint(e.Fingerprint);
                if (s is not null)
                {
                    s.JobId = string.Empty;
                    s.ProgressCurrent = string.Empty;
                    ClearCounts(s);
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
        /// Raised when a satellite has delivered a result: its name, the
        /// inventory as JSON, and whether the result is partial. The
        /// application decides how to merge it.
        /// </summary>
        public event EventHandler<(string SatelliteName, string DevicesJson, bool Partial)>? ResultArrived;

        /// <summary>
        /// Clears the counters of the last method. Leaving them would show the
        /// numbers of whichever method ran last after the run, as if it were
        /// still running.
        /// </summary>
        private static void ClearCounts(Satellite s)
        {
            s.ProgressSent = 0;
            s.ProgressAnswered = 0;
            s.ProgressTotal = 0;
            s.ProgressStep = 0;
            s.ProgressSteps = 0;
        }

        private Satellite? ByFingerprint(string fingerprint) =>
            All.FirstOrDefault(s => string.Equals(s.Fingerprint, fingerprint, StringComparison.OrdinalIgnoreCase));

        /// <summary>
        /// Sends a job to a satellite if it is connected and approved.
        /// </summary>
        /// <param name="satellite">The target satellite.</param>
        /// <param name="jobText">The serialised job.</param>
        /// <param name="token">Cancels sending.</param>
        /// <returns><see langword="true"/> if the satellite accepted the job.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="satellite"/> is <see langword="null"/>.</exception>
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
        /// Whether a satellite run by this instance may also be cancelled by a
        /// main scanner other than the one that gave the job. Passed through to
        /// the job host.
        /// </summary>
        public bool AllowCancelFromAnyReceiver
        {
            get => _jobs.AllowCancelFromAnyReceiver;
            set => _jobs.AllowCancelFromAnyReceiver = value;
        }

        /// <summary>
        /// The job host of this instance acting as a satellite, shared across
        /// all receivers; see <see cref="SatelliteJobHost"/>.
        /// </summary>
        private readonly SatelliteJobHost _jobs = new();

        /// <summary>
        /// Cancels the running job of <b>one</b> satellite.
        /// <para>
        /// Per satellite rather than for all: if one hangs, exactly that one
        /// should be freed without clearing the other segments as well.
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
                // Without a job identifier: if something hangs and the
                // identifier here is out of date, the stop still applies.
                await _listener.CancelAsync(satellite.Fingerprint, null, CancellationToken.None);
                Status = $"Stop sent to \"{satellite.Name}\".";
            }
            catch (Exception ex)
            {
                Status = $"Stop for \"{satellite.Name}\" failed: {ex.Message}";
            }
        }

        /// <summary>Stops listening and marks all satellites as disconnected.</summary>
        public void StopListening()
        {
            _listener?.Stop();
            _listener = null;

            foreach (Satellite s in All) s.IsConnected = false;

            IsListening = false;
            LinkStatus = "Not listening.";
        }

        // ----------------------------------------------- Operation: satellite

        /// <summary>Status text of the connections to the main scanners.</summary>
        [ObservableProperty] private string _clientStatus = "Not connected.";
        /// <summary>At least one main scanner has approved this installation.</summary>
        [ObservableProperty] private bool _isConnectedAsSatellite;

        /// <summary>
        /// Runs a job text and returns the inventory as JSON. Set from outside
        /// so the transport does not depend on the scan engine.
        /// </summary>
        public Func<string, IProgress<ProgressPayload>, CancellationToken, Task<string>>? JobRunner { get; set; }

        /// <summary>
        /// The active connections, one per receiver.
        /// <para>
        /// One per entry rather than a shared one: if the laptop drops out, the
        /// server must not notice, and every connection has its own pinned
        /// fingerprint, its own state and its own reconnect.
        /// </para>
        /// </summary>
        private readonly Dictionary<MainScanner, SatelliteClient> _clients = [];

        /// <summary>Number of receivers currently connected.</summary>
        public int ConnectedHostCount => Hosts.Count(h => h.IsConnected);

        /// <summary>
        /// Adds a receiver. Only the name is required; the port keeps its
        /// default until changed.
        /// </summary>
        [RelayCommand]
        private void AddHost()
        {
            MainScanner host = new() { Host = string.Empty, Port = 27411 };

            Hosts.Add(host);
            SelectedHost = host;

            ClientStatus = "Enter the name or address of the main scanner, then press Connect.";
        }

        /// <summary>Removes a receiver and closes its connection.</summary>
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

        /// <summary>Connects the selected receiver.</summary>
        [RelayCommand]
        private void ConnectHost()
        {
            if (SelectedHost is not null) ConnectTo(SelectedHost);
        }

        /// <summary>Disconnects the selected receiver.</summary>
        [RelayCommand]
        private void DisconnectHost()
        {
            if (SelectedHost is not null) DisconnectHost(SelectedHost);
        }

        /// <summary>
        /// Connects all enabled receivers. Used at startup and by the
        /// "reconnect all" button.
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
        /// Connects this installation as a satellite to a main scanner. The
        /// connection attempt continues until cancelled; see SATELLIT.md,
        /// section 1.
        /// </summary>
        /// <param name="host">The main scanner to connect to.</param>
        /// <exception cref="ArgumentNullException"><paramref name="host"/> is <see langword="null"/>.</exception>
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
                    // Wrapped so the display knows which receiver the job is
                    // for.
                    JobRunner = (text, progress, token) =>
                        RunJobForHostAsync(host, text, progress, token),

                    Jobs = _jobs,

                    // The pinned fingerprint comes from the file. Without it
                    // the satellite would blindly trust the first responder
                    // again after every restart.
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

                // The summary line shows the receiver that reported last: with
                // a single receiver that is its state, with several the most
                // recent change.
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

            // Not host.Host: if a domain is entered and the name is short,
            // only the combination is resolvable.
            client.Start(host.TargetHost, host.Port);
        }

        /// <summary>Closes the connection to a receiver.</summary>
        /// <param name="host">The receiver.</param>
        /// <exception cref="ArgumentNullException"><paramref name="host"/> is <see langword="null"/>.</exception>
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

        /// <summary>Closes all connections.</summary>
        public void DisconnectAllHosts()
        {
            // Iterate over the connections themselves, not the visible list:
            // after a reload there can be connections whose entry no longer
            // exists. Those would otherwise stay open and keep reconnecting;
            // the symptom is a deleted receiver that is still contacted after
            // the service has re-read its host list.
            foreach (MainScanner host in _clients.Keys.ToList()) DisconnectHost(host);

            foreach (MainScanner host in Hosts.ToList()) DisconnectHost(host);

            IsConnectedAsSatellite = false;
            ClientStatus = "Not connected.";
        }

        /// <summary>
        /// The name under which this installation announces itself to the main
        /// scanners. Defaults to the computer name: it exists, is usually
        /// unique, and nobody has to type it.
        /// <para>
        /// Editable because the computer name is not always suitable: two
        /// installations can have the same name. The main scanner recognises a
        /// satellite by its fingerprint and scopes refer to it by identifier,
        /// so a rename keeps the entry, its approval and its scopes.
        /// </para>
        /// </summary>
        [ObservableProperty] private string _ownName = Environment.MachineName;

        /// <summary>
        /// File name of the custom own name, stored machine-wide next to the
        /// key and the host list.
        /// <para>
        /// The service must be able to read it; otherwise it would keep
        /// announcing itself under the computer name while the window shows the
        /// changed one, and the satellite would appear twice at the main
        /// scanner.
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

                // Empty content means "never set", not "nameless"; the
                // computer name stays in effect.
                if (stored.Length > 0) OwnName = stored;
            }
            catch (Exception)
            {
                // Keep the computer name; that is what the default is for.
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

        /// <summary>Resets the name to the computer name.</summary>
        [RelayCommand]
        private void ResetOwnName() => OwnName = Environment.MachineName;

        // ------------------------------------- Identity of this installation

        /// <summary>The computer name as reported by the operating system.</summary>
        [ObservableProperty] private string _hostName = Environment.MachineName;

        /// <summary>The domain of this computer, or a dash.</summary>
        [ObservableProperty] private string _hostDomain = "-";

        /// <summary>The IPv4 addresses of the active adapters, comma-separated.</summary>
        [ObservableProperty] private string _hostIpv4 = "-";

        /// <summary>The IPv6 addresses of the active adapters, comma-separated.</summary>
        [ObservableProperty] private string _hostIpv6 = "-";

        /// <summary>
        /// The networks of this installation in CIDR notation, comma-separated.
        /// The main scanner shows exactly this after the name in its selection.
        /// </summary>
        [ObservableProperty] private string _hostNetworks = "-";

        /// <summary>
        /// Reads the name and addresses under which this installation is
        /// reachable.
        /// <para>
        /// Shown on the main scanner side because these are exactly the values
        /// to enter in the satellite's receiver list. Reading them here avoids
        /// running ipconfig on a computer that may not be at hand.
        /// </para>
        /// </summary>
        public void RefreshHostInfo()
        {
            // The same source the satellite sends: what is shown here arrives
            // at the other end unchanged. Two separate collections would be
            // two chances to differ.
            SiteInfo site = SiteInfo.Read();

            HostName = site.HostName.Length == 0 ? Environment.MachineName : site.HostName;
            HostDomain = site.Domain.Length == 0 ? "-" : site.Domain;
            HostIpv4 = site.Ipv4Text;
            HostIpv6 = site.Ipv6Text;
            HostNetworks = site.NetworksText;
        }

        /// <summary>Sets the own version reported in the handshake.</summary>
        /// <param name="appVersion">The application version.</param>
        public void SetAppVersion(string appVersion) => _appVersion = appVersion ?? string.Empty;

        // ---------------------------------------- The job running locally

        /// <summary>
        /// The main scanner that gave the job currently running on this
        /// installation. Empty if none is running.
        /// <para>
        /// Relevant once several receivers are configured: the satellite
        /// accepts one job at a time, and the local display shows whom it is
        /// working for; otherwise a <c>Busy</c> at the other end would be
        /// unexplained.
        /// </para>
        /// </summary>
        [ObservableProperty] private string _localJobHost = string.Empty;

        /// <summary>Identifier of the local job; empty if none is running.</summary>
        [ObservableProperty] private string _localJobId = string.Empty;

        /// <summary>Progress of the local job in percent.</summary>
        [ObservableProperty] private int _localJobPercent;

        /// <summary>What the local job is currently doing.</summary>
        [ObservableProperty] private string _localJobCurrent = string.Empty;

        /// <summary>The steps of the local job that are done.</summary>
        [ObservableProperty] private string _localJobDone = string.Empty;

        /// <summary>The steps of the local job that are still pending.</summary>
        [ObservableProperty] private string _localJobPending = string.Empty;

        /// <summary>A job from a main scanner is currently running on this installation.</summary>
        public bool IsRunningLocalJob => !string.IsNullOrEmpty(LocalJobId);

        partial void OnLocalJobIdChanged(string value) => OnPropertyChanged(nameof(IsRunningLocalJob));

        /// <summary>
        /// Runs a job and records whom it is for.
        /// <para>
        /// The wrapper around <see cref="JobRunner"/> exists only for the
        /// display: the transport passes the job text through and knows nothing
        /// of a UI, and the scan engine does not know who asked. Both meet only
        /// here.
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

            // Progress goes to the requesting main scanner and also to the
            // local display.
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
        /// Stops the job running on this installation, regardless of who gave
        /// it. Local operators can always stop it.
        /// </summary>
        [RelayCommand]
        private async Task StopLocalJob()
        {
            // If the job runs in the service, the local job host cannot help;
            // the stop has to go where the job runs.
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

        // ------------------------------ The scopes assigned to a satellite

        /// <summary>
        /// The scopes assigned to the selected satellite, as ready-made display
        /// rows.
        /// <para>
        /// Shows what a satellite is responsible for without switching to the
        /// scope management. Filled from outside: the scopes belong to the
        /// window, not to this view model.
        /// </para>
        /// </summary>
        public ObservableCollection<string> RangesOfSelected { get; } = [];

        // ------------------------------------------------------- Firewall

        /// <summary>
        /// Inbound ports allowed by the local firewall, as an aid for choosing
        /// a port, not as a restriction.
        /// </summary>
        public ObservableCollection<string> AllowedInboundPorts { get; } = [];

        /// <summary>The process may create its own firewall rule.</summary>
        [ObservableProperty] private bool _canCreateFirewallRule;
        /// <summary>Status text of the firewall check.</summary>
        [ObservableProperty] private string _firewallStatus = string.Empty;

        /// <summary>
        /// Re-reads the firewall.
        /// <para>
        /// Without elevated rights only ports bound to <em>no</em> program are
        /// shown; only those can be used without a new rule. A rule owned by
        /// another application is of no use to this one, and listing it would
        /// be misleading.
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

        /// <summary>Creates the application's own rule for the given port.</summary>
        /// <param name="port">The inbound TCP port to allow.</param>
        public void CreateFirewallRule(int port)
        {
            FirewallChangeResult result = PlatformServices.Firewall.AllowInboundTcp(port, FirewallRuleName);
            FirewallStatus = result.Message;

            if (result.Success) RefreshFirewall();
        }

        /// <summary>Removes the application's own rule.</summary>
        public void RemoveFirewallRule()
        {
            FirewallChangeResult result = PlatformServices.Firewall.RemoveRule(FirewallRuleName);
            FirewallStatus = result.Message;

            if (result.Success) RefreshFirewall();
        }

        // ----------------------------------------------------------- Commands

        /// <summary>
        /// Adds a satellite that has just announced itself, or updates a known
        /// one.
        /// <para>
        /// There is deliberately no manual creation: the satellite reports its
        /// name itself when it connects. A name typed in here would be a claim
        /// overwritten on the first connection anyway.
        /// </para>
        /// <para>
        /// Satellites are recognised by fingerprint, not by name: if a
        /// satellite renames itself, it stays the same entry including its
        /// approval. Only a new fingerprint creates a new entry, which waits
        /// for approval.
        /// </para>
        /// </summary>
        /// <param name="name">The name the satellite reports.</param>
        /// <param name="fingerprint">The fingerprint of the satellite's certificate.</param>
        /// <param name="version">The satellite's application version.</param>
        /// <param name="os">The satellite's operating system.</param>
        /// <param name="remoteAddress">The address the connection came from.</param>
        /// <param name="site">Host name, domain and networks of the satellite, if reported.</param>
        /// <returns>The new or updated entry.</returns>
        public Satellite Announce(
            string name, string fingerprint, string version, string os, string remoteAddress,
            SitePayload? site = null)
        {
            Satellite? known = All.FirstOrDefault(s =>
                !string.IsNullOrWhiteSpace(fingerprint) &&
                string.Equals(s.Fingerprint, fingerprint, StringComparison.OrdinalIgnoreCase));

            if (known is null)
            {
                known = new Satellite { Fingerprint = fingerprint, Approved = false };

                // The scan extent is taken from the main settings exactly once,
                // here, and never again: what a satellite should scan depends
                // on its segment, not on what was last set here. Changing the
                // main settings later must not silently change every
                // satellite.
                if (ScanScopeDefaults is not null)
                {
                    (bool onlyKnown, IReadOnlyList<string> onlyKnownFor, bool crossCheck) = ScanScopeDefaults();

                    known.OnlyKnownTargets = onlyKnown;
                    known.CrossCheckOnlyKnownTargets = crossCheck;
                    foreach (string id in onlyKnownFor) known.OnlyKnownTargetsFor.Add(id);
                }

                All.Add(known);
                Status = $"\"{name}\" has announced itself and is waiting for approval.";
            }

            known.Name = string.IsNullOrWhiteSpace(name) ? known.Name : name;
            known.Version = version;
            known.Os = os;
            known.RemoteAddress = remoteAddress;
            known.LastSeen = DateTimeOffset.Now;
            known.IsConnected = true;

            // The site information arrives fresh with every announcement and is
            // therefore applied every time; after a restart or a new DHCP
            // lease the stored values would otherwise be stale, and the
            // selection would show a network the satellite is no longer in.
            if (site is not null)
            {
                known.SiteHostName = site.HostName ?? string.Empty;
                known.SiteDomain = site.Domain ?? string.Empty;
                known.SiteIpv4 = site.Ipv4 ?? string.Empty;
                known.SiteIpv6 = site.Ipv6 ?? string.Empty;
                known.SiteNetwork = site.PrimaryNetwork ?? string.Empty;
                known.SiteNetworks = site.Networks ?? string.Empty;
            }

            _satellitesChanged = true;
            Save();
            RefreshNames();
            return known;
        }

        /// <summary>
        /// Supplies the initial scan extent when a satellite connects for the
        /// first time. Set by the window; if unset, a new satellite scans
        /// everything.
        /// </summary>
        public Func<(bool OnlyKnownTargets, IReadOnlyList<string> OnlyKnownTargetsFor,
                     bool CrossCheckOnlyKnownTargets)>? ScanScopeDefaults { get; set; }

        // ------------------------------ Scan extent of the selected satellite

        /// <summary>
        /// A method in the scan extent selection of the selected satellite.
        /// <para>
        /// Needed because <see cref="Satellite.OnlyKnownTargetsFor"/> is a plain
        /// set: a set raises no change notification, so a check mark would
        /// trigger neither the display nor saving. This wrapper holds the check
        /// mark and writes it through.
        /// </para>
        /// </summary>
        public sealed partial class MethodScopeChoice : ObservableObject
        {
            private readonly Satellite _satellite;
            private readonly Action _changed;
            private readonly bool _ready;

            /// <summary>The method identifier.</summary>
            public string Id { get; }
            /// <summary>The method display name.</summary>
            public string DisplayName { get; }

            /// <summary>Creates the choice with the satellite's current setting for the method.</summary>
            /// <param name="satellite">The satellite whose set is edited.</param>
            /// <param name="id">The method identifier.</param>
            /// <param name="displayName">The method display name.</param>
            /// <param name="changed">Called after every change of the check mark.</param>
            public MethodScopeChoice(Satellite satellite, string id, string displayName, Action changed)
            {
                _satellite = satellite;
                _changed = changed;
                Id = id;
                DisplayName = displayName;

                IsChecked = satellite.OnlyKnownTargetsFor.Contains(id);

                // Only from here on does a check mark reach the file; the
                // assignment above is display, not a change.
                _ready = true;
            }

            /// <summary>The method is restricted to known targets on this satellite.</summary>
            [ObservableProperty] private bool _isChecked;

            partial void OnIsCheckedChanged(bool value)
            {
                if (!_ready) return;

                if (value) _satellite.OnlyKnownTargetsFor.Add(Id);
                else _satellite.OnlyKnownTargetsFor.Remove(Id);

                _changed();
            }
        }

        /// <summary>
        /// The restrictable methods (identifier and display name), set by the
        /// window. This view model does not depend on the scan engine.
        /// </summary>
        public IReadOnlyList<(string Id, string DisplayName)> RestrictableMethods { get; set; } = [];

        /// <summary>The scan extent selection for the selected satellite.</summary>
        public ObservableCollection<MethodScopeChoice> ScopeMethods { get; } = [];

        partial void OnSelectedChanged(Satellite? value) => RebuildScopeMethods();

        private void RebuildScopeMethods()
        {
            ScopeMethods.Clear();

            if (Selected is null) return;

            Satellite target = Selected;

            foreach ((string id, string display) in RestrictableMethods)
            {
                ScopeMethods.Add(new MethodScopeChoice(target, id, display, () =>
                {
                    _satellitesChanged = true;
                    Save();
                }));
            }
        }

        [RelayCommand]
        private void Delete()
        {
            if (Selected is null) return;

            string gone = Selected.Name;
            All.Remove(Selected);
            Selected = All.FirstOrDefault();

            // Scopes may now point at an identifier that no longer exists. The
            // selection then shows nothing, and an empty selection runs from
            // this machine; asking for a satellite nobody can see would not
            // help.
            Status = $"\"{gone}\" removed. Ranges still pointing at it will be scanned from this machine.";
        }

        /// <summary>
        /// Withdraws the approval. The satellite may still announce itself but
        /// receives no jobs until it is approved again.
        /// </summary>
        [RelayCommand]
        private void Revoke()
        {
            if (Selected is null) return;

            Selected.Approved = false;
            Status = $"Approval for \"{Selected.Name}\" withdrawn.";
        }

        /// <summary>Approves the selected satellite: the single click described in SATELLIT.md.</summary>
        [RelayCommand]
        private async Task Approve()
        {
            if (Selected is null) return;

            Selected.Approved = true;
            Status = $"\"{Selected.Name}\" approved.";
            // The satellite is usually already connected and waiting. Telling
            // it costs one message and spares it a wrong state until the next
            // connection.
            if (_listener is not null && Selected.IsConnected)
            {
                try
                {
                    await _listener.NotifyApprovedAsync(Selected.Fingerprint, CancellationToken.None);
                }
                catch (Exception)
                {
                    // The approval applies anyway; it is in the list. The
                    // satellite learns of it on the next connection.
                }
            }
        }

        // ------------------------------------------------------------ Service

        /// <summary>
        /// Whether a satellite service is installed and running on this
        /// installation.
        /// <para>
        /// Relevant for the UI: while the service runs, the UI does <b>not</b>
        /// connect by itself. Otherwise two connections with the same key would
        /// reach the same main scanner, which drops the older one, and the two
        /// would keep pushing each other out.
        /// </para>
        /// </summary>
        [ObservableProperty] private bool _isServiceRunning;

        /// <summary>The satellite service is installed.</summary>
        [ObservableProperty] private bool _isServiceInstalled;

        // Not "ServiceStatus": that is the name of the type returned by
        // ServiceControl.Read(), and both in the same scope would shadow each
        // other.
        /// <summary>Status text of the satellite service.</summary>
        [ObservableProperty] private string _serviceStatusText = string.Empty;

        /// <summary>Whether a service can be installed on this platform.</summary>
        public bool IsServiceSupported => PlatformServices.ServiceControl.IsSupported;

        /// <summary>
        /// The UI may connect by itself, i.e. when no service is already doing
        /// the work.
        /// </summary>
        public bool CanConnectFromWindow => !IsServiceRunning;

        partial void OnIsServiceRunningChanged(bool value) => OnPropertyChanged(nameof(CanConnectFromWindow));

        /// <summary>Re-reads the state of the service.</summary>
        [RelayCommand]
        public void RefreshService()
        {
            ServiceStatus status = PlatformServices.ServiceControl.Read();

            IsServiceRunning = status.IsRunning;
            IsServiceInstalled = status.IsInstalled;
            ServiceStatusText = status.Message;

            // While the service runs, it owns the connection. Anything the
            // window still holds open is closed.
            if (IsServiceRunning && _clients.Count > 0) DisconnectAllHosts();

            if (IsServiceRunning) WatchService();
            else StopWatchingService();
        }

        // ------------------------------------------------ Watching the service

        private ServiceControlClient? _watcher;

        /// <summary>
        /// The display currently comes from the service, not from this window.
        /// <para>
        /// The fields are the same but describe a different process. Without
        /// this indication a running job would look as if the window had
        /// accepted it.
        /// </para>
        /// </summary>
        [ObservableProperty] private bool _isShowingService;

        /// <summary>The service is running but does not answer on the control pipe.</summary>
        [ObservableProperty] private bool _serviceUnreachable;

        /// <summary>Starts watching the service.</summary>
        private void WatchService()
        {
            if (_watcher is not null) return;

            _watcher = new ServiceControlClient();

            _watcher.ReachableChanged += (_, reachable) => Post(() =>
            {
                IsShowingService = reachable;
                ServiceUnreachable = !reachable;

                if (!reachable) return;

                // While the service answers, the display fields belong to it.
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
        /// Applies a snapshot of the service to the same properties this window
        /// otherwise fills.
        /// <para>
        /// Deliberately the same: the view should not be built twice, once for
        /// "this window" and once for "the service". It shows the same in both
        /// cases; only the source differs, and the notice above it states the
        /// source.
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

            // The receivers are in the same file the service reads, so the list
            // is already correct. Only their state in the service is applied.
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
        /// Tells the service to re-read the host list and reconnect; this makes
        /// a change effective without stopping the service.
        /// </summary>
        [RelayCommand]
        private async Task ApplyToService()
        {
            SaveHosts();

            ServiceStatusText = await ServiceControlClient.SendCommandAsync(
                ServiceMessageType.Reconnect, CancellationToken.None);
        }

        /// <summary>
        /// Installs the service. Without sufficient rights the application
        /// restarts elevated for this, and the operating system asks for
        /// confirmation.
        /// </summary>
        [RelayCommand]
        private void InstallService()
        {
            // The host list must be saved before the service starts: it reads
            // the list on startup and does not reconnect later just because it
            // is edited here.
            SaveHosts();

            string path = Environment.ProcessPath ?? string.Empty;
            ServiceChangeResult result = PlatformServices.ServiceControl.Install(path);

            ServiceStatusText = result.Message;
            RefreshService();
        }

        /// <summary>Uninstalls the service.</summary>
        [RelayCommand]
        private void UninstallService()
        {
            ServiceChangeResult result = PlatformServices.ServiceControl.Uninstall();

            ServiceStatusText = result.Message;
            RefreshService();
        }

        /// <summary>Stops the service without uninstalling it.</summary>
        [RelayCommand]
        private void StopService()
        {
            ServiceChangeResult result = PlatformServices.ServiceControl.Stop();

            ServiceStatusText = result.Message;
            RefreshService();
        }

        /// <summary>Starts the installed service.</summary>
        [RelayCommand]
        private void StartService()
        {
            ServiceChangeResult result = PlatformServices.ServiceControl.Start();

            ServiceStatusText = result.Message;
            RefreshService();
        }
    }
}
