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
using MyNetworkMonitor.Core.Scanning.Engine.Methods;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>The sections of the navigation bar.</summary>
    public enum ShellSection
    {
        /// <summary>The device table.</summary>
        Devices,
        /// <summary>The local adapters.</summary>
        Network,
        /// <summary>The findings list.</summary>
        Findings,
        /// <summary>The network topology view.</summary>
        Topology,
        /// <summary>The scan scope management.</summary>
        Scopes,
        /// <summary>The port collection.</summary>
        Ports,
        /// <summary>The service definitions.</summary>
        Services,
        /// <summary>The satellite management.</summary>
        Satellites,
        /// <summary>Mapping of custom device names (placeholder section).</summary>
        Names,
        /// <summary>The settings.</summary>
        Settings
    }

    /// <summary>
    /// A scan profile in the command bar: a named set of methods. Covers the
    /// most common cases with one click instead of setting check boxes every
    /// time.
    /// </summary>
    public sealed class ScanProfile
    {
        /// <summary>The profile name.</summary>
        public required string Name { get; init; }
        /// <summary>What the profile does.</summary>
        public required string Description { get; init; }

        /// <summary>Empty for "Custom"; the selection then stays as it is.</summary>
        public IReadOnlyList<string> MethodIds { get; init; } = [];

        /// <summary>The profile leaves the method selection unchanged.</summary>
        public bool IsCustom => MethodIds.Count == 0;
    }

    /// <summary>
    /// The command bar and everything attached to it: scope selection,
    /// profile, method drawer, start and cancel, progress and status line.
    /// <para>
    /// Platform-neutral and independent of the UI framework; the view binds
    /// to it.
    /// </para>
    /// </summary>
    public partial class ShellViewModel : ObservableObject
    {
        private readonly ScanEngine _engine;
        private readonly DeviceStore _store;

        /// <summary>
        /// The running port search, while one is running.
        /// <para>
        /// It does <b>not</b> run through the engine but as a separate module
        /// instance, so <c>_engine.Stop()</c> does not reach it. Without this
        /// reference a search over 65,536 ports could not be cancelled: the
        /// button would report "Cancelling..." and the run would continue until
        /// it finished by itself.
        /// </para>
        /// </summary>
        private ScanningMethod_Services? _portSearch;

        /// <summary>
        /// The UI thread context, captured on construction.
        /// <para>
        /// The run takes place on a background thread, so progress reports
        /// arrive from there. They write bound properties, which is only
        /// allowed from the UI thread; otherwise Avalonia throws on the first
        /// render.
        /// </para>
        /// </summary>
        private readonly SynchronizationContext? _uiContext = SynchronizationContext.Current;

        /// <summary>
        /// Runs the action on the UI thread. Without a captured context (for
        /// example in tests) it runs immediately.
        /// </summary>
        private void OnUi(Action action)
        {
            if (_uiContext is null) action();
            else _uiContext.Post(_ => action(), null);
        }

        /// <summary>
        /// The running port search was cancelled.
        /// <para>
        /// Needed because the module returns normally after cancellation, with
        /// an empty result. Without this distinction the cancellation would
        /// report "not found on any port", a statement about the device that
        /// was never checked.
        /// </para>
        /// </summary>
        private bool _portSearchStopped;

        /// <summary>Creates the shell and all section view models; must be called on the UI thread.</summary>
        /// <param name="engine">The scan engine that runs the methods.</param>
        /// <param name="store">The device store shared by all views.</param>
        /// <exception cref="ArgumentNullException"><paramref name="engine"/> or <paramref name="store"/> is <see langword="null"/>.</exception>
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
                // As a satellite: run an incoming job.
                JobRunner = RunJobAsync
            };

            // The initial scan extent of a newly announced satellite. Applied
            // only on creation; afterwards the satellite keeps its own extent,
            // and changes here explicitly do not affect it.
            SatelliteEditor.ScanScopeDefaults = () =>
                (Settings.OnlyKnownTargets,
                 [.. Settings.OnlyKnownTargetsFor],
                 Settings.CrossCheckOnlyKnownTargets);

            // As the main scanner: merge a satellite result.
            SatelliteEditor.ResultArrived += (_, e) =>
                MergeSatelliteResult(e.SatelliteName, e.DevicesJson, e.Partial);

            // The satellite view shows which scopes point at each satellite.
            // The scopes belong here, not there, so the list is maintained
            // from here.
            SatelliteEditor.PropertyChanged += (_, e) =>
            {
                if (e.PropertyName == nameof(SatelliteEditorViewModel.Selected)) RefreshRangesOfSatellite();
            };

            // ... and likewise when the scopes themselves change.
            //
            // Filling the list only on a selection change is not enough: after
            // assigning "Scanned by" to a scope and returning, the old list
            // would remain until the application is restarted.
            Scopes.CollectionChanged += (_, e) =>
            {
                foreach (ScanScope s in e.OldItems?.OfType<ScanScope>() ?? [])
                {
                    s.PropertyChanged -= OnScopeChangedForSatellite;
                }

                // On Clear the collection reports no old items. Hence every
                // change walks the whole collection and unsubscribes before
                // subscribing: a double subscription would build the list
                // twice on every keystroke.
                foreach (ScanScope s in Scopes)
                {
                    s.PropertyChanged -= OnScopeChangedForSatellite;
                    s.PropertyChanged += OnScopeChangedForSatellite;
                }

                RefreshRangesOfSatellite();
            };
            NetworkView = new NetworkViewModel();
            FindingsView = new FindingsViewModel(store);

            // A check mark in the command bar and a change in the management
            // affect the same list; the counters must be recalculated in both
            // cases.
            ScopeEditor.SelectionChanged += RefreshAvailability;
            PortEditor.PortsChanged += RefreshAvailability;

            foreach (IScanMethod method in _engine.Methods)
            {
                Methods.Add(new ScanMethodChoice { Method = method });
            }

            // Set here, not above with the other satellite editor assignments:
            // the method list is built in the loop above. Set earlier, the
            // per-satellite extent selection would stay empty and only the
            // overall check box would be visible.
            //
            // Methods that listen instead of asking (SSDP, mDNS, ARP table)
            // have no target list and are therefore not included.
            SatelliteEditor.RestrictableMethods =
                [.. Methods.Where(m => m.CanRestrictToKnown)
                           .Select(m => (m.Id, m.Method.DisplayName))];

            _engine.ProgressChanged += OnProgress;
            _engine.MethodFinished += OnMethodFinished;

            ApplyProfile(Profiles[1]); // Standard
        }

        /// <summary>The device table.</summary>
        public DeviceListViewModel Devices { get; }

        /// <summary>The scope management; works on <see cref="Scopes"/>.</summary>
        public ScopeEditorViewModel ScopeEditor { get; }

        /// <summary>The port collection. Writes its selection into <see cref="Settings"/>.</summary>
        public PortEditorViewModel PortEditor { get; }

        /// <summary>Which service is searched for on which ports.</summary>
        public ServiceEditorViewModel ServiceEditor { get; }

        /// <summary>
        /// The satellites: instances that scan in other segments. They feed the
        /// "Scanned by" selection in the scope form. See SATELLIT.md.
        /// </summary>
        public SatelliteEditorViewModel SatelliteEditor { get; }

        /// <summary>The adapters of this computer and their DNS servers.</summary>
        public NetworkViewModel NetworkView { get; }

        /// <summary>All findings in one place.</summary>
        public FindingsViewModel FindingsView { get; }

        /// <summary>The scan scopes, shared by the command bar and the scope management.</summary>
        public ObservableCollection<ScanScope> Scopes { get; } = [];

        /// <summary>All scan methods with their selection and availability.</summary>
        public ObservableCollection<ScanMethodChoice> Methods { get; } = [];

        /// <summary>
        /// The methods that can be restricted to known devices. Methods without
        /// a target list are not included; a check box without effect would be
        /// worse than none.
        /// </summary>
        public IEnumerable<ScanMethodChoice> RestrictableMethods =>
            Methods.Where(m => m.CanRestrictToKnown);

        /// <summary>What the engine skipped in the last run, for the status line.</summary>
        public ObservableCollection<ScanMethodOutcome> LastSkipped { get; } = [];

        /// <summary>The scan settings passed to the engine.</summary>
        public ScanSettings Settings { get; } = new();

        // ----------------------------------------------------------- Settings

        private UserSettings? _userSettings;

        /// <summary>Where the settings files are stored, for display and the folder button.</summary>
        [ObservableProperty] private string _settingsFolder = string.Empty;

        /// <summary>Where the application itself is located.</summary>
        public string ApplicationFolder => AppContext.BaseDirectory;

        // ----------------------------------------------------------- Defaults

        /// <summary>
        /// The methods that query only already discovered devices on first
        /// start.
        /// <para>
        /// Everything that walks a target list and discovers nothing new: the
        /// two name lookups, NetBIOS, ONVIF, the port scans, the SMB version
        /// and service detection. Asked across a whole scope, almost all of
        /// their requests go to addresses where nobody is; that costs most of
        /// a run's time without ever finding a device that ping or ARP had not
        /// already reported.
        /// </para>
        /// <para>
        /// Not included are the methods that discover devices in the first
        /// place (ping and ARP request), because restricted they would only
        /// find what is already listed. SSDP, mDNS and the ARP table have no
        /// target list at all and therefore do not appear.
        /// </para>
        /// </summary>
        private static readonly string[] DefaultOnlyKnownTargetsFor =
        [
            "dns.reverse", "dns.lookup", "netbios", "onvif",
            "ports.tcp", "ports.tcp.all", "ports.udp", "smb.version", "services"
        ];

        /// <summary>
        /// The services grouped into a "+n" in the table by default.
        /// <para>
        /// These are found on nearly every device and therefore distinguish
        /// nothing: name and address services, plus the remote maintenance
        /// tools that are deployed everywhere in corporate networks anyway.
        /// Showing them individually fills the column without helping to tell
        /// one device from the next.
        /// </para>
        /// </summary>
        private static readonly string[] DefaultGroupedServices =
        [
            "DHCP", "DNS_TCP", "DNS_UDP", "NetBIOS",
            "RustdeskServer", "TeamViewer", "UltraVNC"
        ];

        /// <summary>
        /// Expands entries written in an older settings format.
        /// <para>
        /// Settings files written without <see cref="UserSettings.SetStrings"/>
        /// contain the method list joined by commas, where the store expects a
        /// vertical bar. Such an entry holds the whole list in one field. It
        /// does no harm because no method has that name, but it never goes
        /// away unless it is split.
        /// </para>
        /// <para>
        /// Split rather than discarded: the keys in it are valid, and if a
        /// selection consists <em>only</em> of such an entry, discarding it
        /// would lose the setting. Unknown keys are left untouched; they could
        /// belong to a method added in a later version.
        /// </para>
        /// </summary>
        private static IEnumerable<string> ExpandLegacyIds(IEnumerable<string> ids) =>
            ids.SelectMany(id => id.Split(',', StringSplitOptions.RemoveEmptyEntries
                                             | StringSplitOptions.TrimEntries))
               .Where(id => id.Length > 0);

        /// <summary>
        /// Binds the settings to the store: reads the saved state and writes
        /// every change back immediately.
        /// <para>
        /// Immediately rather than on close, because the application can also
        /// crash or be killed; a slider that forgets its value is worse than
        /// one file access per click on a file of a few lines.
        /// </para>
        /// </summary>
        /// <param name="settingsFolder">The folder that holds the user settings.</param>
        public void AttachSettings(string settingsFolder)
        {
            SettingsFolder = settingsFolder;
            _userSettings = new UserSettings(settingsFolder);

            Settings.PortTimeoutMs = _userSettings.GetInt("PortTimeoutMs", Settings.PortTimeoutMs);
            Settings.ScanAllPorts = _userSettings.GetBool("ScanAllPorts", Settings.ScanAllPorts);

            // An empty community string would be a trap: SNMP would then ask
            // without a community and get no answer anywhere.
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

            // Which services are grouped into a "+n" in the table. On by
            // default, with the selection from DefaultGroupedServices.
            ServiceDisplay.GroupSelected = _userSettings.GetBool("GroupServices", true);

            // Checks for the key, not the value: an emptied grouping is a
            // deliberate choice, and the default must not restore it on every
            // start.
            IReadOnlyList<string> grouped = _userSettings.Contains("GroupedServices")
                ? _userSettings.GetStrings("GroupedServices")
                : DefaultGroupedServices;

            foreach (string name in grouped)
            {
                ServiceDisplay.Grouped.Add(name);
            }

            // Open ports without a recognised service ("TCP 8080", "UDP 53",
            // ...) are what overflows the column most often, hence separate
            // switches, on by default, instead of deselecting them one by one
            // in the named list.
            ServiceDisplay.GroupTcpPorts = _userSettings.GetBool("GroupTcpPorts", true);
            ServiceDisplay.GroupUdpPorts = _userSettings.GetBool("GroupUdpPorts", true);

            OnPropertyChanged(nameof(GroupServices));
            BuildGroupableServices();

            // Which methods query only the known devices.
            //
            // On first start, preset DefaultOnlyKnownTargetsFor. Asked across
            // a whole scope, most requests go to addresses without an entry;
            // that only costs time and loads the DNS server.
            //
            // Checks for the key, not the value: an empty selection is a
            // decision and must not be overwritten on every start.
            if (!_userSettings.Contains("OnlyKnownTargetsFor"))
            {
                _userSettings.SetStrings("OnlyKnownTargetsFor", DefaultOnlyKnownTargetsFor);
            }

            IReadOnlyList<string> stored = _userSettings.GetStrings("OnlyKnownTargetsFor");

            foreach (string id in ExpandLegacyIds(stored))
            {
                Settings.OnlyKnownTargetsFor.Add(id);
            }

            // Selections saved before the full port scan existed do not
            // contain it. Add it once; otherwise a full run over all 65535
            // ports across a whole scope would be the rule rather than the
            // exception. The flag ensures that deselecting it later sticks.
            if (!_userSettings.GetBool("OnlyKnownTargetsFor.seededAllPorts", false))
            {
                if (!Settings.OnlyKnownTargetsFor.Contains("ports.tcp.all"))
                {
                    Settings.OnlyKnownTargetsFor.Add("ports.tcp.all");
                }

                _userSettings.SetBool("OnlyKnownTargetsFor.seededAllPorts", true);
            }

            // If expanding changed anything, write back the cleaned state;
            // otherwise the file keeps carrying the old entry even though
            // nothing reads it any more.
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
                        RefreshAvailability(); // enables or blocks "TCP ports"
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

                        // Effective immediately, not only on the next start: the
                        // setting must apply while something is hanging.
                        SatelliteEditor.AllowCancelFromAnyReceiver = Settings.AllowCancelFromAnyReceiver;
                        break;
                    case nameof(ScanSettings.UseOnlineTopologyLibrary):
                        _userSettings.SetBool("UseOnlineTopologyLibrary", Settings.UseOnlineTopologyLibrary);
                        break;
                }
            };
        }

        /// <summary>
        /// Saves the inventory on exit and reloads it on start.
        /// </summary>
        [ObservableProperty] private bool _saveLastScanResult = true;

        partial void OnSaveLastScanResultChanged(bool value) =>
            _userSettings?.SetBool("SaveLastScanResult", value);

        /// <summary>Where the last inventory is stored.</summary>
        public string LastScanResultPath =>
            Path.Combine(SettingsFolder ?? string.Empty, DeviceStoreFile.DefaultFileName);

        /// <summary>
        /// Writes a method's restriction into the settings. The set is the
        /// source of truth; the check boxes only display it.
        /// </summary>
        private void OnMethodRestrictionChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (sender is not ScanMethodChoice choice) return;

            // The cross-check depends on the DNS scan: without it there are no
            // names the servers could disagree on. Its check box must
            // therefore follow when either DNS method is checked or
            // unchecked.
            if (e.PropertyName == nameof(ScanMethodChoice.IsSelected))
            {
                if (IsDnsMethod(choice.Id)) OnPropertyChanged(nameof(CanCrossCheckDns));

                // Everything that depends on the method selection must update
                // on *every* check box.
                //
                // Otherwise the count on the "Methods" button would only be
                // recalculated when the profile or the scopes change, and in
                // between it would show the count of the last chosen profile
                // while the check marks differ.
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
        /// The DNS cross-check can be selected. It is not a method of its own
        /// but a sub-function of the name scan; without that scan it would have
        /// nothing to do, and a check box without effect is worse than one that
        /// is visibly disabled.
        /// </summary>
        public bool CanCrossCheckDns =>
            Methods.Any(m => m.IsEffective && IsDnsMethod(m.Id));

        /// <summary>
        /// Reads the last saved inventory. Without a file the list stays empty;
        /// that is not an error but the first start.
        /// </summary>
        public void LoadLastScanResult()
        {
            if (string.IsNullOrEmpty(SettingsFolder)) return;

            int count = DeviceStoreFile.Load(_store, LastScanResultPath, out string? error);

            if (error is not null)
            {
                // Do not overwrite what could not be read; otherwise the file
                // would be lost on the next close as well.
                _loadFailed = true;
                StatusText = $"The last scan result could not be read, it stays untouched: {error}";
                return;
            }

            if (count == 0) return;

            // Address conflicts are deliberately not stored in the file: stored
            // findings would be a second source of truth next to the data and
            // would need cleaning up once the problem is fixed. Derived anew
            // from the loaded inventory they are always correct: they are back
            // after the start and disappear as soon as a scan no longer
            // produces them.
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

        /// <summary>The last inventory could not be read.</summary>
        private bool _loadFailed;

        // ------------------------------------------------- Services column

        /// <summary>
        /// Groups the selected services into a "+n" in the table instead of
        /// showing each one.
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


        // ------------------------------------------------- System check

        /// <summary>Whether the user chose "Don't show again" for an optional item of the system check.</summary>
        /// <param name="id">The <see cref="SystemRequirement.Id"/>.</param>
        /// <returns>True if the item is not to be shown at start.</returns>
        public bool IsSystemCheckHidden(string id) => _userSettings?.GetBool("SystemCheckHidden." + id, false) == true;

        /// <summary>Remembers or clears "Don't show again" for an optional item of the system check.</summary>
        /// <param name="id">The <see cref="SystemRequirement.Id"/>.</param>
        /// <param name="hidden">True to stop showing it at start.</param>
        public void SetSystemCheckHidden(string id, bool hidden) => _userSettings?.SetBool("SystemCheckHidden." + id, hidden);

        // ------------------------------------------------- MAC vendor list

        /// <summary>Set while downloading, so no second attempt runs in parallel.</summary>
        [ObservableProperty] private bool _isUpdatingMacVendors;

        /// <summary>
        /// Rebuilds the MAC vendor list from Wireshark's manuf file. See
        /// <see cref="MacVendorUpdater"/> for why this yields more matches than
        /// the bundled list (which only knows the classic 24-bit blocks).
        /// </summary>
        [RelayCommand]
        private async Task UpdateMacVendorsAsync()
        {
            if (IsUpdatingMacVendors) return;

            IsUpdatingMacVendors = true;
            StatusText = "Downloading the current MAC vendor list from Wireshark...";

            try
            {
                // Into the user data folder, not next to the program: on Linux
                // the program folder is owned by root, and writing there fails
                // with "Permission denied".
                MacVendorUpdateResult result = await MacVendorUpdater.UpdateAsync(AppDataPaths.MacVendorCsv);

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
        /// All services that can be grouped, with their check marks. Fed from
        /// the service definitions and the methods with their own module, so
        /// the list is complete even without a previous scan.
        /// </summary>
        public ObservableCollection<GroupableService> GroupableServices { get; } = [];

        /// <summary>
        /// The same services, bundled by category as in the definitions. A list
        /// of thirty names in a row cannot be scanned at a glance; sorted by
        /// category, a service is where one expects it.
        /// </summary>
        public ObservableCollection<GroupableServiceGroup> GroupableServiceGroups { get; } = [];

        /// <summary>
        /// The same categories, distributed over two columns (left column).
        /// <para>
        /// The split happens here and not in the layout, because a grid with
        /// equally tall cells aligns to the largest category, leaving a gap the
        /// height of the longest one after a category with two entries. Two
        /// columns that each grow independently do not have this problem and
        /// rebalance by themselves when services are added.
        /// </para>
        /// </summary>
        public ObservableCollection<GroupableServiceGroup> GroupableServicesLeft { get; } = [];

        /// <summary>The right column; see <see cref="GroupableServicesLeft"/>.</summary>
        public ObservableCollection<GroupableServiceGroup> GroupableServicesRight { get; } = [];

        /// <summary>
        /// Distributes the categories over two columns of roughly equal height.
        /// Height is counted in rows: one per service plus one for the heading.
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

                // Always into the currently shorter column; the difference
                // then stays at most one category, however many are added.
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
        /// The categories of the four methods with their own module. They are
        /// not in the service definitions but are services like the others;
        /// without this mapping they would end up in a catch-all category
        /// where nobody looks.
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
        /// Rebuilds the selection list. Must run after the service definitions
        /// are loaded; before that the editor only knows the four methods with
        /// their own module.
        /// </summary>
        public void BuildGroupableServices()
        {
            GroupableServices.Clear();
            GroupableServiceGroups.Clear();

            // Combine name and category: from the definitions where present,
            // the fixed mapping for the four module methods.
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
                        DisplayNameOverride = ServiceNames.DisplayFor(name),
                        IsGrouped = ServiceDisplay.Grouped.Contains(name)
                    };

                    entry.PropertyChanged += OnGroupableServiceChanged;

                    bucket.Services.Add(entry);
                    GroupableServices.Add(entry);
                }

                GroupableServiceGroups.Add(bucket);
            }

            // Open ports without a recognised service match no single name;
            // "TCP 8080", "TCP 8081", "TCP 8443" ... all differ. Own category,
            // own switches (see GroupableService.OnChanged), but visually the
            // same row as any other service.
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

            // Always save the whole set, not the individual change. This
            // automatically handles services being added or removed; there is
            // nothing to forget.
            _userSettings?.SetStrings("GroupedServices", ServiceDisplay.Grouped);

            ServiceDisplay.NotifyChanged();
        }

        /// <summary>
        /// Saves the inventory. Called when the window closes; an error must
        /// not block exiting, so the method only reports whether it worked.
        /// </summary>
        /// <returns><see langword="true"/> if the inventory was saved.</returns>
        public bool SaveLastScanResultNow()
        {
            if (!SaveLastScanResult || string.IsNullOrEmpty(SettingsFolder)) return false;

            // What could not be read at startup is not overwritten either;
            // otherwise a single read error would cost the entire saved
            // inventory.
            if (_loadFailed) return false;

            return DeviceStoreFile.Save(_store, LastScanResultPath);
        }

        /// <summary>The section shown in the main area.</summary>
        [ObservableProperty] private ShellSection _section = ShellSection.Devices;

        /// <summary>The method drawer is open.</summary>
        [ObservableProperty] private bool _isDrawerOpen;

        // ----------------------------------------------------------- Profiles

        // The ARP table is in no profile although it costs nothing: it returns
        // the local computer's cache and thus devices that were not queried in
        // the run, some long switched off. Included in passing, the result
        // would look like more was checked than actually was. It can be
        // checked explicitly.
        //
        // The same applies to the DNS cross-check, see ApplyProfile.
        /// <summary>The available scan profiles: Quick, Standard, Thorough and Custom.</summary>
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

        /// <summary>The selected profile.</summary>
        [ObservableProperty] private ScanProfile? _selectedProfile;

        /// <summary>
        /// Sets the method selection to the profile. "Custom" leaves it
        /// untouched; otherwise switching would erase the custom selection.
        /// </summary>
        /// <param name="profile">The profile to apply.</param>
        /// <exception cref="ArgumentNullException"><paramref name="profile"/> is <see langword="null"/>.</exception>
        public void ApplyProfile(ScanProfile profile)
        {
            ArgumentNullException.ThrowIfNull(profile);
            SelectedProfile = profile;

            if (profile.IsCustom) return;

            foreach (ScanMethodChoice choice in Methods)
            {
                // Regardless of availability: the profile states what is
                // wanted. What can run right now is decided by IsEffective, and
                // as soon as a method can run again it is included again.
                choice.IsSelected = profile.MethodIds.Contains(choice.Id);
            }

            // No profile enables the DNS cross-check. It queries every address
            // at every server individually and in both directions; that is not
            // something to include in passing with a profile, so it has to be
            // checked explicitly.
            Settings.CrossCheckDnsServers = false;

            OnPropertyChanged(nameof(SelectedMethodCount));
            OnPropertyChanged(nameof(CanCrossCheckDns));
            OnPropertyChanged(nameof(CanStart));
        }

        // ------------------------------------------------------------- Scopes

        /// <summary>
        /// Targets entered by hand. Allows a quick check without creating a
        /// scope first, the most common reason to open the scope management at
        /// all. Applies in addition to the checked scopes; if none is checked,
        /// this is the whole selection.
        /// </summary>
        [ObservableProperty] private string _customTargets = string.Empty;

        /// <summary>The scope parsed from <see cref="CustomTargets"/>, if valid.</summary>
        public ScanScope? CustomScope { get; private set; }

        /// <summary>What is wrong with the input; empty if it is valid.</summary>
        [ObservableProperty] private string _customTargetsProblem = string.Empty;

        /// <summary>
        /// An adapter to choose for the custom targets. The first entry has an
        /// empty identifier and means "use the one the operating system would
        /// route through anyway".
        /// </summary>
        public sealed class AdapterChoice
        {
            /// <summary>The network interface identifier; empty for automatic.</summary>
            public required string Id { get; init; }
            /// <summary>Adapter name and IPv4 addresses, for display.</summary>
            public required string Display { get; init; }
            public override string ToString() => Display;
        }

        /// <summary>
        /// The adapters through which custom targets can be scanned.
        /// <para>
        /// Needed because a single target has no scope from which the adapter
        /// could be derived. Without this choice everything would fall back to
        /// the default adapter, which is wrong as soon as the computer is in
        /// several networks and the target is in the other one.
        /// </para>
        /// </summary>
        public ObservableCollection<AdapterChoice> CustomTargetAdapters { get; } = [];

        /// <summary>The adapter chosen for the custom targets.</summary>
        [ObservableProperty] private AdapterChoice? _selectedCustomAdapter;

        partial void OnSelectedCustomAdapterChanged(AdapterChoice? value)
        {
            if (CustomScope is not null) CustomScope.InterfaceId = value?.Id ?? string.Empty;

            RefreshAvailability();
        }

        /// <summary>Re-reads the adapter list for the custom targets, keeping the current choice if possible.</summary>
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

                // The adapter choice also applies to newly typed input;
                // otherwise it would have to be made again after every edit.
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

        /// <summary>The checked scopes plus the custom scope, if any.</summary>
        public IEnumerable<ScanScope> SelectedScopes
        {
            get
            {
                foreach (ScanScope scope in Scopes.Where(s => s.IsSelected)) yield return scope;
                if (CustomScope is not null) yield return CustomScope;
            }
        }

        /// <summary>Number of selected scopes including the custom scope.</summary>
        public int SelectedScopeCount => SelectedScopes.Count();

        /// <summary>
        /// Number of methods a run would actually execute now: checked
        /// <em>and</em> runnable.
        /// </summary>
        public int SelectedMethodCount => Methods.Count(m => m.IsEffective);

        /// <summary>
        /// Count and estimate flag are computed together because both need the
        /// same scope resolution. Recomputed on every selection change, hence
        /// without enumerating the addresses.
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

        /// <summary>Total number of targets across all selected scopes.</summary>
        public long TargetCount => CountTargets().Count;

        /// <summary>At least one scope yields only an estimate.</summary>
        public bool TargetCountIsEstimate => CountTargets().IsEstimate;

        /// <summary>
        /// Rough duration estimate for the command bar. Deliberately simple; it
        /// shows the order of magnitude so that nobody starts a run of several
        /// hours by accident.
        /// </summary>
        public TimeSpan EstimatedDuration
        {
            get
            {
                long targets = TargetCount;
                if (targets == 0) return TimeSpan.Zero;

                int methods = Math.Max(1, Methods.Count(m => m.IsEffective && !m.IsPassive));

                // Empirical value: about 40 targets per second and method,
                // because work runs in parallel.
                double seconds = targets * methods / 40.0;
                return TimeSpan.FromSeconds(Math.Max(1, seconds));
            }
        }

        /// <summary>No run is active and at least one scope and one runnable method are selected.</summary>
        public bool CanStart => !IsRunning && SelectedScopeCount > 0 && SelectedMethodCount > 0;

        /// <summary>
        /// Call after every change of the scope selection: re-evaluates the
        /// availability of all methods and updates the counters.
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
        /// Ensures that a local network interface is set.
        /// <para>
        /// Methods that open a listener instead of querying targets (SSDP,
        /// ONVIF, the DHCP capture) bind it to
        /// <c>SupportMethods.SelectedNetworkInterfaceInfos.IPv4</c>. There is
        /// no selection list for this value; if it stays empty, SSDP is
        /// permanently blocked without any visible reason.
        /// </para>
        /// <para>
        /// The interface of the first selected scope is used: that is where
        /// the scan happens, so the listener belongs there. Without a scope,
        /// the first operational interface with a gateway is used.
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

        /// <summary>Short text of the scope selection for the command bar.</summary>
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

        // ----------------------------------------------------------- Progress

        /// <summary>A run is active.</summary>
        [ObservableProperty] private bool _isRunning;
        /// <summary>Label of the running method, including its sub-step where there is one.</summary>
        [ObservableProperty] private string _currentMethodName = string.Empty;
        /// <summary>Requests sent by the current method.</summary>
        [ObservableProperty] private int _progressCurrent;
        /// <summary>Total targets of the current method.</summary>
        [ObservableProperty] private int _progressTotal;
        /// <summary>Targets that have answered the current method.</summary>
        [ObservableProperty] private int _progressResponded;
        /// <summary>The status line text.</summary>
        [ObservableProperty] private string _statusText = "Ready.";

        /// <summary>Progress of the current method between 0 and 1.</summary>
        public double ProgressFraction =>
            ProgressTotal <= 0 ? 0 : Math.Clamp((double)ProgressCurrent / ProgressTotal, 0, 1);

        // ------------------------------------------------------- Run sequence

        /// <summary>
        /// The methods of this run in execution order and what became of each.
        /// This produces the display "done: Ping, ARP - pending: SMB, Services,
        /// SNMP": a run consists of several methods, and without this list only
        /// the current one is visible, not how much is still to come.
        /// </summary>
        private readonly List<string> _planned = [];
        private readonly List<string> _done = [];

        /// <summary>The completed methods, in the order they finished.</summary>
        public string CompletedScansText => _done.Count == 0 ? "-" : string.Join(", ", _done);

        /// <summary>What is still pending, the running method first.</summary>
        public string PendingScansText
        {
            get
            {
                List<string> open = [.. _planned.Where(name => !_done.Contains(name))];
                return open.Count == 0 ? "-" : string.Join(", ", open);
            }
        }

        /// <summary>The line is only meaningful during and after a run.</summary>
        public bool HasScanPlan => _planned.Count > 0;

        private void NotifyPlanChanged()
        {
            OnPropertyChanged(nameof(CompletedScansText));
            OnPropertyChanged(nameof(PendingScansText));
            OnPropertyChanged(nameof(HasScanPlan));
        }

        /// <summary>
        /// Progress of a method. Arrives from the scan thread and is therefore
        /// marshalled to the UI thread before anything bound is written.
        /// </summary>
        private void OnProgress(ScanProgress progress) => OnUi(() => ApplyProgress(progress));

        private void ApplyProgress(ScanProgress progress)
        {
            // Including the sub-step where there is one: service detection
            // goes service by service, and otherwise this would show only
            // "Services" for minutes.
            CurrentMethodName = progress.Label;
            ProgressCurrent = progress.Current;
            ProgressTotal = progress.Total;
            ProgressResponded = progress.Responded;
            OnPropertyChanged(nameof(ProgressFraction));

            // Also record it on the method itself. The command bar shows only
            // the running one, but the numbers of the finished methods are
            // what is compared at the end: which method yielded how much.
            ScanMethodChoice? choice = Methods.FirstOrDefault(m =>
                string.Equals(m.Id, progress.MethodId, StringComparison.OrdinalIgnoreCase));

            if (choice is null) return;

            choice.Sent = progress.Current;
            choice.Responded = progress.Responded;
            choice.Total = progress.Total;
            choice.HasProgress = true;
        }

        /// <summary>
        /// A method has finished. Writes to <see cref="LastSkipped"/>, a bound
        /// collection, so this also happens on the UI thread only.
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

        /// <summary>Starts a run over the selected scopes with the effective methods.</summary>
        [RelayCommand]
        private async Task StartAsync()
        {
            if (!CanStart) return;

            await RunAsync([.. SelectedScopes]);
        }

        /// <summary>
        /// Rescans only the selected devices, with the methods chosen in the
        /// command bar.
        /// <para>
        /// This uses a target list as a separate scope: each device is listed
        /// with its IPv4 addresses and its best IPv6 address, so the run
        /// refreshes both families. Scope settings such as domain, DNS servers
        /// and gateway come from the scope the device originates from;
        /// otherwise the second look would run under different conditions than
        /// the first and the results would not be comparable.
        /// </para>
        /// </summary>
        [RelayCommand]
        private async Task RescanSelectedAsync()
        {
            if (IsRunning) return;

            // Deliberately not SelectedMethodCount: it only counts what is
            // effective against the selected scopes, and when rescanning often
            // no scope is selected. The question is whether any method is
            // checked at all; the targets come from the selected rows, not from
            // a scope.
            if (!Methods.Any(m => m.IsSelected))
            {
                StatusText = "No scan method selected.";
                return;
            }

            List<ScanScope> scopes = BuildRescanScopes(Devices.ActionTargets);

            if (scopes.Count == 0)
            {
                StatusText = "Nothing selected to rescan.";
                return;
            }

            await RunAsync(scopes);
        }

        /// <summary>
        /// Builds one target list per originating scope. The split is needed
        /// because domain and DNS servers belong to the scope: two devices from
        /// different scopes in one list would both get the settings of one of
        /// them.
        /// </summary>
        private List<ScanScope> BuildRescanScopes(IReadOnlyList<Device> devices)
        {
            Dictionary<string, List<string>> byGroup = [];

            foreach (Device device in devices)
            {
                List<string> addresses = [.. device.Ipv4Addresses.Select(a => a.Info.Canonical)];

                // Of the IPv6 addresses, the best one is enough. A device
                // usually has several, most of them short-lived; querying all
                // of them costs time and yields the same result.
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
                    // The rescan inherits the scope's satellite: otherwise it
                    // would run from here and thus without ARP, while the
                    // scope itself is scanned from within the segment.
                    ScannedBy = origin?.ScannedBy ?? string.Empty,
                    Targets = [.. addresses]
                });
            }

            return scopes;
        }

        // -------------------------------------------------- Satellite operation

        /// <summary>
        /// Distributes the scopes that belong to a satellite to their
        /// satellites: <b>one</b> job per satellite with all of its scopes, so
        /// nothing is scanned twice (SATELLIT.md, section 3).
        /// </summary>
        private async Task DispatchToSatellitesAsync(List<ScanScope> remote)
        {
            List<string> scanning = [];
            List<string> missing = [];

            foreach (IGrouping<string, ScanScope> group in
                     remote.GroupBy(s => s.ScannedBy, StringComparer.OrdinalIgnoreCase))
            {
                // Matched by identifier, not by name: the name can change, and
                // a rename must not break an assignment.
                Satellite? satellite = SatelliteEditor.ById(group.Key);

                if (satellite is null || !satellite.IsConnected || !satellite.Approved)
                {
                    // Unreachable means "not scanned", not silently scanned
                    // locally; otherwise the result would contain numbers
                    // obtained differently than assumed.
                    missing.Add(satellite?.Name ?? SatelliteEditor.DisplayNameOf(group.Key));
                    continue;
                }

                string jobText = JobRequest.Format(
                    [.. group],
                    Methods.Where(m => m.IsEffective).Select(m => m.Method.Id),
                    Settings.TcpPorts,
                    Settings.UdpPorts,
                    Settings.PortTimeoutMs,

                    // "Query only what is already listed" comes from the
                    // satellite, not from the main settings: what is worth
                    // restricting depends on its segment. A scope full of
                    // offline addresses costs the full timeout per port in
                    // service detection; at another site exactly that setting
                    // can be wrong.
                    satellite.EffectiveOnlyKnownFor(
                        Methods.Where(m => m.CanRestrictToKnown).Select(m => m.Id)),

                    satellite.CrossCheckOnlyKnownTargets);

                if (await SatelliteEditor.SendJobAsync(satellite, jobText, CancellationToken.None))
                {
                    scanning.Add(satellite.Name);
                }
                else
                {
                    // The message shows the name, not the identifier.
                    missing.Add(satellite.Name);
                }
            }

            SatelliteScanNote = Describe(scanning, missing);
        }

        /// <summary>
        /// A sentence for the status line about what is running on the
        /// satellites. Empty if none is involved.
        /// <para>
        /// A property of its own rather than text set once, because the local
        /// run keeps writing the status line meanwhile: without it the notice
        /// would disappear after the first method although the satellite is
        /// still working.
        /// </para>
        /// </summary>
        public string SatelliteScanNote { get; private set; } = string.Empty;

        /// <summary>What was skipped or scanned locally instead.</summary>
        private string _skippedNote = string.Empty;

        /// <summary>
        /// Composes the status line from the main result and the satellite
        /// notes, in one place so the notes are not assembled separately in
        /// three places.
        /// </summary>
        private string WithSatelliteNotes(string main) =>
            string.Join("  ·  ", new[] { main, SatelliteScanNote, _skippedNote }
                .Where(t => !string.IsNullOrWhiteSpace(t)));

        /// <summary>
        /// Confirmation dialogs. Set by the view.
        /// <para>
        /// Without a dialog service (in service mode and in tests) nothing is
        /// asked, and the answer counts as "no". That is the safe side: better
        /// a scope not scanned than one with wrong numbers, and there is nobody
        /// in front of a service who could answer.
        /// </para>
        /// </summary>
        public IDialogService? Dialogs { get; set; }

        /// <summary>
        /// Whether the scope belongs to a satellite that actually exists.
        /// <para>
        /// Empty means "from this machine", and so does a value for which no
        /// satellite exists any more. That happens with older saved scopes: the
        /// selection shows nothing because the value matches no entry. If it
        /// still counted as a satellite scope, the run would report an
        /// "(unknown satellite)" as not connected and ask about a satellite
        /// nobody ever set up. What the selection shows as empty is treated as
        /// empty.
        /// </para>
        /// </summary>
        private bool IsAssignedToSatellite(ScanScope scope) =>
            scope.IsScannedRemotely && SatelliteEditor.ById(scope.ScannedBy) is not null;

        /// <summary>
        /// Whether this satellite is reachable right now: connected and
        /// approved.
        /// <para>
        /// Looked up by identifier, because that is what
        /// <c>ScanScope.ScannedBy</c> holds. Comparing against the
        /// <em>name</em> never matches: every scope would count as "satellite
        /// not connected", and the run would ask whether to scan from here
        /// instead although the satellite is connected.
        /// </para>
        /// </summary>
        private bool IsSatelliteReady(string id)
        {
            Satellite? satellite = SatelliteEditor.ById(id);
            return satellite is not null && satellite.IsConnected && satellite.Approved;
        }

        /// <summary>
        /// Asks what should happen to scopes whose satellite is unreachable.
        /// <para>
        /// Asked rather than decided silently: scanning from here gives a
        /// different result (no ARP, everything through the router, longer
        /// response times). That may still be wanted in a given case, but it is
        /// a decision, not a side effect, so the message states the
        /// difference.
        /// </para>
        /// </summary>
        private async Task<bool> AskToScanLocallyAsync(List<ScanScope> orphaned)
        {
            if (Dialogs is null) return false;

            // The scope holds the identifier; a message shows the name
            // instead.
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
        /// Warns about a run that cannot find anything and asks whether to
        /// start it anyway.
        /// <para>
        /// The case: every selected method is restricted to "only devices
        /// already in the table", and the table is empty. Restricting to known
        /// targets then leaves nothing, every method runs over an empty list,
        /// and the result is zero devices, without an error, because from the
        /// methods' point of view that is correct.
        /// </para>
        /// <para>
        /// A satellite is affected more than this installation: its job runs
        /// against a freshly created, <em>empty</em> inventory, not against the
        /// main scanner's table, of which it knows nothing. For a satellite the
        /// restriction alone is therefore enough to produce nothing.
        /// </para>
        /// <para>
        /// A method that discovers devices by itself is no reason to warn: one
        /// without a target list (a broadcast such as SSDP or mDNS) or one that
        /// is not restricted. It fills the table, and the restricted methods
        /// afterwards have something to query; that staging is the purpose of
        /// the restriction.
        /// </para>
        /// </summary>
        private async Task<bool> ConfirmRunWithoutTargetsAsync(
            List<ScanScope> local, List<ScanScope> remote)
        {
            List<ScanMethodChoice> chosen = [.. Methods.Where(m => m.IsEffective)];

            if (chosen.Count == 0) return true;

            IReadOnlyList<string> restrictable =
                [.. chosen.Where(m => m.CanRestrictToKnown).Select(m => m.Id)];

            // Does any of the selected methods discover devices by itself?
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

            // Without a dialog service (in service mode and in tests) nothing
            // is asked and nothing is cancelled; the run proceeds. Unlike with
            // an unreachable satellite, the risk here is not a wrong result,
            // only an empty one.
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
        /// Runs a job text on the satellite side. Runs against a
        /// <em>separate</em> inventory: what is sent back is what this job
        /// found, not the satellite computer's whole inventory.
        /// </summary>
        /// <param name="jobText">The serialised job from the main scanner.</param>
        /// <param name="progress">Receives progress reports for the main scanner.</param>
        /// <param name="token">Cancels the job; the devices found so far are still returned.</param>
        /// <returns>The devices found, as JSON.</returns>
        /// <exception cref="InvalidOperationException">The job text could not be read.</exception>
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

            // The restriction comes from the job, not from the local settings:
            // what counts is what the main scanner checked, not what was once
            // set on the satellite.
            foreach (string id in job.OnlyKnownFor) settings.OnlyKnownTargetsFor.Add(id);

            // Likewise the cross-check: if the job does not specify it, the
            // local default applies.
            settings.CrossCheckOnlyKnownTargets =
                job.CrossCheckOnlyKnown ?? Settings.CrossCheckOnlyKnownTargets;

            List<IScanMethod> methods = job.MethodIds.Count > 0
                ? [.. _engine.Methods.Where(m => job.MethodIds.Contains(m.Id, StringComparer.OrdinalIgnoreCase))]
                : [.. Methods.Where(m => m.IsEffective).Select(m => m.Method)];

            DeviceStore jobStore = new();

            // Progress: the same state the local display shows, i.e. the
            // running method, its share and its three numbers.
            //
            // Reporting only when a method *finishes*, with the percentage as
            // the share of finished methods, would mean 0, then a long silence,
            // then 33 for three methods. During a long method it would be
            // impossible to tell from outside whether the satellite is working
            // or hanging.
            int done = 0;
            List<string> completed = [];

            // The last known state from which every report is built.
            ScanProgress? latest = null;
            DateTimeOffset lastSent = DateTimeOffset.MinValue;
            string lastMethod = string.Empty;
            Lock progressSync = new();

            ProgressPayload BuildPayload()
            {
                ScanProgress? p = latest;

                return new ProgressPayload
                {
                    // Progress of the running method, e.g. "Ping 40 %".
                    Percent = p is null || p.Total <= 0
                        ? 0
                        : (int)Math.Clamp((double)p.Current / p.Total * 100, 0, 100),
                    // With sub-step, as locally: the main scanner should read
                    // the same as the satellite's own display.
                    Current = p?.Label ?? string.Empty,
                    Step = done + 1,
                    Steps = methods.Count,
                    Sent = p?.Current ?? 0,
                    Answered = p?.Responded ?? 0,
                    Total = p?.Total ?? 0,
                    // As locally: a dash instead of an empty line; otherwise
                    // "nothing finished yet" looks like "display broken".
                    Done = completed.Count == 0 ? "-" : string.Join(", ", completed),
                    Pending = Listed(methods.Select(m => m.DisplayName).Where(n => !completed.Contains(n)))
                };

                static string Listed(IEnumerable<string> names)
                {
                    string text = string.Join(", ", names);
                    return text.Length == 0 ? "-" : text;
                }
            }

            // Report on change, but at most every two seconds, and at least
            // every ten even if nothing has changed.
            //
            // Unthrottled it would be one message per checked target: with 254
            // targets and a dozen methods thousands of messages, just to make
            // a bar flicker. Without a minimum rate, on the other hand, the
            // display would freeze as soon as a method runs into timeouts for
            // a long time, which is exactly when it matters that the
            // connection is still alive.
            TimeSpan minGap = TimeSpan.FromSeconds(2);
            TimeSpan heartbeat = TimeSpan.FromSeconds(10);

            void SendProgress(bool force)
            {
                ProgressPayload payload;

                lock (progressSync)
                {
                    // Before the engine's first report there is nothing to
                    // send. Otherwise the heartbeat would replace "starting"
                    // with an empty line.
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

                // A method change is sent immediately: it is what the other
                // side waits for, and two seconds later the number next to it
                // would already be different.
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

            // The heartbeat for the case that nothing changes.
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

            // Cancellation must stop the engine, not only end the wait.
            // Otherwise the scan would continue after a stop while
            // "cancelled" is already reported, so this does what the local
            // stop button does with _engine.Stop().
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
                // Cancellation does not discard the findings: what was found
                // up to that point goes back to the main scanner.
                //
                // A partial result must not look complete; the answer is to
                // mark it, not to discard the work. The main scanner marks it
                // as cancelled (see MessageType.Result, field Partial).
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
        /// A scope has changed. Only the fields shown in the list trigger a
        /// rebuild; <c>IsSelected</c>, for example, changes with every check
        /// mark in the command bar and would otherwise rebuild the list
        /// constantly.
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
        /// Rewrites scopes that still point at a satellite's <em>name</em> to
        /// its identifier, once.
        /// <para>
        /// Called on loading. If no satellite of that name exists, the value is
        /// cleared and the scope runs from this machine. A value that matches
        /// no entry leaves the selection in the form empty, and what is shown
        /// empty must mean empty; otherwise the run would ask for a satellite
        /// that does not appear in the form.
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

        /// <summary>
        /// Updates which scopes point at the currently selected satellite, for
        /// the display in the satellite management.
        /// </summary>
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

        /// <summary>Merges a result sent by a satellite.</summary>
        /// <param name="satelliteName">The satellite name, for the status line.</param>
        /// <param name="devicesJson">The devices found, as JSON.</param>
        /// <param name="partial">The job was cancelled and the scope not fully scanned.</param>
        public void MergeSatelliteResult(string satelliteName, string devicesJson, bool partial = false)
        {
            try
            {
                List<Device> devices = DeviceStoreFile.FromJson(devicesJson);
                int taken = _store.MergeFrom(devices);

                // On cancellation the message states that the run did not
                // complete. The devices are real, but the absence of a device
                // means nothing here, and the message must say so.
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

        /// <summary>
        /// The actual run. Shared by the full scan and the rescan of
        /// individual devices; the two differ only in the scopes, everything
        /// before and after is the same.
        /// </summary>
        private async Task RunAsync(List<ScanScope> scopes)
        {
            // At the very beginning, before "Scan running..." and the plan:
            // can this run find anything at all? If all selected methods are
            // restricted to known devices and there are none, it runs empty;
            // see the explanation at ConfirmRunWithoutTargetsAsync. Asked
            // later, the line would already show "Scan running..." during the
            // question although nothing is running yet.
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

            // Otherwise the unselected methods would still show the numbers of
            // the previous run, as if they had just worked.
            foreach (ScanMethodChoice method in Methods) method.ResetProgress();

            // Effective against the scopes of this run, not the globally
            // checked ones. When rescanning individual devices the targets come
            // from the table, and often no scope is selected; measured against
            // the empty selection every method would be "not applicable" and
            // the run would stay empty. For the normal scan the passed scopes
            // are the selected ones, so the result is the same.
            ScanContext runProbe = BuildProbeContext(ScopeRuntimeFactory.Build(scopes));

            List<ScanMethodChoice> chosen =
                [.. Methods.Where(m => m.IsSelected && m.Method.CheckAvailability(runProbe).CanRun)];
            List<string> methods = [.. chosen.Select(m => m.Id)];

            // The plan is fixed before the start, so the status line can tell
            // from the beginning what is still to come.
            _planned.Clear();
            _done.Clear();
            _planned.AddRange(chosen.Select(m => m.DisplayName));
            NotifyPlanChanged();

            try
            {
                // During the run the list collects the reports and catches up
                // at short intervals, so the table fills while scanning instead
                // of all at once at the end.
                using (Devices.BeginLiveUpdates())
                {
                    // Scopes taken over by a satellite are split off here and
                    // sent there. Scanning them locally as well would be worse
                    // than not at all: without ARP, through the router, with
                    // different response times, and the scope would be scanned
                    // twice.
                    List<ScanScope> remote = [.. scopes.Where(IsAssignedToSatellite)];
                    List<ScanScope> local = [.. scopes.Where(s => !IsAssignedToSatellite(s))];

                    SatelliteScanNote = string.Empty;
                    _skippedNote = string.Empty;

                    if (remote.Count > 0)
                    {
                        // First the scopes whose satellite is not there at all.
                        // They are not skipped silently; a confirmation decides
                        // whether they run from here instead.
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

                        // Show it immediately: the satellite is working from
                        // now on, and in a satellite-only run this is the only
                        // message there is.
                        if (SatelliteScanNote.Length > 0) StatusText = WithSatelliteNotes(string.Empty);
                    }

                    if (local.Count == 0)
                    {
                        // Do not start the engine at all if there is nothing to
                        // do here.
                        //
                        // Without this guard it would run with an empty scope
                        // list, and the broadcast methods (SSDP, mDNS,
                        // WS-Discovery) do not ask targets but send their packet
                        // to everyone on the local adapters. They would find
                        // devices *here* although every selected scope belongs
                        // to a satellite. That must not happen: a scope runs
                        // either locally or through a satellite (SATELLIT.md,
                        // section 3).
                        StatusText = WithSatelliteNotes("Nothing runs from this machine");

                        // The plan belongs to the *local* run, which does not
                        // take place here. If it stayed, the line would show
                        // "done: -" and all methods as pending indefinitely,
                        // since nothing runs that could work through them, right
                        // next to "Nothing runs from this machine". The
                        // satellite's progress is shown in its own display.
                        _planned.Clear();
                        _done.Clear();
                        NotifyPlanChanged();
                    }
                    else
                    {
                        // Task.Run is not incidental here; it is the reason the
                        // table fills during the run at all.
                        //
                        // No module in the chain uses ConfigureAwait(false). If
                        // the engine is awaited from the UI thread, *every*
                        // continuation returns there: with 254 targets that is
                        // the waiting of all probes, the evaluation of every
                        // answer and the whole in-memory merge, all on the one
                        // thread that is also supposed to render. The table
                        // then catches up every 400 ms but cannot keep up with
                        // the flood and looks as if it fills only at the end.
                        //
                        // Task.Run starts without a synchronisation context;
                        // the continuations run in the thread pool, and the UI
                        // thread only has to render.
                        ScanRunResult result = await Task.Run(() =>
                            _engine.RunAsync(local, methods, Settings, _store));

                        // Back on the UI thread from here. Determine the
                        // address conflicts only now: the evaluation writes
                        // bound properties on the device and needs the complete
                        // inventory; during the run every finding would be
                        // preliminary.
                        lock (_store.SyncRoot)
                        {
                            result.ConflictCount = DuplicateDetector.Analyze(_store.Devices);
                        }

                        // The local run is finished, the satellite usually not
                        // yet. Its notice therefore stays appended; otherwise
                        // the run would look finished while some scopes are
                        // still being scanned.
                        StatusText = WithSatelliteNotes(Describe(result));

                        // The cross-check depends on the run's result and
                        // therefore runs afterwards, not as a method in between.
                        //
                        // Over "local" and not all scopes: the DNS servers of a
                        // satellite scope are in its segment. Queried from
                        // here they do not answer, or worse, a server of the
                        // same name answers here and the comparison reports a
                        // mismatch that does not exist.
                        if (Settings.CrossCheckDnsServers && !result.WasCancelled)
                        {
                            await CrossCheckDnsAsync(local);
                        }
                    }

                    // The rules run automatically once the run is finished; a
                    // finding that needs a click to become visible goes
                    // unnoticed.
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

        // ------------------------------------------------- DNS cross-check

        /// <summary>
        /// After a run, checks every resolved address against each known DNS
        /// server individually. The servers come from the scopes just scanned;
        /// otherwise the check would use different servers than the run.
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
                // Only devices with names: where no name was ever involved,
                // there is nothing the servers could disagree on.
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
                    // A device that cannot be checked must not end the
                    // comparison of the others.
                }
            }

            StatusText = mismatches == 0
                ? StatusText + " All DNS servers agree."
                : StatusText + $" {mismatches} address(es) are answered differently - see Findings.";
        }

        /// <summary>
        /// The same comparison for the selected rows, from the context menu.
        /// The tool for a single suspicious device: do all servers say the
        /// same about it?
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

                    // Also into the detail panel, not only the findings: a
                    // targeted check of one device shows the answers of all
                    // servers side by side, including the matching ones.
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
        /// Searches the whole port range for a single service.
        /// <para>
        /// For the case where a service runs, but not on its usual port, so the
        /// regular scan never sees it. All 65,536 ports take time, hence one
        /// device and one service per call instead of including it in the
        /// full run.
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

            // The same service file as the regular service scan; otherwise the
            // port search would look for a different service definition than
            // the one configured in the service management.
            ScanningMethod_Services scanner = new(
                Path.Combine(SettingsFolder ?? string.Empty, "services.xml"));

            // From here on the search is reachable by the stop button.
            _portSearch = scanner;
            _portSearchStopped = false;

            // Through the UI thread here as well: the search runs in the
            // thread pool, and the progress bar is bound.
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

                // Into the thread pool, as with the full run: 65,536 probes
                // with their continuations on the UI thread would freeze the
                // window, including the stop button, which would then not
                // respond in time.
                IPToScan found = await Task.Run(() => scanner.FindServicePortAsync(
                    new IPToScan { IPorHostname = address }, service));

                // Open or responding counts. "Filtered" means a firewall is in
                // between; that is not a finding of the service.
                List<int> ports = [.. found.Services.Services
                    .Where(s => s.Service == service)
                    .SelectMany(s => s.Ports)
                    .Where(p => p.Status is PortStatus.Open or PortStatus.IsRunning)
                    .SelectMany(p => p.Ports)
                    .Distinct()
                    .Order()];

                if (ports.Count == 0)
                {
                    // A cancellation is not a finding: everything beyond the
                    // point reached is unchecked.
                    StatusText = _portSearchStopped
                        ? $"Port search for {service} on {device.DisplayName} was cancelled."
                        : $"{service} was not found on any port of {device.DisplayName}.";
                    return;
                }

                // The actual finding belongs in the device's service list,
                // where the regular service scan stores its hits too. Kept only
                // in the status line and a detail row, the "Running services"
                // column, the service filter and the port count would know
                // nothing of it, and the search over 65,536 ports would be lost
                // on the next save.
                MergeFoundPorts(device, service, found);

                // The detail note is kept in addition: it records that this port
                // comes from the full-range search, not from the regular port
                // selection.
                device.Details[$"{service} port search"] =
                    $"found on port {string.Join(", ", ports)}";
                device.NotifyDisplayChanged();

                // The service selection and the facet counts are built from the
                // inventory; without this trigger a service not seen before
                // would not appear in the filter.
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
        /// Adds the findings of the port search to the device's service list.
        /// <para>
        /// Deliberately through <c>Observe</c> rather than appending to
        /// <c>device.Services</c> directly: the in-memory merge decides by
        /// service <b>and</b> ports whether a finding is new or extends an
        /// existing one. Bypassing it puts the same service in the list twice
        /// as soon as the search is repeated.
        /// </para>
        /// <para>
        /// Only what answered is taken over. "Filtered" or "no answer" over
        /// 65,536 ports would not be a finding but the log of an attempt, and
        /// would clutter the service list.
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

                    // As in the scan: only the port whose answer matched the
                    // protocol carries the name of the searched service. Over
                    // 65,536 ports that is the difference between a finding
                    // and a list in which every open port of the device would
                    // carry the name of the searched service. See
                    // docs/FEHLERGEDAECHTNIS.md, No. 2.
                    bool unidentifiedOpen = port.Status == PortStatus.Open && port.Ports.Count == 1;

                    DeviceServiceResult result = new()
                    {
                        ServiceName = unidentifiedOpen ? $"TCP {port.Ports[0]}" : ServiceNames.Of(service),
                        Category = unidentifiedOpen ? "Open ports" : ServiceCategories.Of(service),
                        Ports = [.. port.Ports],
                        PortLog = string.IsNullOrWhiteSpace(port.PortLog) ? null : port.PortLog
                    };

                    if (address.Family == IpFamily.IPv6) result.StatusIPv6 = port.Status;
                    else result.StatusIPv4 = port.Status;

                    results.Add(result);
                }
            }

            if (results.Count == 0) return;

            // As in the full run: what the industrial protocols report about
            // themselves belongs in the details, not only in the "running"
            // row.
            Dictionary<string, string>? details = null;

            string? label = ServiceNames.InfoLabelOf(service);

            if (!string.IsNullOrEmpty(label))
            {
                // As in the full run: the mere confirmation sentence of a
                // successful detection is no information and does not belong
                // under a heading in the details.
                string? log = results
                    .FirstOrDefault(r => r.IsRunning && LegacyScanMethod.IsDeviceInfo(r.PortLog))?.PortLog;

                if (!string.IsNullOrWhiteSpace(log))
                {
                    details = new Dictionary<string, string> { [label] = log };
                }
            }

            _store.Observe(new DeviceObservation
            {
                Source = "Port search",
                Address = address,
                IsResponding = true,
                Details = details,
                Services = results
            });
        }

        /// <summary>
        /// The services offered by the port search; the same enumeration the
        /// service scan uses.
        /// </summary>
        public static IReadOnlyList<ServiceType> AllServiceTypes { get; } =
            [.. Enum.GetValues<ServiceType>()];

        /// <summary>
        /// Cancels whatever is running: the engine's scan <b>and</b> a port
        /// search alongside it. The two are separate runs, but they share one
        /// button.
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

            // Satellites are excluded here: their job is stopped individually
            // in the satellite management. A button that clears all segments at
            // once would be too coarse; usually exactly the one that hangs
            // needs to be freed.
            StatusText = "Cancelling...";
        }

        /// <summary>Clears the device table and the run plan.</summary>
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
        /// Summarises the run in one sentence. Skipped methods are mentioned,
        /// not concealed; otherwise missing results would be unexplained.
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

            // The finding goes at the start of the sentence, not the end: it is
            // the reason for scanning in the first place.
            if (result.ConflictCount > 0)
            {
                summary = $"{result.ConflictCount} device(s) with duplicate addresses or names. " + summary;
            }

            return summary;
        }

        /// <summary>
        /// A context with sample targets only, for the availability
        /// check. It contains the scopes completely (the IPv6 assessment
        /// depends on them), but enumerating the targets would be wasted here
        /// because it would run again on every check mark.
        /// </summary>
        private ScanContext BuildProbeContext(IReadOnlyList<ScopeRuntime>? forRuntimes = null)
        {
            // One or two sample targets per scope are enough for the methods
            // to recognise the address families present.
            List<ScanTargetEntry> sample = [];
            IReadOnlyList<ScopeRuntime> runtimes = forRuntimes ?? _lastRuntimes;

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
                ReportStepProgress = (_, _, _, _, _, _) => { }
            };
        }
    }
}
