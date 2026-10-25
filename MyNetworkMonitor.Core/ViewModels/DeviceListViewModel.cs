// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using CommunityToolkit.Mvvm.ComponentModel;
using MyNetworkMonitor.Core.Model;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>A service name with its hit count, for the service selection in the filter.</summary>
    public sealed class ServiceFacet
    {
        /// <summary>The service name.</summary>
        public required string Name { get; init; }
        /// <summary>The category the service belongs to.</summary>
        public required string Category { get; init; }

        /// <summary>Number of devices on which the service was found.</summary>
        public int DeviceCount { get; set; }

        /// <summary>Number of those devices on which it is actually running.</summary>
        public int RunningCount { get; set; }

        public override string ToString() => $"{Name} ({DeviceCount})";
    }

    /// <summary>
    /// A scanned scope with its hit count, for the scope selection in the
    /// filter. Built like <see cref="ServiceFacet"/> for the same reason: the
    /// scopes change with the network being worked on, and a fixed list would
    /// be wrong after the next change of location.
    /// </summary>
    public sealed class ScopeFacet
    {
        /// <summary>The scope description as stored on the device.</summary>
        public required string Name { get; init; }

        /// <summary>Number of devices from this scope.</summary>
        public int DeviceCount { get; set; }

        /// <summary>Number of those devices that are currently answering.</summary>
        public int OnlineCount { get; set; }

        public override string ToString() => $"{Name} ({DeviceCount})";
    }

    /// <summary>
    /// The result table: takes the devices from the <see cref="DeviceStore"/>,
    /// applies the filter and keeps the visible list up to date.
    /// <para>
    /// The service selection in the filter is built from the services actually
    /// found, not from a fixed list, so only existing services can be selected
    /// and their counts are visible right away.
    /// </para>
    /// </summary>
    public partial class DeviceListViewModel : ObservableObject
    {
        private readonly DeviceStore _store;

        /// <summary>
        /// The UI thread on which the list must be built. During a scan the
        /// modules report from arbitrary tasks; without marshalling back,
        /// <see cref="Visible"/> would be modified from a background thread,
        /// which Avalonia rejects.
        /// </summary>
        private readonly SynchronizationContext? _uiContext = SynchronizationContext.Current;

        private Timer? _liveTimer;
        private int _pending;

        /// <summary>
        /// Devices whose display properties must be recomputed during a run.
        /// Collected because the notification itself belongs on the UI thread.
        /// </summary>
        private readonly HashSet<Device> _dirty = [];

        /// <summary>Creates the view model on the UI thread and subscribes to the store.</summary>
        /// <param name="store">The device store that supplies the devices.</param>
        /// <exception cref="ArgumentNullException"><paramref name="store"/> is <see langword="null"/>.</exception>
        public DeviceListViewModel(DeviceStore store)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));

            Filter.Changed += Refresh;
            ((INotifyCollectionChanged)_store.Devices).CollectionChanged += (_, _) => RequestRefresh();
            _store.DeviceChanged += OnDeviceChanged;

            // The service column is computed and depends on a setting outside
            // the device; without this trigger the table would not update
            // until something else changes.
            ServiceDisplay.Changed += OnServiceDisplayChanged;

            Refresh();
        }

        /// <summary>
        /// The display option has changed; every visible row must recompute
        /// its service column.
        /// </summary>
        private void OnServiceDisplayChanged()
        {
            foreach (Device device in Visible) device.NotifyDisplayChanged();
        }

        private void OnDeviceChanged(Device device)
        {
            if (_liveTimer is not null)
            {
                lock (_dirty) _dirty.Add(device);
            }

            RequestRefresh();
        }

        /// <summary>The filter applied to the table.</summary>
        public DeviceFilter Filter { get; } = new();

        /// <summary>The devices that pass the filter, in display order.</summary>
        public ObservableCollection<Device> Visible { get; } = [];

        /// <summary>All services found, with hit counts, sorted by category and name.</summary>
        public ObservableCollection<ServiceFacet> AvailableServices { get; } = [];

        /// <summary>All scopes devices come from, with hit counts.</summary>
        public ObservableCollection<ScopeFacet> AvailableScopes { get; } = [];

        [ObservableProperty] private int _totalCount;
        [ObservableProperty] private int _visibleCount;
        [ObservableProperty] private int _ipv6CapableCount;
        [ObservableProperty] private int _onlineCount;

        /// <summary>Groups the table by scope instead of showing a flat list.</summary>
        [ObservableProperty] private bool _groupByScope;

        /// <summary>The row that was clicked last.</summary>
        [ObservableProperty] private Device? _selected;

        /// <summary>
        /// All selected rows, not just the last one clicked. The table updates
        /// this list on every selection change; rescanning selected devices
        /// depends on it and would be of little use with a single row.
        /// </summary>
        public ObservableCollection<Device> SelectedDevices { get; } = [];

        /// <summary>
        /// The devices a context-menu action applies to: the selection, or the
        /// clicked row if nothing is selected.
        /// </summary>
        public IReadOnlyList<Device> ActionTargets =>
            SelectedDevices.Count > 0 ? [.. SelectedDevices] :
            Selected is not null ? [Selected] :
            [];

        /// <summary>Number of devices currently hidden by the filter.</summary>
        public int FilteredOutCount => TotalCount - VisibleCount;

        /// <summary>
        /// The minimum interval between list rebuilds during a run. A scan of
        /// 254 addresses reports several hundred times; processing each report
        /// individually would stall the UI, and rebuilding only at the end
        /// leaves the table looking empty for minutes.
        /// </summary>
        private static readonly TimeSpan LiveInterval = TimeSpan.FromMilliseconds(400);

        /// <summary>
        /// Enables live updates during a scan: the table fills while scanning
        /// instead of all at once at the end. Disposing the returned object
        /// performs a final refresh.
        /// </summary>
        /// <returns>An object that ends the live updates when disposed.</returns>
        public IDisposable BeginLiveUpdates()
        {
            _liveTimer?.Dispose();

            // The store stops notifying by itself while live updates are on;
            // otherwise the notifications would reach visible rows from the
            // scan threads.
            _store.DeferDisplayNotifications = true;

            _liveTimer = new Timer(_ => Flush(), null, LiveInterval, LiveInterval);
            return new LiveSession(this);
        }

        /// <summary>
        /// Marks a pending change. Outside a run the list is updated
        /// immediately; there the notifications arrive one at a time and from
        /// the UI thread.
        /// </summary>
        private void RequestRefresh()
        {
            Interlocked.Exchange(ref _pending, 1);

            // Outside a run update immediately; during a run the timer does
            // it. Going through Flush is correct here as well: a module can
            // still deliver a late report after the run has ended, and that
            // report must not rebuild the list from its own thread.
            if (_liveTimer is null) Flush();
        }

        /// <summary>Applies a pending change on the UI thread.</summary>
        private void Flush()
        {
            if (Interlocked.Exchange(ref _pending, 0) == 0) return;

            if (_uiContext is null) Refresh();
            else _uiContext.Post(_ => Refresh(), null);
        }

        /// <summary>
        /// Re-applies the filter, updates the visible list, the counters and
        /// the service and scope selections. Must run on the UI thread.
        /// </summary>
        public void Refresh()
        {
            // Deliver the accumulated display notifications first, here on the
            // UI thread rather than where they originated.
            NotifyDirtyDevices();

            // Evaluate under the store lock, apply outside of it: during a run
            // the scan threads keep writing, and the UI must not block them
            // longer than necessary.
            List<Device> matching;
            List<ServiceFacet> facets;
            List<ScopeFacet> scopes;
            int total, capable, online;

            lock (_store.SyncRoot)
            {
                matching = [.. _store.Devices
                    .Where(Filter.Matches)
                    .OrderByDescending(d => ConflictsFirst ? d.ConflictRank : 0)
                    .ThenBy(SortKeyOf, ByteArrayComparer.Instance)];
                facets = BuildServiceFacets();
                scopes = BuildScopeFacets();

                total = _store.Devices.Count;
                capable = _store.Devices.Count(d => d.IsIpv6Capable);
                online = _store.Devices.Count(d => d.IsOnline);
            }

            // Synchronise in place instead of refilling so the selection and the
            // scroll position are preserved.
            SyncInto(Visible, matching);

            TotalCount = total;
            VisibleCount = Visible.Count;
            Ipv6CapableCount = capable;
            OnlineCount = online;
            OnPropertyChanged(nameof(FilteredOutCount));

            ApplyServiceFacets(facets);
            ApplyScopeFacets(scopes);
        }

        /// <summary>
        /// Sorts address conflicts to the top. A finding on row 380 is easily
        /// missed, so the list can be ordered by it without hiding the other
        /// devices.
        /// </summary>
        [ObservableProperty] private bool _conflictsFirst;

        partial void OnConflictsFirstChanged(bool value) => Refresh();

        /// <summary>
        /// Sorts by the primary address. The 128-bit key puts IPv4 and IPv6
        /// into one meaningful order; sorting by text would place .10 before .9.
        /// </summary>
        private static byte[] SortKeyOf(Device device) =>
            device.PrimaryAddress?.Info.SortKey ?? new byte[16];

        private static void SyncInto(ObservableCollection<Device> target, List<Device> source)
        {
            for (int i = target.Count - 1; i >= 0; i--)
            {
                if (!source.Contains(target[i])) target.RemoveAt(i);
            }

            for (int i = 0; i < source.Count; i++)
            {
                int existing = target.IndexOf(source[i]);

                if (existing < 0) target.Insert(i, source[i]);
                else if (existing != i) target.Move(existing, i);
            }
        }

        /// <summary>
        /// Rebuilds the service selection. Deliberately over all devices, not
        /// only the visible ones; otherwise the selection itself would remove
        /// the entries needed to undo it.
        /// <para>
        /// Only services that answered are counted. Scans run against all
        /// service definitions; including the closed ones would list three
        /// hundred services of which four exist.
        /// </para>
        /// </summary>
        private List<ServiceFacet> BuildServiceFacets()
        {
            Dictionary<string, ServiceFacet> facets = new(StringComparer.OrdinalIgnoreCase);

            foreach (Device device in _store.Devices)
            {
                foreach (DeviceServiceResult service in device.OpenServices)
                {
                    if (!facets.TryGetValue(service.ServiceName, out ServiceFacet? facet))
                    {
                        facet = new ServiceFacet { Name = service.ServiceName, Category = service.Category };
                        facets[service.ServiceName] = facet;
                    }

                    facet.DeviceCount++;
                    if (service.IsRunning) facet.RunningCount++;
                }
            }

            // By category, then alphabetically by name. The selection shows the
            // category as a subheading and indents the services below it;
            // without the subheadings the order would look random because the
            // category would not be visible.
            //
            // Case is ignored; otherwise "MSSQLServer" and "MariaDB" would end
            // up far apart.
            return
            [
                .. facets.Values
                    .OrderBy(f => f.Category, StringComparer.CurrentCultureIgnoreCase)
                    .ThenBy(f => SortKey(f.Name).Text, StringComparer.CurrentCultureIgnoreCase)
                    .ThenBy(f => SortKey(f.Name).Number)
            ];
        }

        /// <summary>
        /// Splits a service name into its text and a trailing number.
        /// <para>
        /// The placeholders for open ports are named "TCP 21", "TCP 5900" and
        /// so on. Sorted purely by characters, "TCP 102" would come before
        /// "TCP 21", which is not how ports are looked up. Names without a
        /// number are left unchanged.
        /// </para>
        /// </summary>
        private static (string Text, int Number) SortKey(string name)
        {
            int space = name.LastIndexOf(' ');

            return space > 0 && int.TryParse(name[(space + 1)..], out int number)
                ? (name[..space], number)
                : (name, -1);
        }

        /// <summary>
        /// Applies the facets only if something has changed. The service
        /// selection is built from this list; clearing and refilling it every
        /// 400 ms during a run would make an open drop-down jump while in use.
        /// </summary>
        private void ApplyServiceFacets(List<ServiceFacet> facets)
        {
            bool same =
                facets.Count == AvailableServices.Count &&
                facets.Zip(AvailableServices).All(pair =>
                    string.Equals(pair.First.Name, pair.Second.Name, StringComparison.OrdinalIgnoreCase) &&
                    pair.First.DeviceCount == pair.Second.DeviceCount &&
                    pair.First.RunningCount == pair.Second.RunningCount);

            if (same) return;

            AvailableServices.Clear();
            foreach (ServiceFacet facet in facets) AvailableServices.Add(facet);
        }

        /// <summary>Toggles a service in the filter.</summary>
        /// <param name="serviceName">The service name; blank names are ignored.</param>
        public void ToggleService(string serviceName)
        {
            if (string.IsNullOrWhiteSpace(serviceName)) return;

            if (!Filter.Services.Remove(serviceName)) Filter.Services.Add(serviceName);

            Filter.NotifyServicesChanged();
        }

        /// <summary>
        /// Rebuilds the scope selection. Like the service selection it covers
        /// all devices, not only the visible ones; otherwise the selection
        /// would remove the entries needed to undo it.
        /// <para>
        /// The scope a device comes from is stored on the device itself. The
        /// entered scopes are not a suitable source: they change between runs,
        /// and after loading the last saved inventory they no longer exist,
        /// while the devices do.
        /// </para>
        /// </summary>
        private List<ScopeFacet> BuildScopeFacets()
        {
            Dictionary<string, ScopeFacet> facets = new(StringComparer.OrdinalIgnoreCase);

            foreach (Device device in _store.Devices)
            {
                string key = DeviceFilter.ScopeKeyOf(device);

                if (!facets.TryGetValue(key, out ScopeFacet? facet))
                {
                    facet = new ScopeFacet { Name = key };
                    facets[key] = facet;
                }

                facet.DeviceCount++;
                if (device.IsOnline) facet.OnlineCount++;
            }

            // "No range" goes last: it is the catch-all, not the first scope
            // anyone looks for.
            return
            [
                .. facets.Values
                    .OrderBy(f => f.Name == DeviceFilter.NoScopeKey)
                    .ThenBy(f => f.Name, StringComparer.CurrentCulture)
            ];
        }

        /// <summary>
        /// Applies the scopes only on an actual change, for the same reason as
        /// with the services: an open drop-down must not be rebuilt while in
        /// use during a run.
        /// </summary>
        private void ApplyScopeFacets(List<ScopeFacet> facets)
        {
            bool same =
                facets.Count == AvailableScopes.Count &&
                facets.Zip(AvailableScopes).All(pair =>
                    string.Equals(pair.First.Name, pair.Second.Name, StringComparison.OrdinalIgnoreCase) &&
                    pair.First.DeviceCount == pair.Second.DeviceCount &&
                    pair.First.OnlineCount == pair.Second.OnlineCount);

            if (same) return;

            AvailableScopes.Clear();
            foreach (ScopeFacet facet in facets) AvailableScopes.Add(facet);
        }

        /// <summary>Toggles a scope in the filter.</summary>
        /// <param name="scopeName">The scope key; blank names are ignored.</param>
        public void ToggleScope(string scopeName)
        {
            if (string.IsNullOrWhiteSpace(scopeName)) return;

            if (!Filter.Scopes.Remove(scopeName)) Filter.Scopes.Add(scopeName);

            Filter.NotifyScopesChanged();
        }

        /// <summary>
        /// Raises the collected display notifications. Must run on the UI
        /// thread; that is why they were collected.
        /// </summary>
        private void NotifyDirtyDevices()
        {
            List<Device> devices;

            lock (_dirty)
            {
                if (_dirty.Count == 0) return;

                devices = [.. _dirty];
                _dirty.Clear();
            }

            foreach (Device device in devices) device.NotifyDisplayChanged();
        }

        private sealed class LiveSession(DeviceListViewModel owner) : IDisposable
        {
            public void Dispose()
            {
                Timer? timer = owner._liveTimer;
                owner._liveTimer = null;
                timer?.Dispose();

                owner._store.DeferDisplayNotifications = false;
                owner.Refresh();
            }
        }
    }
}
