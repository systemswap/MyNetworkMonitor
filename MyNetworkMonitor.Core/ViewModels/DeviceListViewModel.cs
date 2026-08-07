using System.Collections.ObjectModel;
using System.Collections.Specialized;
using CommunityToolkit.Mvvm.ComponentModel;
using MyNetworkMonitor.Core.Model;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>Ein Dienstname samt Trefferzahl - fuer die Dienstauswahl im Filter.</summary>
    public sealed class ServiceFacet
    {
        public required string Name { get; init; }
        public required string Category { get; init; }

        /// <summary>Auf wie vielen Geraeten der Dienst vorkommt.</summary>
        public int DeviceCount { get; set; }

        /// <summary>Auf wie vielen davon er tatsaechlich laeuft.</summary>
        public int RunningCount { get; set; }

        public override string ToString() => $"{Name} ({DeviceCount})";
    }

    /// <summary>
    /// Die Ergebnistabelle: nimmt die Geraete aus dem <see cref="DeviceStore"/>,
    /// wendet den Filter an und haelt die sichtbare Liste aktuell.
    /// <para>
    /// Die Dienstauswahl im Filter wird aus den tatsaechlich gefundenen
    /// Diensten gebildet, nicht aus einer festen Liste - man kann also nur nach
    /// etwas filtern, das es auch gibt, und sieht gleich, wie oft.
    /// </para>
    /// </summary>
    public partial class DeviceListViewModel : ObservableObject
    {
        private readonly DeviceStore _store;

        /// <summary>
        /// Der Oberflaechen-Thread, auf dem die Liste gebaut werden muss.
        /// Waehrend eines Scans melden die Module aus beliebigen Aufgaben - ohne
        /// diesen Rueckweg wuerde <see cref="Visible"/> aus einem
        /// Hintergrund-Thread veraendert, was Avalonia wie WPF ablehnen.
        /// </summary>
        private readonly SynchronizationContext? _uiContext = SynchronizationContext.Current;

        private Timer? _liveTimer;
        private int _pending;

        /// <summary>
        /// Geraete, deren Anzeigeeigenschaften waehrend eines Laufs neu
        /// berechnet werden muessen. Gesammelt, weil die Meldung selbst auf
        /// den Oberflaechen-Thread gehoert.
        /// </summary>
        private readonly HashSet<Device> _dirty = [];

        public DeviceListViewModel(DeviceStore store)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));

            Filter.Changed += Refresh;
            ((INotifyCollectionChanged)_store.Devices).CollectionChanged += (_, _) => RequestRefresh();
            _store.DeviceChanged += OnDeviceChanged;

            Refresh();
        }

        private void OnDeviceChanged(Device device)
        {
            if (_liveTimer is not null)
            {
                lock (_dirty) _dirty.Add(device);
            }

            RequestRefresh();
        }

        public DeviceFilter Filter { get; } = new();

        /// <summary>Die Geraete, die der Filter durchlaesst - in Anzeigereihenfolge.</summary>
        public ObservableCollection<Device> Visible { get; } = [];

        /// <summary>Alle gefundenen Dienste mit Trefferzahl, alphabetisch.</summary>
        public ObservableCollection<ServiceFacet> AvailableServices { get; } = [];

        [ObservableProperty] private int _totalCount;
        [ObservableProperty] private int _visibleCount;
        [ObservableProperty] private int _ipv6CapableCount;
        [ObservableProperty] private int _onlineCount;

        /// <summary>Nach Bereich gruppieren statt flach anzeigen.</summary>
        [ObservableProperty] private bool _groupByScope;

        [ObservableProperty] private Device? _selected;

        /// <summary>Wie viele Geraete der Filter gerade ausblendet.</summary>
        public int FilteredOutCount => TotalCount - VisibleCount;

        /// <summary>
        /// Wie oft die Liste waehrend eines Laufs hoechstens neu gebaut wird.
        /// Ein Scan ueber 254 Adressen meldet mehrere hundert Mal; jede Meldung
        /// einzeln zu verarbeiten wuerde die Oberflaeche lahmlegen, einmal am
        /// Ende laesst die Tabelle minutenlang leer aussehen.
        /// </summary>
        private static readonly TimeSpan LiveInterval = TimeSpan.FromMilliseconds(400);

        /// <summary>
        /// Schaltet die laufende Aktualisierung waehrend eines Scans ein: die
        /// Tabelle fuellt sich, waehrend gescannt wird, statt am Ende auf
        /// einen Schlag. Beim Freigeben wird ein letztes Mal nachgezogen.
        /// </summary>
        public IDisposable BeginLiveUpdates()
        {
            _liveTimer?.Dispose();

            // Der Store meldet ab jetzt nicht mehr selbst - die Meldungen kaemen
            // sonst aus den Scan-Threads an bereits sichtbare Zeilen.
            _store.DeferDisplayNotifications = true;

            _liveTimer = new Timer(_ => Flush(), null, LiveInterval, LiveInterval);
            return new LiveSession(this);
        }

        /// <summary>
        /// Merkt eine Aenderung vor. Ausserhalb eines Laufs wird sofort
        /// aktualisiert - dort kommen die Meldungen einzeln und vom
        /// Oberflaechen-Thread.
        /// </summary>
        private void RequestRefresh()
        {
            Interlocked.Exchange(ref _pending, 1);

            // Ausserhalb eines Laufs sofort nachziehen; waehrend eines Laufs
            // uebernimmt das der Zeitgeber. Der Weg ueber Flush ist auch hier
            // richtig - ein Modul kann nach dem Ende des Laufs noch eine
            // verspaetete Meldung nachreichen, und die darf die Liste nicht
            // aus ihrem eigenen Thread heraus umbauen.
            if (_liveTimer is null) Flush();
        }

        /// <summary>Zieht eine vorgemerkte Aenderung auf dem Oberflaechen-Thread nach.</summary>
        private void Flush()
        {
            if (Interlocked.Exchange(ref _pending, 0) == 0) return;

            if (_uiContext is null) Refresh();
            else _uiContext.Post(_ => Refresh(), null);
        }

        public void Refresh()
        {
            // Erst die aufgelaufenen Anzeigemeldungen nachholen - hier, auf dem
            // Oberflaechen-Thread, statt dort, wo sie entstanden sind.
            NotifyDirtyDevices();

            // Auswerten unter der Sperre des Bestands, anwenden ausserhalb:
            // waehrend eines Laufs schreiben die Scan-Threads weiter, und die
            // Oberflaeche darf sie nicht laenger aufhalten als noetig.
            List<Device> matching;
            List<ServiceFacet> facets;
            int total, capable, online;

            lock (_store.SyncRoot)
            {
                matching = [.. _store.Devices.Where(Filter.Matches).OrderBy(SortKeyOf, ByteArrayComparer.Instance)];
                facets = BuildServiceFacets();

                total = _store.Devices.Count;
                capable = _store.Devices.Count(d => d.IsIpv6Capable);
                online = _store.Devices.Count(d => d.IsOnline);
            }

            // Gezielt abgleichen statt neu befuellen, damit die Auswahl des
            // Nutzers und die Bildlaufposition erhalten bleiben.
            SyncInto(Visible, matching);

            TotalCount = total;
            VisibleCount = Visible.Count;
            Ipv6CapableCount = capable;
            OnlineCount = online;
            OnPropertyChanged(nameof(FilteredOutCount));

            ApplyServiceFacets(facets);
        }

        /// <summary>
        /// Sortiert nach der Hauptadresse. Der 128-Bit-Schluessel bringt IPv4
        /// und IPv6 in eine sinnvolle gemeinsame Reihenfolge; ohne ihn wuerde
        /// nach Text sortiert und .10 laege vor .9.
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
        /// Baut die Dienstauswahl neu auf. Bewusst ueber alle Geraete, nicht
        /// nur die sichtbaren - sonst verschwaende die eigene Auswahl die
        /// Eintraege, mit denen man sie wieder aufheben will.
        /// <para>
        /// Gezaehlt wird nur, was geantwortet hat. Gescannt wird gegen alle
        /// Dienstdefinitionen; stuenden die geschlossenen mit darin, meldete
        /// die Auswahl dreihundert Dienste, von denen vier existieren.
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

            return
            [
                .. facets.Values
                    .OrderBy(f => f.Category, StringComparer.CurrentCulture)
                    .ThenBy(f => f.Name, StringComparer.CurrentCulture)
            ];
        }

        /// <summary>
        /// Uebernimmt die Facetten nur, wenn sich etwas geaendert hat. Die
        /// Dienstauswahl wird aus dieser Liste aufgebaut; sie waehrend eines
        /// Laufs alle 400 ms zu leeren und neu zu fuellen liesse ein
        /// geoeffnetes Ausklappmenue unter der Hand des Nutzers springen.
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

        /// <summary>Schaltet einen Dienst im Filter um.</summary>
        public void ToggleService(string serviceName)
        {
            if (string.IsNullOrWhiteSpace(serviceName)) return;

            if (!Filter.Services.Remove(serviceName)) Filter.Services.Add(serviceName);

            Filter.NotifyServicesChanged();
        }

        /// <summary>
        /// Loest die gesammelten Anzeigemeldungen aus. Muss auf dem
        /// Oberflaechen-Thread laufen - genau dafuer wurden sie gesammelt.
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
