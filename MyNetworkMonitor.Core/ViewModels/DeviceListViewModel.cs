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
        private bool _suspended;

        public DeviceListViewModel(DeviceStore store)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));

            Filter.Changed += Refresh;
            ((INotifyCollectionChanged)_store.Devices).CollectionChanged += (_, _) => Refresh();
            _store.DeviceChanged += _ => Refresh();

            Refresh();
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
        /// Waehrend eines Scans laufen viele Meldungen ein. Der Aufrufer kann
        /// die Neuberechnung so lange aussetzen und einmal am Ende nachziehen,
        /// statt sie je Geraet anzustossen.
        /// </summary>
        public IDisposable SuspendRefresh()
        {
            _suspended = true;
            return new Resumer(this);
        }

        public void Refresh()
        {
            if (_suspended) return;

            List<Device> matching = [.. _store.Devices.Where(Filter.Matches).OrderBy(SortKeyOf, ByteArrayComparer.Instance)];

            // Gezielt abgleichen statt neu befuellen, damit die Auswahl des
            // Nutzers und die Bildlaufposition erhalten bleiben.
            SyncInto(Visible, matching);

            TotalCount = _store.Devices.Count;
            VisibleCount = Visible.Count;
            Ipv6CapableCount = _store.Devices.Count(d => d.IsIpv6Capable);
            OnlineCount = _store.Devices.Count(d => d.IsOnline);
            OnPropertyChanged(nameof(FilteredOutCount));

            RebuildServiceFacets();
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
        /// </summary>
        private void RebuildServiceFacets()
        {
            Dictionary<string, ServiceFacet> facets = new(StringComparer.OrdinalIgnoreCase);

            foreach (Device device in _store.Devices)
            {
                foreach (DeviceServiceResult service in device.Services)
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

            AvailableServices.Clear();

            foreach (ServiceFacet facet in facets.Values
                         .OrderBy(f => f.Category, StringComparer.CurrentCulture)
                         .ThenBy(f => f.Name, StringComparer.CurrentCulture))
            {
                AvailableServices.Add(facet);
            }
        }

        /// <summary>Schaltet einen Dienst im Filter um.</summary>
        public void ToggleService(string serviceName)
        {
            if (string.IsNullOrWhiteSpace(serviceName)) return;

            if (!Filter.Services.Remove(serviceName)) Filter.Services.Add(serviceName);

            Filter.NotifyServicesChanged();
        }

        private sealed class Resumer(DeviceListViewModel owner) : IDisposable
        {
            public void Dispose()
            {
                owner._suspended = false;
                owner.Refresh();
            }
        }
    }
}
