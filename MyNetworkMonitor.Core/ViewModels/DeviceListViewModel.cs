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
    /// Ein gescannter Bereich samt Trefferzahl - fuer die Bereichsauswahl im
    /// Filter. Gebaut wie <see cref="ServiceFacet"/>, aus demselben Grund: die
    /// Bereiche aendern sich, je nachdem wo man arbeitet, und eine feste Liste
    /// waere nach dem naechsten Ortswechsel falsch.
    /// </summary>
    public sealed class ScopeFacet
    {
        /// <summary>Die Beschreibung des Bereichs, wie sie am Geraet steht.</summary>
        public required string Name { get; init; }

        /// <summary>Wie viele Geraete aus diesem Bereich stammen.</summary>
        public int DeviceCount { get; set; }

        /// <summary>Wie viele davon gerade antworten.</summary>
        public int OnlineCount { get; set; }

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

            // Die Dienstspalte ist berechnet und haengt an einer Einstellung
            // ausserhalb des Geraets - ohne diesen Anstoss bliebe die Tabelle
            // stehen, bis sich sonst etwas ruehrt.
            ServiceDisplay.Changed += OnServiceDisplayChanged;

            Refresh();
        }

        /// <summary>
        /// Die Anzeigeoption hat sich geaendert - jede sichtbare Zeile muss
        /// ihre Dienstspalte neu berechnen.
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

        public DeviceFilter Filter { get; } = new();

        /// <summary>Die Geraete, die der Filter durchlaesst - in Anzeigereihenfolge.</summary>
        public ObservableCollection<Device> Visible { get; } = [];

        /// <summary>Alle gefundenen Dienste mit Trefferzahl, alphabetisch.</summary>
        public ObservableCollection<ServiceFacet> AvailableServices { get; } = [];

        /// <summary>Alle Bereiche, aus denen Geraete stammen, mit Trefferzahl.</summary>
        public ObservableCollection<ScopeFacet> AvailableScopes { get; } = [];

        [ObservableProperty] private int _totalCount;
        [ObservableProperty] private int _visibleCount;
        [ObservableProperty] private int _ipv6CapableCount;
        [ObservableProperty] private int _onlineCount;

        /// <summary>Nach Bereich gruppieren statt flach anzeigen.</summary>
        [ObservableProperty] private bool _groupByScope;

        [ObservableProperty] private Device? _selected;

        /// <summary>
        /// Alle markierten Zeilen, nicht nur die zuletzt angeklickte. Die
        /// Tabelle traegt sie bei jeder Aenderung der Markierung ein - daran
        /// haengt das erneute Scannen ausgewaehlter Geraete, das mit einer
        /// einzelnen Zeile wenig wert waere.
        /// </summary>
        public ObservableCollection<Device> SelectedDevices { get; } = [];

        /// <summary>
        /// Die Geraete, auf die sich eine Aktion aus dem Kontextmenue bezieht:
        /// die Markierung, und falls es keine gibt, die angeklickte Zeile.
        /// </summary>
        public IReadOnlyList<Device> ActionTargets =>
            SelectedDevices.Count > 0 ? [.. SelectedDevices] :
            Selected is not null ? [Selected] :
            [];

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

            // Gezielt abgleichen statt neu befuellen, damit die Auswahl des
            // Nutzers und die Bildlaufposition erhalten bleiben.
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
        /// Doppelbelegungen nach oben. Ein Befund, der auf Zeile 380 steht,
        /// ist so gut wie keiner - darum laesst sich die Liste danach ordnen,
        /// ohne dass man die uebrigen Geraete ausblenden muss.
        /// </summary>
        [ObservableProperty] private bool _conflictsFirst;

        partial void OnConflictsFirstChanged(bool value) => Refresh();

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
        /// Baut die Bereichsauswahl neu auf - wie die Dienstauswahl ueber alle
        /// Geraete und nicht nur die sichtbaren, sonst raeumte die eigene
        /// Auswahl die Eintraege weg, mit denen man sie zuruecknimmt.
        /// <para>
        /// Woher ein Geraet stammt, steht an ihm selbst. Die eingegebenen
        /// Bereiche waeren die naheliegendere Quelle, taugen dafuer aber nicht:
        /// sie aendern sich zwischen zwei Laeufen, und nach dem Laden des
        /// letzten Bestands gibt es sie gar nicht mehr - die Geraete aber schon.
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

            // "Ohne Bereich" ans Ende: es ist der Sammelposten, nicht der
            // erste Bereich, den man sucht.
            return
            [
                .. facets.Values
                    .OrderBy(f => f.Name == DeviceFilter.NoScopeKey)
                    .ThenBy(f => f.Name, StringComparer.CurrentCulture)
            ];
        }

        /// <summary>
        /// Uebernimmt die Bereiche nur bei echter Aenderung - derselbe Grund
        /// wie bei den Diensten: ein geoeffnetes Ausklappmenue darf waehrend
        /// eines Laufs nicht unter der Hand des Nutzers neu aufgebaut werden.
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

        /// <summary>Schaltet einen Bereich im Filter um.</summary>
        public void ToggleScope(string scopeName)
        {
            if (string.IsNullOrWhiteSpace(scopeName)) return;

            if (!Filter.Scopes.Remove(scopeName)) Filter.Scopes.Add(scopeName);

            Filter.NotifyScopesChanged();
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
