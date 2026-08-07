using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>Wie dringend ein Befund ist.</summary>
    public enum FindingSeverity
    {
        /// <summary>Gut zu wissen, kein Handlungsdruck.</summary>
        Note = 0,

        /// <summary>Sollte angesehen werden.</summary>
        Warning = 1,

        /// <summary>Etwas ist kaputt oder offen und gehoert abgestellt.</summary>
        Critical = 2
    }

    /// <summary>
    /// Wozu ein Befund gehoert. Gruppiert die Liste und laesst sie wachsen,
    /// ohne dass sie unuebersichtlich wird.
    /// <para>
    /// Die IPv6-Kategorien stehen hier bereits, obwohl die Verfahren dahinter
    /// noch fehlen: <see cref="RouterAdvertisement"/> und
    /// <see cref="Reachability"/> sind der Grund, warum es diese Seite gibt.
    /// Sie jetzt zu benennen kostet nichts und haelt die Gliederung stabil -
    /// nachtraeglich eingefuegte Kategorien verschieben sonst die ganze
    /// Anzeige.
    /// </para>
    /// </summary>
    public enum FindingCategory
    {
        /// <summary>Adressen und Namen: doppelt vergeben, widersprüchlich, verwaist.</summary>
        Addressing,

        /// <summary>Dienste und Ports.</summary>
        Services,

        /// <summary>Der eigene Rechner - Adapter, Namensserver, Rechte.</summary>
        LocalMachine,

        /// <summary>Router Advertisements und Praefixe. Kommt mit dem RA-Mitschnitt.</summary>
        RouterAdvertisement,

        /// <summary>Erreichbarkeit von aussen, NAT und Firewall-Luecken.</summary>
        Reachability
    }

    /// <summary>
    /// Ein einzelner Befund. Bewusst flach und ohne Bezug zur Oberflaeche - was
    /// die Regeln finden, soll sich auch ausgeben oder abspeichern lassen.
    /// </summary>
    public sealed class Finding
    {
        public required FindingSeverity Severity { get; init; }

        public required FindingCategory Category { get; init; }

        /// <summary>
        /// Welche Adressfamilie betroffen ist, oder <c>null</c>, wenn es keine
        /// Rolle spielt. Traegt die Farbgebung des Entwurfs - Tuerkis fuer
        /// IPv4, Indigo fuer IPv6 - auch in diese Liste, und macht die
        /// IPv6-Befunde spaeter auf einen Blick erkennbar.
        /// </summary>
        public IpFamily? Family { get; init; }

        /// <summary>Kurzbezeichnung der Regel, etwa "Duplicate address".</summary>
        public required string Title { get; init; }

        /// <summary>Was konkret gefunden wurde, in einem Satz.</summary>
        public required string Detail { get; init; }

        /// <summary>Woran es haengt - Geraetename oder Adapter.</summary>
        public string Subject { get; init; } = string.Empty;

        /// <summary>
        /// Das betroffene Geraet, falls es eines gibt. Daran haengt der Sprung
        /// in die Geraeteliste; ein Befund, den man nicht aufsuchen kann, ist
        /// nur halb so viel wert.
        /// </summary>
        public Device? Device { get; init; }

        public string SeverityText => Severity switch
        {
            FindingSeverity.Critical => "CRITICAL",
            FindingSeverity.Warning => "WARNING",
            _ => "NOTE"
        };

        public string CategoryText => Category switch
        {
            FindingCategory.Addressing => "Addressing",
            FindingCategory.Services => "Services",
            FindingCategory.LocalMachine => "This machine",
            FindingCategory.RouterAdvertisement => "Router",
            FindingCategory.Reachability => "Reachability",
            _ => string.Empty
        };

        /// <summary>Kuerzel der Adressfamilie fuer die schmale Spalte.</summary>
        public string FamilyText => Family switch
        {
            IpFamily.IPv4 => "v4",
            IpFamily.IPv6 => "v6",
            _ => string.Empty
        };

        public override string ToString() => $"[{SeverityText}] {Title}: {Detail}";
    }

    /// <summary>
    /// Sammelt alle Befunde an einer Stelle.
    /// <para>
    /// Die Regeln selbst laufen anderswo - Doppelbelegungen im
    /// <see cref="DuplicateDetector"/>, die Adapterpruefung in
    /// <see cref="NetworkAdapters"/>. Hier werden sie nur eingesammelt und
    /// nach Dringlichkeit sortiert. Verteilt ueber die Gerätetabelle findet
    /// man einen Befund naemlich nur, wenn man ohnehin schon weiss, dass es
    /// ihn gibt.
    /// </para>
    /// </summary>
    public sealed partial class FindingsViewModel : ObservableObject
    {
        private readonly DeviceStore _store;

        public FindingsViewModel(DeviceStore store)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
        }

        public ObservableCollection<Finding> Findings { get; } = [];

        [ObservableProperty] private Finding? _selected;

        /// <summary>Nur das Dringende zeigen.</summary>
        [ObservableProperty] private bool _criticalOnly;

        partial void OnCriticalOnlyChanged(bool value) => Refresh();

        [ObservableProperty] private int _criticalCount;
        [ObservableProperty] private int _warningCount;
        [ObservableProperty] private int _noteCount;

        /// <summary>Wann die Regeln zuletzt gelaufen sind.</summary>
        [ObservableProperty] private DateTimeOffset _lastRun;

        public bool HasFindings => Findings.Count > 0;

        /// <summary>
        /// Was oben steht, wenn nichts gefunden wurde. Ein leerer Bildschirm
        /// liesse offen, ob geprueft wurde oder ob nur nichts angezeigt wird.
        /// </summary>
        public string EmptyText =>
            LastRun == default
                ? "Nothing checked yet. Run a scan, then the rules run over the result."
                : "No findings. Every rule ran and none of them matched.";

        [RelayCommand]
        public void Refresh()
        {
            Findings.Clear();

            List<Finding> found = [];

            lock (_store.SyncRoot)
            {
                CollectDuplicates(found);
                CollectServices(found);
                CollectDnsCrossChecks(found);
            }

            CollectAdapters(found);

            IEnumerable<Finding> visible = CriticalOnly
                ? found.Where(f => f.Severity == FindingSeverity.Critical)
                : found;

            foreach (Finding finding in visible
                         .OrderByDescending(f => (int)f.Severity)
                         .ThenBy(f => f.Title, StringComparer.CurrentCulture)
                         .ThenBy(f => f.Subject, StringComparer.CurrentCulture))
            {
                Findings.Add(finding);
            }

            CriticalCount = found.Count(f => f.Severity == FindingSeverity.Critical);
            WarningCount = found.Count(f => f.Severity == FindingSeverity.Warning);
            NoteCount = found.Count(f => f.Severity == FindingSeverity.Note);

            LastRun = DateTimeOffset.Now;

            OnPropertyChanged(nameof(HasFindings));
            OnPropertyChanged(nameof(EmptyText));
        }

        // ------------------------------------------------------- Die Regeln

        /// <summary>
        /// Doppelt vergebene Adressen und Namen. Der Detektor hat sie am Ende
        /// des Laufs bereits bestimmt - hier werden sie nur uebersetzt.
        /// </summary>
        private void CollectDuplicates(List<Finding> found)
        {
            foreach (Device device in _store.Devices.Where(d => d.HasConflict))
            {
                foreach (string line in device.ConflictDetails
                             .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    found.Add(new Finding
                    {
                        // Eine doppelte Adresse kostet Pakete, ein doppelter
                        // Name kostet Nerven - das ist nicht dasselbe.
                        Severity = device.Conflicts.HasFlag(DeviceConflict.Address)
                            ? FindingSeverity.Critical
                            : FindingSeverity.Warning,
                        Category = FindingCategory.Addressing,
                        Title = TitleFor(device.Conflicts),
                        Detail = line,
                        Subject = device.DisplayName,
                        Device = device
                    });
                }
            }
        }

        private static string TitleFor(DeviceConflict conflicts) =>
            conflicts.HasFlag(DeviceConflict.Address) ? "Duplicate address" :
            conflicts.HasFlag(DeviceConflict.DnsMultipleAddresses) ? "Name resolves to several addresses" :
            conflicts.HasFlag(DeviceConflict.HostName) ? "Duplicate host name" :
            conflicts.HasFlag(DeviceConflict.DuplicateAlias) ? "Duplicate alias" :
            conflicts.HasFlag(DeviceConflict.DnsMismatch) ? "DNS points elsewhere" :
            conflicts.HasFlag(DeviceConflict.MultipleIpv4) ? "Several IPv4 addresses" :
            "Duplicate assignment";

        /// <summary>
        /// Namensserver, die dieselbe Adresse verschieden beantworten.
        /// <para>
        /// Der Befund ist nicht "der Name stimmt nicht", sondern "die Server
        /// sind sich uneinig" - und er nennt den Server beim Namen. Ohne diese
        /// Angabe wuesste man zwar, dass etwas klemmt, nicht aber, wo man
        /// nachsehen muss.
        /// </para>
        /// </summary>
        private void CollectDnsCrossChecks(List<Finding> found)
        {
            foreach (Device device in _store.Devices)
            {
                if (device.DnsCrossCheck is not { HasMismatch: true } check) continue;

                found.Add(new Finding
                {
                    // Widersprechen sich die Server, loest derselbe Name je
                    // nach Rechner etwas anderes auf - das trifft im Betrieb
                    // sofort jemanden. Ein stummer oder verwaister Eintrag ist
                    // ein Pflegethema und wiegt leichter.
                    Severity = check.DistinctNames.Count > 1
                        ? FindingSeverity.Critical
                        : FindingSeverity.Warning,
                    Category = FindingCategory.Addressing,
                    Title = check.DistinctNames.Count > 1
                        ? "DNS servers disagree"
                        : "DNS server does not resolve cleanly",
                    Detail = check.Summary,
                    Subject = device.DisplayName,
                    Device = device
                });
            }
        }

        /// <summary>
        /// Was an den gefundenen Diensten auffaellt. Bisher zwei Regeln, die
        /// ohne IPv6 auskommen; die uebrigen - offene Ports ohne NAT,
        /// abweichende Antworten je Adressfamilie - kommen mit den passiven
        /// IPv6-Verfahren dazu.
        /// </summary>
        private void CollectServices(List<Finding> found)
        {
            foreach (Device device in _store.Devices)
            {
                foreach (DeviceServiceResult service in device.OpenServices)
                {
                    // SMB 1.0 ist seit Jahren abgekuendigt und der Weg, auf dem
                    // WannaCry durch die Netze gelaufen ist.
                    if (string.Equals(service.ServiceName, "SMB", StringComparison.OrdinalIgnoreCase) &&
                        service.PortLog?.Contains("1.0", StringComparison.Ordinal) == true)
                    {
                        found.Add(new Finding
                        {
                            Severity = FindingSeverity.Critical,
                            Category = FindingCategory.Services,
                            Title = "SMB 1.0 still enabled",
                            Detail = $"{device.DisplayName} still answers SMB 1.0 ({service.PortLog}). " +
                                     "The protocol is deprecated and should be switched off.",
                            Subject = device.DisplayName,
                            Device = device
                        });
                    }

                    // Der Befund, den es ohne die Gegenueberstellung beider
                    // Familien gar nicht gaebe.
                    if (service.IsExposedOnlyViaIpv6)
                    {
                        found.Add(new Finding
                        {
                            Severity = FindingSeverity.Critical,
                            Category = FindingCategory.Reachability,
                            Family = IpFamily.IPv6,
                            Title = "Service open over IPv6 only",
                            Detail = $"{service.ServiceName} on {device.DisplayName} answers over IPv6 but not " +
                                     "over IPv4 - a firewall rule that covers only IPv4.",
                            Subject = device.DisplayName,
                            Device = device
                        });
                    }
                }

                if (device.HasGloballyRoutableAddress && device.OpenPortCount > 0)
                {
                    found.Add(new Finding
                    {
                        Severity = FindingSeverity.Warning,
                        Category = FindingCategory.Reachability,
                        Title = "Open ports on a globally routable address",
                        Detail = $"{device.DisplayName} has {device.OpenPortCount} open port(s) and an address " +
                                 "reachable from the internet without NAT.",
                        Subject = device.DisplayName,
                        Device = device
                    });
                }
            }
        }

        /// <summary>
        /// Die eigene Seite: Adapter, die sich zu viele Namensserver gezogen
        /// haben. Kostet bei jedem fehlschlagenden Server Wartezeit und faellt
        /// sonst nirgends auf.
        /// </summary>
        private static void CollectAdapters(List<Finding> found)
        {
            foreach (AdapterInfo adapter in NetworkAdapters.Read().Where(a => a.HasTooManyDnsServers))
            {
                found.Add(new Finding
                {
                    Severity = FindingSeverity.Warning,
                    Category = FindingCategory.LocalMachine,
                    Title = "Too many DNS servers on one adapter",
                    Detail = $"{adapter.Name} has {adapter.DnsServerCount} DNS servers ({adapter.DnsText}). " +
                             "Usually a leftover from repeated DHCP leases.",
                    Subject = adapter.Name
                });
            }
        }
    }
}
