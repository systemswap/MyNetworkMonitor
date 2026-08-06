using System.Collections.ObjectModel;
using System.Net.NetworkInformation;
using CommunityToolkit.Mvvm.ComponentModel;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Model
{
    /// <summary>
    /// Womit ein Geraet wiedererkannt wird - von der verlaesslichsten Angabe
    /// abwaerts. Die Reihenfolge ist die Rangfolge: was weiter oben steht,
    /// gewinnt beim Zusammenfuehren.
    /// </summary>
    public enum IdentityKey
    {
        /// <summary>Nichts Belastbares vorhanden.</summary>
        None,

        /// <summary>
        /// DHCPv6-DUID. Ueberlebt Adresswechsel, Praefixwechsel und teils sogar
        /// MAC-Randomisierung - die stabilste Kennung, die es gibt.
        /// </summary>
        Duid,

        /// <summary>MAC-Adresse, aus ARP, Neighbor Cache oder einem EUI-64-Identifier.</summary>
        Mac,

        /// <summary>Voll qualifizierter Hostname.</summary>
        Hostname,

        /// <summary>
        /// Nur eine Adresse bekannt. Schwach: unter IPv6 kann dieselbe Adresse
        /// morgen zu einem anderen Geraet gehoeren.
        /// </summary>
        Address
    }

    /// <summary>
    /// Ein Geraet im Netz. Kein Datensatz mehr, sondern ein Aggregat:
    /// Identitaetskaskade, mehrere Adressen und eine Beobachtungshistorie.
    /// <para>
    /// Das ist der Bruch gegenueber <see cref="IPToScan"/>, wo Scan-Auftrag,
    /// Ergebnis und Identitaet in einer Klasse steckten und die IP zugleich der
    /// Schluessel war. Unter IPv6 traegt ein Geraet regulaer vier bis sechs
    /// Adressen, von denen mehrere taeglich wechseln - die Adresse taugt damit
    /// nicht mehr als Identitaet.
    /// </para>
    /// </summary>
    public partial class Device : ObservableObject
    {
        public Guid Id { get; init; } = Guid.NewGuid();

        // ------------------------------------------------------- Identitaet

        /// <summary>DHCPv6-DUID in Hex-Schreibweise, falls beobachtet.</summary>
        [ObservableProperty] private string? _duid;

        [ObservableProperty] private PhysicalAddress? _mac;

        /// <summary>Hersteller, aus der MAC bestimmt.</summary>
        [ObservableProperty] private string _vendor = string.Empty;

        [ObservableProperty] private string _hostName = string.Empty;
        [ObservableProperty] private string _domain = string.Empty;
        [ObservableProperty] private string _netBiosName = string.Empty;

        /// <summary>Vom Nutzer vergebener Name. Sticht jede erkannte Bezeichnung.</summary>
        [ObservableProperty] private string _internalName = string.Empty;

        /// <summary>Aus welchem Bereich das Geraet stammt - fuer die Gruppierung.</summary>
        [ObservableProperty] private string _groupDescription = string.Empty;

        /// <summary>Worueber das Geraet aktuell wiedererkannt wird.</summary>
        public IdentityKey IdentityKey =>
            !string.IsNullOrWhiteSpace(Duid) ? IdentityKey.Duid :
            Mac is not null ? IdentityKey.Mac :
            !string.IsNullOrWhiteSpace(HostName) ? IdentityKey.Hostname :
            Addresses.Count > 0 ? IdentityKey.Address :
            IdentityKey.None;

        /// <summary>
        /// Name fuer die Anzeige. Der vom Nutzer vergebene Name geht vor, dann
        /// der Hostname, dann NetBIOS, dann die beste Adresse.
        /// </summary>
        public string DisplayName
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(InternalName)) return InternalName;
                if (!string.IsNullOrWhiteSpace(HostName)) return HostName;
                if (!string.IsNullOrWhiteSpace(NetBiosName)) return NetBiosName;
                return PrimaryAddress?.Info.Canonical ?? "- unbenannt -";
            }
        }

        // -------------------------------------------------------- Adressen

        public ObservableCollection<DeviceAddress> Addresses { get; } = [];

        /// <summary>
        /// Die Adresse, die in der Uebersicht steht. Bevorzugt wird, was am
        /// wenigsten wechselt: erst IPv4, dann eine globale IPv6-Adresse mit
        /// stabilem Identifier, zuletzt Link-Local.
        /// </summary>
        public DeviceAddress? PrimaryAddress =>
            Addresses.Where(a => a.Info.Family == IpFamily.IPv4).OrderBy(a => a.Info.SortKey, ByteArrayComparer.Instance).FirstOrDefault()
            ?? BestIpv6Address;

        /// <summary>
        /// Die aussagekraeftigste IPv6-Adresse: global vor lokal, stabil vor
        /// zufaellig. Eine Privacy-Adresse waere die schlechteste Wahl, weil
        /// sie morgen anders lautet.
        /// </summary>
        public DeviceAddress? BestIpv6Address =>
            Addresses
                .Where(a => a.Info.Family == IpFamily.IPv6 && !a.IsExpired)
                .OrderBy(a => a.Info.Scope switch
                {
                    IpAddressScope.Global => 0,
                    IpAddressScope.UniqueLocal => 1,
                    IpAddressScope.LinkLocal => 2,
                    _ => 3
                })
                .ThenBy(a => a.Info.InterfaceIdKind == InterfaceIdKind.Random ? 1 : 0)
                .ThenBy(a => a.Info.SortKey, ByteArrayComparer.Instance)
                .FirstOrDefault();

        public IEnumerable<DeviceAddress> Ipv4Addresses =>
            Addresses.Where(a => a.Info.Family == IpFamily.IPv4);

        public IEnumerable<DeviceAddress> Ipv6Addresses =>
            Addresses.Where(a => a.Info.Family == IpFamily.IPv6);

        /// <summary>Das Geraet ist ueber IPv6 ansprechbar - nicht nur ueber Link-Local.</summary>
        public bool IsIpv6Capable =>
            Ipv6Addresses.Any(a => a.Info.Scope is IpAddressScope.Global or IpAddressScope.UniqueLocal);

        /// <summary>
        /// Das Geraet wurde ausschliesslich ueber IPv6 gefunden. Genau diese
        /// Geraete sieht die bisherige Anwendung nicht.
        /// </summary>
        public bool IsIpv6Only => Addresses.Count > 0 && !Ipv4Addresses.Any();

        /// <summary>
        /// Mindestens eine Adresse ist ohne NAT aus dem Internet erreichbar.
        /// Grundlage fuer die Bewertung offener Ports.
        /// </summary>
        public bool HasGloballyRoutableAddress =>
            Addresses.Any(a => a.Info.IsGloballyRoutable && !a.IsExpired);

        // ---------------------------------------------------- Beobachtungen

        [ObservableProperty] private DateTimeOffset _firstSeen;
        [ObservableProperty] private DateTimeOffset _lastSeen;

        /// <summary>Zuletzt hat mindestens eine Adresse geantwortet.</summary>
        public bool IsOnline => Addresses.Any(a => a.IsResponding);

        /// <summary>Welche Verfahren dieses Geraet geliefert haben.</summary>
        public HashSet<string> SeenBy { get; } = new(StringComparer.OrdinalIgnoreCase);

        // -------------------------------------------------------- Ergebnisse

        /// <summary>
        /// Dienste und Ports, getrennt nach Adressfamilie. Aus dem Vergleich
        /// beider Seiten entsteht der Befund "unter IPv4 hinter NAT, unter IPv6
        /// global offen".
        /// </summary>
        public List<DeviceServiceResult> Services { get; } = [];

        /// <summary>Freitextangaben der Module: SNMP, mDNS, SSDP, SMB, ONVIF.</summary>
        public Dictionary<string, string> Details { get; } = new(StringComparer.OrdinalIgnoreCase);

        public override string ToString() =>
            $"{DisplayName} [{IdentityKey}] {Addresses.Count} Adresse(n)";
    }

    /// <summary>
    /// Ein erkannter Dienst am Geraet, mit dem Portzustand je Adressfamilie.
    /// </summary>
    public sealed class DeviceServiceResult
    {
        public required string ServiceName { get; init; }

        /// <summary>Kategorie fuer die Gruppierung: Netzwerk, Remote, Datenbanken, Dateidienste.</summary>
        public string Category { get; init; } = string.Empty;

        public List<int> Ports { get; init; } = [];

        /// <summary>Zustand ueber IPv4. <c>null</c>, wenn nicht geprueft.</summary>
        public PortStatus? StatusIPv4 { get; set; }

        /// <summary>Zustand ueber IPv6. <c>null</c>, wenn nicht geprueft.</summary>
        public PortStatus? StatusIPv6 { get; set; }

        /// <summary>Rohe Antwort des Ziels, fuer die Detailansicht.</summary>
        public string? PortLog { get; set; }

        /// <summary>
        /// Der Dienst laeuft ueber IPv6, ist aber ueber IPv4 nicht erreichbar.
        /// Fast immer ein Loch im Regelwerk, weil Firewalls oft nur IPv4 abdecken.
        /// </summary>
        public bool IsExposedOnlyViaIpv6 =>
            StatusIPv6 is PortStatus.IsRunning or PortStatus.Open &&
            StatusIPv4 is PortStatus.Filtered or PortStatus.Closed or PortStatus.NoResponse;

        public bool IsRunning =>
            StatusIPv4 == PortStatus.IsRunning || StatusIPv6 == PortStatus.IsRunning;

        public override string ToString() =>
            $"{ServiceName} [{string.Join(",", Ports)}] v4={StatusIPv4?.ToString() ?? "-"} v6={StatusIPv6?.ToString() ?? "-"}";
    }

    /// <summary>Vergleicht Adress-Sortierschluessel byteweise.</summary>
    public sealed class ByteArrayComparer : IComparer<byte[]>
    {
        public static readonly ByteArrayComparer Instance = new();

        public int Compare(byte[]? x, byte[]? y)
        {
            if (ReferenceEquals(x, y)) return 0;
            if (x is null) return -1;
            if (y is null) return 1;
            return x.AsSpan().SequenceCompareTo(y);
        }
    }
}
