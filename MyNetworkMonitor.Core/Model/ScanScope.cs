using System.Net;
using System.Net.Sockets;
using CommunityToolkit.Mvvm.ComponentModel;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Model
{
    /// <summary>
    /// Art eines Scan-Bereichs. Der bisherige Von/Bis-Bereich ist einer von
    /// vieren - dadurch passt IPv6 in dieselbe Liste, ohne dass IPv4 etwas
    /// verliert.
    /// </summary>
    public enum ScanScopeKind
    {
        /// <summary>Von/Bis oder CIDR. Entspricht dem bisherigen Verhalten.</summary>
        IPv4Range,

        /// <summary>
        /// Feste Adressen und Hostnamen, v4 und v6 gemischt. Fuer IPv6 der
        /// praktisch wichtigste Typ, weil sich ein /64 nicht durchlaufen laesst.
        /// </summary>
        TargetList,

        /// <summary>
        /// Ein IPv6-Praefix samt der Verfahren, mit denen es untersucht wird.
        /// Wird nicht durchlaufen - siehe <see cref="Ipv6Discovery"/>.
        /// </summary>
        IPv6Prefix,

        /// <summary>
        /// An einen Netzwerkadapter gebunden. Holt IPv4-Subnetz und
        /// IPv6-Praefixe selbst und ersetzt damit den bisherigen Tab "From NIC".
        /// </summary>
        NetworkInterface
    }

    /// <summary>
    /// Verfahren, mit denen ein IPv6-Praefix untersucht wird. Ein /64 umfasst
    /// 18 Trillionen Adressen - Durchlaufen scheidet aus, es bleibt nur gezielt
    /// fragen oder zuhoeren.
    /// </summary>
    [Flags]
    public enum Ipv6Discovery
    {
        None = 0,

        /// <summary>Nachbarschaftstabelle des Betriebssystems auslesen (ersetzt arp -a).</summary>
        NeighborCache = 1 << 0,

        /// <summary>Echo an ff02::1 - antwortet praktisch jedes Geraet im Segment.</summary>
        MulticastPing = 1 << 1,

        /// <summary>Router Advertisements mithoeren.</summary>
        ListenRouterAdvertisements = 1 << 2,

        /// <summary>MLD-Berichte auswerten - liefert Dienste ohne ein einziges gesendetes Paket.</summary>
        ListenMulticastGroups = 1 << 3,

        /// <summary>::1 bis ::ff durchprobieren - dort liegen von Hand vergebene Adressen.</summary>
        LowByteSweep = 1 << 4,

        /// <summary>Aus bekannten MAC-Adressen EUI-64-Adressen bilden und pruefen.</summary>
        Eui64FromKnownMacs = 1 << 5,

        /// <summary>Der uebliche Satz: alles Passive plus Multicast-Ping.</summary>
        Default = NeighborCache | MulticastPing | ListenRouterAdvertisements | ListenMulticastGroups
    }

    /// <summary>
    /// Ein Scan-Bereich. Loest die bisherige <see cref="Models.IpGroup"/> ab,
    /// behaelt aber jedes ihrer Felder - Gruppe, Geraetebeschreibung, Domain,
    /// eigene DNS-Server, Reihenfolge, Auto-Scan und das Gateway fuer entfernte
    /// Segmente. Neu ist allein <see cref="Kind"/>.
    /// <para>
    /// <see cref="IsSelected"/> loest die fruehere Spalte "Active" ab. Sie wird
    /// nicht mehr in der Verwaltung bearbeitet, sondern ueber die Auswahl im
    /// Kommandobalken gesetzt - gespeichert wird sie weiterhin, damit die
    /// Auswahl einen Neustart uebersteht.
    /// </para>
    /// </summary>
    public partial class ScanScope : ObservableObject
    {
        /// <summary>Bleibt ueber Umsortieren und Umbenennen hinweg stabil.</summary>
        public Guid Id { get; init; } = Guid.NewGuid();

        /// <summary>Laufende Nummer, bestimmt die Reihenfolge beim Scan.</summary>
        [ObservableProperty] private int _index;

        /// <summary>Geht in den naechsten Scan ein. Frueher "Active".</summary>
        [ObservableProperty] private bool _isSelected;

        [ObservableProperty] private ScanScopeKind _kind = ScanScopeKind.IPv4Range;

        [ObservableProperty] private string _groupDescription = string.Empty;
        [ObservableProperty] private string _deviceDescription = string.Empty;

        // --- IPv4Range -----------------------------------------------------
        [ObservableProperty] private string _firstIP = string.Empty;
        [ObservableProperty] private string _lastIP = string.Empty;

        // --- TargetList ----------------------------------------------------
        /// <summary>Adressen und Hostnamen, v4 und v6 gemischt.</summary>
        public List<string> Targets { get; init; } = [];

        // --- IPv6Prefix ----------------------------------------------------
        [ObservableProperty] private string _prefix = string.Empty;
        [ObservableProperty] private int _prefixLength = 64;
        [ObservableProperty] private Ipv6Discovery _ipv6Discovery = Ipv6Discovery.Default;

        // --- NetworkInterface ----------------------------------------------
        /// <summary>Id des Adapters laut <see cref="System.Net.NetworkInformation.NetworkInterface"/>.</summary>
        [ObservableProperty] private string _interfaceId = string.Empty;

        // --- Namensaufloesung, gilt fuer alle Arten -------------------------
        [ObservableProperty] private string _domain = string.Empty;
        [ObservableProperty] private string _dnsServers = string.Empty;

        // --- Entfernter Zugriff ---------------------------------------------
        [ObservableProperty] private string _gatewayIP = string.Empty;
        [ObservableProperty] private string _gatewayPort = string.Empty;

        // --- Automatischer Scan ----------------------------------------------
        [ObservableProperty] private bool _automaticScan;
        [ObservableProperty] private int _scanIntervalMinutes;

        /// <summary>Zeitpunkt des letzten Durchlaufs. Nicht gespeichert.</summary>
        [ObservableProperty] private DateTimeOffset? _lastScanned;

        /// <summary>Die DNS-Server dieses Bereichs, getrennt nach Komma oder Semikolon.</summary>
        public IReadOnlyList<string> DnsServerList =>
            string.IsNullOrWhiteSpace(DnsServers)
                ? []
                : DnsServers.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        /// <summary>Der Bereich wird ueber eine entfernte Instanz gescannt.</summary>
        public bool UsesGateway => !string.IsNullOrWhiteSpace(GatewayIP);

        // ------------------------------------------------------------ Pruefung

        /// <summary>
        /// Prueft, ob der Bereich vollstaendig genug ist, um gescannt zu werden.
        /// Liefert bei einem Mangel einen Satz, der dem Nutzer sagt, was fehlt.
        /// </summary>
        public bool TryValidate(out string? problem)
        {
            problem = null;

            switch (Kind)
            {
                case ScanScopeKind.IPv4Range:
                    if (!IPAddress.TryParse(FirstIP, out IPAddress? first) ||
                        first.AddressFamily != AddressFamily.InterNetwork)
                    {
                        problem = "Die erste Adresse ist keine gueltige IPv4-Adresse.";
                        return false;
                    }
                    if (!IPAddress.TryParse(LastIP, out IPAddress? last) ||
                        last.AddressFamily != AddressFamily.InterNetwork)
                    {
                        problem = "Die letzte Adresse ist keine gueltige IPv4-Adresse.";
                        return false;
                    }
                    if (ToUInt32(last) < ToUInt32(first))
                    {
                        problem = "Die letzte Adresse liegt vor der ersten.";
                        return false;
                    }
                    return true;

                case ScanScopeKind.TargetList:
                    if (Targets.Count == 0)
                    {
                        problem = "Die Zielliste ist leer.";
                        return false;
                    }
                    return true;

                case ScanScopeKind.IPv6Prefix:
                    if (!IPAddress.TryParse(Prefix, out IPAddress? prefix) ||
                        prefix.AddressFamily != AddressFamily.InterNetworkV6)
                    {
                        problem = "Das Praefix ist keine gueltige IPv6-Adresse.";
                        return false;
                    }
                    if (PrefixLength is < 1 or > 128)
                    {
                        problem = "Die Praefixlaenge muss zwischen 1 und 128 liegen.";
                        return false;
                    }
                    if (Ipv6Discovery == Ipv6Discovery.None)
                    {
                        problem = "Fuer ein IPv6-Praefix muss mindestens ein Verfahren gewaehlt sein.";
                        return false;
                    }
                    return true;

                case ScanScopeKind.NetworkInterface:
                    if (string.IsNullOrWhiteSpace(InterfaceId))
                    {
                        problem = "Es ist kein Netzwerkadapter zugeordnet.";
                        return false;
                    }
                    return true;

                default:
                    problem = "Unbekannte Bereichsart.";
                    return false;
            }
        }

        // ------------------------------------------------------------ Umfang

        /// <summary>
        /// Wie viele Ziele der Bereich umfasst. Bei
        /// <see cref="ScanScopeKind.IPv6Prefix"/> nur eine Schaetzung, weil die
        /// Zahl davon abhaengt, was Neighbor Cache und Multicast hergeben -
        /// dann ist <paramref name="isEstimate"/> gesetzt.
        /// </summary>
        public long CountTargets(out bool isEstimate)
        {
            isEstimate = false;

            switch (Kind)
            {
                case ScanScopeKind.IPv4Range:
                    if (!IPAddress.TryParse(FirstIP, out IPAddress? f) ||
                        !IPAddress.TryParse(LastIP, out IPAddress? l)) return 0;
                    long span = (long)ToUInt32(l) - ToUInt32(f) + 1;
                    return span < 0 ? 0 : span;

                case ScanScopeKind.TargetList:
                    return Targets.Count;

                case ScanScopeKind.IPv6Prefix:
                    isEstimate = true;
                    // Nur der Low-Byte-Durchlauf hat eine feste Groesse. Alles
                    // Uebrige findet, was da ist - vorher nicht bezifferbar.
                    return Ipv6Discovery.HasFlag(Ipv6Discovery.LowByteSweep) ? 255 : 0;

                case ScanScopeKind.NetworkInterface:
                    isEstimate = true;
                    return 0; // wird beim Scan aus dem Adapter bestimmt

                default:
                    return 0;
            }
        }

        // ------------------------------------------------------------ Ziele

        /// <summary>
        /// Zaehlt die Adressen eines IPv4-Bereichs auf - linear, nicht
        /// oktettweise. Damit umfasst 10.20.4.200 bis 10.20.5.50 auch
        /// tatsaechlich die 107 Adressen dazwischen.
        /// <para>
        /// Bewusst nicht ueber <c>IpRanges.IPRange</c>: das zaehlt je Oktett
        /// getrennt hoch und liefert bei einem Bereich ueber eine
        /// Oktettgrenze hinweg ein falsches Ergebnis. Die Klasse bleibt fuer
        /// ihre bisherigen Aufrufer unveraendert.
        /// </para>
        /// </summary>
        public IEnumerable<IPAddress> EnumerateIPv4Range()
        {
            if (Kind != ScanScopeKind.IPv4Range) yield break;
            if (!IPAddress.TryParse(FirstIP, out IPAddress? first) ||
                !IPAddress.TryParse(LastIP, out IPAddress? last)) yield break;
            if (first.AddressFamily != AddressFamily.InterNetwork ||
                last.AddressFamily != AddressFamily.InterNetwork) yield break;

            uint from = ToUInt32(first);
            uint to = ToUInt32(last);
            if (to < from) yield break;

            for (uint value = from; ; value++)
            {
                yield return FromUInt32(value);
                if (value == to) break; // so herum, damit 255.255.255.255 nicht ueberlaeuft
            }
        }

        /// <summary>
        /// Die Eintraege der Zielliste, soweit sie sich als Adresse lesen
        /// lassen. Hostnamen bleiben als Text stehen und werden erst beim Scan
        /// aufgeloest - darum zwei Rueckgabelisten.
        /// </summary>
        public (List<IpAddressInfo> Addresses, List<string> Hostnames) SplitTargetList()
        {
            List<IpAddressInfo> addresses = [];
            List<string> hostnames = [];

            foreach (string entry in Targets)
            {
                if (string.IsNullOrWhiteSpace(entry)) continue;

                if (IpAddressAnalyzer.TryAnalyze(entry, out IpAddressInfo? info) && info is not null)
                {
                    addresses.Add(info);
                }
                else
                {
                    hostnames.Add(entry.Trim());
                }
            }

            return (addresses, hostnames);
        }

        // ------------------------------------------------------- Beschreibung

        /// <summary>Einzeiler fuer Liste und Auswahl, etwa "10.20.4.1 - 10.20.4.254".</summary>
        public string DescribeAddressPart() => Kind switch
        {
            ScanScopeKind.IPv4Range => string.IsNullOrWhiteSpace(FirstIP) ? "-" : $"{FirstIP} - {LastIP}",
            ScanScopeKind.TargetList => $"{Targets.Count} Eintraege",
            ScanScopeKind.IPv6Prefix => string.IsNullOrWhiteSpace(Prefix) ? "-" : $"{Prefix}/{PrefixLength}",
            ScanScopeKind.NetworkInterface => string.IsNullOrWhiteSpace(InterfaceId) ? "-" : "vom Adapter",
            _ => "-"
        };

        public override string ToString() =>
            $"{Index}. {GroupDescription} [{Kind}] {DescribeAddressPart()}";

        // ------------------------------------------------- Bestandsuebernahme

        /// <summary>
        /// Uebernimmt eine bestehende <see cref="Models.IpGroup"/>. Sie wird
        /// immer zu einem <see cref="ScanScopeKind.IPv4Range"/> - genau das
        /// war sie bisher auch. Damit lesen sich gespeicherte XML-Dateien ohne
        /// Zutun weiter, und niemand verliert seine Bereiche.
        /// <para>
        /// <c>IsActive</c> wird zu <see cref="IsSelected"/>: was bisher aktiv
        /// war, ist nach dem Umstieg ausgewaehlt.
        /// </para>
        /// </summary>
        public static ScanScope FromIpGroup(Models.IpGroup group)
        {
            ArgumentNullException.ThrowIfNull(group);

            return new ScanScope
            {
                Kind = ScanScopeKind.IPv4Range,
                Index = group.Index,
                IsSelected = group.IsActive,
                GroupDescription = group.IpGroupDescription,
                DeviceDescription = group.DeviceDescription,
                FirstIP = group.FirstIP,
                LastIP = group.LastIP,
                Domain = group.Domain,
                DnsServers = group.DnsServers,
                GatewayIP = group.NmGatewayIP,
                GatewayPort = group.NmGatewayPort,
                AutomaticScan = group.AutomaticScan,
                ScanIntervalMinutes = int.TryParse(group.ScanIntervalMinutes, out int minutes) ? minutes : 0
            };
        }

        /// <summary>
        /// Zurueck in das bisherige Format - fuer das Speichern, solange die
        /// alte XML-Datei noch geschrieben wird. Bereiche, die kein
        /// <see cref="ScanScopeKind.IPv4Range"/> sind, lassen sich so nicht
        /// abbilden und ergeben <c>null</c>.
        /// </summary>
        public Models.IpGroup? ToIpGroup()
        {
            if (Kind != ScanScopeKind.IPv4Range) return null;

            return new Models.IpGroup
            {
                Index = Index,
                IsActive = IsSelected,
                IpGroupDescription = GroupDescription,
                DeviceDescription = DeviceDescription,
                FirstIP = FirstIP,
                LastIP = LastIP,
                Domain = Domain,
                DnsServers = DnsServers,
                NmGatewayIP = GatewayIP,
                NmGatewayPort = GatewayPort,
                AutomaticScan = AutomaticScan,
                ScanIntervalMinutes = ScanIntervalMinutes > 0 ? ScanIntervalMinutes.ToString() : string.Empty
            };
        }

        // ------------------------------------------------------------ Helfer

        private static uint ToUInt32(IPAddress address)
        {
            byte[] b = address.GetAddressBytes();
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }

        private static IPAddress FromUInt32(uint value) => new(new[]
        {
            (byte)(value >> 24),
            (byte)(value >> 16),
            (byte)(value >> 8),
            (byte)value
        });
    }
}
