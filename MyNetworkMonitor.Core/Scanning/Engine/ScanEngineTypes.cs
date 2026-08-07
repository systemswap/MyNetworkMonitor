using System.Net.NetworkInformation;
using CommunityToolkit.Mvvm.ComponentModel;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine
{
    /// <summary>
    /// Stufe eines Scans. Die Reihenfolge ist zugleich die Ausfuehrungsfolge -
    /// erst finden, dann bestimmen, dann Dienste pruefen. Sie entspricht den
    /// Spalten der Verfahren-Schublade in der Oberflaeche.
    /// </summary>
    public enum ScanPhase
    {
        /// <summary>Welche Geraete gibt es? Ping, ARP, Neighbor Cache, SSDP, mDNS.</summary>
        Discovery = 0,

        /// <summary>Was ist das fuer ein Geraet? Hostname, SNMP, NetBIOS, ONVIF.</summary>
        Identification = 1,

        /// <summary>Was laeuft darauf? Ports, Diensterkennung, SMB-Version.</summary>
        Services = 2
    }

    /// <summary>Welche Adressfamilien ein Verfahren bedienen kann.</summary>
    [Flags]
    public enum FamilySupport
    {
        None = 0,
        IPv4 = 1 << 0,
        IPv6 = 1 << 1,
        Both = IPv4 | IPv6
    }

    /// <summary>Warum ein Verfahren nicht laeuft.</summary>
    public enum ScanMethodState
    {
        /// <summary>Laeuft.</summary>
        Available,

        /// <summary>
        /// Nicht anwendbar - kein passendes Ziel vorhanden. Kein Fehler,
        /// sondern der Normalfall, etwa NetBIOS bei reinen IPv6-Zielen.
        /// </summary>
        NotApplicable,

        /// <summary>
        /// Grundsaetzlich moeglich, aber hier blockiert - fehlende Rechte,
        /// abgeschaltetes IPv6, fehlende Plattformunterstuetzung. Gehoert dem
        /// Nutzer gemeldet statt still uebersprungen.
        /// </summary>
        Blocked
    }

    /// <summary>
    /// Ob ein Verfahren im vorliegenden Fall laufen kann - und wenn nicht,
    /// warum. Der Grund ist fuer die Oberflaeche gedacht und steht dort im
    /// Tooltip des ausgegrauten Kaestchens.
    /// </summary>
    public sealed class ScanMethodAvailability
    {
        public required ScanMethodState State { get; init; }

        /// <summary>Leer, wenn das Verfahren laeuft.</summary>
        public string Reason { get; init; } = string.Empty;

        public bool CanRun => State == ScanMethodState.Available;

        public static ScanMethodAvailability Available { get; } =
            new() { State = ScanMethodState.Available };

        public static ScanMethodAvailability NotApplicable(string reason) =>
            new() { State = ScanMethodState.NotApplicable, Reason = reason };

        public static ScanMethodAvailability Blocked(string reason) =>
            new() { State = ScanMethodState.Blocked, Reason = reason };

        public override string ToString() =>
            State == ScanMethodState.Available ? "verfuegbar" : $"{State}: {Reason}";
    }

    /// <summary>
    /// Ein einzelnes Scan-Ziel: eine konkrete Adresse samt dem Bereich, aus dem
    /// sie stammt. Der Bereich wird mitgefuehrt, weil Domain, DNS-Server und
    /// Gateway je Bereich verschieden sind - dieselbe Adresse in zwei Bereichen
    /// wird unterschiedlich aufgeloest.
    /// </summary>
    public sealed class ScanTargetEntry
    {
        /// <summary>Gesetzt, wenn das Ziel als Adresse vorliegt.</summary>
        public IpAddressInfo? Address { get; init; }

        /// <summary>Gesetzt, wenn das Ziel ein noch nicht aufgeloester Hostname ist.</summary>
        public string? HostName { get; init; }

        public required ScopeRuntime Scope { get; init; }

        public IpFamily? Family => Address?.Family;

        /// <summary>Was an das Verfahren uebergeben wird - Adresse oder Hostname.</summary>
        public string TargetText => Address?.Canonical ?? HostName ?? string.Empty;

        public override string ToString() => TargetText;
    }

    /// <summary>
    /// Ein Bereich mit allem, was zur Laufzeit dazugehoert: der zugeordnete
    /// Adapter und wie weit IPv6 dort nutzbar ist.
    /// <para>
    /// Die IPv6-Pruefung sitzt bewusst hier und nicht global. Eine Auswahl kann
    /// mehrere Bereiche mit verschiedenen Adaptern umfassen - ein Scan ueber
    /// vier Bereiche kann IPv6 in zweien nutzen und in zweien ueberspringen.
    /// </para>
    /// </summary>
    public sealed class ScopeRuntime
    {
        public required ScanScope Scope { get; init; }

        public NetworkInterface? Interface { get; init; }

        public required Ipv6Readiness Ipv6 { get; init; }

        public override string ToString() => $"{Scope.GroupDescription} [{Ipv6.Availability}]";
    }

    /// <summary>Fortschritt eines laufenden Verfahrens.</summary>
    public sealed class ScanProgress
    {
        public required string MethodId { get; init; }
        public required string MethodName { get; init; }
        public required ScanPhase Phase { get; init; }

        public int Current { get; init; }
        public int Total { get; init; }

        /// <summary>Wie viele Ziele geantwortet haben.</summary>
        public int Responded { get; init; }

        public ScanStatus Status { get; init; } = ScanStatus.running;

        public double Fraction => Total <= 0 ? 0 : Math.Clamp((double)Current / Total, 0, 1);

        public override string ToString() => $"{MethodName} {Current}/{Total}";
    }

    /// <summary>
    /// Einstellungen, die fuer den gesamten Durchlauf gelten. Was heute ueber
    /// Schieberegler und Kaestchen im Hauptfenster verstreut ist.
    /// </summary>
    public sealed partial class ScanSettings : ObservableObject
    {
        /// <summary>Zeitlimit je Port, in Millisekunden. Entspricht dem bisherigen Schieberegler.</summary>
        [ObservableProperty] private int _portTimeoutMs = 1000;

        public List<int> TcpPorts { get; init; } = [];
        public List<int> UdpPorts { get; init; } = [];

        /// <summary>Alle 65 536 Ports statt der Auswahl.</summary>
        [ObservableProperty] private bool _scanAllPorts;

        /// <summary>Zu pruefende Dienste. Leer heisst: alle aktivierten.</summary>
        public List<ServiceType> Services { get; init; } = [];

        /// <summary>
        /// Nur Ziele pruefen, die schon in der Tabelle stehen. Aus einem Scan
        /// ueber 254 Adressen wird damit ein Nachfassen bei den zwoelf, die
        /// tatsaechlich da sind.
        /// </summary>
        [ObservableProperty] private bool _onlyKnownTargets;

        /// <summary>
        /// Abweichender DNS-Server fuer die Namensaufloesung. Sticht die
        /// Server, die am Bereich hinterlegt sind - fuer den Fall, dass man
        /// gegen einen bestimmten Server pruefen will.
        /// </summary>
        [ObservableProperty] private string? _overrideDnsServer;

        /// <summary>ARP-Cache vor dem Scan leeren.</summary>
        [ObservableProperty] private bool _clearArpCacheFirst;
    }
}
