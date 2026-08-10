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
        /// <summary>
        /// Zeitlimit je Port, in Millisekunden. Entspricht dem bisherigen
        /// Schieberegler.
        /// <para>
        /// 2500 statt der frueheren 1000: eine Sekunde reicht im eigenen
        /// Segment, aber nicht ueber eine WAN-Strecke oder zu einem Geraet,
        /// das erst aufwacht - dort meldet der Scan dann "zu", wo in Wahrheit
        /// nur niemand schnell genug war. Ein falsches "zu" faellt niemandem
        /// auf und ist darum teurer als die Wartezeit.
        /// </para>
        /// </summary>
        [ObservableProperty] private int _portTimeoutMs = 2500;

        public List<int> TcpPorts { get; init; } = [];
        public List<int> UdpPorts { get; init; } = [];

        /// <summary>Alle 65 536 Ports statt der Auswahl.</summary>
        [ObservableProperty] private bool _scanAllPorts;

        /// <summary>
        /// Die SNMP-Gemeinschaftskennung, mit der Switches und verwaltete
        /// Geraete gefragt werden.
        /// <para>
        /// "public" ist die Werkseinstellung und in vielen Netzen lesend noch
        /// gesetzt. Wo nicht, bleibt die Switchport-Abfrage ohne Ergebnis - ein
        /// Fall, der bewusst still bleibt: eine Fehlermeldung je nicht
        /// antwortendem Geraet waere hier ein Dauerrauschen.
        /// </para>
        /// </summary>
        [ObservableProperty] private string _snmpCommunity = "public";

        /// <summary>Zu pruefende Dienste. Leer heisst: alle aktivierten.</summary>
        public List<ServiceType> Services { get; init; } = [];

        /// <summary>
        /// Nur Ziele pruefen, die schon in der Tabelle stehen. Aus einem Scan
        /// ueber 254 Adressen wird damit ein Nachfassen bei den zwoelf, die
        /// tatsaechlich da sind.
        /// </summary>
        [ObservableProperty] private bool _onlyKnownTargets;

        /// <summary>
        /// Verfahren, die nur die bereits gefundenen Geraete abfragen sollen -
        /// als Schluesselmenge von <see cref="IScanMethod.Id"/>.
        /// <para>
        /// Die Beschraenkung je Verfahren statt fuer den ganzen Lauf, weil beide
        /// Seiten gebraucht werden: Ping, ARP und SNMP sollen den ganzen Bereich
        /// abklopfen, weil dort die meisten Geraete antworten - der Port- und
        /// Dienstscan danach nur noch die, die sich gemeldet haben. Als eine
        /// Einstellung fuer alles liesse sich das nicht ausdruecken.
        /// </para>
        /// <para>
        /// Ausgewertet wird vor jedem Verfahren neu, nicht einmal am Anfang:
        /// die Liste waechst waehrend des Laufs, und genau davon lebt die
        /// Abstufung.
        /// </para>
        /// </summary>
        public HashSet<string> OnlyKnownTargetsFor { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Dieses Verfahren fragt nur die bereits gefundenen Geraete ab.</summary>
        public bool IsRestrictedToKnown(string methodId) =>
            OnlyKnownTargets || OnlyKnownTargetsFor.Contains(methodId);

        /// <summary>
        /// Abweichender DNS-Server fuer die Namensaufloesung. Sticht die
        /// Server, die am Bereich hinterlegt sind - fuer den Fall, dass man
        /// gegen einen bestimmten Server pruefen will.
        /// </summary>
        [ObservableProperty] private string? _overrideDnsServer;

        /// <summary>
        /// Wie viele Adressen die Rueckwaertsaufloesung gleichzeitig abfragt.
        /// <para>
        /// Die Vorgabe 8 ist auf einen Heimrouter zugeschnitten: der verliert
        /// unter einem Schwall gleichzeitiger PTR-Anfragen die meisten
        /// UDP-Pakete, bevor die Zeitgrenze ablaeuft - bei 50 kamen an einem
        /// echten /24 nur 4 von 32 Geraeten zurueck, bei 8 alle.
        /// </para>
        /// <para>
        /// Ein richtiger Namensserver im Firmennetz steckt dagegen 32 oder 64
        /// muehelos weg, und genau dort faellt die Vorgabe als Bremse auf: eine
        /// Adresse, die gar nicht beantwortet wird, kostet das volle Budget aus
        /// Zeitlimit mal Wiederholungen, und davon laufen eben nur acht
        /// nebeneinander. Darum einstellbar statt fest.
        /// </para>
        /// </summary>
        [ObservableProperty] private int _reverseLookupConcurrency = 8;

        /// <summary>
        /// Nach der Namensaufloesung jede Adresse gegen <b>jeden</b> bekannten
        /// Namensserver einzeln pruefen und die Antworten vergleichen.
        /// <para>
        /// Eine Unterfunktion des DNS-Scans und kein eigenes Verfahren: sie
        /// braucht dessen Ergebnis und liefe ohne es ins Leere. Weichen die
        /// Server voneinander ab, entsteht daraus ein Befund - mit Angabe,
        /// welcher Server nicht sauber aufloest.
        /// </para>
        /// <para>
        /// Kostet Zeit: je Adresse eine Abfrage an jeden Server, und das in
        /// beide Richtungen. Darum abschaltbar und standardmaessig aus.
        /// </para>
        /// </summary>
        [ObservableProperty] private bool _crossCheckDnsServers;

        /// <summary>
        /// Der Quervergleich fragt nur die Geraete, die im Lauf geantwortet
        /// haben, statt jede Zeile der Tabelle.
        /// <para>
        /// Voreingestellt an, und das ist die Zeitersparnis, um die es geht:
        /// je Adresse laeuft eine Abfrage an <em>jeden</em> Namensserver, und
        /// zwar zweimal. Ueber eine gewachsene Tabelle mit hunderten
        /// Altbestaenden - Geraeten, die es laengst nicht mehr gibt - sind das
        /// tausende Abfragen fuer eine Auskunft, die niemanden interessiert.
        /// </para>
        /// <para>
        /// Ausgeschaltet prueft er auch die Karteileichen. Das hat seinen
        /// Sinn: ein Name, der noch aufloest, obwohl das Geraet weg ist, ist
        /// genau der Eintrag, den man im Namensdienst aufraeumen will.
        /// </para>
        /// </summary>
        [ObservableProperty] private bool _crossCheckOnlyKnownTargets = true;

        /// <summary>ARP-Cache vor dem Scan leeren.</summary>
        [ObservableProperty] private bool _clearArpCacheFirst;

        // --- Satellitenbetrieb, siehe SATELLIT.md ----------------------------
        //
        // Die Ports sind Einstellungen und keine Konstanten: in manchen Netzen
        // sind nur bestimmte erlaubt, und dann muss man ausweichen koennen.

        /// <summary>Auf Satelliten horchen. Ohne das kommt keiner herein.</summary>
        [ObservableProperty] private bool _satelliteListenEnabled;

        /// <summary>Port, auf dem der Hauptscanner horcht.</summary>
        [ObservableProperty] private int _satelliteListenPort = 27411;

        /// <summary>
        /// Diese Instanz als Satellit betreiben und sich zum Hauptscanner
        /// hinausverbinden.
        /// </summary>
        [ObservableProperty] private bool _satelliteModeEnabled;

        /// <summary>
        /// Der Hauptscanner, zu dem sich diese Instanz als Satellit verbindet -
        /// Name oder Adresse. Ein Name ist vorzuziehen: er ueberlebt einen
        /// Adresswechsel, etwa wenn der Hauptscanner ein Laptop ist.
        /// </summary>
        [ObservableProperty] private string _mainScannerHost = string.Empty;

        /// <summary>Port des Hauptscanners.</summary>
        [ObservableProperty] private int _mainScannerPort = 27411;

        /// <summary>
        /// Als Satellit: jeder freigegebene Hauptscanner darf einen laufenden
        /// Auftrag abbrechen, nicht nur der, der ihn gestartet hat.
        /// <para>
        /// Vorgabe an, weil ein haengender Auftrag den Satelliten fuer alle
        /// sperrt und wer davorsitzt ihn freibekommen soll. Aus heisst: nur der
        /// Auftraggeber.
        /// </para>
        /// </summary>
        [ObservableProperty] private bool _allowCancelFromAnyReceiver = true;

        /// <summary>
        /// Die Bibliothek der 3D-Topologie vom CDN laden statt aus dem
        /// Programmordner. Dann ist die erzeugte Seite fuer sich allein
        /// weitergebbar - dafuer braucht sie eine Internetverbindung.
        /// </summary>
        [ObservableProperty] private bool _useOnlineTopologyLibrary;
    }
}
