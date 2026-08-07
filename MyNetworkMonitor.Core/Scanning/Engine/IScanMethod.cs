using MyNetworkMonitor.Core.Model;

namespace MyNetworkMonitor.Core.Scanning.Engine
{
    /// <summary>
    /// Was ein Verfahren waehrend seines Laufs zur Verfuegung hat: die Ziele,
    /// die Einstellungen, einen Weg Ergebnisse zu melden und einen fuer den
    /// Fortschritt.
    /// <para>
    /// Ein Verfahren pflegt die Geraeteliste <b>nicht</b> selbst. Es meldet
    /// Sichtungen ueber <see cref="Report"/>; die Zuordnung uebernimmt der
    /// <see cref="DeviceStore"/>. Nur dadurch lassen sich aktive Scans und
    /// passive Quellen wie der RA-Mitschnitt gleich behandeln.
    /// </para>
    /// </summary>
    public sealed class ScanContext
    {
        public required IReadOnlyList<ScopeRuntime> Scopes { get; init; }

        public required IReadOnlyList<ScanTargetEntry> Targets { get; init; }

        public required ScanSettings Settings { get; init; }

        public required DeviceStore Store { get; init; }

        /// <summary>Meldet eine Sichtung. Threadsicher ueber die Sperre des Aufrufers.</summary>
        public required Action<DeviceObservation> Report { get; init; }

        /// <summary>Meldet den Fortschritt des laufenden Verfahrens.</summary>
        public required Action<int, int, int> ReportProgress { get; init; }

        /// <summary>Die Ziele einer Adressfamilie.</summary>
        public IEnumerable<ScanTargetEntry> TargetsOf(Network.IpFamily family) =>
            Targets.Where(t => t.Family == family);

        /// <summary>Es gibt mindestens ein Ziel dieser Familie.</summary>
        public bool HasTargetsOf(Network.IpFamily family) =>
            Targets.Any(t => t.Family == family);

        /// <summary>
        /// Mindestens ein Bereich erlaubt IPv6 im eigenen Segment. Massgeblich
        /// fuer Verfahren, die mit Link-Local auskommen - Neighbor Discovery,
        /// ff02::1, RA-Mitschnitt, MLD.
        /// </summary>
        public bool AnyScopeAllowsLocalIpv6 => Scopes.Any(s => s.Ipv6.CanScanLocalSegment);

        /// <summary>Mindestens ein Bereich erlaubt IPv6 ueber Segmentgrenzen hinweg.</summary>
        public bool AnyScopeAllowsRoutedIpv6 => Scopes.Any(s => s.Ipv6.CanScanRoutedTargets);

        /// <summary>
        /// Der Grund, warum IPv6 nirgends geht - fuer die Meldung an den
        /// Nutzer. Nimmt den Grund des ersten Bereichs, weil er in aller Regel
        /// fuer alle gilt.
        /// </summary>
        public string Ipv6BlockReason =>
            Scopes.FirstOrDefault()?.Ipv6.Reason ?? "No range selected.";
    }

    /// <summary>
    /// Ein Scan-Verfahren. Alle Module - die 16 bestehenden wie die kuenftigen
    /// IPv6-Verfahren - werden hierueber gleich behandelt. Ein neues Verfahren
    /// hinzuzufuegen heisst dann: implementieren und registrieren.
    /// <para>
    /// Die bestehenden Module bleiben dabei unveraendert. Sie werden von
    /// Adaptern umschlossen, die ihre Ereignisse auf
    /// <see cref="ScanContext.Report"/> umsetzen.
    /// </para>
    /// </summary>
    public interface IScanMethod
    {
        /// <summary>
        /// Unveraenderlicher Schluessel, etwa "ping" oder "ndp.neighborcache".
        /// Wird gespeichert - Anzeigenamen duerfen sich aendern, dieser nicht.
        /// </summary>
        string Id { get; }

        /// <summary>Name in der Oberflaeche.</summary>
        string DisplayName { get; }

        ScanPhase Phase { get; }

        FamilySupport Families { get; }

        /// <summary>
        /// Das Verfahren hoert zu, statt zu fragen - Router Advertisements,
        /// MLD, der Neighbor Cache. Passive Verfahren laufen weiter, wenn der
        /// Scan endet, und sind der Grund, warum aus dem Scanner ein Monitor wird.
        /// </summary>
        bool IsPassive { get; }

        /// <summary>
        /// Das Verfahren geht eine Zielliste durch, statt einmal in die Runde
        /// zu fragen.
        /// <para>
        /// Nur solche Verfahren lassen sich auf die bereits gefundenen Geraete
        /// beschraenken - bei SSDP, mDNS oder dem ARP-Cache gibt es keine
        /// Zielliste, die man kuerzen koennte. An diesem Merkmal haengt, ob die
        /// Oberflaeche fuer das Verfahren ein Kaestchen unter "scan only
        /// devices in table" anbietet.
        /// </para>
        /// </summary>
        bool EnumeratesTargets { get; }

        /// <summary>
        /// Braucht Raw Sockets und damit erhoehte Rechte bzw. unter Linux
        /// CAP_NET_RAW. Die Oberflaeche kann das vorab pruefen und melden,
        /// statt es scheitern zu lassen.
        /// </summary>
        bool RequiresElevation { get; }

        /// <summary>
        /// Prueft vor dem Lauf, ob das Verfahren hier etwas ausrichten kann.
        /// Muss guenstig sein - keine Netzwerkzugriffe.
        /// </summary>
        ScanMethodAvailability CheckAvailability(ScanContext context);

        /// <summary>
        /// Fuehrt das Verfahren aus. Bei Abbruch ueber
        /// <paramref name="cancellationToken"/> zuegig zurueckkehren; eine
        /// <see cref="OperationCanceledException"/> ist zulaessig und wird von
        /// der Engine als Abbruch gewertet, nicht als Fehler.
        /// </summary>
        Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken);
    }
}
