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

        /// <summary>
        /// Meldet den Fortschritt einschliesslich des laufenden Teilschritts.
        /// Nur die Diensterkennung hat welche - sie geht Dienst fuer Dienst
        /// vor, und "Services" allein sagt eine Minute lang nichts darueber,
        /// wo der Lauf steht.
        /// </summary>
        public required Action<int, int, int, string?, int, int> ReportStepProgress { get; init; }

        /// <summary>
        /// Meldet den Fortschritt eines Verfahrens, das aus einem Stueck
        /// besteht - der Normalfall.
        /// </summary>
        public void ReportProgress(int current, int responded, int total) =>
            ReportStepProgress(current, responded, total, null, 0, 0);

        /// <summary>Die Ziele einer Adressfamilie.</summary>
        public IEnumerable<ScanTargetEntry> TargetsOf(Network.IpFamily family) =>
            Targets.Where(t => t.Family == family);

        /// <summary>
        /// Es gibt mindestens ein Ziel dieser Familie.
        /// <para>
        /// Ein Ziel, das nur als Hostname vorliegt, zaehlt fuer <em>jede</em>
        /// Familie mit: welche es wird, entscheidet erst die Namensaufloesung
        /// beim Lauf. Bis dahin ist die Familie schlicht unbekannt.
        /// </para>
        /// <para>
        /// Ohne diese Ausnahme war jedes Verfahren gesperrt, sobald in der
        /// eigenen Eingabe nur ein Hostname stand und kein Bereich angehakt
        /// war: Ping erschien ausgegraut mit "No IPv4 targets selected",
        /// obwohl der Name auf eine IPv4 zeigte. Ein Verfahren nicht
        /// anzubieten, das laufen koennte, ist der schlechtere Fehler - laeuft
        /// es ins Leere, sagt das Ergebnis es sauber.
        /// </para>
        /// </summary>
        public bool HasTargetsOf(Network.IpFamily family) =>
            Targets.Any(t => t.Family == family || (t.Family is null && t.HostName is not null));

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

        /// <summary>
        /// Was das Verfahren findet und wofuer man es benutzt - in der Sprache
        /// dessen, der vor der Liste sitzt und entscheiden muss, ob er den
        /// Haken setzt.
        /// <para>
        /// Der Verfahrensname allein beantwortet diese Frage nicht: "SNMP"
        /// sagt niemandem, ob es sich lohnt. Der Text nennt darum zwei Dinge -
        /// <b>welche Geraete das ueblicherweise sprechen</b> und <b>was dabei
        /// herauskommt</b>. Keine Protokollkunde, keine Abkuerzungen, die nicht
        /// vorher erklaert sind.
        /// </para>
        /// </summary>
        string Explanation { get; }

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
