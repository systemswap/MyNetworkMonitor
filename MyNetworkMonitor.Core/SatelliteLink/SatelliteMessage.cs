using System.Text.Json.Serialization;

// Der Namensraum heisst SatelliteLink und nicht Satellite: der Typ
// Models.Satellite traegt diesen Namen, und ein gleichnamiger Namensraum
// verdeckt ihn ueberall in Core.
namespace MyNetworkMonitor.Core.SatelliteLink
{
    /// <summary>Die Nachrichtenarten des Satellitenprotokolls. Siehe SATELLIT.md, Abschnitt 6.</summary>
    public static class MessageType
    {
        // Satellit -> Hauptscanner
        public const string Hello = "hello";
        public const string Progress = "progress";
        public const string Accepted = "accepted";
        public const string Busy = "busy";
        public const string Result = "result";
        public const string Cancelled = "cancelled";
        public const string Error = "error";
        public const string Pong = "pong";

        // Hauptscanner -> Satellit
        public const string Welcome = "welcome";
        public const string Pending = "pending";
        public const string Job = "job";
        public const string Cancel = "cancel";
        public const string ResultAck = "resultAck";
        public const string ListenPortChanged = "listenPortChanged";
        public const string Ping = "ping";
    }

    /// <summary>
    /// Eine Nachricht des Satellitenprotokolls.
    /// <para>
    /// Bewusst <em>ein</em> Umschlag mit lauter freilassbaren Feldern statt
    /// einer Klasse je Art: das erspart die Polymorphie beim Lesen und macht
    /// einen Mitschnitt lesbar. Was zu einer Art gehoert, steht am jeweiligen
    /// Feld.
    /// </para>
    /// </summary>
    public sealed class SatelliteMessage
    {
        /// <summary>Eine der Konstanten aus <see cref="MessageType"/>.</summary>
        public string Type { get; set; } = string.Empty;

        /// <summary>
        /// Fassung des Protokolls. Starr: passt sie nicht, wird abgelehnt -
        /// halb verstandene Auftraege sind schlimmer als eine klare Meldung.
        /// </summary>
        public int ProtocolVersion { get; set; }

        // --- Begruessung -----------------------------------------------------

        /// <summary>Der Name, den der Satellit sich selbst gibt.</summary>
        public string? Name { get; set; }

        /// <summary>Anwendungsversion der Gegenstelle.</summary>
        public string? AppVersion { get; set; }

        /// <summary>Betriebssystem der Gegenstelle.</summary>
        public string? Os { get; set; }

        /// <summary>
        /// Wo der Satellit steht: Rechnername, Domaene, Adressen und Netze.
        /// <para>
        /// Wird bei <em>jeder</em> Anmeldung neu erhoben und mitgeschickt, nicht
        /// nur beim ersten Mal. Nach einem Neustart, einem Adapterwechsel oder
        /// einer neuen DHCP-Lease stehen drueben sonst weiter die alten
        /// Adressen, und die Auswahl zeigte einen Bereich, den es nicht mehr
        /// gibt.
        /// </para>
        /// <para>
        /// Ohne diese Angaben sieht man am Hauptscanner nur einen Namen und
        /// muesste raten, ob dieser Satellit fuer einen Bereich der richtige
        /// ist - genau das war der Anlass.
        /// </para>
        /// </summary>
        public SitePayload? Site { get; set; }

        // --- Auftrag und Lauf ------------------------------------------------

        /// <summary>Kennung des Auftrags, auf den sich die Nachricht bezieht.</summary>
        public string? JobId { get; set; }

        /// <summary>Wer abgebrochen hat - damit ein Auftrag nie unerklaert verschwindet.</summary>
        public string? CancelledBy { get; set; }

        /// <summary>Fortschritt: Verfahren, gesendet, geantwortet, gesamt.</summary>
        public ProgressPayload? Progress { get; set; }

        // --- Sonstiges -------------------------------------------------------

        /// <summary>
        /// Bei <see cref="MessageType.Job"/> der Auftragstext, bei
        /// <see cref="MessageType.Error"/> die Meldung fuer den Nutzer.
        /// </summary>
        public string? Text { get; set; }

        /// <summary>
        /// Bei <see cref="MessageType.Result"/> der gefundene Bestand, im
        /// selben Format wie <c>lastScanResult.json</c>.
        /// </summary>
        public string? Devices { get; set; }

        /// <summary>
        /// Bei <see cref="MessageType.Result"/>: der Auftrag wurde abgebrochen,
        /// der Bestand ist der Stand bis dahin.
        /// <para>
        /// Ein abgebrochener Lauf hat nicht alles gesehen. Ohne diesen Merker
        /// waere sein Ergebnis von einem vollstaendigen nicht zu
        /// unterscheiden, und aus "hier stehen nur diese Geraete" wuerde ein
        /// Schluss, den die Daten nicht hergeben. Aeltere Satelliten setzen
        /// das Feld nicht - dann ist es <c>false</c>, und das ist richtig so:
        /// sie schicken bei Abbruch ueberhaupt nichts.
        /// </para>
        /// </summary>
        public bool Partial { get; set; }

        /// <summary>Neuer Port des Hauptscanners, fuer den naechsten Verbindungsaufbau.</summary>
        public int? ListenPort { get; set; }

        [JsonIgnore]
        public bool IsHello => Type == MessageType.Hello;
    }

    /// <summary>
    /// Fortschritt eines laufenden Auftrags.
    /// <para>
    /// Traegt dieselben Angaben wie die oertliche Anzeige: welches Verfahren
    /// laeuft, wie weit der Auftrag ist, was fertig und was offen ist - und
    /// die drei Zahlen des laufenden Verfahrens. Ohne sie sieht man aus der
    /// Ferne nur, <em>dass</em> der Satellit arbeitet; ob ein Verfahren noch
    /// etwas bringt oder nur noch in Zeitueberschreitungen laeuft, steht
    /// genau in diesen Zahlen.
    /// </para>
    /// </summary>
    public sealed class ProgressPayload
    {
        /// <summary>
        /// 0 bis 100 - der Stand des <em>laufenden Verfahrens</em>, nicht der
        /// des ganzen Auftrags.
        /// <para>
        /// Vorher stand hier der Anteil fertiger Verfahren. Bei drei
        /// Verfahren sprang die Zahl damit von 0 auf 33 auf 67 auf 100, und
        /// zwischen den Spruengen stand sie minutenlang still - gerade
        /// waehrend der langen Verfahren sah es aus, als haenge der Satellit.
        /// Gefragt ist, wie weit das gerade laufende Verfahren ist: "Ping
        /// 40 %".
        /// </para>
        /// </summary>
        public int Percent { get; set; }

        /// <summary>Das Verfahren, das gerade laeuft.</summary>
        public string Current { get; set; } = string.Empty;

        /// <summary>Das wievielte Verfahren des Auftrags gerade laeuft.</summary>
        public int Step { get; set; }

        /// <summary>Wie viele Verfahren der Auftrag umfasst.</summary>
        public int Steps { get; set; }

        /// <summary>Was schon fertig ist - wie <c>CompletedScansText</c> oertlich.</summary>
        public string Done { get; set; } = string.Empty;

        /// <summary>Was noch aussteht - wie <c>PendingScansText</c> oertlich.</summary>
        public string Pending { get; set; } = string.Empty;

        // --- Die drei Zahlen des laufenden Verfahrens ------------------------
        //
        // Dieselbe Bedeutung wie oertlich im Kommandobalken: abgeschickt,
        // geantwortet, gesamt. Aeltere Satelliten kennen die Felder nicht und
        // lassen sie auf 0 - die Anzeige blendet sie dann aus, statt drei
        // Nullen zu zeigen.

        /// <summary>Abgeschickte Anfragen des laufenden Verfahrens.</summary>
        public int Sent { get; set; }

        /// <summary>Ziele, die darauf geantwortet haben.</summary>
        public int Answered { get; set; }

        /// <summary>Ziele des laufenden Verfahrens insgesamt.</summary>
        public int Total { get; set; }
    }

    /// <summary>
    /// Der Standort eines Satelliten, wie er ihn selbst meldet.
    /// <para>
    /// Bewusst schlichte Zeichenketten und keine Adressobjekte: die Angaben
    /// werden drueben nur angezeigt und verglichen, nie gerechnet. Was der
    /// Satellit meldet, ist ausserdem eine Auskunft und keine Zusicherung -
    /// der Hauptscanner scannt weiterhin die Bereiche, die <em>er</em>
    /// zugewiesen hat, nicht die, die der Satellit nennt.
    /// </para>
    /// </summary>
    public sealed class SitePayload
    {
        public string HostName { get; set; } = string.Empty;

        public string Domain { get; set; } = string.Empty;

        /// <summary>Alle brauchbaren IPv4-Adressen, durch Komma getrennt.</summary>
        public string Ipv4 { get; set; } = string.Empty;

        /// <summary>Alle brauchbaren IPv6-Adressen, durch Komma getrennt.</summary>
        public string Ipv6 { get; set; } = string.Empty;

        /// <summary>
        /// Das Netz, das den Satelliten am ehesten beschreibt, etwa
        /// <c>192.0.2.0/24</c> - das des Adapters mit Standardgateway. Genau
        /// dieses steht drueben in der Auswahl hinter dem Namen.
        /// </summary>
        public string PrimaryNetwork { get; set; } = string.Empty;

        /// <summary>Alle Netze, durch Komma getrennt.</summary>
        public string Networks { get; set; } = string.Empty;
    }
}
