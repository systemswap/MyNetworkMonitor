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

        // --- Auftrag und Lauf ------------------------------------------------

        /// <summary>Kennung des Auftrags, auf den sich die Nachricht bezieht.</summary>
        public string? JobId { get; set; }

        /// <summary>Wer abgebrochen hat - damit ein Auftrag nie unerklaert verschwindet.</summary>
        public string? CancelledBy { get; set; }

        /// <summary>Fortschritt: Verfahren, gesendet, geantwortet, gesamt.</summary>
        public ProgressPayload? Progress { get; set; }

        // --- Sonstiges -------------------------------------------------------

        /// <summary>Klartext fuer den Nutzer - bei <see cref="MessageType.Error"/>.</summary>
        public string? Text { get; set; }

        /// <summary>Neuer Port des Hauptscanners, fuer den naechsten Verbindungsaufbau.</summary>
        public int? ListenPort { get; set; }

        [JsonIgnore]
        public bool IsHello => Type == MessageType.Hello;
    }

    /// <summary>Fortschritt eines Verfahrens - speist die dreiteilige Anzeige.</summary>
    public sealed class ProgressPayload
    {
        public string MethodId { get; set; } = string.Empty;
        public int Sent { get; set; }
        public int Responded { get; set; }
        public int Total { get; set; }
    }
}
