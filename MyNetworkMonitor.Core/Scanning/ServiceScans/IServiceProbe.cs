using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Was eine Sonde waehrend eines Laufs an Rahmenbedingungen vorfindet.
    /// <para>
    /// Die beiden Werte sind die bisherigen Konstanten aus
    /// <c>ScanningMethod_Services</c> und stehen hier nur, damit sie nicht
    /// wieder fest verdrahtet sind. Bewusst <b>nicht</b> vorbelegt aus
    /// <c>ScanSettings.PortTimeoutMs</c>: die Diensterkennung hat den
    /// Schieberegler noch nie benutzt, und das jetzt nebenbei zu aendern
    /// wuerde die Laufzeit jedes Scans verschieben, ohne dass es jemand
    /// entschieden haette.
    /// </para>
    /// </summary>
    public sealed class ProbeContext
    {
        /// <summary>Zeitlimit fuer Verbindungsaufbau und Antwort, in Millisekunden.</summary>
        public int TimeoutMs { get; init; } = 2000;

        /// <summary>Versuche je Port, bevor "keine Antwort" gilt.</summary>
        public int RetryCount { get; init; } = 3;
    }

    /// <summary>
    /// Ein Dienst, nach dem gesucht werden kann - mit allem, was ihn ausmacht,
    /// an einer Stelle: seine Ports, sein Hello-Paket, seine Antwortpruefung
    /// und, wo noetig, ein eigener Ablauf.
    /// <para>
    /// Vorher lag das ueber vier Schalter in einer Datei mit 2600 Zeilen
    /// verteilt - Ports in <c>GetDefaultServicePorts</c>, Paket in
    /// <c>GetDetectionPacket</c>, Pruefung in <c>IdentifyServices</c>, Ablauf
    /// in <c>ScanServicePortAsync</c>. Einen Dienst hinzuzufuegen hiess, alle
    /// vier zu finden; jetzt ist es eine Datei.
    /// </para>
    /// <para>
    /// Die Regel fuer die Erkennungspakete gilt unveraendert: die Byte-Felder
    /// sind experimentell ermittelt und werden nicht "aufgeraeumt". Wandern
    /// duerfen sie nur woertlich, und der Beweis dafuer ist ein byteweiser
    /// Vergleich gegen den alten Stand.
    /// </para>
    /// </summary>
    public interface IServiceProbe
    {
        ServiceType Service { get; }

        /// <summary>Gruppe fuer die Dienstverwaltung - "Network", "Databases", ...</summary>
        string Group { get; }

        /// <summary>
        /// Die Ports, an denen dieser Dienst ueblicherweise sitzt. Vorgabe:
        /// <c>services.xml</c> kann sie ueberlagern, und genau dafuer ist sie da.
        /// </summary>
        IReadOnlyList<int> DefaultPorts { get; }

        /// <summary>
        /// Was gesendet wird, um eine Antwort zu bekommen. Leer bei Diensten,
        /// die von sich aus gruessen - FTP, MySQL, MariaDB.
        /// </summary>
        byte[] Hello { get; }

        /// <summary>Passt die Antwort zum Protokoll dieses Dienstes?</summary>
        bool Identify(byte[] response);

        /// <summary>
        /// Einmal je Lauf, bevor das erste Ziel angefasst wird. Fuer Dienste,
        /// die nicht Ziel fuer Ziel arbeiten - DHCP fragt einmal in die Runde
        /// und vergleicht danach nur noch, wer geantwortet hat.
        /// </summary>
        Task PrepareAsync(ProbeContext context, IReadOnlyList<string> targets, CancellationToken token);

        /// <summary>Ein Ziel, ein Port.</summary>
        Task<PortResult> ProbeAsync(ProbeContext context, string address, int port, CancellationToken token);
    }
}
