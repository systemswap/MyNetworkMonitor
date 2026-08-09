namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// Schaetzt aus der Rest-TTL einer Ping-Antwort das Betriebssystem des
    /// Ziels.
    /// <para>
    /// Der Trick dahinter: jedes Betriebssystem setzt beim Absenden eine
    /// typische Anfangs-TTL, und jeder Router auf dem Rueckweg zieht genau eins
    /// ab. Aufgerundet auf den naechsten ueblichen Startwert steht also die
    /// Herkunft im Paket - und die Zahl der Zwischenstationen gleich mit.
    /// </para>
    /// <para>
    /// Bewusst als <b>Vermutung</b> benannt und nicht als Feststellung. Die
    /// Anfangs-TTL laesst sich verstellen, und ein Ziel hinter einem NAT-Gateway
    /// kann eine fremde tragen. Fuer die Frage "was steht da ueberhaupt
    /// herum" reicht es trotzdem, und es kostet kein einziges Paket extra.
    /// </para>
    /// </summary>
    public static class TtlFingerprint
    {
        /// <summary>
        /// Die ueblichen Anfangswerte. 64 deckt Linux, macOS, Android und die
        /// allermeisten eingebetteten Geraete ab; 128 ist Windows; 255 nutzen
        /// Netzwerkgeraete und einige aeltere Unix-Systeme.
        /// </summary>
        private static readonly (int Initial, string Guess)[] Known =
        [
            (64, "Linux / Unix / Android"),
            (128, "Windows"),
            (255, "Network device")
        ];

        /// <summary>
        /// Wie weit die Rest-TTL hoechstens unter dem Startwert liegen darf,
        /// damit der Startwert noch als der richtige gilt.
        /// <para>
        /// 32 Zwischenstationen sind im lokalen Netz, um das es hier geht,
        /// masslos viel - eine groessere Spanne wuerde aber anfangen, 128er in
        /// den 255er-Topf zu ziehen und damit jeden Windows-Rechner hinter
        /// genug Routern zum Switch zu erklaeren.
        /// </para>
        /// </summary>
        private const int MaxHops = 32;

        /// <summary>
        /// Das vermutete Betriebssystem, oder <c>null</c>, wenn die TTL zu
        /// keinem der bekannten Startwerte passt.
        /// </summary>
        public static string? Guess(int ttl)
        {
            if (ttl <= 0) return null;

            foreach ((int initial, string guess) in Known)
            {
                if (ttl <= initial && ttl > initial - MaxHops) return guess;
            }

            return null;
        }

        /// <summary>
        /// Die Zahl der Zwischenstationen auf dem Rueckweg, oder <c>null</c>,
        /// wenn der Startwert nicht zu bestimmen ist. Null Stationen heisst:
        /// das Ziel liegt im selben Segment.
        /// </summary>
        public static int? Hops(int ttl)
        {
            if (ttl <= 0) return null;

            foreach ((int initial, _) in Known)
            {
                if (ttl <= initial && ttl > initial - MaxHops) return initial - ttl;
            }

            return null;
        }

        /// <summary>
        /// Die fertige Zeile fuer die Detailansicht, etwa
        /// <c>"Windows (TTL 128, same segment)"</c>. <c>null</c>, wenn nichts
        /// gemessen wurde - dann soll auch keine Zeile erscheinen.
        /// </summary>
        public static string? Describe(int ttl)
        {
            string? guess = Guess(ttl);
            if (guess is null) return null;

            int hops = Hops(ttl) ?? 0;

            string distance = hops == 0
                ? "same segment"
                : hops == 1 ? "1 hop away" : $"{hops} hops away";

            return $"{guess} (TTL {ttl}, {distance})";
        }
    }
}
