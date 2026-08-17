using System.Net.Sockets;
using System.Text;
namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// File Transfer Protocol. Gruesst von sich aus mit "220 ..." - es gibt
    /// nichts zu senden, und genau darum steht als Hello-Paket ein leeres
    /// Feld. Frueher stand dort ein rohes TCP-SYN-Paket aus einem Mitschnitt;
    /// aufgefallen war das nie, weil ein FTP-Server ohnehin antwortet, egal
    /// was ankommt.
    /// </summary>
    public sealed class FtpProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.FTP;
        public override string Group => ServiceGroups.Network;
        public override IReadOnlyList<int> DefaultPorts => [21];

        /// <summary>Nichts zu senden - siehe oben.</summary>
        public override byte[] Hello => [];

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;
            string str_serviceResponse = Encoding.ASCII.GetString(response);

            // ?? FTP
            if (service == ServiceType.FTP)
            {
                if (str_serviceResponse.StartsWith("220 "))
                {
                    serviceMatched = true;
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// Die Begruessung ohne den Zahlencode. Fast jeder Server nennt sich
        /// darin selbst - "220 (vsFTPd 3.0.3)", "220 Microsoft FTP Service",
        /// "220 ProFTPD 1.3.5 Server ready" - und damit Produkt und oft die
        /// Version, ohne dass danach gefragt werden muesste.
        /// </summary>
        protected override string? Describe(byte[] response)
        {
            string banner = FirstLine(Encoding.ASCII.GetString(response));

            // Die drei Ziffern und das Leerzeichen sind der Protokollcode und
            // sagen nur "bereit" - die Auskunft ist, was dahinter steht.
            string text = banner.Length > 4 ? banner[4..].Trim() : string.Empty;

            return text.Length > 0 ? $"Banner: {text}" : null;
        }

        /// <summary>
        /// Die zwei Fragen, die jeder FTP-Client vor der Anmeldung stellen darf.
        /// <para>
        /// <c>SYST</c> nennt die Systemart, mit der der Server sich meldet -
        /// "215 UNIX Type: L8", "215 Windows_NT". <c>FEAT</c> listet seine
        /// Erweiterungen, und dort steht die eigentlich wichtige Auskunft: fehlt
        /// <c>AUTH TLS</c>, laeuft die Anmeldung dieses Servers im Klartext
        /// durchs Netz. Beides ohne Benutzernamen, ohne Passwort.
        /// </para>
        /// <para>
        /// Ein <c>QUIT</c> hinterher waere hoeflich, kostet aber einen weiteren
        /// Umlauf; die Verbindung wird ohnehin gleich geschlossen.
        /// </para>
        /// </summary>
        protected override async Task<string?> InterrogateAsync(
            NetworkStream stream, byte[] firstResponse, ProbeContext context, CancellationToken token)
        {
            List<string> lines = [];

            string system = FirstLine(await AskLineAsync(stream, "SYST", token));

            // Nur die geglueckte Antwort: 215 ist die einzige Zusage auf SYST,
            // alles andere ist eine Ablehnung und keine Auskunft.
            if (system.StartsWith("215", StringComparison.Ordinal) && system.Length > 4)
            {
                lines.Add($"System: {system[4..].Trim()}");
            }

            string features = await AskLineAsync(stream, "FEAT", token);

            if (features.Length > 0)
            {
                bool supportsTls =
                    features.Contains("AUTH TLS", StringComparison.OrdinalIgnoreCase) ||
                    features.Contains("AUTH SSL", StringComparison.OrdinalIgnoreCase);

                // Bewusst als Aussage ueber den Server und nicht als blosse
                // Merkmalsliste: dass hier "no" steht, ist der Befund.
                lines.Add($"Encryption (AUTH TLS): {(supportsTls ? "yes" : "no")}");

                string extensions = FeatureList(features);
                if (extensions.Length > 0) lines.Add($"Features: {extensions}");
            }

            return lines.Count > 0 ? string.Join(Environment.NewLine, lines) : null;
        }

        /// <summary>
        /// Macht aus der mehrzeiligen FEAT-Antwort eine Zeile. Der Aufbau ist
        /// festgelegt: "211-Features:", dann je Erweiterung eine mit Leerzeichen
        /// eingerueckte Zeile, dann "211 End". Genommen wird allein das
        /// Eingerueckte - die Rahmenzeilen sind Protokoll, keine Erweiterung.
        /// </summary>
        private static string FeatureList(string response)
        {
            List<string> features = [];

            foreach (string raw in response.Split('\n'))
            {
                // Das Zeilenende faellt weg, die Einrueckung entscheidet.
                string line = raw.TrimEnd('\r');
                if (line.Length < 2 || line[0] != ' ') continue;

                string feature = Printable(line.Trim(), 40);
                if (feature.Length > 0 && !features.Contains(feature)) features.Add(feature);
            }

            // Genug, um den Server einzuordnen, ohne die Detailansicht mit einer
            // Auflistung von dreissig Erweiterungen zu fluten.
            return string.Join(", ", features.Take(12));
        }
    }
}
