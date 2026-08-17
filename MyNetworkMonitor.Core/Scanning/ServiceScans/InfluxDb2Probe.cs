using System.Text;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// InfluxDB 2. Sitzt auf 8086 und damit auf einem Port, der auch in der
    /// Webliste steht - beide Sonden pruefen ihn, und welcher Befund stehen
    /// bleibt, entscheidet die Antwort.
    /// </summary>
    public sealed class InfluxDb2Probe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.InfluxDB2;
        public override string Group => ServiceGroups.NoSqlDatabases;
        public override IReadOnlyList<int> DefaultPorts => [8086];

        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => Encoding.ASCII.GetBytes(
                "GET /health HTTP/1.1\r\nHost: influxdb\r\nConnection: close\r\n\r\n");

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;
            string str_serviceResponse = Encoding.ASCII.GetString(response);

            // ?? InfluxDB 2
            if (service == ServiceType.InfluxDB2)
            {
                if (str_serviceResponse.ToLower().Contains("influxdb"))
                {
                    serviceMatched = true;
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// Liest Fassung und Zustand aus der Antwort auf <c>/health</c> - der
        /// Auskunftsseite, die InfluxDB ohne Anmeldung fuer genau diesen Zweck
        /// bereithaelt. Gefragt wird sie ohnehin schon; die Antwort traegt die
        /// Fassung sowohl im Kopf <c>X-Influxdb-Version</c> als auch im Text.
        /// </summary>
        protected override string? Describe(byte[] response)
        {
            string text = Encoding.ASCII.GetString(response);

            List<string> lines = [];

            string version = HeaderValue(text, "X-Influxdb-Version");
            if (version.Length > 0) lines.Add($"Version: {version}");

            string build = HeaderValue(text, "X-Influxdb-Build");
            if (build.Length > 0) lines.Add($"Build: {build}");

            // Der Zustandsbericht steht als JSON im Rumpf. Ohne Parser gelesen:
            // gebraucht wird ein einziges Feld, und dafuer lohnt keine
            // Abhaengigkeit.
            string status = JsonValue(text, "status");
            if (status.Length > 0) lines.Add($"Status: {status}");

            return lines.Count > 0 ? string.Join(Environment.NewLine, lines) : null;
        }

        /// <summary>Der Wert eines HTTP-Kopffeldes, oder leer.</summary>
        private static string HeaderValue(string response, string name)
        {
            foreach (string raw in response.Split('\n'))
            {
                string line = raw.TrimEnd('\r');

                if (!line.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase)) continue;

                return Printable(line[(name.Length + 1)..].Trim(), 60);
            }

            return string.Empty;
        }

        /// <summary>
        /// Der Wert eines JSON-Feldes aus dem Rumpf. Bewusst schlicht: gesucht
        /// wird der Name in Anfuehrungszeichen, genommen wird die Zeichenkette
        /// dahinter. Fuer verschachtelte Felder taugt das nicht - hier steht
        /// aber nur eine flache Auskunft.
        /// </summary>
        private static string JsonValue(string response, string field)
        {
            int key = response.IndexOf($"\"{field}\"", StringComparison.OrdinalIgnoreCase);
            if (key < 0) return string.Empty;

            int colon = response.IndexOf(':', key);
            if (colon < 0) return string.Empty;

            int open = response.IndexOf('"', colon);
            if (open < 0) return string.Empty;

            int close = response.IndexOf('"', open + 1);
            if (close <= open) return string.Empty;

            return Printable(response[(open + 1)..close], 60);
        }
    }
}
