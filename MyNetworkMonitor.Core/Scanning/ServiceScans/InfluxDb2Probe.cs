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
    }
}
