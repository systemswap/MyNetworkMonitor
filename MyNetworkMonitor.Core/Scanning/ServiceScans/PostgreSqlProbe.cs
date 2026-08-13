namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// PostgreSQL. Gefragt wird mit der SSLRequest; die Antwort ist ein
    /// einzelnes Byte - 'S', wenn der Server TLS anbietet, 'N', wenn nicht.
    /// Erkannt wird ausserdem die direkte Fehler- bzw. Statusantwort ohne
    /// TLS-Verhandlung.
    /// </summary>
    public sealed class PostgreSqlProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.PostgreSQL;
        public override string Group => ServiceGroups.SqlDatabases;
        public override IReadOnlyList<int> DefaultPorts => [5432];

        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => new byte[]
            {
                0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F
            };

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // ?? PostgreSQL-Erkennung: Antwort auf die SSLRequest ist ein einzelnes
            // Byte - 'S' (0x53), wenn der Server TLS anbietet, 'N' (0x4e), wenn nicht.
            // Server ohne TLS ueberwiegen in der Praxis nicht - ein Server, der die
            // uebliche, sicherere Antwort 'S' gibt, wurde hier bisher schlicht
            // uebersehen.
            if (service == ServiceType.PostgreSQL)
            {
                if (response.Length == 1 && (response[0] == 0x53 || response[0] == 0x4e))
                {
                    serviceMatched = true;
                }
                if (response.Length >= 8)
                {
                    // Direkte "ReadyForQuery"/Fehlerantwort ohne SSL-Verhandlung.
                    if (response[0] == 0x52 && response[1] == 0x00 && response[2] == 0x00)
                    {
                        serviceMatched = true;
                    }
                }
            }

            return serviceMatched;
        }
    }
}
