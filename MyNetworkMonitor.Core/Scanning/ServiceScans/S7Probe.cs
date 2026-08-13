namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Siemens S7 ueber ISO-on-TCP. 102 ist der Standardport, 1020 kommt bei
    /// abweichend eingerichteten Anlagen vor.
    /// </summary>
    public sealed class S7Probe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.S7;
        public override string Group => ServiceGroups.Industrial;
        public override IReadOnlyList<int> DefaultPorts => [102, 1020];

        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => new byte[]
            {
                0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00, 0x00, 0x01,
                0x00, 0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02,
                0x01, 0x02
            };

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // ?? Siemens S7: Antwort auf die COTP-Verbindungsanfrage ist ein
            // TPKT-Paket (0x03 0x00 ...), dessen COTP-Teil den Code 0xD0
            // (Connection Confirm) traegt - an derselben Stelle, an der die
            // eigene Anfrage 0xE0 (Connection Request) trug.
            if (service == ServiceType.S7)
            {
                if (response.Length >= 6 && response[0] == 0x03 && response[1] == 0x00 && response[5] == 0xD0)
                {
                    serviceMatched = true;
                }
            }

            return serviceMatched;
        }
    }
}
