namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Microsoft Remote Desktop. Gefragt wird mit einer X.224-Verbindungs-
    /// anfrage; die Antwort ist ein TPKT-Paket, das im COTP-Teil den Code
    /// "Connection Confirm" traegt.
    /// </summary>
    public sealed class RdpProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.RDP;
        public override string Group => ServiceGroups.Remote;
        public override IReadOnlyList<int> DefaultPorts => [3389];

        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => new byte[] { 0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00 };

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // ?? RDP: Antwort auf die X.224-Verbindungsanfrage ist ein TPKT-Paket
            // (0x03 0x00 ...), das im COTP-Teil den Code 0xD0 (Connection Confirm)
            // traegt.
            if (service == ServiceType.RDP)
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
