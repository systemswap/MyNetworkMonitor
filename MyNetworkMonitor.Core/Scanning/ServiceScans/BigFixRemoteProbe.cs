namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// BigFix Remote Control. Antwortet mit einem Paket fester Laenge, dessen
    /// Kopf die Kennung traegt.
    /// </summary>
    public sealed class BigFixRemoteProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.BigFixRemote;
        public override string Group => ServiceGroups.Remote;
        public override IReadOnlyList<int> DefaultPorts => [888];

        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => new byte[] { 0x14, 0x2B, 0xB4, 0x91, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // BigFix Remote Control
            if (service == ServiceType.BigFixRemote)
            {
                // BigFix Antwort-Paket 1: 04-2B-B4-90-05-02 / Paket 2: 00-00-00-00-00-00   antwort in c# wegen tcpclient in einem array
                byte[] bigFixHeader = { 0x04, 0x2B, 0xB4, 0x90, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

                if (response.Length == 12)
                {
                    bool match = response.SequenceEqual(bigFixHeader);

                    if (match)
                    {
                        serviceMatched = true;
                    }
                }
            }

            return serviceMatched;
        }
    }
}
