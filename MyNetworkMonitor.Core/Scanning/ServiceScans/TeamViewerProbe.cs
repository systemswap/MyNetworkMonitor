namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// TeamViewer. Erkannt an zwei festen Stellen der Antwort - dem Kopf und
    /// einer zweiten Marke weiter hinten im selben Paket.
    /// </summary>
    public sealed class TeamViewerProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.TeamViewer;
        public override string Group => ServiceGroups.Remote;
        public override IReadOnlyList<int> DefaultPorts => [5938];

        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => new byte[]
            {
                0x17, 0x24, 0x0A, 0x20, 0x00, 0xE1, 0xBF, 0xE5,
                0x2A, 0x88, 0x13, 0x80, 0x00, 0x48, 0x00, 0x80,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x14, 0x80, 0x00,
                0x00, 0x4F, 0xB3, 0x80, 0x80, 0x6E, 0xBD, 0xF3,
                0x9B, 0x8E, 0xDF, 0xA9, 0x03
            };

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // ?? TeamViewer-Erkennung
            if (service == ServiceType.TeamViewer)
            {
                byte[] teamViewerHeader1 = { 0x17, 0x24, 0x0A, 0x20 };  // Header 1
                byte[] teamViewerHeader2 = { 0x11, 0x30, 0x36, 0x00 };  // Header 2

                bool match1 = response.Take(4).SequenceEqual(teamViewerHeader1);
                bool match2 = response.Skip(37).Take(4).SequenceEqual(teamViewerHeader2);
                if (match1 && match2)
                {
                    serviceMatched = true;
                }
            }

            return serviceMatched;
        }
    }
}
