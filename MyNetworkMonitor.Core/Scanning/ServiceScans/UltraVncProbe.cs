namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// VNC. Ein Server gruesst beim Verbinden von sich aus mit seiner
    /// Protokollkennung ("RFB 003.008"); das Hello-Paket ist die
    /// Gegenvorstellung.
    /// <para>
    /// Die vier Ports sind die Anzeigen 0 bis 3 - ein Rechner mit mehreren
    /// Sitzungen belegt sie der Reihe nach.
    /// </para>
    /// </summary>
    public sealed class UltraVncProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.UltraVNC;
        public override string Group => ServiceGroups.Remote;
        public override IReadOnlyList<int> DefaultPorts => [5900, 5901, 5902, 5903];

        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => new byte[] { 0x52, 0x46, 0x42, 0x20, 0x30, 0x30, 0x33 };

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // ?? UltraVNC-Erkennung        
            if (service == ServiceType.UltraVNC)
            {
                //UlraVNC Header RFB als hex
                byte[] ultraVncHeader = { 0x52, 0x46, 0x42 };

                if (response.Take(ultraVncHeader.Length).SequenceEqual(ultraVncHeader))
                {
                    serviceMatched = true;
                }
            }

            return serviceMatched;
        }
    }
}
