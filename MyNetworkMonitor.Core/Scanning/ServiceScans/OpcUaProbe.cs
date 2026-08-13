namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>OPC UA. Gefragt wird mit einer Hello-Nachricht des Binaerprotokolls.</summary>
    public sealed class OpcUaProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.OPCUA;
        public override string Group => ServiceGroups.Industrial;
        public override IReadOnlyList<int> DefaultPorts => [4840];

        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => new byte[]
            {
                0x48, 0x45, 0x4C, 0x46, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
                0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00,
                0x6F, 0x70, 0x63, 0x2E, 0x74, 0x63, 0x70, 0x3A, 0x2F, 0x2F, 0x31, 0x37, 0x33, 0x2E, 0x31, 0x38,
                0x33, 0x2E, 0x31, 0x34, 0x37, 0x2E, 0x31, 0x30, 0x33, 0x3A, 0x34, 0x38, 0x34, 0x30, 0x2F

            };

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // ?? OPC UA
            if (service == ServiceType.OPCUA)
            {
                if (response.Length >= 4)
                {
                    byte[] opcUaHelloHeader = { 0x48, 0x45, 0x4C, 0x46 }; // HELF
                    byte[] opcUaAckHeader = { 0x41, 0x43, 0x4B, 0x46 };   // ACKF

                    if (response.Take(4).SequenceEqual(opcUaHelloHeader))
                    {
                        //OPC UA Hello Frame erkannt
                        serviceMatched = true;
                    }
                    else if (response.Take(4).SequenceEqual(opcUaAckHeader))
                    {
                        //OPC UA Acknowledge Frame erkannt
                        serviceMatched = true;
                    }
                }
            }

            return serviceMatched;
        }
    }
}
