namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// BigFix Remote Control. Answers with a fixed-length packet whose header
    /// carries the identifier.
    /// </summary>
    public sealed class BigFixRemoteProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.BigFixRemote;
        public override string Group => ServiceGroups.Remote;
        public override IReadOnlyList<int> DefaultPorts => [888];

        /// <summary>The 12-byte request that BigFix Remote Control answers with its fixed header.</summary>
        public override byte[] Hello => new byte[] { 0x14, 0x2B, 0xB4, 0x91, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        /// <summary>Matches only the exact 12-byte answer.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // BigFix Remote Control
            if (service == ServiceType.BigFixRemote)
            {
                // BigFix sends two packets, 04-2B-B4-90-05-02 and 00-00-00-00-00-00;
                // TcpClient reads both into one buffer.
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
