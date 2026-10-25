namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// RustDesk server. A server occupies a block of five ports around its
    /// base port: base-1 NAT test, base ID and heartbeat, base+1 relay,
    /// base+2 and +3 WebSocket.
    /// <para>
    /// Only the two ports that answer the NAT test are listed; only they can
    /// pass the check. The relay port stays silent on everything, the
    /// WebSocket ports speak HTTP.
    /// </para>
    /// <para>
    /// 5990/5991 are not the vendor defaults but a different base port, as
    /// used by self-hosted servers. Harmless, because the answer is really
    /// checked: a different service on these ports does not pass as RustDesk.
    /// 5900 is not used: it is the VNC port, and without a real answer check
    /// every VNC host would also be reported as a RustDesk server. See
    /// docs/FEHLERGEDAECHTNIS.md, No. 2.
    /// </para>
    /// </summary>
    public sealed class RustdeskServerProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.RustdeskServer;
        public override string Group => ServiceGroups.Remote;
        public override IReadOnlyList<int> DefaultPorts => [5990, 5991, 21115, 21116];

        /// <summary>The NAT test request.</summary>
        public override byte[] Hello => new byte[] { 0x14, 0xa2, 0x01, 0x02, 0x08, 0x03 };

        /// <summary>Matches the NAT test answer, which carries the source port of this connection.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // RustDesk server (hbbs, ports 21115-21117 or a custom base port)
            //
            // To the hello packet, the NAT test request, the server answers with
            // the source port it sees for this connection:
            //
            //   1c aa 01 04 08 <port as varint>
            //
            // Measured on a real server over four connections: the returned value
            // was exactly the TCP source port of the connection every time. That
            // is more than a pattern; the answer depends on the connection and
            // cannot be reproduced by another service by chance.
            //
            // The length is not fixed: a source port below 16384 fits into two
            // varint bytes instead of three. The length field is therefore checked
            // against the actual length rather than requiring 8 bytes.
            if (service == ServiceType.RustdeskServer)
            {
                serviceMatched = response.Length is >= 7 and <= 9
                    && response[0] == 0x1C
                    && response[1] == 0xAA && response[2] == 0x01   // field 21, length-delimited
                    && response[3] == response.Length - 4           // inner length matches the rest
                    && response[4] == 0x08                          // field 1, varint: the port
                    && TryReadVarint(response, 5, out int publicPort)
                    && publicPort is > 0 and <= 65535;
            }

            return serviceMatched;
        }
    }
}
