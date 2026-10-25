// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Microsoft Remote Desktop. Asks with an X.224 Connection Request; the
    /// answer is a TPKT packet whose COTP part carries the code "Connection
    /// Confirm" (MS-RDPBCGR 2.2.1.1 and 2.2.1.2).
    /// </summary>
    public sealed class RdpProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.RDP;
        public override string Group => ServiceGroups.Remote;
        public override IReadOnlyList<int> DefaultPorts => [3389];

        /// <summary>
        /// X.224 Connection Request with an RDP Negotiation Request
        /// (MS-RDPBCGR 2.2.1.1.1) asking for TLS and CredSSP.
        /// </summary>
        public override byte[] Hello => new byte[] { 0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00 };

        /// <summary>Matches a TPKT packet whose X.224 code is Connection Confirm (0xD0).</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // RDP: the answer to the X.224 Connection Request is a TPKT packet
            // (0x03 0x00 ...) whose COTP part carries the code 0xD0 (Connection
            // Confirm).
            if (service == ServiceType.RDP)
            {
                if (response.Length >= 6 && response[0] == 0x03 && response[1] == 0x00 && response[5] == 0xD0)
                {
                    serviceMatched = true;
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// The security layer the server selects for the login.
        /// <para>
        /// The detection packet already asks for TLS and CredSSP; the last four
        /// bytes of the request are exactly these two flags. What the server
        /// selects in response is in its answer and is the actual information:
        /// <c>CredSSP</c> means a client must authenticate <em>before</em> a
        /// login screen appears. Without it, the server accepts every connection
        /// up to the login screen, the situation worms exploiting BlueKeep
        /// (CVE-2019-0708) relied on.
        /// </para>
        /// <para>
        /// Only the answer to the packet that is sent anyway is read; no login
        /// attempt and no second connection.
        /// </para>
        /// </summary>
        protected override string? Describe(byte[] response)
        {
            // The negotiation part starts after the TPKT header (4) and the X.224
            // Connection Confirm (7). If it is missing, the server confirmed
            // without negotiation, which is the information itself: standard
            // RDP security applies.
            const int negotiation = 11;

            if (response.Length < negotiation + 1)
            {
                return "Security: Standard RDP (no NLA)";
            }

            byte type = response[negotiation];

            // 0x02, RDP_NEG_RSP (MS-RDPBCGR 2.2.1.2.1): the server names the
            // selected protocol in the four bytes from offset 15, little-endian.
            if (type == 0x02 && response.Length >= negotiation + 8)
            {
                int selected = response[negotiation + 4]
                    | response[negotiation + 5] << 8
                    | response[negotiation + 6] << 16
                    | response[negotiation + 7] << 24;

                return $"Security: {ProtocolName(selected)}";
            }

            // 0x03, RDP_NEG_FAILURE (MS-RDPBCGR 2.2.1.2.2): it rejects the
            // request and names the reason. That too is a statement about its
            // configuration, not a fault.
            if (type == 0x03 && response.Length >= negotiation + 8)
            {
                return $"Security: {FailureReason(response[negotiation + 4])}";
            }

            return "Security: Standard RDP (no NLA)";
        }

        /// <summary>The protocols from MS-RDPBCGR 2.2.1.1.1; they are bit flags.</summary>
        private static string ProtocolName(int selected) => selected switch
        {
            0x00 => "Standard RDP (no NLA)",
            0x01 => "TLS, no NLA",
            0x02 => "CredSSP (NLA)",
            0x08 => "RDSTLS",
            0x10 => "CredSSP with early user authentication",
            _ => $"protocol {selected}"
        };

        /// <summary>
        /// The failure codes. Two of them are not bad news: a server that
        /// <em>requires</em> TLS or NLA is configured more strictly than one
        /// that accepts everything.
        /// </summary>
        private static string FailureReason(byte code) => code switch
        {
            0x01 => "TLS required by server",
            0x02 => "TLS not allowed by server",
            0x03 => "no server certificate installed",
            0x05 => "CredSSP (NLA) required by server",
            0x06 => "TLS with user authentication required",
            _ => $"negotiation refused (code {code})"
        };
    }
}
