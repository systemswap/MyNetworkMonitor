namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// PostgreSQL. Asks with an SSLRequest; the answer is a single byte: 'S'
    /// if the server offers TLS, 'N' if not. A direct answer without TLS
    /// negotiation is also recognised.
    /// </summary>
    public sealed class PostgreSqlProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.PostgreSQL;
        public override string Group => ServiceGroups.SqlDatabases;
        public override IReadOnlyList<int> DefaultPorts => [5432];

        /// <summary>An SSLRequest: length 8 and the request code 80877103 (0x04D2162F).</summary>
        public override byte[] Hello => new byte[]
            {
                0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F
            };

        /// <summary>Matches the one-byte answer to the SSLRequest or a direct protocol message.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // The answer to the SSLRequest is a single byte: 'S' (0x53) if the
            // server offers TLS, 'N' (0x4e) if not. Both must be accepted; servers
            // without TLS are not the majority, and checking only for 'N' would
            // miss every server with the common, more secure answer 'S'.
            if (service == ServiceType.PostgreSQL)
            {
                if (response.Length == 1 && (response[0] == 0x53 || response[0] == 0x4e))
                {
                    serviceMatched = true;
                }
                if (response.Length >= 8)
                {
                    // A direct protocol message ('R') without TLS negotiation.
                    if (response[0] == 0x52 && response[1] == 0x00 && response[2] == 0x00)
                    {
                        serviceMatched = true;
                    }
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// Whether the server offers encryption, the only information available
        /// before login.
        /// <para>
        /// PostgreSQL does not reveal a version number: it is a session
        /// parameter sent only after a successful login. The answer to the
        /// SSLRequest is exactly one byte, and it answers the question that
        /// matters here: whether logins to this server are encrypted or in
        /// plain text.
        /// </para>
        /// </summary>
        protected override string? Describe(byte[] response)
        {
            if (response.Length == 1)
            {
                return response[0] switch
                {
                    // 'S': the server switches to TLS.
                    0x53 => "Encryption: offered (TLS)",

                    // 'N': it declines; the login would be unencrypted.
                    0x4E => "Encryption: not offered - credentials would travel unencrypted",
                    _ => null
                };
            }

            return null;
        }
    }
}
