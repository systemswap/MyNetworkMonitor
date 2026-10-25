using System.Text;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Oracle. Does not speak first: unlike FTP or MySQL it needs a real TNS
    /// Connect packet, otherwise the line stays silent. A refusal also counts
    /// as a match: a service that rejects the connection proves its presence
    /// just as well.
    /// </summary>
    public sealed class OracleDbProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.OracleDB;
        public override string Group => ServiceGroups.SqlDatabases;
        public override IReadOnlyList<int> DefaultPorts => [1521];

        /// <summary>A TNS Connect packet; see <see cref="BuildTnsConnectPacket"/>.</summary>
        public override byte[] Hello => BuildTnsConnectPacket();

        /// <summary>
        /// Builds a TNS Connect packet in the basic Oracle Net format: an 8-byte header
        /// (total length, checksum 0, packet type 1 = Connect, flag 0, header checksum 0)
        /// followed by the version, connection options and the connect descriptor as
        /// ASCII text. Not yet verified against a real Oracle server. A raw TCP SYN
        /// packet taken from a capture instead of a TNS message would have no effect at
        /// all; see docs/FEHLERGEDAECHTNIS.md, No. 2.
        /// </summary>
        private static byte[] BuildTnsConnectPacket()
        {
            const string connectDescriptor =
                "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=orcl)(CID=(PROGRAM=)(HOST=)(USER=)))" +
                "(ADDRESS=(PROTOCOL=TCP)(HOST=localhost)(PORT=1521)))";

            byte[] descriptorBytes = Encoding.ASCII.GetBytes(connectDescriptor);

            // Version 314 (0x013A), service options 0x0801, SDU/TDU 0x0800 each,
            // protocol characteristics 0x7F08: common values from publicly
            // documented TNS Connect packets.
            byte[] body = new byte[]
            {
                0x01, 0x3A, 0x01, 0x2C, 0x08, 0x01, 0x08, 0x00, 0x08, 0x00, 0x7F, 0x08,
                0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            };

            byte[] packet = new byte[8 + body.Length + descriptorBytes.Length];
            int totalLength = packet.Length;

            packet[0] = (byte)(totalLength >> 8);
            packet[1] = (byte)(totalLength & 0xFF);
            packet[2] = 0x00; // checksum (unused)
            packet[3] = 0x00;
            packet[4] = 0x01; // packet type: Connect
            packet[5] = 0x00; // flags
            packet[6] = 0x00; // header checksum (unused)
            packet[7] = 0x00;

            Array.Copy(body, 0, packet, 8, body.Length);
            Array.Copy(descriptorBytes, 0, packet, 8 + body.Length, descriptorBytes.Length);

            return packet;
        }

        /// <summary>Matches a TNS packet of type Accept, Refuse or Redirect.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // Oracle TNS: the answer type is in byte 4 of the TNS header.
            // 2 = Accept, 4 = Refuse (the service rejects but is present), 11 = Redirect.
            if (service == ServiceType.OracleDB)
            {
                if (response.Length >= 8 && response[4] is 0x02 or 0x04 or 0x0B)
                {
                    serviceMatched = true;
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// What the listener reveals about itself in its answer.
        /// <para>
        /// The most informative case is the refusal: it comes back as a
        /// plain-text description carrying <c>VSNNUM</c>, the server version as
        /// a decimal number, and the error code that says <em>why</em> the
        /// connection was refused. No login is needed; the information is in
        /// the answer to the Connect packet that is sent anyway.
        /// </para>
        /// </summary>
        protected override string? Describe(byte[] response)
        {
            List<string> lines = [];

            // The packet type in byte 4 tells how the listener received the
            // request.
            string reaction = response.Length >= 8
                ? response[4] switch
                {
                    0x02 => "accepted the connection",
                    0x04 => "refused the connection",
                    0x0B => "redirected to another listener",
                    _ => string.Empty
                }
                : string.Empty;

            if (reaction.Length > 0) lines.Add($"Listener: {reaction}");

            string text = Encoding.ASCII.GetString(response);

            if (ReadVersionNumber(text) is { } version) lines.Add($"Version: {version}");

            // The error code names the refusal. 12514, for example, means the
            // listener is running but does not know the requested service name,
            // which is expected, since "orcl" is a guess.
            string error = FieldValue(text, "ERR");
            if (error.Length > 0 && error != "0") lines.Add($"Oracle error: ORA-{error}");

            return lines.Count > 0 ? string.Join(Environment.NewLine, lines) : null;
        }

        /// <summary>
        /// Converts <c>VSNNUM</c> into the usual notation. The number is a
        /// packed version: the top byte holds the major version, followed by
        /// the other parts in nibble and byte steps. 186647552 becomes
        /// 11.2.0.4.0.
        /// </summary>
        private static string? ReadVersionNumber(string text)
        {
            string raw = FieldValue(text, "VSNNUM");
            if (raw.Length == 0) return null;

            if (!uint.TryParse(raw, out uint packed) || packed == 0) return null;

            int major = (int)(packed >> 24 & 0xFF);
            int minor = (int)(packed >> 20 & 0x0F);
            int update = (int)(packed >> 12 & 0xFF);
            int portRelease = (int)(packed >> 8 & 0x0F);
            int portUpdate = (int)(packed & 0xFF);

            // A major version of 0 is not an Oracle version but a misread field.
            return major == 0 ? null : $"{major}.{minor}.{update}.{portRelease}.{portUpdate}";
        }

        /// <summary>
        /// The value of a field from the plain-text description. It is built of
        /// nested parentheses, <c>(KEY=value)</c>, and only single leaves are
        /// needed here.
        /// </summary>
        private static string FieldValue(string text, string key)
        {
            int start = text.IndexOf($"({key}=", StringComparison.OrdinalIgnoreCase);
            if (start < 0) return string.Empty;

            int valueStart = start + key.Length + 2;
            int end = text.IndexOf(')', valueStart);

            if (end <= valueStart) return string.Empty;

            return Printable(text[valueStart..end], 40);
        }
    }
}
