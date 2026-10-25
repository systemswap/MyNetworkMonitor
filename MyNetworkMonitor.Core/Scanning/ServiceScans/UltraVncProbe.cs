using System.Net.Sockets;
using System.Text;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// VNC. A server greets on connect with its protocol version
    /// ("RFB 003.008", RFC 6143, section 7.1.1); the hello packet is the
    /// client's own version.
    /// <para>
    /// The four ports are displays 0 to 3; a host with several sessions
    /// occupies them in order.
    /// </para>
    /// </summary>
    public sealed class UltraVncProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.UltraVNC;
        public override string Group => ServiceGroups.Remote;
        public override IReadOnlyList<int> DefaultPorts => [5900, 5901, 5902, 5903];

        /// <summary>The first seven characters of the client version line ("RFB 003").</summary>
        public override byte[] Hello => new byte[] { 0x52, 0x46, 0x42, 0x20, 0x30, 0x30, 0x33 };

        /// <summary>Matches an answer that starts with "RFB".</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            if (service == ServiceType.UltraVNC)
            {
                // "RFB" protocol header as bytes
                byte[] ultraVncHeader = { 0x52, 0x46, 0x42 };

                if (response.Take(ultraVncHeader.Length).SequenceEqual(ultraVncHeader))
                {
                    serviceMatched = true;
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// The protocol version from the greeting. It has a fixed format,
        /// "RFB 003.008", and the last digits tell which handshake the server
        /// expects.
        /// </summary>
        protected override string? Describe(byte[] response)
        {
            string banner = FirstLine(Encoding.ASCII.GetString(response));

            return banner.Length >= 11 ? $"Protocol: {banner[..11]}" : null;
        }

        /// <summary>
        /// Queries how a viewer would have to authenticate.
        /// <para>
        /// The RFB handshake provides this unprompted: after both sides have
        /// stated their version, the server sends the list of its security
        /// types before any password is due (RFC 6143, section 7.1.2). If the
        /// list contains <c>None</c>, anyone can reach this screen without a
        /// password, which is the reason for asking.
        /// </para>
        /// <para>
        /// The detection packet is unchanged. It carries the first seven
        /// characters of the version line; the server then still waits for the
        /// five missing to the required twelve. Exactly these are sent here,
        /// as a continuation of the hello rather than a change to it.
        /// </para>
        /// </summary>
        protected override async Task<string?> InterrogateAsync(
            NetworkStream stream, byte[] firstResponse, ProbeContext context, CancellationToken token)
        {
            string banner = FirstLine(Encoding.ASCII.GetString(firstResponse));
            if (banner.Length < 11) return null;

            // The client version must not exceed the server's, otherwise the
            // server rejects it; the server's own version is therefore echoed.
            byte[] rest = Encoding.ASCII.GetBytes(banner[7..11] + "\n");
            await stream.WriteAsync(rest, token);

            byte[] buffer = new byte[256];
            int read = await stream.ReadAsync(buffer, token);
            if (read < 1) return null;

            // From 3.7: a count, then one byte per security type. Zero does not
            // mean "none" but that the server rejects the connection and sends
            // the reason as text.
            int count = buffer[0];

            if (count == 0)
            {
                string reason = Printable(Encoding.ASCII.GetString(buffer, 1, read - 1), 120);
                return reason.Length > 0 ? $"Rejected: {reason}" : null;
            }

            List<string> methods = [];
            bool openAccess = false;

            for (int i = 1; i < read && i <= count; i++)
            {
                if (buffer[i] == 1) openAccess = true;

                string name = SecurityTypeName(buffer[i]);
                if (!methods.Contains(name)) methods.Add(name);
            }

            if (methods.Count == 0) return null;

            List<string> lines = [$"Authentication: {string.Join(", ", methods)}"];

            // A separate line in plain words: in a list of security types
            // "None" is easily overlooked, and it is the finding that matters
            // here.
            if (openAccess) lines.Add("Warning: accepts connections without a password");

            return string.Join(Environment.NewLine, lines);
        }

        /// <summary>
        /// The security type numbers from the RFB specification (RFC 6143,
        /// section 7.2, and the IANA registry), plus common vendor-specific
        /// ones. Unknown types are shown with their number rather than hidden;
        /// the number tells an expert more than "unknown".
        /// </summary>
        private static string SecurityTypeName(byte type) => type switch
        {
            1 => "None",
            2 => "VNC password",
            5 => "RA2",
            6 => "RA2ne",
            16 => "Tight",
            17 => "Ultra",
            18 => "TLS",
            19 => "VeNCrypt",
            20 => "SASL",
            30 => "Apple Remote Desktop",

            // The numbers above 112 are specific to UltraVNC and not part of any
            // general specification. MS-Logon takes the credentials from the
            // Windows login, so access uses a domain account rather than a
            // separate VNC password.
            113 => "MS-Logon II",
            114 => "MS-Logon I",
            _ => $"Type {type}"
        };
    }
}
