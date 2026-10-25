using System.Net.Sockets;
using System.Text;
namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// File Transfer Protocol. Greets on its own with "220 ..."; there is
    /// nothing to send, which is why the hello packet is empty. A wrong hello
    /// packet would go unnoticed here, because an FTP server answers whatever
    /// arrives. See docs/FEHLERGEDAECHTNIS.md, No. 2.
    /// </summary>
    public sealed class FtpProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.FTP;
        public override string Group => ServiceGroups.Network;
        public override IReadOnlyList<int> DefaultPorts => [21];

        /// <summary>Nothing to send; see above.</summary>
        public override byte[] Hello => [];

        /// <summary>Matches a greeting that starts with "220 " (RFC 959, section 4.2).</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;
            string str_serviceResponse = Encoding.ASCII.GetString(response);

            if (service == ServiceType.FTP)
            {
                if (str_serviceResponse.StartsWith("220 "))
                {
                    serviceMatched = true;
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// The greeting without the reply code. Almost every server names itself
        /// in it, such as "220 (vsFTPd 3.0.3)", "220 Microsoft FTP Service" or
        /// "220 ProFTPD 1.3.5 Server ready", and with it the product and often
        /// the version, without having to ask.
        /// </summary>
        protected override string? Describe(byte[] response)
        {
            string banner = FirstLine(Encoding.ASCII.GetString(response));

            // The three digits and the space are the reply code and only mean
            // "ready"; the information is what follows.
            string text = banner.Length > 4 ? banner[4..].Trim() : string.Empty;

            return text.Length > 0 ? $"Banner: {text}" : null;
        }

        /// <summary>
        /// The two requests every FTP client may send before logging in.
        /// <para>
        /// <c>SYST</c> (RFC 959) names the system type the server reports, such
        /// as "215 UNIX Type: L8" or "215 Windows_NT". <c>FEAT</c> (RFC 2389)
        /// lists its extensions, and that is where the important information
        /// is: without <c>AUTH TLS</c> (RFC 4217), logins to this server cross
        /// the network in plain text. Neither request needs a user name or
        /// password.
        /// </para>
        /// <para>
        /// A <c>QUIT</c> afterwards would be polite but costs another round
        /// trip; the connection is closed right after anyway.
        /// </para>
        /// </summary>
        protected override async Task<string?> InterrogateAsync(
            NetworkStream stream, byte[] firstResponse, ProbeContext context, CancellationToken token)
        {
            List<string> lines = [];

            string system = FirstLine(await AskLineAsync(stream, "SYST", token));

            // Only the successful reply: 215 is the only positive reply to SYST;
            // everything else is a rejection and carries no information.
            if (system.StartsWith("215", StringComparison.Ordinal) && system.Length > 4)
            {
                lines.Add($"System: {system[4..].Trim()}");
            }

            string features = await AskLineAsync(stream, "FEAT", token);

            if (features.Length > 0)
            {
                bool supportsTls =
                    features.Contains("AUTH TLS", StringComparison.OrdinalIgnoreCase) ||
                    features.Contains("AUTH SSL", StringComparison.OrdinalIgnoreCase);

                // Deliberately a statement about the server rather than a mere
                // feature list: a "no" here is the finding.
                lines.Add($"Encryption (AUTH TLS): {(supportsTls ? "yes" : "no")}");

                string extensions = FeatureList(features);
                if (extensions.Length > 0) lines.Add($"Features: {extensions}");
            }

            return lines.Count > 0 ? string.Join(Environment.NewLine, lines) : null;
        }

        /// <summary>
        /// Turns the multi-line FEAT reply into one line. The layout is fixed
        /// (RFC 2389, section 3.2): "211-Features:", then one line per extension
        /// indented by a space, then "211 End". Only the indented lines are
        /// taken; the frame lines are protocol, not extensions.
        /// </summary>
        private static string FeatureList(string response)
        {
            List<string> features = [];

            foreach (string raw in response.Split('\n'))
            {
                // Drop the line ending; the indentation decides.
                string line = raw.TrimEnd('\r');
                if (line.Length < 2 || line[0] != ' ') continue;

                string feature = Printable(line.Trim(), 40);
                if (feature.Length > 0 && !features.Contains(feature)) features.Add(feature);
            }

            // Enough to classify the server without flooding the details view
            // with a list of thirty extensions.
            return string.Join(", ", features.Take(12));
        }
    }
}
