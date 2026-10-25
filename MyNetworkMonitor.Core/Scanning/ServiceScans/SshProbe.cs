// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Text;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Secure Shell. The server greets with its protocol identification
    /// ("SSH-2.0-...") as soon as the connection is established; the hello
    /// packet is only the client's own identification, so that the remote
    /// side starts the negotiation (RFC 4253, section 4.2).
    /// <para>
    /// The common case: connect, hello, read, check, all in
    /// <see cref="ServiceProbeBase"/>.
    /// </para>
    /// </summary>
    public sealed class SshProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.SSH;
        public override string Group => ServiceGroups.Network;
        public override IReadOnlyList<int> DefaultPorts => [22];

        /// <summary>The client identification string.</summary>
        public override byte[] Hello => Encoding.ASCII.GetBytes("SSH-2.0-MySSHClient\r\n");

        /// <summary>Matches an answer that starts with "SSH-2.0".</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // SSH / SFTP
            if (service == ServiceType.SSH)
            {
                string sshResponse = Encoding.ASCII.GetString(response);

                // Check whether the answer starts with the typical "SSH-2.0".
                if (sshResponse.StartsWith("SSH-2.0"))
                {
                    serviceMatched = true;
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// Splits the greeting line by which the service is detected anyway. Its
        /// layout is fixed (RFC 4253, section 4.2):
        /// <c>SSH-&lt;protoversion&gt;-&lt;softwareversion&gt; &lt;comments&gt;</c>.
        /// <para>
        /// The software part names program and version ("OpenSSH_8.9p1"), and
        /// the comment after it is the suffix Linux distributions add to their
        /// package: "Ubuntu-3ubuntu0.4" names operating system and package
        /// revision. Both arrive unprompted and before any login.
        /// </para>
        /// </summary>
        protected override string? Describe(byte[] response)
        {
            string banner = FirstLine(Encoding.ASCII.GetString(response));
            if (banner.Length == 0) return null;

            // The identification of the remote side starts after "SSH-2.0-". The
            // second hyphen separates it from the protocol part and is not part of it.
            int softwareStart = banner.IndexOf('-', banner.IndexOf('-') + 1);
            if (softwareStart < 0 || softwareStart + 1 >= banner.Length) return null;

            string identification = banner[(softwareStart + 1)..].Trim();
            if (identification.Length == 0) return null;

            // The first space separates the software from the free-form comment.
            int space = identification.IndexOf(' ');
            string software = space > 0 ? identification[..space] : identification;
            string remark = space > 0 ? identification[(space + 1)..].Trim() : string.Empty;

            List<string> lines = [$"Software: {software}"];

            if (remark.Length > 0) lines.Add($"Remark: {remark}");

            // The protocol version is between the two hyphens. Practically
            // always 2.0; a server that still offers 1.99 also speaks the
            // obsolete SSH-1 and is a finding in itself (RFC 4253, section 5.1).
            string protocol = banner[4..softwareStart];
            if (protocol.Length > 0 && protocol != "2.0") lines.Add($"Protocol: {protocol}");

            return string.Join(Environment.NewLine, lines);
        }
    }
}
