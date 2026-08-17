using System.Text;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Secure Shell. Der Server gruesst mit seiner Protokollkennung
    /// ("SSH-2.0-..."), sobald die Verbindung steht - das Hello-Paket ist nur
    /// die Gegenvorstellung, damit die Gegenseite die Verhandlung beginnt.
    /// <para>
    /// Der Normalfall: verbinden, Hello, lesen, pruefen - alles in
    /// <see cref="ServiceProbeBase"/>.
    /// </para>
    /// </summary>
    public sealed class SshProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.SSH;
        public override string Group => ServiceGroups.Network;
        public override IReadOnlyList<int> DefaultPorts => [22];

        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => Encoding.ASCII.GetBytes("SSH-2.0-MySSHClient\r\n");

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // ?? SSH / SFTP
            if (service == ServiceType.SSH)
            {
                string sshResponse = Encoding.ASCII.GetString(response);

                // Prüfen, ob die Antwort das typische "SSH-2.0" enthält
                // Die Bedingung ist unveraendert. Weggefallen ist allein eine
                // Console-Ausgabe, die den ganzen Rest der Antwort mitschrieb -
                // also auch die Rohbytes der Schluesselverhandlung hinter dem
                // Begruessungstext. Ausgewertet hat sie niemand.
                if (sshResponse.StartsWith("SSH-2.0"))
                {
                    serviceMatched = true;
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// Zerlegt die Begruessungszeile, an der der Dienst ohnehin erkannt
        /// wird. Ihr Aufbau ist festgelegt:
        /// <c>SSH-&lt;Protokoll&gt;-&lt;Software&gt; &lt;Bemerkung&gt;</c>.
        /// <para>
        /// Die Software nennt Programm und Version - "OpenSSH_8.9p1" -, und die
        /// Bemerkung dahinter ist der Zusatz, den Linux-Ausgaben ihrem Paket
        /// mitgeben: "Ubuntu-3ubuntu0.4" sagt Betriebssystem und Paketstand.
        /// Beides kommt ungefragt und vor jeder Anmeldung.
        /// </para>
        /// </summary>
        protected override string? Describe(byte[] response)
        {
            string banner = FirstLine(Encoding.ASCII.GetString(response));
            if (banner.Length == 0) return null;

            // Hinter "SSH-2.0-" beginnt die Kennung der Gegenseite. Der zweite
            // Bindestrich trennt sie vom Protokollteil und gehoert nicht dazu.
            int softwareStart = banner.IndexOf('-', banner.IndexOf('-') + 1);
            if (softwareStart < 0 || softwareStart + 1 >= banner.Length) return null;

            string identification = banner[(softwareStart + 1)..].Trim();
            if (identification.Length == 0) return null;

            // Das erste Leerzeichen trennt Software von der freien Bemerkung.
            int space = identification.IndexOf(' ');
            string software = space > 0 ? identification[..space] : identification;
            string remark = space > 0 ? identification[(space + 1)..].Trim() : string.Empty;

            List<string> lines = [$"Software: {software}"];

            if (remark.Length > 0) lines.Add($"Remark: {remark}");

            // Die Protokollfassung steht zwischen den beiden Bindestrichen.
            // Praktisch immer 2.0; ein Server, der noch 1.99 anbietet, spricht
            // auch das alte SSH-1 und ist damit ein Befund fuer sich.
            string protocol = banner[4..softwareStart];
            if (protocol.Length > 0 && protocol != "2.0") lines.Add($"Protocol: {protocol}");

            return string.Join(Environment.NewLine, lines);
        }
    }
}
