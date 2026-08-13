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
    }
}
