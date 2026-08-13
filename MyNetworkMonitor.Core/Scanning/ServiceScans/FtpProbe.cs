using System.Text;
namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// File Transfer Protocol. Gruesst von sich aus mit "220 ..." - es gibt
    /// nichts zu senden, und genau darum steht als Hello-Paket ein leeres
    /// Feld. Frueher stand dort ein rohes TCP-SYN-Paket aus einem Mitschnitt;
    /// aufgefallen war das nie, weil ein FTP-Server ohnehin antwortet, egal
    /// was ankommt.
    /// </summary>
    public sealed class FtpProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.FTP;
        public override string Group => ServiceGroups.Network;
        public override IReadOnlyList<int> DefaultPorts => [21];

        /// <summary>Nichts zu senden - siehe oben.</summary>
        public override byte[] Hello => [];

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;
            string str_serviceResponse = Encoding.ASCII.GetString(response);

            // ?? FTP
            if (service == ServiceType.FTP)
            {
                if (str_serviceResponse.StartsWith("220 "))
                {
                    serviceMatched = true;
                }
            }

            return serviceMatched;
        }
    }
}
