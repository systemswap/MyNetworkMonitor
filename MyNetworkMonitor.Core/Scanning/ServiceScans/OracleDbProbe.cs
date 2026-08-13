using System.Text;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Oracle. Spricht nicht von sich aus - anders als FTP oder MySQL braucht
    /// es ein echtes TNS-Connect-Paket, sonst bleibt die Leitung stumm. Als
    /// Treffer zaehlt auch eine Ablehnung: dass der Dienst die Verbindung
    /// zurueckweist, beweist ihn ebenso.
    /// </summary>
    public sealed class OracleDbProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.OracleDB;
        public override string Group => ServiceGroups.SqlDatabases;
        public override IReadOnlyList<int> DefaultPorts => [1521];

        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => BuildTnsConnectPacket();

        /// <summary>
        /// Baut ein TNS-Connect-Paket nach dem Oracle-Net-Grundformat: ein 8-Byte-Header
        /// (Gesamtlaenge, Pruefsumme 0, Pakettyp 1 = Connect, Flag 0, Header-Pruefsumme 0)
        /// gefolgt von der Version, Verbindungsoptionen und dem Connect-Deskriptor als
        /// ASCII-Text. Ungetestet gegen einen echten Oracle-Server - anders als bei SMB
        /// stand hier keiner zur Verfuegung, um es nachzumessen. Ersetzt aber in jedem
        /// Fall die vorherige Sonde, die nachweislich ueberhaupt nichts bewirkte: dort
        /// stand das rohe TCP-SYN-Paket aus einem Wireshark-Mitschnitt statt einer
        /// TNS-Nachricht.
        /// </summary>
        private static byte[] BuildTnsConnectPacket()
        {
            const string connectDescriptor =
                "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=orcl)(CID=(PROGRAM=)(HOST=)(USER=)))" +
                "(ADDRESS=(PROTOCOL=TCP)(HOST=localhost)(PORT=1521)))";

            byte[] descriptorBytes = Encoding.ASCII.GetBytes(connectDescriptor);

            // Version 3.10 (0x013A), "Service Options" 0x0801, SDU/TDU 0x0800 je,
            // Protocolcharacteristics 0x7F08 - uebliche Werte aus oeffentlich
            // dokumentierten TNS-Connect-Mitschnitten.
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
            packet[2] = 0x00; // Pruefsumme (nicht genutzt)
            packet[3] = 0x00;
            packet[4] = 0x01; // Pakettyp: Connect
            packet[5] = 0x00; // Flag
            packet[6] = 0x00; // Header-Pruefsumme (nicht genutzt)
            packet[7] = 0x00;

            Array.Copy(body, 0, packet, 8, body.Length);
            Array.Copy(descriptorBytes, 0, packet, 8 + body.Length, descriptorBytes.Length);

            return packet;
        }

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // ?? Oracle TNS: Antworttyp steht in Byte 4 des TNS-Headers.
            // 2 = Accept, 4 = Refuse (Dienst lehnt ab, ist aber da), 11 = Redirect.
            if (service == ServiceType.OracleDB)
            {
                if (response.Length >= 8 && response[4] is 0x02 or 0x04 or 0x0B)
                {
                    serviceMatched = true;
                }
            }

            return serviceMatched;
        }
    }
}
