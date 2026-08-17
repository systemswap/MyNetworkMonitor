using System.Text;
namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// MySQL und die Server, die dasselbe Protokoll sprechen. Gruesst
    /// unaufgefordert mit dem Handshake-Paket; erkannt wird dessen Geruest,
    /// und die Sorte steht im Versionstext daraus.
    /// <para>
    /// Teilt sich Port 3306 mit MariaDB, und die Trennung liegt allein in
    /// diesem Text: fuehrt er "-MariaDB" oder das Scheinpraefix "5.5.5-",
    /// gehoert der Befund dorthin, sonst hierher. Ableger wie Percona oder
    /// TiDB melden ihre Version ohne diese Kennung und landen darum hier -
    /// die Reihe stimmt damit, der Hersteller ist damit nicht gesagt.
    /// </para>
    /// </summary>
    public sealed class MySqlProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.MySQL;
        public override string Group => ServiceGroups.SqlDatabases;
        public override IReadOnlyList<int> DefaultPorts => [3306];

        /// <summary>Gruesst von sich aus - es gibt nichts zu senden.</summary>
        public override byte[] Hello => [];

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;
            string str_serviceResponse = Encoding.ASCII.GetString(response);

            // ?? MariaDB / MySQL: beide gruessen unaufgefordert mit demselben
            // Handshake-Paket. Dass es eines ist, entscheidet sein Geruest
            // (siehe ReadMySqlServerVersion) - welche der beiden Sorten dort
            // laeuft, entscheidet der Versionstext daraus.
            //
            // Die frueheren drei gepruften Byte reichten dafuer nicht: eine
            // Sequenznummer 0 an Stelle 3 und eine 10 an Stelle 4 fallen auch bei
            // anderen Protokollen an, und ohne den Versionstext sauber zu lesen,
            // wurde "kein 'mariadb' im ganzen Puffer" als MySQL gewertet - also
            // auch dann, wenn dort gar keine Begruessung stand.
            if (service == ServiceType.MariaDB || service == ServiceType.MySQL)
            {
                string? serverVersion = ReadMySqlServerVersion(response);

                if (serverVersion is not null)
                {
                    // MariaDB ab 10.0 stellt der echten Version das Scheinpraefix
                    // "5.5.5-" voran, damit alte Clients die Hauptversion nicht
                    // fuer zu alt halten, und haengt "-MariaDB" an - gemessen an
                    // einem 10.0er Server: "5.5.5-10.0.20-MariaDB". Kein Server
                    // der MySQL-Reihe fuehrt eines von beiden; die meldet ihre
                    // Version schlicht als "8.0.36" oder "5.7.44-log".
                    bool isMariaDb =
                        serverVersion.Contains("mariadb", StringComparison.OrdinalIgnoreCase) ||
                        serverVersion.StartsWith("5.5.5-", StringComparison.Ordinal);

                    serviceMatched = service == ServiceType.MariaDB ? isMariaDb : !isMariaDb;
                }
                else if (response.Length >= 7 && response[3] == 0x00 && response[4] == 0xFF)
                {
                    // Statt zu gruessen weist der Server die Verbindung ab -
                    // "Host ... is not allowed to connect to this MariaDB server",
                    // "blocked because of many connection errors". Das ist ein
                    // Fehlerpaket (0xff) und damit ebenso ein Beweis, dass dort
                    // einer laeuft; welcher, sagt er im Klartext selbst.
                    bool namesMariaDb = str_serviceResponse.Contains("mariadb", StringComparison.OrdinalIgnoreCase);
                    bool namesMySql = str_serviceResponse.Contains("mysql", StringComparison.OrdinalIgnoreCase);

                    serviceMatched = service == ServiceType.MariaDB
                        ? namesMariaDb
                        : namesMySql && !namesMariaDb;
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// Der Versionstext aus der Begruessung - dieselbe Zeichenkette, an der
        /// die Erkennung schon entscheidet, ob hier MySQL oder MariaDB laeuft.
        /// Gelesen wurde sie bisher also ohnehin, nur nirgends angezeigt.
        /// </summary>
        protected override string? Describe(byte[] response) => MySqlDetails(response);
    }
}
