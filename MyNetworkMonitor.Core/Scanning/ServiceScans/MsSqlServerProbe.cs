using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Microsoft SQL Server. Der Normalfall ist eine TDS-Anfrage an 1433 und
    /// das Pre-Login-Paket als Antwort.
    /// <para>
    /// Eigener Ablauf wegen der benannten Instanzen: die lauschen nicht auf
    /// 1433, sondern auf einem Port, den sie sich beim Start vom System geben
    /// lassen. Bleibt 1433 also stumm, wird der SQL-Browser gefragt, welche
    /// Instanzen es gibt und auf welchen Ports sie sitzen - sonst gaelte jeder
    /// Server ohne Standardinstanz als nicht vorhanden.
    /// </para>
    /// </summary>
    public sealed class MsSqlServerProbe : ServiceProbeBase
    {
        /// <summary>
        /// Zeitlimit fuer die Rueckfrage beim SQL-Browser. Kurz gehalten: sie
        /// laeuft nur, wenn der Hauptport ohnehin schon nichts geliefert hat,
        /// und darf den Lauf nicht aufhalten.
        /// </summary>
        private static readonly TimeSpan BrowserTimeout = TimeSpan.FromSeconds(3);

        public override ServiceType Service => ServiceType.MSSQLServer;
        public override string Group => ServiceGroups.SqlDatabases;
        public override IReadOnlyList<int> DefaultPorts => [1433];


        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => new byte[]
            {
                0x12, 0x01, 0x00, 0x66, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x24, 0x00, 0x06, 0x01, 0x00, 0x2a,
                0x00, 0x01, 0x02, 0x00, 0x2b, 0x00, 0x09, 0x03, 0x00, 0x34, 0x00, 0x04, 0x04, 0x00, 0x38, 0x00,
                0x01, 0x05, 0x00, 0x39, 0x00, 0x24, 0x06, 0x00, 0x5d, 0x00, 0x01, 0xff, 0x03, 0x0f, 0x5a, 0xfc,
                0x01, 0x00, 0x00, 0x6e, 0x65, 0x78, 0x65, 0x6e, 0x73, 0x6f, 0x73, 0x00, 0x00, 0x00, 0x65, 0x00,
                0x00, 0xf2, 0x82, 0x2a, 0x72, 0x26, 0x01, 0x5c, 0x4b, 0xb8, 0x8d, 0xd4, 0x59, 0x35, 0xb5, 0x28,
                0xe7, 0xc3, 0xa9, 0x3e, 0x17, 0xbc, 0x75, 0xa4, 0x4a, 0x8e, 0x94, 0x7e, 0xfd, 0xcf, 0x33, 0x44,
                0x86, 0x02, 0x00, 0x00, 0x00, 0x01
            };
        public override async Task<PortResult> ProbeAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            PortResult portResult = await base.ProbeAsync(context, address, port, token);

            if (portResult.Status == PortStatus.IsRunning) return portResult;

            try
            {
                using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                cts.CancelAfter(BrowserTimeout);

                BrowserAnswer browser = await GetMSSQLDynamicPortsAsync(address)
                    .WaitAsync(cts.Token);

                if (browser.Ports.Count > 0)
                {
                    portResult.Ports = browser.Ports;
                    portResult.Status = PortStatus.IsRunning;

                    // Der Browser nennt die Instanzen beim Namen und mit ihrer
                    // Fassung. Bisher wurde aus derselben Antwort nur die
                    // Portnummer gelesen und der Rest verworfen - dabei ist
                    // gerade er die Auskunft, die auf 1433 nicht zu holen war.
                    if (browser.Description.Length > 0) portResult.PortLog = browser.Description;
                }
            }
            catch (Exception) when (!token.IsCancellationRequested)
            {
                // Kein Browserdienst, keine Antwort, Zeitlimit - alles kein
                // Fehler, sondern schlicht kein Zusatzbefund. Es bleibt beim
                // Ergebnis des Hauptports.
            }

            return portResult;
        }

        /// <summary>
        /// Was der SQL-Browser zurueckgemeldet hat: die Ports, an denen die
        /// Instanzen sitzen, und die Beschreibung fuer die Detailansicht.
        /// </summary>
        private readonly record struct BrowserAnswer(List<int> Ports, string Description);

        /// <summary>
        /// Die Rueckfrage beim SQL-Browser auf UDP 1434, wortgleich aus
        /// <c>ScanningMethod_Services</c> uebernommen: drei Versuche, je zwei
        /// Sekunden, und aus der Antwort werden <em>alle</em> "tcp;"-Ports
        /// gelesen - ein Server kann mehrere benannte Instanzen tragen.
        /// <para>
        /// Neu ist allein, dass die Antwort nicht mehr nur nach Portnummern
        /// durchsucht, sondern vollstaendig gelesen wird. Dasselbe Paket, das
        /// die Ports traegt, nennt zu jeder Instanz auch ihren Namen und ihre
        /// Fassung - ohne Anmeldung, denn der Browser ist genau dafuer da.
        /// </para>
        /// </summary>
        private static async Task<BrowserAnswer> GetMSSQLDynamicPortsAsync(string serverIP)
        {
            const int MaxRetries = 3;
            const int TimeoutMilliseconds = 2000;
            var foundPorts = new List<int>();
            string description = string.Empty;

            using (UdpClient udpClient = new UdpClient())
            {
                udpClient.Client.ReceiveTimeout = TimeoutMilliseconds;
                IPEndPoint sqlServerEndpoint = new IPEndPoint(IPAddress.Parse(serverIP), 1434);
                byte[] request = Encoding.ASCII.GetBytes("\x02"); // Anfrage fuer SQL-Browser-Information

                for (int attempt = 1; attempt <= MaxRetries; attempt++)
                {
                    try
                    {
                        await udpClient.SendAsync(request, request.Length, sqlServerEndpoint);

                        // Warte auf eine Antwort mit Timeout
                        var receiveTask = udpClient.ReceiveAsync();
                        if (await Task.WhenAny(receiveTask, Task.Delay(TimeoutMilliseconds)) == receiveTask)
                        {
                            UdpReceiveResult response = await receiveTask;
                            string responseText = Encoding.ASCII.GetString(response.Buffer);

                            // Alle "tcp;" Ports suchen, nicht nur den ersten
                            var matches = Regex.Matches(responseText, @"tcp;(\d+)");
                            foreach (Match match in matches)
                            {
                                if (match.Groups.Count > 1 && int.TryParse(match.Groups[1].Value, out int port))
                                {
                                    foundPorts.Add(port);
                                }
                            }

                            if (foundPorts.Count > 0)
                            {
                                description = DescribeInstances(responseText);
                                return new BrowserAnswer(foundPorts, description);
                            }
                        }
                    }
                    catch (SocketException)
                    {
                        // Kein Browserdienst erreichbar - naechster Versuch.
                    }
                }
            }

            return new BrowserAnswer(foundPorts, description);
        }

        /// <summary>
        /// Macht aus der Browser-Antwort die Zeilen fuer die Detailansicht.
        /// <para>
        /// Der Aufbau ist eine Kette aus Name-Wert-Paaren, durch Semikolon
        /// getrennt, und je Instanz beginnt sie neu mit <c>ServerName</c>:
        /// <c>ServerName;HOST;InstanceName;SQLEXPRESS;IsClustered;No;Version;15.0.2000.5;tcp;1433;;</c>
        /// </para>
        /// </summary>
        private static string DescribeInstances(string response)
        {
            List<string> lines = [];

            // Der Trenner steht am Anfang jedes Abschnitts; der erste Teil vor
            // dem ersten "ServerName" ist leer und faellt weg.
            string[] blocks = response.Split("ServerName;", StringSplitOptions.RemoveEmptyEntries);

            foreach (string block in blocks)
            {
                string[] parts = block.Split(';');

                string instance = ValueOf(parts, "InstanceName");
                string version = ValueOf(parts, "Version");
                string clustered = ValueOf(parts, "IsClustered");

                if (instance.Length == 0 && version.Length == 0) continue;

                List<string> fields = [];

                if (instance.Length > 0) fields.Add(instance);
                if (version.Length > 0) fields.Add($"version {version}");

                // Nur erwaehnen, wenn es zutrifft - "IsClustered: No" ist bei
                // den allermeisten Servern der Normalfall und keine Auskunft.
                if (clustered.Equals("Yes", StringComparison.OrdinalIgnoreCase)) fields.Add("clustered");

                lines.Add($"Instance: {string.Join(", ", fields)}");
            }

            return lines.Count > 0 ? string.Join(Environment.NewLine, lines) : string.Empty;
        }

        /// <summary>
        /// Der Wert hinter einem Schluessel in der Semikolon-Kette. Der erste
        /// Abschnitt eines Blocks ist der Servername selbst und traegt keinen
        /// eigenen Schluessel mehr - er wurde beim Trennen verbraucht.
        /// </summary>
        private static string ValueOf(string[] parts, string key)
        {
            for (int i = 0; i < parts.Length - 1; i++)
            {
                if (parts[i].Equals(key, StringComparison.OrdinalIgnoreCase))
                {
                    return Printable(parts[i + 1].Trim(), 40);
                }
            }

            return string.Empty;
        }

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // ?? Microsoft SQL Server
            if (service == ServiceType.MSSQLServer)
            {
                // MSSQL-TDS-Erkennung (Pre-Login-Paket)
                if (response.Length > 8 && response[0] == 0x04 && response[1] == 0x01)
                {
                    // Mindestlänge und typische Struktur prüfen
                    int packetLength = response[2] << 8 | response[3]; // Paketlänge aus Byte 2 und 3
                    if (packetLength > 8 && packetLength < 512)
                    {
                        serviceMatched = true;
                    }
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// Liest Fassung und Verschluesselungshaltung aus der PRELOGIN-Antwort.
        /// <para>
        /// Sie ist der erste Zug jeder TDS-Verbindung und laeuft vor jeder
        /// Anmeldung ab - ein Client muss wissen, ob er auf TLS umschalten muss,
        /// bevor er ein Passwort schickt. Der Server nennt darin ungefragt seine
        /// Fassung. Genau dieses Paket beantwortet das Erkennungspaket bereits;
        /// gelesen wurden bisher nur die ersten vier Byte.
        /// </para>
        /// </summary>
        protected override string? Describe(byte[] response)
        {
            // Hinter dem 8 Byte langen TDS-Kopf beginnt die Merkmalsliste. Ihre
            // Eintraege sind je 5 Byte - Kennung, Abstand, Laenge -, und die
            // Abstaende zaehlen ab dem Beginn dieser Liste.
            const int payload = 8;
            const int entrySize = 5;

            if (response.Length <= payload) return null;

            List<string> lines = [];

            for (int at = payload; at + entrySize <= response.Length; at += entrySize)
            {
                byte token = response[at];

                // 0xFF schliesst die Liste ab.
                if (token == 0xFF) break;

                int offset = payload + (response[at + 1] << 8 | response[at + 2]);
                int length = response[at + 3] << 8 | response[at + 4];

                if (offset + length > response.Length) continue;

                switch (token)
                {
                    // VERSION: Hauptfassung, Nebenfassung, Baunummer.
                    case 0x00 when length >= 4:
                    {
                        int major = response[offset];
                        int minor = response[offset + 1];
                        int build = response[offset + 2] << 8 | response[offset + 3];

                        string product = ProductName(major, minor);

                        lines.Add(product.Length > 0
                            ? $"Version: {major}.{minor}.{build} ({product})"
                            : $"Version: {major}.{minor}.{build}");

                        break;
                    }

                    // ENCRYPTION: was der Server von der Verschluesselung haelt.
                    case 0x01 when length >= 1:
                    {
                        string state = EncryptionState(response[offset]);
                        if (state.Length > 0) lines.Add($"Encryption: {state}");

                        break;
                    }
                }
            }

            return lines.Count > 0 ? string.Join(Environment.NewLine, lines) : null;
        }

        /// <summary>
        /// Der Handelsname zur Fassungsnummer. Die Nebenfassung zaehlt nur bei
        /// der 10 - 10.0 ist 2008, 10.50 ist 2008 R2.
        /// </summary>
        private static string ProductName(int major, int minor) => major switch
        {
            8 => "SQL Server 2000",
            9 => "SQL Server 2005",
            10 => minor >= 50 ? "SQL Server 2008 R2" : "SQL Server 2008",
            11 => "SQL Server 2012",
            12 => "SQL Server 2014",
            13 => "SQL Server 2016",
            14 => "SQL Server 2017",
            15 => "SQL Server 2019",
            16 => "SQL Server 2022",
            17 => "SQL Server 2025",
            _ => string.Empty
        };

        /// <summary>
        /// Die vier Haltungen aus der TDS-Festlegung. Der Unterschied zwischen
        /// "moeglich" und "gefordert" ist der, auf den es ankommt: nur bei
        /// "gefordert" ist ausgeschlossen, dass ein Client sein Passwort
        /// unverschluesselt schickt.
        /// </summary>
        private static string EncryptionState(byte value) => value switch
        {
            0x00 => "available, but not required",
            0x01 => "in use for login",
            0x02 => "not supported by server",
            0x03 => "required by server",
            _ => string.Empty
        };
    }
}
