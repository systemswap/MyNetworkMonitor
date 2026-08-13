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

                List<int> dynamicPorts = await GetMSSQLDynamicPortsAsync(address)
                    .WaitAsync(cts.Token);

                if (dynamicPorts.Count > 0)
                {
                    portResult.Ports = dynamicPorts;
                    portResult.Status = PortStatus.IsRunning;
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
        /// Die Rueckfrage beim SQL-Browser auf UDP 1434, wortgleich aus
        /// <c>ScanningMethod_Services</c> uebernommen: drei Versuche, je zwei
        /// Sekunden, und aus der Antwort werden <em>alle</em> "tcp;"-Ports
        /// gelesen - ein Server kann mehrere benannte Instanzen tragen.
        /// </summary>
        private static async Task<List<int>> GetMSSQLDynamicPortsAsync(string serverIP)
        {
            const int MaxRetries = 3;
            const int TimeoutMilliseconds = 2000;
            var foundPorts = new List<int>();

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
                                return foundPorts;
                            }
                        }
                    }
                    catch (SocketException)
                    {
                        // Kein Browserdienst erreichbar - naechster Versuch.
                    }
                }
            }

            return foundPorts;
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
    }
}
