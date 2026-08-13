using System.Net.Sockets;
using System.Text;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Dieselbe Anfrage wie ueber TCP, nur ueber UDP - der Weg, den
    /// Namensaufloesung ueblicherweise nimmt. Getrennt gefuehrt, weil ein
    /// Server durchaus das eine koennen und das andere nicht.
    /// </summary>
    public sealed class DnsUdpProbe : ServiceProbeBase
    {
        /// <summary>Wie beim TCP-Weg ein Name, den es nicht gibt.</summary>
        private const string ProbeDomain = "gotme.udp.com";

        public override ServiceType Service => ServiceType.DNS_UDP;
        public override string Group => ServiceGroups.Network;
        public override IReadOnlyList<int> DefaultPorts => [53];

        /// <summary>Wie beim TCP-Weg: die Anfrage entsteht erst zur Laufzeit.</summary>
        public override byte[] Hello => [];

        public override Task<PortResult> ProbeAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();

            return SendUdpDnsQuery(address, DnsRequest.Build(ProbeDomain), port);
        }

        /// <summary>
        /// Die Anfrage ueber UDP, wortgleich aus <c>ScanningMethod_Services</c>
        /// uebernommen: drei Versuche mit je einer Sekunde Geduld. Ueber UDP
        /// gibt es kein Verbindungsergebnis - es zaehlt allein, ob etwas
        /// zurueckkommt.
        /// </summary>
        private static async Task<PortResult> SendUdpDnsQuery(string dnsServer, byte[] query, int port = 53)
        {
            PortResult portResult = new PortResult { Ports = new List<int> { port }, Status = PortStatus.NoResponse };

            using UdpClient udpClient = new UdpClient();
            udpClient.Connect(dnsServer, port);

            for (int attempt = 1; attempt <= 3; attempt++) // Maximal 3 Wiederholungen
            {
                try
                {
                    await udpClient.SendAsync(query, query.Length);

                    using var cts = new CancellationTokenSource(1000); // 1 Sekunde Timeout
                    var receiveTask = udpClient.ReceiveAsync();

                    if (await Task.WhenAny(receiveTask, Task.Delay(1000, cts.Token)) == receiveTask)
                    {
                        // Erst das Ergebnis holen, dann werten - nicht umgekehrt.
                        //
                        // WhenAny endet auch bei einem *fehlgeschlagenen*
                        // Empfang. Der Socket ist hier verbunden, und damit
                        // stellt Windows die ICMP-Absage "Port nicht
                        // erreichbar" zuverlaessig zu: bei jedem Rechner ohne
                        // Namensdienst schlaegt der Empfang also sofort fehl.
                        //
                        // Vorher stand die Zeile mit IsRunning davor. Der
                        // Zugriff darunter warf, der Fang unten schluckte die
                        // Ausnahme - und der bereits gesetzte Zustand blieb
                        // stehen. Damit galt ausgerechnet die Absage als
                        // laufender Namensdienst.
                        byte[] antwort = receiveTask.Result.Buffer;

                        // Und die Antwort muss zur eigenen Frage gehoeren:
                        // dieselbe Transaktionskennung und das Antwortbit
                        // gesetzt. Sonst zaehlte jedes Datagramm, das an
                        // diesem Socket ankommt.
                        if (DnsRequest.IsAnswerTo(query, antwort))
                        {
                            portResult.Status = PortStatus.IsRunning;
                            portResult.PortLog = Encoding.ASCII.GetString(antwort);
                            return portResult;
                        }

                        portResult.Status = PortStatus.Open;
                        portResult.PortLog = "Antwort kam, gehoert aber nicht zu dieser Anfrage.";
                        return portResult;
                    }
                }
                catch (OperationCanceledException)
                {
                    portResult.Status = PortStatus.NoResponse;
                }
                catch (Exception)
                {
                    // Kein Namensserver an dieser Stelle - naechster Versuch.
                }

                if (attempt < 3) await Task.Delay(200); // Kurze Pause vor naechstem Versuch
            }

            return portResult; // Falls nach 3 Versuchen keine Antwort kam
        }

        /// <summary>
        /// Dieser Dienst hat keine eigene Antwortsignatur - er wird ueber
        /// seinen eigenen Ablauf erkannt, nicht ueber ein Bytemuster. Es bleibt
        /// bei der alten Regel fuer solche Faelle: eine Antwort zaehlt.
        /// </summary>
        public override bool Identify(byte[] response) => response.Length > 0;
    }
}
