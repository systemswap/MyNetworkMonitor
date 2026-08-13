using System.Net.Sockets;
using System.Text;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Namensaufloesung ueber TCP. Eigener Ablauf: gefragt wird mit einer
    /// echten DNS-Anfrage nach einem Namen, den es nicht gibt - wer darauf
    /// ueberhaupt in der Form eines DNS-Pakets antwortet, ist ein Namensserver.
    /// Ob der Name aufloest, ist dabei gleichgueltig.
    /// </summary>
    public sealed class DnsTcpProbe : ServiceProbeBase
    {
        /// <summary>
        /// Der abgefragte Name. Absichtlich einer, der nirgends existiert:
        /// gefragt wird nach dem Dienst, nicht nach einer Antwort.
        /// </summary>
        private const string ProbeDomain = "gotme.tcp.com";

        public override ServiceType Service => ServiceType.DNS_TCP;
        public override string Group => ServiceGroups.Network;
        public override IReadOnlyList<int> DefaultPorts => [53];

        /// <summary>
        /// Kein festes Paket: die Anfrage wird um den Namen herum gebaut, und
        /// sie traegt eine Kennung, die je Anfrage neu ist.
        /// </summary>
        public override byte[] Hello => [];

        public override Task<PortResult> ProbeAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();

            return SendTcpDnsQuery(address, DnsRequest.Build(ProbeDomain), port);
        }

        /// <summary>
        /// Die Anfrage ueber TCP, wortgleich aus <c>ScanningMethod_Services</c>
        /// uebernommen: drei Versuche, und ueber TCP steht vor der Anfrage ihre
        /// Laenge in zwei Bytes - dieselbe Laenge kommt vor der Antwort zurueck.
        /// </summary>
        private static async Task<PortResult> SendTcpDnsQuery(string dnsServer, byte[] query, int port)
        {
            PortResult portResult = new PortResult { Ports = new List<int> { port }, Status = PortStatus.NoResponse };

            for (int attempt = 1; attempt <= 3; attempt++) // Maximal 3 Wiederholungen
            {
                try
                {
                    using TcpClient client = new TcpClient();
                    var connectTask = client.ConnectAsync(dnsServer, port);
                    var timeoutTask = Task.Delay(2000); // 2 Sekunden Timeout fuer Verbindung

                    if (await Task.WhenAny(connectTask, timeoutTask) != connectTask)
                    {
                        portResult.Status = PortStatus.Filtered; // Verbindung zu lange, Port gefiltert
                        return portResult;
                    }

                    if (!client.Connected)
                    {
                        portResult.Status = PortStatus.NoResponse; // Verbindung nicht erfolgreich
                        return portResult;
                    }

                    portResult.Status = PortStatus.Open;
                    using NetworkStream stream = client.GetStream();

                    // DNS-Anfrage mit Laengenpraefix
                    byte[] tcpQuery = new byte[query.Length + 2];
                    tcpQuery[0] = (byte)(query.Length >> 8);
                    tcpQuery[1] = (byte)(query.Length & 0xFF);
                    Buffer.BlockCopy(query, 0, tcpQuery, 2, query.Length);

                    await stream.WriteAsync(tcpQuery, 0, tcpQuery.Length);

                    // Antwort-Laengenfeld zuerst lesen (mit Timeout)
                    byte[] lengthBuffer = new byte[2];
                    var cts = new CancellationTokenSource(2000); // Antwort-Timeout (2s)
                    int lengthRead = await stream.ReadAsync(lengthBuffer, 0, 2, cts.Token);

                    if (lengthRead < 2)
                    {
                        portResult.Status = PortStatus.NoResponse;
                        continue; // Erneut versuchen
                    }

                    int responseLength = (lengthBuffer[0] << 8) | lengthBuffer[1];

                    // Antwortdaten lesen (mit Timeout)
                    byte[] responseBuffer = new byte[responseLength];
                    int bytesRead = await stream.ReadAsync(responseBuffer, 0, responseLength, cts.Token);

                    if (bytesRead > 0)
                    {
                        portResult.Status = PortStatus.IsRunning;
                        portResult.PortLog = Encoding.ASCII.GetString(responseBuffer);
                        return portResult; // Erfolgreich
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

                await Task.Delay(200); // Kurze Pause vor naechstem Versuch
            }

            return portResult; // Keine Antwort nach 3 Versuchen
        }

        /// <summary>
        /// Dieser Dienst hat keine eigene Antwortsignatur - er wird ueber
        /// seinen eigenen Ablauf erkannt, nicht ueber ein Bytemuster. Es bleibt
        /// bei der alten Regel fuer solche Faelle: eine Antwort zaehlt.
        /// </summary>
        public override bool Identify(byte[] response) => response.Length > 0;
    }
}
