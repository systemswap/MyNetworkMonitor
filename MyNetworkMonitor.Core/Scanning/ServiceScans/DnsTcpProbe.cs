// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net.Sockets;
using System.Text;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Name resolution over TCP. Own procedure: a real DNS query asks for a
    /// name that does not exist; whoever answers with a DNS message at all is
    /// a name server. Whether the name resolves does not matter.
    /// </summary>
    public sealed class DnsTcpProbe : ServiceProbeBase
    {
        /// <summary>
        /// The queried name. Deliberately one that does not exist: the probe
        /// asks for the service, not for an answer.
        /// </summary>
        private const string ProbeDomain = "gotme.tcp.com";

        public override ServiceType Service => ServiceType.DNS_TCP;
        public override string Group => ServiceGroups.Network;
        public override IReadOnlyList<int> DefaultPorts => [53];

        /// <summary>
        /// No fixed packet: the query is built around the name at run time by
        /// <see cref="DnsRequest.Build"/>.
        /// </summary>
        public override byte[] Hello => [];

        public override Task<PortResult> ProbeAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();

            return SendTcpDnsQuery(address, DnsRequest.Build(ProbeDomain), port);
        }

        /// <summary>
        /// The query over TCP: three attempts. Over TCP the message is preceded
        /// by its length in two bytes, and the answer comes back with the same
        /// prefix (RFC 1035, section 4.2.2).
        /// </summary>
        private static async Task<PortResult> SendTcpDnsQuery(string dnsServer, byte[] query, int port)
        {
            PortResult portResult = new PortResult { Ports = new List<int> { port }, Status = PortStatus.NoResponse };

            for (int attempt = 1; attempt <= 3; attempt++) // at most 3 attempts
            {
                try
                {
                    using TcpClient client = new TcpClient();
                    var connectTask = client.ConnectAsync(dnsServer, port);
                    var timeoutTask = Task.Delay(2000); // 2-second connect timeout

                    if (await Task.WhenAny(connectTask, timeoutTask) != connectTask)
                    {
                        portResult.Status = PortStatus.Filtered; // connect took too long: filtered
                        return portResult;
                    }

                    if (!client.Connected)
                    {
                        portResult.Status = PortStatus.NoResponse; // connection failed
                        return portResult;
                    }

                    portResult.Status = PortStatus.Open;
                    using NetworkStream stream = client.GetStream();

                    // DNS query with length prefix
                    byte[] tcpQuery = new byte[query.Length + 2];
                    tcpQuery[0] = (byte)(query.Length >> 8);
                    tcpQuery[1] = (byte)(query.Length & 0xFF);
                    Buffer.BlockCopy(query, 0, tcpQuery, 2, query.Length);

                    await stream.WriteAsync(tcpQuery, 0, tcpQuery.Length);

                    // Read the answer length field first (with timeout)
                    byte[] lengthBuffer = new byte[2];
                    var cts = new CancellationTokenSource(2000); // answer timeout (2 s)
                    int lengthRead = await stream.ReadAsync(lengthBuffer, 0, 2, cts.Token);

                    if (lengthRead < 2)
                    {
                        portResult.Status = PortStatus.NoResponse;
                        continue; // try again
                    }

                    int responseLength = (lengthBuffer[0] << 8) | lengthBuffer[1];

                    // Read the answer data (with timeout)
                    byte[] responseBuffer = new byte[responseLength];
                    int bytesRead = await stream.ReadAsync(responseBuffer, 0, responseLength, cts.Token);

                    // As over UDP, the answer must belong to this query: same
                    // transaction ID, QR bit set. Over TCP the length field
                    // comes first, so the check applies to the body read.
                    if (bytesRead > 0 && DnsRequest.IsAnswerTo(query, responseBuffer))
                    {
                        portResult.Status = PortStatus.IsRunning;
                        portResult.PortLog = Encoding.ASCII.GetString(responseBuffer, 0, bytesRead);
                        return portResult; // success
                    }

                    if (bytesRead > 0)
                    {
                        // The port accepts connections and sends something,
                        // but it does not answer the query in DNS.
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
                    // No name server here; try again.
                }

                await Task.Delay(200); // short pause before the next attempt
            }

            return portResult; // no answer after 3 attempts
        }

        /// <summary>
        /// This service has no answer signature of its own; it is detected by
        /// its own procedure, not by a byte pattern. For such cases any answer
        /// counts.
        /// </summary>
        public override bool Identify(byte[] response) => response.Length > 0;
    }
}
