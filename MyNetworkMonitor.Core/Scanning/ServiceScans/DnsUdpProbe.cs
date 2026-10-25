// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net.Sockets;
using System.Text;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// The same query as over TCP, but over UDP, the usual transport for name
    /// resolution. Kept separate because a server may support one and not
    /// the other.
    /// </summary>
    public sealed class DnsUdpProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.DNS_UDP;
        public override string Group => ServiceGroups.Network;
        public override IReadOnlyList<int> DefaultPorts => [53];

        /// <summary>As for TCP, the query is built at run time.</summary>
        public override byte[] Hello => [];

        public override Task<PortResult> ProbeAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();

            return SendUdpDnsQuery(address, DnsRequest.Build(DnsRequest.NonexistentName), port);
        }

        /// <summary>
        /// The query over UDP: three attempts with one second each. UDP has no
        /// connection result; only whether something comes back counts.
        /// </summary>
        private static async Task<PortResult> SendUdpDnsQuery(string dnsServer, byte[] query, int port = 53)
        {
            PortResult portResult = new PortResult { Ports = new List<int> { port }, Status = PortStatus.NoResponse };

            using UdpClient udpClient = new UdpClient();
            udpClient.Connect(dnsServer, port);

            for (int attempt = 1; attempt <= 3; attempt++) // at most 3 attempts
            {
                try
                {
                    await udpClient.SendAsync(query, query.Length);

                    using var cts = new CancellationTokenSource(1000); // 1-second timeout
                    var receiveTask = udpClient.ReceiveAsync();

                    if (await Task.WhenAny(receiveTask, Task.Delay(1000, cts.Token)) == receiveTask)
                    {
                        // Fetch the result first, then set the status, not the
                        // other way round.
                        //
                        // WhenAny also completes on a *failed* receive. The
                        // socket is connected here, so Windows reliably
                        // delivers the ICMP "port unreachable" message: on every
                        // host without a name service the receive fails at once.
                        //
                        // With IsRunning set before this line, the access below
                        // would throw, the catch would swallow the exception,
                        // and the status already set would remain, so the
                        // rejection itself would count as a running name
                        // service.
                        byte[] answer = receiveTask.Result.Buffer;

                        // The answer must also belong to this query: same
                        // transaction ID and QR bit set. Otherwise every
                        // datagram arriving at this socket would count.
                        if (DnsRequest.IsAnswerTo(query, answer))
                        {
                            portResult.Status = PortStatus.IsRunning;
                            portResult.PortLog = Encoding.ASCII.GetString(answer);
                            return portResult;
                        }

                        portResult.Status = PortStatus.Open;
                        portResult.PortLog = "An answer came, but it does not belong to this query.";
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

                if (attempt < 3) await Task.Delay(200); // short pause before the next attempt
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
