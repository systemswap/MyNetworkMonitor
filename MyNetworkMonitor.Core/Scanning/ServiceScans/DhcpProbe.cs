// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net;
using System.Net.Sockets;
using MyNetworkMonitor;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// DHCP server. The only service that is not queried target by target: a
    /// DHCPDISCOVER goes out as a broadcast, and whoever answers has named
    /// itself. Afterwards each target is only compared against this list.
    /// <para>
    /// That is what <see cref="PrepareAsync"/> is for. The broadcast is sent
    /// once per run and guarded by a lock; sent per target, a /24 network
    /// would receive 254 broadcasts, and 30 concurrent targets would write to
    /// the answer list at the same time.
    /// </para>
    /// </summary>
    public sealed class DhcpProbe : ServiceProbeBase
    {
        /// <summary>The port a server answers from, regardless of the port asked.</summary>
        private const int ServerPort = 67;

        private readonly SemaphoreSlim _once = new(1, 1);
        private List<string> _servers = [];
        private bool _asked;

        public override ServiceType Service => ServiceType.DHCP;
        public override string Group => ServiceGroups.Network;
        public override IReadOnlyList<int> DefaultPorts => [ServerPort];


        /// <summary>
        /// A DHCPDISCOVER (RFC 2131, section 4.4.1) with the broadcast flag set,
        /// client hardware address DE:AD:C0:DE:CA:FE and a parameter request
        /// list (option 55).
        /// </summary>
        public override byte[] Hello => new byte[]
            {
                0x01, 0x01, 0x06, 0x00, 0x60, 0xE7, 0xC5, 0x78, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xC0, 0xDE,
                0xCA, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63,
                0x35, 0x01, 0x01, 0x37, 0x40, 0xFC, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
                0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
                0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A,
                0x3B, 0x3C, 0x3D, 0x43, 0x42, 0xFF
            };
        public override Task PrepareAsync(
            ProbeContext context, IReadOnlyList<string> targets, CancellationToken token) =>
            AskOnceAsync(token);

        public override async Task<PortResult> ProbeAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();

            // Ask even if the caller skipped the preparation; without the
            // broadcast there would silently never be a finding.
            await AskOnceAsync(token);

            return new PortResult
            {
                // Reports the server port, not the one asked: the server
                // answered from 67, and that is where it is reachable.
                Ports = [ServerPort],
                Status = _servers.Contains(address) ? PortStatus.IsRunning : PortStatus.NoResponse
            };
        }

        private async Task AskOnceAsync(CancellationToken token)
        {
            if (_asked) return;

            await _once.WaitAsync(token);

            try
            {
                if (_asked) return;

                _servers = SendDhcpDiscover(Hello, token);
            }
            finally
            {
                _asked = true;
                _once.Release();
            }
        }

        /// <summary>
        /// The broadcast itself. Binds to the selected interface and listens for
        /// two seconds; <see cref="GetDhcpServerIp"/> names the sender of each
        /// answer.
        /// </summary>
        private static List<string> SendDhcpDiscover(byte[] dhcpDiscoverPacket, CancellationToken token)
        {
            List<string> dhcpServers = new List<string>();

            try
            {
                using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, true);
                    // Port 68 on the selected interface, not on Any; with
                    // several adapters the wrong one would catch the answer.
                    socket.Bind(new IPEndPoint(SupportMethods.SelectedNetworkInterfaceInfos.IPv4, 68));

                    IPEndPoint dhcpServerEndPoint = new IPEndPoint(IPAddress.Broadcast, 67);
                    socket.SendTo(dhcpDiscoverPacket, dhcpServerEndPoint);

                    DateTime startTime = DateTime.Now;
                    int timeout = 2000;  // 2-second timeout

                    try
                    {
                        while ((DateTime.Now - startTime).TotalMilliseconds < timeout
                               && !token.IsCancellationRequested)
                        {
                            if (socket.Poll(100000, SelectMode.SelectRead))  // wait up to 100 ms for data
                            {
                                byte[] buffer = new byte[1024];
                                EndPoint remoteEndPoint = new IPEndPoint(SupportMethods.SelectedNetworkInterfaceInfos.IPv4, 0);
                                int receivedBytes = socket.ReceiveFrom(buffer, ref remoteEndPoint);

                                if (receivedBytes >= 28)
                                {
                                    string dhcpServerIp = GetDhcpServerIp(buffer);
                                    if (!string.IsNullOrEmpty(dhcpServerIp) && !dhcpServers.Contains(dhcpServerIp))
                                    {
                                        dhcpServers.Add(dhcpServerIp);
                                    }
                                }
                            }
                        }
                    }
                    catch (SocketException)
                    {
                    }

                    return dhcpServers;
                }
            }
            catch
            {
            }

            return dhcpServers;
        }

        /// <summary>
        /// Who answered: first option 54 (server identifier, RFC 2132,
        /// section 9.7), otherwise the relay (giaddr), finally siaddr.
        /// </summary>
        private static string GetDhcpServerIp(byte[] response)
        {
            // 1. Option 54, the most reliable information
            int index = Array.IndexOf(response, (byte)54);
            if (index > 0)
                return new IPAddress(response.Skip(index + 2).Take(4).ToArray()).ToString();

            // 2. giaddr, if a relay agent is in between
            string relayAgentIp = new IPAddress(response.Skip(24).Take(4).ToArray()).ToString();
            if (relayAgentIp != "0.0.0.0")
                return relayAgentIp;

            // 3. siaddr as the last resort
            return new IPAddress(response.Skip(16).Take(4).ToArray()).ToString();
        }

        /// <summary>
        /// This service has no answer signature of its own; it is detected by
        /// its own procedure, not by a byte pattern. For such cases any answer
        /// counts.
        /// </summary>
        public override bool Identify(byte[] response) => response.Length > 0;
    }
}
