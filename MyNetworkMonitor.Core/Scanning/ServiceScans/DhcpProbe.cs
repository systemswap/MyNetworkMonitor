using System.Net;
using System.Net.Sockets;
using MyNetworkMonitor;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// DHCP-Server. Der einzige Dienst, der nicht Ziel fuer Ziel gefragt wird:
    /// ein DISCOVER geht als Rundruf ins Netz, und wer antwortet, hat sich
    /// damit selbst benannt. Danach ist je Ziel nur noch zu vergleichen, ob es
    /// in dieser Liste steht.
    /// <para>
    /// Genau dafuer gibt es <see cref="PrepareAsync"/>. Vorher stand der
    /// Rundruf im Ablauf je Ziel und wurde durch ein Flag gebremst, das die
    /// Schleife bei <em>jedem</em> Ziel neu setzte - der DISCOVER ging also
    /// einmal je Adresse hinaus statt einmal je Lauf, bei einem /24 also 254
    /// Mal, und die Antwortliste wurde dabei aus 30 nebenlaeufigen Zielen
    /// beschrieben.
    /// </para>
    /// </summary>
    public sealed class DhcpProbe : ServiceProbeBase
    {
        /// <summary>Der Port, unter dem ein Server antwortet - unabhaengig vom gefragten.</summary>
        private const int ServerPort = 67;

        private readonly SemaphoreSlim _once = new(1, 1);
        private List<string> _servers = [];
        private bool _asked;

        public override ServiceType Service => ServiceType.DHCP;
        public override string Group => ServiceGroups.Network;
        public override IReadOnlyList<int> DefaultPorts => [ServerPort];


        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
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

            // Auch dann fragen, wenn der Aufrufer die Vorbereitung ausgelassen
            // hat - ohne den Rundruf gaebe es sonst still nie einen Fund.
            await AskOnceAsync(token);

            return new PortResult
            {
                // Gemeldet wird der Serverport, nicht der gefragte: geantwortet
                // hat der Server von 67 aus, und dort ist er auch erreichbar.
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
        /// Der Rundruf selbst, wortgleich aus <c>ScanningMethod_Services</c>
        /// uebernommen. Gebunden wird an die gewaehlte Schnittstelle, gehorcht
        /// wird zwei Sekunden lang; jede Antwort benennt ueber
        /// <see cref="GetDhcpServerIp"/> ihren Absender.
        /// </summary>
        private static List<string> SendDhcpDiscover(byte[] dhcpDiscoverPacket, CancellationToken token)
        {
            List<string> dhcpServers = new List<string>();

            try
            {
                using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, true);
                    // Port 68 auf der gewaehlten Schnittstelle, nicht auf Any -
                    // sonst faengt bei mehreren Karten die falsche die Antwort.
                    socket.Bind(new IPEndPoint(SupportMethods.SelectedNetworkInterfaceInfos.IPv4, 68));

                    IPEndPoint dhcpServerEndPoint = new IPEndPoint(IPAddress.Broadcast, 67);
                    socket.SendTo(dhcpDiscoverPacket, dhcpServerEndPoint);

                    DateTime startTime = DateTime.Now;
                    int timeout = 2000;  // 2 Sekunden Timeout

                    try
                    {
                        while ((DateTime.Now - startTime).TotalMilliseconds < timeout
                               && !token.IsCancellationRequested)
                        {
                            if (socket.Poll(100000, SelectMode.SelectRead))  // 100 ms warten, ob Daten verfuegbar sind
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
        /// Wer hat geantwortet: erst Option 54, sonst der Relay (GIADDR),
        /// zuletzt SIADDR.
        /// </summary>
        private static string GetDhcpServerIp(byte[] response)
        {
            // 1 Option 54 - die verlaesslichste Auskunft
            int index = Array.IndexOf(response, (byte)54);
            if (index > 0)
                return new IPAddress(response.Skip(index + 2).Take(4).ToArray()).ToString();

            // 2 GIADDR, falls ein Relay dazwischensteht
            string relayAgentIp = new IPAddress(response.Skip(24).Take(4).ToArray()).ToString();
            if (relayAgentIp != "0.0.0.0")
                return relayAgentIp;

            // 3 SIADDR als letzte Zuflucht
            return new IPAddress(response.Skip(16).Take(4).ToArray()).ToString();
        }

        /// <summary>
        /// Dieser Dienst hat keine eigene Antwortsignatur - er wird ueber
        /// seinen eigenen Ablauf erkannt, nicht ueber ein Bytemuster. Es bleibt
        /// bei der alten Regel fuer solche Faelle: eine Antwort zaehlt.
        /// </summary>
        public override bool Identify(byte[] response) => response.Length > 0;
    }
}
