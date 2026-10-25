using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Microsoft SQL Server. The common case is a TDS request to 1433 and the
    /// PRELOGIN packet as the answer.
    /// <para>
    /// Own procedure because of named instances: they do not listen on 1433
    /// but on a port assigned by the system at startup. If 1433 stays silent,
    /// the SQL Server Browser is asked which instances exist and on which
    /// ports they listen; otherwise every server without a default instance
    /// would count as absent.
    /// </para>
    /// </summary>
    public sealed class MsSqlServerProbe : ServiceProbeBase
    {
        /// <summary>
        /// Timeout for the SQL Server Browser query. Kept short: it runs only
        /// when the main port has returned nothing and must not hold up the run.
        /// </summary>
        private static readonly TimeSpan BrowserTimeout = TimeSpan.FromSeconds(3);

        public override ServiceType Service => ServiceType.MSSQLServer;
        public override string Group => ServiceGroups.SqlDatabases;
        public override IReadOnlyList<int> DefaultPorts => [1433];


        /// <summary>
        /// TDS PRELOGIN (MS-TDS, section 2.2.6.5) for the default instance, with zero thread and trace IDs – no values of a
        /// particular client or server. See docs/FEHLERGEDAECHTNIS.md, No. 14.
        /// </summary>
        public override byte[] Hello => new byte[]
            {
                0x12, 0x01, 0x00, 0x5E, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x24, 0x00, 0x06, 0x01, 0x00, 0x2A,
                0x00, 0x01, 0x02, 0x00, 0x2B, 0x00, 0x01, 0x03, 0x00, 0x2C, 0x00, 0x04, 0x04, 0x00, 0x30, 0x00,
                0x01, 0x05, 0x00, 0x31, 0x00, 0x24, 0x06, 0x00, 0x55, 0x00, 0x01, 0xFF, 0x03, 0x0F, 0x5A, 0xFC,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
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

                    // The browser names the instances and their versions. That
                    // is exactly the information that 1433 did not provide.
                    if (browser.Description.Length > 0) portResult.PortLog = browser.Description;
                }
            }
            catch (Exception) when (!token.IsCancellationRequested)
            {
                // No browser service, no answer, timeout: none of these is an
                // error, just no additional finding. The result of the main
                // port stands.
            }

            return portResult;
        }

        /// <summary>
        /// What the SQL Server Browser reported: the ports of the instances and
        /// the description for the details view.
        /// </summary>
        private readonly record struct BrowserAnswer(List<int> Ports, string Description);

        /// <summary>
        /// The SQL Server Browser query on UDP 1434 (SQL Server Resolution
        /// Protocol, MC-SQLR): three attempts of two seconds each, and
        /// <em>all</em> "tcp;" ports are read from the answer, because a server
        /// can host several named instances.
        /// <para>
        /// The answer is read completely, not only for port numbers. The same
        /// packet that carries the ports also names each instance and its
        /// version, without login; that is the purpose of the browser.
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
                byte[] request = Encoding.ASCII.GetBytes("\x02"); // CLNT_BCAST_EX: request for instance information

                for (int attempt = 1; attempt <= MaxRetries; attempt++)
                {
                    try
                    {
                        await udpClient.SendAsync(request, request.Length, sqlServerEndpoint);

                        // Wait for an answer with timeout
                        var receiveTask = udpClient.ReceiveAsync();
                        if (await Task.WhenAny(receiveTask, Task.Delay(TimeoutMilliseconds)) == receiveTask)
                        {
                            UdpReceiveResult response = await receiveTask;
                            string responseText = Encoding.ASCII.GetString(response.Buffer);

                            // Find all "tcp;" ports, not only the first
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
                        // No browser service reachable; try again.
                    }
                }
            }

            return new BrowserAnswer(foundPorts, description);
        }

        /// <summary>
        /// Turns the browser answer into the lines for the details view.
        /// <para>
        /// The layout is a chain of name-value pairs separated by semicolons,
        /// starting again with <c>ServerName</c> for each instance:
        /// <c>ServerName;HOST;InstanceName;SQLEXPRESS;IsClustered;No;Version;15.0.2000.5;tcp;1433;;</c>
        /// </para>
        /// </summary>
        private static string DescribeInstances(string response)
        {
            List<string> lines = [];

            // The separator is at the start of each block; the part before the
            // first "ServerName" is empty and is dropped.
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

                // Mention only if true: "IsClustered: No" is the normal case for
                // almost all servers and carries no information.
                if (clustered.Equals("Yes", StringComparison.OrdinalIgnoreCase)) fields.Add("clustered");

                lines.Add($"Instance: {string.Join(", ", fields)}");
            }

            return lines.Count > 0 ? string.Join(Environment.NewLine, lines) : string.Empty;
        }

        /// <summary>
        /// The value after a key in the semicolon chain. The first part of a
        /// block is the server name itself and has no key of its own; the key
        /// was consumed by the split.
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

        /// <summary>Matches a TDS response packet (type 0x04, status 0x01) of plausible length.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // Microsoft SQL Server
            if (service == ServiceType.MSSQLServer)
            {
                // TDS detection (PRELOGIN response)
                if (response.Length > 8 && response[0] == 0x04 && response[1] == 0x01)
                {
                    // Check minimum length and typical structure
                    int packetLength = response[2] << 8 | response[3]; // packet length from bytes 2 and 3
                    if (packetLength > 8 && packetLength < 512)
                    {
                        serviceMatched = true;
                    }
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// Reads version and encryption setting from the PRELOGIN answer.
        /// <para>
        /// PRELOGIN is the first exchange of every TDS connection and happens
        /// before any login: a client must know whether to switch to TLS before
        /// it sends a password. The server states its version in it unprompted.
        /// This is the packet that answers the detection packet.
        /// </para>
        /// </summary>
        protected override string? Describe(byte[] response)
        {
            // The option list starts after the 8-byte TDS header. Its entries are
            // 5 bytes each (token, offset, length), and the offsets count from
            // the start of this list.
            const int payload = 8;
            const int entrySize = 5;

            if (response.Length <= payload) return null;

            List<string> lines = [];

            for (int at = payload; at + entrySize <= response.Length; at += entrySize)
            {
                byte token = response[at];

                // 0xFF terminates the list.
                if (token == 0xFF) break;

                int offset = payload + (response[at + 1] << 8 | response[at + 2]);
                int length = response[at + 3] << 8 | response[at + 4];

                if (offset + length > response.Length) continue;

                switch (token)
                {
                    // VERSION: major, minor, build.
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

                    // ENCRYPTION: the encryption setting of the server.
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
        /// The product name for a version number. The minor version matters
        /// only for 10: 10.0 is 2008, 10.50 is 2008 R2.
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
        /// The four ENCRYPTION values from MS-TDS 2.2.6.5. The difference
        /// between "available" and "required" is what matters: only with
        /// "required" can no client send its password unencrypted.
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
