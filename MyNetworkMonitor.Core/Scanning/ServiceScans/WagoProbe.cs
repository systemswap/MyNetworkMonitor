using System.Net.Sockets;
using System.Text;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// WAGO controllers via their service port 6626 (WBC, the protocol of the
    /// vendor's upload tool). A single command reads the device
    /// identification, and the answer carries everything in plain text: order
    /// number, description, serial number, hardware revision and the actual
    /// firmware.
    /// <para>
    /// Unlike OPC UA, which only knows the CODESYS runtime, and unlike BACnet
    /// or SNMP, which must first be enabled on the device, this port is open
    /// whenever the controller is running. Read-only.
    /// </para>
    /// <para>
    /// The protocol is derived from a capture of the vendor's upload tool;
    /// the tool's own code is in a proprietary native library. Request and
    /// answer are verified against two product series.
    /// </para>
    /// </summary>
    public sealed class WagoProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.Wago;
        public override string Group => ServiceGroups.Industrial;
        public override IReadOnlyList<int> DefaultPorts => [6626];

        /// <summary>
        /// The command 0x0108 ("read device identification") in the WBC frame.
        /// <para>
        /// Layout: the identifier <c>88 12</c>, a transaction number that the
        /// remote side only echoes, four fixed bytes, eight zero bytes, the
        /// length of the command part (2) and the command itself.
        /// </para>
        /// </summary>
        public override byte[] Hello => new byte[]
            {
                0x88, 0x12,             // WBC identifier
                0x01, 0x00,             // transaction number (echoed)
                0x01, 0x00, 0x01, 0x00, // fixed header
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x02, 0x00,             // length of the command part
                0x08, 0x01              // command 0x0108
            };

        /// <summary>
        /// An answer is WAGO if it carries the WBC identifier and contains the
        /// plain-text identification. A different service on the same port
        /// does not produce both by chance.
        /// </summary>
        public override bool Identify(byte[] response)
        {
            if (response.Length < 4 || response[0] != 0x88 || response[1] != 0x12) return false;

            return IndexOfAscii(response, "ORDER=") >= 0;
        }

        /// <summary>
        /// Connects, sends the command, reads the identification and splits it
        /// into lines for the details view. Own procedure, because the result
        /// goes beyond yes/no and carries the fields.
        /// </summary>
        public override async Task<PortResult> ProbeAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            var portResult = new PortResult { Ports = new List<int> { port } };
            var log = new StringBuilder();

            for (int attempt = 1; attempt <= context.RetryCount; attempt++)
            {
                token.ThrowIfCancellationRequested();

                using var client = new TcpClient();

                try
                {
                    Task connect = client.ConnectAsync(address, port, token).AsTask();

                    if (await Task.WhenAny(connect, Task.Delay(context.TimeoutMs, token)) != connect)
                    {
                        portResult.Status = PortStatus.Filtered;
                        log.AppendLine("Timeout: Port möglicherweise durch Firewall blockiert.");
                        portResult.PortLog = log.ToString();
                        return portResult;
                    }

                    await connect;   // rethrows the connection exception, if any
                    portResult.Status = PortStatus.Open;

                    NetworkStream stream = client.GetStream();
                    await stream.WriteAsync(Hello, token);

                    byte[]? response = await ReadResponseAsync(stream, context.TimeoutMs, token);

                    if (response is null || response.Length == 0)
                    {
                        log.AppendLine("Port ist offen, aber keine Antwort von einer Anwendung.");
                        portResult.PortLog = log.ToString();
                        return portResult;
                    }

                    if (Identify(response))
                    {
                        portResult.Status = PortStatus.IsRunning;
                        portResult.PortLog = FormatIdentification(response);
                    }
                    else
                    {
                        log.AppendLine("Port offen, Antwort kam, passt aber nicht zum erwarteten Protokoll - vermutlich ein anderer Dienst auf demselben Port.");
                        portResult.PortLog = log.ToString();
                    }

                    return portResult;
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.ConnectionRefused)
                    {
                        portResult.Status = PortStatus.Closed;
                        log.AppendLine("Verbindung verweigert: Kein Dienst lauscht auf diesem Port.");
                        portResult.PortLog = log.ToString();
                        return portResult;
                    }

                    if (attempt == context.RetryCount)
                    {
                        portResult.Status = PortStatus.NoResponse;
                        log.AppendLine($"Fehler nach {context.RetryCount} Versuchen: {ex.Message}");
                    }
                }
                catch (IOException ex)
                {
                    // The remote side closed the connection while reading: a
                    // result of this port, not an error of the run. The
                    // connection was established, so the port stays "open".
                    log.AppendLine($"Verbindung wurde von der Gegenseite geschlossen: {ex.Message}");
                    portResult.PortLog = log.ToString();
                    return portResult;
                }
            }

            portResult.PortLog = log.ToString();
            return portResult;
        }

        /// <summary>
        /// Reads until the plain-text identification is complete. It ends with
        /// the last semicolon; once that is in the buffer, nothing more follows.
        /// </summary>
        private static async Task<byte[]?> ReadResponseAsync(
            NetworkStream stream, int timeoutMs, CancellationToken token)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(timeoutMs);

            var collected = new List<byte>();
            var buffer = new byte[4096];

            try
            {
                while (collected.Count < 8192)
                {
                    int read = await stream.ReadAsync(buffer, timeout.Token);
                    if (read <= 0) break;

                    collected.AddRange(buffer[..read]);

                    // As soon as the identification including the final
                    // semicolon is there, the answer is complete.
                    byte[] soFar = [.. collected];
                    int order = IndexOfAscii(soFar, "ORDER=");
                    if (order >= 0 && Array.LastIndexOf(soFar, (byte)';') > order) break;

                    if (!stream.DataAvailable) break;
                }
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            {
                // Only the read timeout; what has arrived so far is evaluated.
            }

            return collected.Count > 0 ? [.. collected] : null;
        }

        /// <summary>
        /// Turns the semicolon list into the lines for the details view. The
        /// layout is <c>KEY=value;KEY=value;</c>, with the same keys the
        /// vendor's tool reads.
        /// </summary>
        private static string FormatIdentification(byte[] response)
        {
            int start = IndexOfAscii(response, "ORDER=");
            if (start < 0) return string.Empty;

            // From "ORDER=" to the first non-printable character.
            int end = start;
            while (end < response.Length && response[end] is >= 0x20 and <= 0x7E) end++;

            string text = Encoding.ASCII.GetString(response, start, end - start);

            Dictionary<string, string> fields = new(StringComparer.OrdinalIgnoreCase);
            foreach (string part in text.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                int eq = part.IndexOf('=');
                if (eq <= 0) continue;

                string key = part[..eq].Trim();
                string value = part[(eq + 1)..].Trim();
                if (value.Length > 0 && !fields.ContainsKey(key)) fields[key] = value;
            }

            // In a fixed order and with descriptive labels. "Firmware" is
            // deliberately named this way: the OPC UA follow-up uses it to see
            // that the firmware of this device is already known.
            (string Key, string Label)[] wanted =
            [
                ("ORDER", "Order number"),
                ("DESCR", "Description"),
                ("SW-VER", "Firmware"),
                ("HW-VER", "Hardware"),
                ("FWL-VER", "Firmware loader"),
                ("SN", "Serial")
            ];

            List<string> lines = [];
            foreach ((string key, string label) in wanted)
            {
                if (fields.TryGetValue(key, out string? value)) lines.Add($"{label}: {value}");
            }

            return lines.Count > 0 ? string.Join(Environment.NewLine, lines) : string.Empty;
        }

        /// <summary>The position where the ASCII string starts in the buffer, or -1.</summary>
        private static int IndexOfAscii(byte[] haystack, string needle)
        {
            byte[] pattern = Encoding.ASCII.GetBytes(needle);
            if (pattern.Length == 0 || haystack.Length < pattern.Length) return -1;

            for (int i = 0; i <= haystack.Length - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (haystack[i + j] != pattern[j]) { match = false; break; }
                }

                if (match) return i;
            }

            return -1;
        }
    }
}
