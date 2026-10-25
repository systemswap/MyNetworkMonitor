// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net.Sockets;
using System.Text;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// The common case: connect, send the hello packet if there is one, read
    /// the answer and check it. Most services need nothing else.
    /// <para>
    /// The order of states is what the result list evaluates:
    /// <c>Filtered</c> on timeout, <c>Closed</c> when the connection is
    /// refused, <c>Open</c> as soon as the connection is established, and
    /// <c>IsRunning</c> only when the answer matches the protocol. An open
    /// port without a matching answer stays <c>Open</c> and is not labelled
    /// with the name of this service. See docs/FEHLERGEDAECHTNIS.md, No. 2.
    /// </para>
    /// </summary>
    public abstract class ServiceProbeBase : IServiceProbe
    {
        /// <inheritdoc/>
        public abstract ServiceType Service { get; }

        /// <inheritdoc/>
        public abstract string Group { get; }

        /// <inheritdoc/>
        public abstract IReadOnlyList<int> DefaultPorts { get; }

        /// <summary>
        /// <see cref="Hello"/> and <see cref="Identify"/> are deliberately
        /// abstract: a service without a hello packet and an answer check
        /// cannot be detected. A new probe fails at compile time rather than
        /// by finding nothing in the network.
        /// </summary>
        public abstract byte[] Hello { get; }

        /// <inheritdoc cref="Hello"/>
        public abstract bool Identify(byte[] response);

        /// <summary>The common case has nothing to prepare.</summary>
        public virtual Task PrepareAsync(ProbeContext context, IReadOnlyList<string> targets, CancellationToken token) =>
            Task.CompletedTask;

        /// <summary>
        /// The log text written when a probe has nothing more to say about the
        /// device. Public because the details view must recognise it: it
        /// confirms a successful detection but carries no information and
        /// does not belong under "MORE DETAILS".
        /// </summary>
        public const string ProtocolMatched = "The answer matches the expected protocol.";

        /// <summary>
        /// The same text as stored by earlier versions in saved results
        /// (<c>lastScanResult.json</c>), which the details view must still
        /// recognise.
        /// </summary>
        public const string ProtocolMatchedGerman = "Antwort passt zum erwarteten Protokoll.";

        /// <summary>
        /// What the first answer reveals about the device: version, software,
        /// security posture. <c>null</c> if it reveals nothing.
        /// <para>
        /// The buffer is read anyway, also for services without a hello packet,
        /// while <see cref="Identify"/> only answers yes or no. An SSH server
        /// names its software and version in the same line by which it is
        /// detected; that is the difference between "SSH is running" and
        /// "OpenSSH 8.9p1 on Ubuntu".
        /// </para>
        /// <para>
        /// Explicitly <b>no</b> second connection and no login attempt: only
        /// what the remote side sent on its own is evaluated. The detection
        /// packets are not affected.
        /// </para>
        /// </summary>
        protected virtual string? Describe(byte[] response) => null;

        /// <summary>
        /// The follow-up request on the <em>already established</em> connection,
        /// after the service has been detected. For protocols whose information
        /// is not in the greeting but needs a second exchange: FTP names its
        /// operating system only on <c>SYST</c>, VNC its security types only
        /// after the version exchange.
        /// <para>
        /// It stays with the one connection that already exists and with
        /// requests every client sends before logging in. The result is
        /// appended to the result of <see cref="Describe"/>.
        /// </para>
        /// <para>
        /// Errors here are not errors of the run: if the follow-up fails, the
        /// finding from the first answer stands.
        /// </para>
        /// </summary>
        protected virtual Task<string?> InterrogateAsync(
            NetworkStream stream, byte[] firstResponse, ProbeContext context, CancellationToken token) =>
            Task.FromResult<string?>(null);

        /// <inheritdoc/>
        public virtual async Task<PortResult> ProbeAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            var portResult = new PortResult { Ports = new List<int> { port } };
            var logBuilder = new StringBuilder();

            byte[] detectionPacket = Hello;

            for (int attempt = 1; attempt <= context.RetryCount; attempt++)
            {
                token.ThrowIfCancellationRequested();

                using var client = new TcpClient();

                try
                {
                    Task connectTask = client.ConnectAsync(address, port);

                    if (await Task.WhenAny(connectTask, Task.Delay(context.TimeoutMs)) != connectTask)
                    {
                        portResult.Status = PortStatus.Filtered;
                        logBuilder.AppendLine("Timeout: the port may be blocked by a firewall.");
                        portResult.PortLog = logBuilder.ToString();
                        return portResult;
                    }

                    await connectTask; // rethrows the actual connection exception, if any

                    portResult.Status = PortStatus.Open;

                    // One stream for writing and reading. TcpClient.GetStream() returns
                    // the same underlying connection on every call, but disposing it in
                    // between (for example to scope only the write) also closes the
                    // socket; the second call then fails with "operation not allowed on
                    // non-connected sockets" instead of reading.
                    NetworkStream stream = client.GetStream();

                    if (detectionPacket.Length > 0)
                    {
                        await stream.WriteAsync(detectionPacket, 0, detectionPacket.Length, token);
                    }

                    // Always read, even without a payload: greeting protocols such as
                    // FTP, MySQL and MariaDB send their identification unprompted.
                    var buffer = new byte[4096];

                    using var readCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                    readCts.CancelAfter(context.TimeoutMs);

                    try
                    {
                        int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, readCts.Token);

                        if (bytesRead > 0)
                        {
                            byte[] response = buffer[..bytesRead];

                            if (Identify(response))
                            {
                                portResult.Status = PortStatus.IsRunning;

                                // First evaluate what the answer itself reveals,
                                // then, only where a probe needs it, ask on
                                // the same connection.
                                string? description = Describe(response);

                                try
                                {
                                    // A separate time budget instead of the rest of
                                    // readCts: that clock started before the first
                                    // answer, and a server that was slow with its
                                    // greeting would have no time left for the
                                    // follow-up.
                                    using CancellationTokenSource askCts =
                                        CancellationTokenSource.CreateLinkedTokenSource(token);
                                    askCts.CancelAfter(context.TimeoutMs);

                                    string? more = await InterrogateAsync(stream, response, context, askCts.Token);

                                    if (!string.IsNullOrWhiteSpace(more))
                                    {
                                        description = string.IsNullOrWhiteSpace(description)
                                            ? more
                                            : description + Environment.NewLine + more;
                                    }
                                }
                                catch (Exception) when (!token.IsCancellationRequested)
                                {
                                    // Timeout, rejected request, closed connection:
                                    // the service is detected, only the additional
                                    // information is missing. No reason to discard
                                    // the result of the port.
                                }

                                logBuilder.AppendLine(
                                    string.IsNullOrWhiteSpace(description) ? ProtocolMatched : description);
                            }
                            else
                            {
                                logBuilder.AppendLine("Port open and an answer came, but it does not match the expected protocol - probably another service on this port.");
                            }
                        }
                        else
                        {
                            logBuilder.AppendLine("Port open, but no answer from an application.");
                        }
                    }
                    catch (OperationCanceledException) when (!token.IsCancellationRequested)
                    {
                        // Only the answer timeout has expired. Cancellation of
                        // the whole run, in contrast, is passed up and not
                        // logged as "took too long".
                        logBuilder.AppendLine("The server took too long to answer.");
                    }

                    portResult.PortLog = logBuilder.ToString();
                    return portResult;
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.ConnectionRefused)
                    {
                        portResult.Status = PortStatus.Closed;
                        logBuilder.AppendLine("Connection refused: no service listens on this port.");
                        portResult.PortLog = logBuilder.ToString();
                        return portResult;
                    }

                    if (attempt == context.RetryCount)
                    {
                        portResult.Status = PortStatus.NoResponse;
                        logBuilder.AppendLine($"Failed after {context.RetryCount} attempts: {ex.Message}");
                    }
                }
                catch (IOException ex)
                {
                    // The remote side closed the connection while reading
                    // ("connection reset by peer"). That is a result of this
                    // one port and not an error of the run: the connection was
                    // established, so the port stays "open", just without a
                    // usable answer.
                    //
                    // Uncaught, the exception would propagate up to the run and
                    // end the whole service scan; every service after the
                    // affected one would never be checked.
                    logBuilder.AppendLine($"The connection was closed by the remote side: {ex.Message}");

                    portResult.PortLog = logBuilder.ToString();
                    return portResult;
                }
            }

            portResult.PortLog = logBuilder.ToString();
            return portResult;
        }

        /// <summary>
        /// Reads a Protocol Buffers varint from <paramref name="offset"/> to the
        /// end of <paramref name="data"/>.
        /// <para>
        /// Strict: the number must end exactly at the end of the data. A
        /// truncated or overlong field is not a match; otherwise arbitrary
        /// noise would pass as a valid number.
        /// </para>
        /// </summary>
        protected static bool TryReadVarint(byte[] data, int offset, out int value)
        {
            value = 0;
            int shift = 0;

            for (int i = offset; i < data.Length; i++)
            {
                if (shift > 28) return false;

                value |= (data[i] & 0x7F) << shift;
                shift += 7;

                // Last byte of the number: the continuation bit is clear.
                if ((data[i] & 0x80) == 0) return i == data.Length - 1;
            }

            return false;
        }

        /// <summary>
        /// Reads the version text from the greeting of a MySQL-family server.
        /// <c>null</c> if the answer is not such a greeting.
        /// <para>
        /// Packet layout (Protocol::HandshakeV10, identical for MySQL and
        /// MariaDB): 3 bytes payload length (little-endian), 1 byte sequence
        /// number (always 0 for the greeting), then the payload: 1 byte protocol
        /// version (10), the version text with terminating zero, 4 bytes
        /// connection ID, 8 bytes of the authentication nonce, 1 filler byte 0.
        /// </para>
        /// <para>
        /// The structure is checked, not the content: lengths are not
        /// constants. Fixed are only the sequence number, the protocol version,
        /// the filler byte at the position given by the text length, and a
        /// printable, zero-terminated text. A different service on the same port
        /// does not meet all of these by chance.
        /// </para>
        /// </summary>
        protected static string? ReadMySqlServerVersion(byte[] response)
        {
            // No server reports a longer version; the limit rejects a buffer
            // that happens to contain no zero for a long stretch.
            const int MaxVersionLength = 64;

            if (response.Length < 5) return null;
            if (response[3] != 0x00) return null;   // sequence number of the greeting
            if (response[4] != 0x0A) return null;   // protocol version 10

            int payloadLength = response[0] | response[1] << 8 | response[2] << 16;

            // A greeting cannot be shorter than its mandatory fields: protocol
            // version, one version character plus zero, connection ID, nonce,
            // filler byte.
            if (payloadLength < 1 + 2 + 4 + 8 + 1) return null;

            int end = Array.IndexOf(response, (byte)0x00, 5);
            if (end < 0 || end == 5 || end - 5 > MaxVersionLength) return null;

            for (int i = 5; i < end; i++)
            {
                if (response[i] < 0x20 || response[i] > 0x7E) return null;
            }

            // The filler byte after connection ID and nonce. If it is not yet in
            // the bytes read, the rest of the payload is still in transit; the
            // structure checked so far is then accepted.
            int filler = end + 1 + 4 + 8;
            if (filler < response.Length && response[filler] != 0x00) return null;

            return Encoding.ASCII.GetString(response, 5, end - 5);
        }

        /// <summary>
        /// The information of a MySQL-family server as shown in the details
        /// view. Shared by both probes, because both see the same greeting and
        /// differ only in which of them accepts it.
        /// <para>
        /// MariaDB 10.0 and later prefixes the real version with the fake
        /// "5.5.5-". The real version is shown; the prefix is a workaround for
        /// old clients and says nothing about the server.
        /// </para>
        /// </summary>
        protected static string? MySqlDetails(byte[] response)
        {
            string? version = ReadMySqlServerVersion(response);

            if (version is null)
            {
                // No handshake, but possibly the error packet with which a
                // server rejects the connection. It states the reason in plain
                // text, which is information in itself ("Host ... is not
                // allowed to connect").
                if (response.Length < 7 || response[3] != 0x00 || response[4] != 0xFF) return null;

                // Layout of the ERR packet after 0xFF: two bytes error code, with
                // protocol 4.1 a '#' and a five-character SQL state, and only then
                // the text. Without skipping the code, its low byte would appear
                // as a character in front of the message.
                int at = 5;

                int code = response[at] | response[at + 1] << 8;
                at += 2;

                if (at < response.Length && response[at] == (byte)'#') at += 6;
                if (at >= response.Length) return null;

                string message = Printable(Encoding.ASCII.GetString(response, at, response.Length - at));

                // The code is part of the information: 1130 means "host not
                // allowed", 1045 "access denied", two very different situations.
                return message.Length > 0 ? $"Rejected ({code}): {message}" : null;
            }

            string real = version.StartsWith("5.5.5-", StringComparison.Ordinal) ? version[6..] : version;

            return real.Length > 0 ? $"Version: {real}" : null;
        }

        /// <summary>
        /// Sends a text line and reads the answer, the exchange of every
        /// line-based protocol (FTP, SMTP, POP3). Empty text if nothing comes
        /// back.
        /// </summary>
        protected static async Task<string> AskLineAsync(
            NetworkStream stream, string command, CancellationToken token)
        {
            byte[] request = Encoding.ASCII.GetBytes(command + "\r\n");
            await stream.WriteAsync(request, token);

            return await ReadTextAsync(stream, token);
        }

        /// <summary>
        /// Reads what is currently available and returns it as text. Empty text
        /// on timeout or error.
        /// </summary>
        protected static async Task<string> ReadTextAsync(NetworkStream stream, CancellationToken token)
        {
            byte[] buffer = new byte[4096];

            try
            {
                int read = await stream.ReadAsync(buffer, token);
                return read > 0 ? Encoding.ASCII.GetString(buffer, 0, read) : string.Empty;
            }
            catch (Exception)
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// The first line of a text, without line ending and control characters.
        /// A server greeting is text for humans, but nothing prevents a server
        /// from sending bytes that do not belong in a user interface.
        /// </summary>
        protected static string FirstLine(string text)
        {
            if (string.IsNullOrEmpty(text)) return string.Empty;

            int end = text.IndexOfAny(['\r', '\n']);
            string line = end >= 0 ? text[..end] : text;

            return Printable(line);
        }

        /// <summary>
        /// Only printable characters, limited to one line length. Protects
        /// against raw bytes and against a server that answers a harmless
        /// request with kilobytes.
        /// </summary>
        protected static string Printable(string text, int maxLength = 200)
        {
            if (string.IsNullOrEmpty(text)) return string.Empty;

            StringBuilder clean = new(Math.Min(text.Length, maxLength));

            foreach (char c in text)
            {
                if (clean.Length >= maxLength) break;
                if (c is >= ' ' and <= '~') clean.Append(c);
            }

            return clean.ToString().Trim();
        }

        public override string ToString() => $"{Service} [{string.Join(", ", DefaultPorts)}]";
    }
}
