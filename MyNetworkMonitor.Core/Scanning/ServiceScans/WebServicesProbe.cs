using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Web interfaces. One of the services with their own procedure: instead
    /// of comparing raw bytes, it sends an HTTP request and evaluates the
    /// status line, and also sends the same request over TLS.
    /// <para>
    /// The reason for the special path: a web server does not speak first and
    /// does not answer arbitrary bytes. Without a valid request the line stays
    /// silent, and the port would count as open without a service.
    /// </para>
    /// </summary>
    public sealed class WebServicesProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.WebServices;
        public override string Group => ServiceGroups.Network;

        public override IReadOnlyList<int> DefaultPorts =>
            [80, 443, 1880, 3000, 5000, 5001, 8080, 8086, 8443];

        /// <summary>
        /// No fixed packet: the own procedure builds the request, because it
        /// carries the target in the Host header and differs per target.
        /// </summary>
        public override byte[] Hello => [];

        /// <summary>
        /// Asks unencrypted first, then over TLS, and takes the stronger of the
        /// two results. The timeouts are fixed in the two requests, so
        /// <paramref name="context"/> is not used.
        /// </summary>
        public override async Task<PortResult> ProbeAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();

            PortResult portResult = new PortResult { Ports = new List<int> { port }, Status = PortStatus.NoResponse };

            // Ask over HTTP and keep the result before HTTPS overwrites it
            bool httpSuccess = await CheckHttpAsync(address, port, portResult);
            PortStatus httpStatus = portResult.Status;

            bool httpsSuccess = await CheckHttpsAsync(address, port, portResult);
            PortStatus httpsStatus = portResult.Status;

            // Precedence of the two results: running beats error beats open
            // beats filtered
            if (httpSuccess || httpsSuccess)
            {
                portResult.Status = PortStatus.IsRunning;
            }
            else if (httpStatus == PortStatus.Error || httpsStatus == PortStatus.Error)
            {
                portResult.Status = PortStatus.Error;
            }
            else if (httpStatus == PortStatus.Open || httpsStatus == PortStatus.Open)
            {
                portResult.Status = PortStatus.Open;
            }
            else if (httpStatus == PortStatus.Filtered || httpsStatus == PortStatus.Filtered)
            {
                portResult.Status = PortStatus.Filtered;
            }
            else
            {
                portResult.Status = PortStatus.NoResponse;
            }

            return portResult;
        }

        /// <summary>
        /// Unencrypted request. A web server is whatever sends a status line
        /// with 2xx to 5xx or has HTML in the body; a 404 is also an answer and
        /// therefore a service.
        /// </summary>
        private static async Task<bool> CheckHttpAsync(string ipAddress, int port, PortResult portResult)
        {
            using (var tcpClient = new TcpClient())
            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2))) // 2-second timeout
            {
                try
                {
                    Task connectTask = tcpClient.ConnectAsync(ipAddress, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(2000, cts.Token)) != connectTask)
                    {
                        portResult.Status = PortStatus.NoResponse; // timeout
                        return false;
                    }

                    if (!tcpClient.Connected)
                    {
                        portResult.Status = PortStatus.Filtered; // connection refused
                        return false;
                    }

                    using (NetworkStream stream = tcpClient.GetStream())
                    using (var writer = new StreamWriter(stream, Encoding.ASCII, leaveOpen: true))
                    using (var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true))
                    {
                        writer.NewLine = "\r\n"; // HTTP requires CRLF
                        writer.AutoFlush = true;

                        await writer.WriteLineAsync($"GET / HTTP/1.1");
                        await writer.WriteLineAsync($"Host: {ipAddress}");
                        await writer.WriteLineAsync("Connection: close");
                        await writer.WriteLineAsync("User-Agent: Mozilla/5.0 (compatible; MyScanner/1.0)");
                        await writer.WriteLineAsync("Accept: */*"); // accept any content type
                        await writer.WriteLineAsync("Accept-Encoding: identity"); // no compressed answer
                        await writer.WriteLineAsync(""); // empty line ends the request header

                        Task<string> readTask = reader.ReadToEndAsync();
                        if (await Task.WhenAny(readTask, Task.Delay(2000, cts.Token)) != readTask)
                        {
                            portResult.Status = PortStatus.NoResponse; // answer took too long
                            return false;
                        }

                        string response = await readTask;

                        // [2345] covers all relevant HTTP status classes:
                        // 2xx success, 3xx redirection, 4xx client error
                        // (the device still answers), 5xx server error
                        if (Regex.IsMatch(response, @"^HTTP/\d\.\d [2345]\d{2}") || response.ToLower().Contains("<html"))
                        {
                            portResult.Status = PortStatus.IsRunning; // web page detected
                            return true;
                        }

                        portResult.Status = PortStatus.Open; // connection open, but no web server detected
                        return false;
                    }
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.ConnectionRefused)
                    {
                        portResult.Status = PortStatus.Filtered; // firewall or no service running
                    }
                    else
                    {
                        portResult.Status = PortStatus.Error; // network error
                    }
                }
                catch (IOException)
                {
                    portResult.Status = PortStatus.Error; // connection closed unexpectedly
                }
                catch (OperationCanceledException)
                {
                    portResult.Status = PortStatus.NoResponse; // timeout
                }
            }

            return false;
        }

        /// <summary>
        /// The same request over TLS. Certificate errors are deliberately
        /// accepted: the question is whether a web server is there, not
        /// whether it has a valid certificate.
        /// </summary>
        private static async Task<bool> CheckHttpsAsync(string ipAddress, int port, PortResult portResult)
        {
            using (var tcpClient = new TcpClient())
            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(1))) // 1-second connect timeout
            {
                try
                {
                    Task connectTask = tcpClient.ConnectAsync(ipAddress, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(1000, cts.Token)) != connectTask)
                    {
                        portResult.Status = PortStatus.NoResponse; // no answer from the port
                        return false;
                    }

                    if (!tcpClient.Connected)
                    {
                        portResult.Status = PortStatus.Filtered; // connection refused, firewall
                        return false;
                    }

                    using (SslStream sslStream = new SslStream(tcpClient.GetStream(), false, (sender, cert, chain, sslPolicyErrors) => true))
                    using (var sslCts = new CancellationTokenSource(TimeSpan.FromSeconds(2))) // TLS handshake timeout
                    {
                        var sslTask = sslStream.AuthenticateAsClientAsync(ipAddress);
                        if (await Task.WhenAny(sslTask, Task.Delay(2000, sslCts.Token)) != sslTask)
                        {
                            portResult.Status = PortStatus.NoResponse; // TLS timeout, server does not answer
                            return false;
                        }

                        // First check that the handshake really succeeded
                        if (!sslStream.IsAuthenticated)
                        {
                            portResult.Status = PortStatus.Error; // TLS error
                            return false;
                        }

                        // Only now may the request be sent
                        byte[] requestBytes = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: " + ipAddress + "\r\nConnection: close\r\n\r\n");
                        await sslStream.WriteAsync(requestBytes, 0, requestBytes.Length, sslCts.Token);

                        byte[] buffer = new byte[4096];
                        var readTask = sslStream.ReadAsync(buffer, 0, buffer.Length, sslCts.Token);
                        if (await Task.WhenAny(readTask, Task.Delay(2000, sslCts.Token)) != readTask)
                        {
                            portResult.Status = PortStatus.NoResponse; // no answer received
                            return false;
                        }

                        int bytesRead = await readTask;
                        if (bytesRead > 0)
                        {
                            string response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                            // Same rule as unencrypted: 2xx to 5xx
                            // or HTML in the body
                            if (Regex.IsMatch(response, @"^HTTP/\d\.\d [2345]\d{2}") || response.ToLower().Contains("<html"))
                            {
                                portResult.Status = PortStatus.IsRunning; // web page detected
                                return true;
                            }

                            portResult.Status = PortStatus.Open; // port is open, but no web page
                            return false;
                        }
                    }
                }
                catch (InvalidOperationException)
                {
                    portResult.Status = PortStatus.Error; // TLS connection failed
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
                {
                    portResult.Status = PortStatus.Filtered; // connection refused
                }
                catch (Exception)
                {
                    portResult.Status = PortStatus.Error; // other error
                }
            }

            return false;
        }

        /// <summary>
        /// This service has no answer signature of its own; it is detected by
        /// its own procedure, not by a byte pattern. For such cases any answer
        /// counts.
        /// </summary>
        public override bool Identify(byte[] response) => response.Length > 0;
    }
}
