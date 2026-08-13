using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Weboberflaechen. Einer der sechs Dienste mit eigenem Ablauf: hier
    /// werden keine rohen Bytes verglichen, sondern eine HTTP-Anfrage
    /// gestellt und die Statuszeile ausgewertet - und schlaegt das fehl,
    /// dieselbe Anfrage ueber TLS.
    /// <para>
    /// Der Grund fuer den Sonderweg: ein Webserver antwortet nicht von sich
    /// aus und auch nicht auf beliebige Bytes. Ohne gueltige Anfrage bleibt
    /// die Leitung stumm, und der Port gaelte als offen ohne Dienst.
    /// </para>
    /// </summary>
    public sealed class WebServicesProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.WebServices;
        public override string Group => ServiceGroups.Network;

        public override IReadOnlyList<int> DefaultPorts =>
            [80, 443, 1880, 3000, 5000, 5001, 8080, 8086, 8443];

        /// <summary>
        /// Kein festes Paket: die Anfrage baut der eigene Ablauf, weil sie den
        /// Zielnamen im Host-Kopf traegt und damit je Ziel anders aussieht.
        /// </summary>
        public override byte[] Hello => [];

        /// <summary>
        /// Erst unverschluesselt fragen, dann ueber TLS - und aus beiden
        /// Befunden den staerkeren nehmen. Die Zeitlimits stecken in den beiden
        /// Abfragen fest; darum bleibt <paramref name="context"/> ungenutzt.
        /// </summary>
        public override async Task<PortResult> ProbeAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();

            PortResult portResult = new PortResult { Ports = new List<int> { port }, Status = PortStatus.NoResponse };

            // HTTP fragen und den Befund festhalten, bevor HTTPS ihn ueberschreibt
            bool httpSuccess = await CheckHttpAsync(address, port, portResult);
            PortStatus httpStatus = portResult.Status;

            bool httpsSuccess = await CheckHttpsAsync(address, port, portResult);
            PortStatus httpsStatus = portResult.Status;

            // Rangfolge der beiden Befunde: laeuft schlaegt Fehler schlaegt
            // offen schlaegt gefiltert
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
        /// Unverschluesselte Anfrage. Als Webserver gilt, wer eine Statuszeile
        /// mit 2xx bis 5xx schickt oder HTML im Rumpf hat - auch ein 404 ist
        /// eine Antwort und damit ein Dienst.
        /// </summary>
        private static async Task<bool> CheckHttpAsync(string ipAddress, int port, PortResult portResult)
        {
            using (var tcpClient = new TcpClient())
            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2))) // 2s Timeout
            {
                try
                {
                    Task connectTask = tcpClient.ConnectAsync(ipAddress, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(2000, cts.Token)) != connectTask)
                    {
                        portResult.Status = PortStatus.NoResponse; // Timeout erreicht
                        return false;
                    }

                    if (!tcpClient.Connected)
                    {
                        portResult.Status = PortStatus.Filtered; // Verbindung verweigert
                        return false;
                    }

                    using (NetworkStream stream = tcpClient.GetStream())
                    using (var writer = new StreamWriter(stream, Encoding.ASCII, leaveOpen: true))
                    using (var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true))
                    {
                        writer.NewLine = "\r\n"; // HTTP erfordert CRLF
                        writer.AutoFlush = true;

                        await writer.WriteLineAsync($"GET / HTTP/1.1");
                        await writer.WriteLineAsync($"Host: {ipAddress}");
                        await writer.WriteLineAsync("Connection: close");
                        await writer.WriteLineAsync("User-Agent: Mozilla/5.0 (compatible; MyScanner/1.0)");
                        await writer.WriteLineAsync("Accept: */*"); // Erlaubt alle Antworten
                        await writer.WriteLineAsync("Accept-Encoding: identity"); // Verhindert GZIP-Probleme
                        await writer.WriteLineAsync(""); // Leere Zeile fuer HTTP-Protokollkonformitaet

                        Task<string> readTask = reader.ReadToEndAsync();
                        if (await Task.WhenAny(readTask, Task.Delay(2000, cts.Token)) != readTask)
                        {
                            portResult.Status = PortStatus.NoResponse; // Antwort zu lange gebraucht
                            return false;
                        }

                        string response = await readTask;

                        // [2345] erfasst alle wichtigen HTTP-Statuscodes:
                        // 2xx Erfolg, 3xx Weiterleitung, 4xx Client-Fehler
                        // (Geraet antwortet trotzdem), 5xx Server-Fehler
                        if (Regex.IsMatch(response, @"^HTTP/\d\.\d [2345]\d{2}") || response.ToLower().Contains("<html"))
                        {
                            portResult.Status = PortStatus.IsRunning; // Webseite erkannt
                            return true;
                        }

                        portResult.Status = PortStatus.Open; // Verbindung offen, aber kein Webserver erkannt
                        return false;
                    }
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.ConnectionRefused)
                    {
                        portResult.Status = PortStatus.Filtered; // Firewall oder kein Dienst aktiv
                    }
                    else
                    {
                        portResult.Status = PortStatus.Error; // Netzwerkfehler
                    }
                }
                catch (IOException)
                {
                    portResult.Status = PortStatus.Error; // Verbindung wurde unerwartet geschlossen
                }
                catch (OperationCanceledException)
                {
                    portResult.Status = PortStatus.NoResponse; // Timeout erreicht
                }
            }

            return false;
        }

        /// <summary>
        /// Dieselbe Anfrage ueber TLS. Zertifikatsfehler werden bewusst
        /// hingenommen - gefragt ist, ob dort ein Webserver steht, nicht ob er
        /// ein gueltiges Zertifikat traegt.
        /// </summary>
        private static async Task<bool> CheckHttpsAsync(string ipAddress, int port, PortResult portResult)
        {
            using (var tcpClient = new TcpClient())
            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(1))) // Timeout von 1 Sekunde fuer Verbindung
            {
                try
                {
                    Task connectTask = tcpClient.ConnectAsync(ipAddress, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(1000, cts.Token)) != connectTask)
                    {
                        portResult.Status = PortStatus.NoResponse; // Keine Antwort vom Port
                        return false;
                    }

                    if (!tcpClient.Connected)
                    {
                        portResult.Status = PortStatus.Filtered; // Verbindung verweigert, Firewall
                        return false;
                    }

                    using (SslStream sslStream = new SslStream(tcpClient.GetStream(), false, (sender, cert, chain, sslPolicyErrors) => true))
                    using (var sslCts = new CancellationTokenSource(TimeSpan.FromSeconds(2))) // Timeout fuer SSL-Handshake
                    {
                        var sslTask = sslStream.AuthenticateAsClientAsync(ipAddress);
                        if (await Task.WhenAny(sslTask, Task.Delay(2000, sslCts.Token)) != sslTask)
                        {
                            portResult.Status = PortStatus.NoResponse; // SSL-Timeout, Server antwortet nicht
                            return false;
                        }

                        // Erst pruefen, ob der Handshake wirklich stand
                        if (!sslStream.IsAuthenticated)
                        {
                            portResult.Status = PortStatus.Error; // SSL-Fehler
                            return false;
                        }

                        // Nur jetzt darf die Anfrage gesendet werden
                        byte[] requestBytes = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: " + ipAddress + "\r\nConnection: close\r\n\r\n");
                        await sslStream.WriteAsync(requestBytes, 0, requestBytes.Length, sslCts.Token);

                        byte[] buffer = new byte[4096];
                        var readTask = sslStream.ReadAsync(buffer, 0, buffer.Length, sslCts.Token);
                        if (await Task.WhenAny(readTask, Task.Delay(2000, sslCts.Token)) != readTask)
                        {
                            portResult.Status = PortStatus.NoResponse; // Antwort nicht erhalten
                            return false;
                        }

                        int bytesRead = await readTask;
                        if (bytesRead > 0)
                        {
                            string response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                            // Dieselbe Regel wie unverschluesselt: 2xx bis 5xx
                            // oder HTML im Rumpf
                            if (Regex.IsMatch(response, @"^HTTP/\d\.\d [2345]\d{2}") || response.ToLower().Contains("<html"))
                            {
                                portResult.Status = PortStatus.IsRunning; // Webseite erkannt
                                return true;
                            }

                            portResult.Status = PortStatus.Open; // Port ist offen, aber keine Webseite
                            return false;
                        }
                    }
                }
                catch (InvalidOperationException)
                {
                    portResult.Status = PortStatus.Error; // SSL-Verbindung kam nicht zustande
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
                {
                    portResult.Status = PortStatus.Filtered; // Verbindung verweigert
                }
                catch (Exception)
                {
                    portResult.Status = PortStatus.Error; // Sonstiger Fehler
                }
            }

            return false;
        }

        /// <summary>
        /// Dieser Dienst hat keine eigene Antwortsignatur - er wird ueber
        /// seinen eigenen Ablauf erkannt, nicht ueber ein Bytemuster. Es bleibt
        /// bei der alten Regel fuer solche Faelle: eine Antwort zaehlt.
        /// </summary>
        public override bool Identify(byte[] response) => response.Length > 0;
    }
}
