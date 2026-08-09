using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    /// <summary>
    /// Fragt eine offene Weboberflaeche danach, wer sie ist: Seitentitel,
    /// Serverkennung und das TLS-Zertifikat.
    /// <para>
    /// <b>Der Unterschied zum Portscan:</b> der sagt "Port 443 ist offen". Hier
    /// steht danach "Drucker HP LaserJet, Zertifikat selbst ausgestellt,
    /// abgelaufen seit 2019". Erst damit laesst sich eine Liste von Adressen zu
    /// einer Liste von Geraeten machen.
    /// </para>
    /// <para>
    /// Die Namen im Feld <c>Subject Alternative Name</c> sind der zweite Gewinn:
    /// dort stehen haeufig weitere Hostnamen des Geraets, die im DNS gar nicht
    /// auftauchen. Sie gehen als Aliase ins Modell und damit in die Pruefung auf
    /// doppelt vergebene Namen.
    /// </para>
    /// </summary>
    public class ScanningMethod_WebIdentity
    {
        /// <summary>
        /// Die Ports, die gepruft werden, wenn das Geraet keine eigenen offenen
        /// Webports gemeldet hat. Bewusst kurz: das hier ist kein Portscan,
        /// sondern die Nachfrage an einer bekannten Tuer.
        /// </summary>
        public static readonly int[] DefaultPorts = [80, 443, 8080, 8443];

        /// <summary>Welche dieser Ports ueber TLS sprechen.</summary>
        private static readonly HashSet<int> TlsPorts = [443, 8443];

        public event Action<int, int, int, ScanStatus>? ProgressUpdated;
        public event Action<WebIdentityResult>? WebIdentityFound;

        private int current;
        private int responded;
        private int total;

        private CancellationTokenSource _cts = new();

        /// <summary>Wie lange auf eine Antwort gewartet wird.</summary>
        public int TimeoutMs { get; set; } = 3000;

        public void StopScan()
        {
            if (_cts != null && !_cts.IsCancellationRequested) _cts.Cancel();

            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.stopped);
        }

        private void StartNewScan()
        {
            if (_cts != null)
            {
                if (!_cts.IsCancellationRequested) _cts.Cancel();
                _cts.Dispose();
            }

            _cts = new CancellationTokenSource();

            current = 0;
            responded = 0;
            total = 0;
        }

        /// <summary>
        /// Prueft je Ziel dessen Webports. <paramref name="portsPerTarget"/>
        /// nennt die Ports, die am jeweiligen Ziel bereits als offen bekannt
        /// sind - fehlt ein Eintrag, werden <see cref="DefaultPorts"/> genommen.
        /// </summary>
        public async Task ScanAsync(
            IReadOnlyList<string> targets,
            IReadOnlyDictionary<string, List<int>>? portsPerTarget = null)
        {
            ArgumentNullException.ThrowIfNull(targets);

            StartNewScan();

            total = targets.Count;
            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running);

            // Zwanzig gleichzeitig: jede Probe haelt eine Verbindung ueber bis
            // zu drei Sekunden, und mehr davon bringt bei Webports nichts, weil
            // die allermeisten Ziele gar keinen offen haben.
            using SemaphoreSlim gate = new(20);

            IEnumerable<Task> work = targets.Select(async address =>
            {
                try
                {
                    await gate.WaitAsync(_cts.Token);
                }
                catch (OperationCanceledException)
                {
                    return;
                }

                try
                {
                    List<int> ports = portsPerTarget is not null &&
                                      portsPerTarget.TryGetValue(address, out List<int>? known) &&
                                      known.Count > 0
                        ? known
                        : [.. DefaultPorts];

                    WebIdentityResult? result = await ProbeAsync(address, ports);

                    int done = Interlocked.Increment(ref current);

                    if (result is not null)
                    {
                        int found = Interlocked.Increment(ref responded);
                        ProgressUpdated?.Invoke(done, found, total, ScanStatus.running);
                        WebIdentityFound?.Invoke(result);
                    }
                    else
                    {
                        ProgressUpdated?.Invoke(done, responded, total, ScanStatus.running);
                    }
                }
                finally
                {
                    gate.Release();
                }
            });

            try
            {
                await Task.WhenAll(work);
            }
            catch (OperationCanceledException)
            {
                // Abbruch ist kein Fehler.
            }
        }

        /// <summary>
        /// Probiert die Ports der Reihe nach und nimmt den ersten, der
        /// antwortet. TLS-Ports zuerst - dort gibt es zusaetzlich das
        /// Zertifikat, also mehr Auskunft fuer dieselbe Verbindung.
        /// </summary>
        private async Task<WebIdentityResult?> ProbeAsync(string address, List<int> ports)
        {
            foreach (int port in ports.OrderByDescending(p => TlsPorts.Contains(p)))
            {
                if (_cts.Token.IsCancellationRequested) return null;

                WebIdentityResult? result = TlsPorts.Contains(port)
                    ? await ProbeTlsAsync(address, port)
                    : await ProbePlainAsync(address, port);

                if (result is not null) return result;
            }

            return null;
        }

        private async Task<WebIdentityResult?> ProbeTlsAsync(string address, int port)
        {
            try
            {
                using TcpClient client = new();
                if (!await ConnectAsync(client, address, port)) return null;

                X509Certificate2? certificate = null;

                // Jedes Zertifikat annehmen: hier wird geprueft, was da steht,
                // nicht ob man ihm trauen kann. Ein selbst ausgestelltes oder
                // abgelaufenes Zertifikat abzulehnen hiesse, genau den Fall
                // wegzuwerfen, um den es geht.
                using SslStream tls = new(client.GetStream(), false, (_, cert, _, _) =>
                {
                    if (cert is not null) certificate = new X509Certificate2(cert);
                    return true;
                });

                using CancellationTokenSource timeout =
                    CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                timeout.CancelAfter(TimeoutMs);

                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = address
                }, timeout.Token);

                string? title = await ReadTitleAsync(tls, address, timeout.Token);

                return BuildResult(address, port, true, title, certificate);
            }
            catch (Exception)
            {
                return null;
            }
        }

        private async Task<WebIdentityResult?> ProbePlainAsync(string address, int port)
        {
            try
            {
                using TcpClient client = new();
                if (!await ConnectAsync(client, address, port)) return null;

                using CancellationTokenSource timeout =
                    CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                timeout.CancelAfter(TimeoutMs);

                string? title = await ReadTitleAsync(client.GetStream(), address, timeout.Token);

                return title is null ? null : BuildResult(address, port, false, title, null);
            }
            catch (Exception)
            {
                return null;
            }
        }

        private async Task<bool> ConnectAsync(TcpClient client, string address, int port)
        {
            Task connect = client.ConnectAsync(address, port, _cts.Token).AsTask();
            Task finished = await Task.WhenAny(connect, Task.Delay(TimeoutMs, _cts.Token));

            if (finished != connect || !client.Connected) return false;

            await connect;
            return true;
        }

        /// <summary>
        /// Holt die Startseite und liest Titel und Serverkennung heraus.
        /// <para>
        /// Bewusst von Hand gesprochenes HTTP statt <c>HttpClient</c>: das Ziel
        /// ist oft ein Geraet mit einem eigenwilligen Webserver, der auf einer
        /// Umleitung oder einem fehlenden Feld besteht. Ein roher Lesevorgang
        /// bekommt hier mehr zu sehen als eine Bibliothek, die auf
        /// Wohlgeformtheit besteht.
        /// </para>
        /// </summary>
        private async Task<string?> ReadTitleAsync(
            System.IO.Stream stream, string address, CancellationToken token)
        {
            byte[] request = Encoding.ASCII.GetBytes(
                $"GET / HTTP/1.1\r\nHost: {address}\r\nUser-Agent: MyNetworkMonitor\r\n" +
                "Accept: text/html\r\nConnection: close\r\n\r\n");

            await stream.WriteAsync(request, token);
            await stream.FlushAsync(token);

            using System.IO.MemoryStream buffer = new();
            byte[] chunk = new byte[4096];

            // 64 KB reichen fuer Kopfzeilen und Titel bei Weitem. Mehr zu lesen
            // hiesse, sich von einer Geraeteseite mit eingebettetem Bild die
            // Zeit stehlen zu lassen.
            while (buffer.Length < 65536)
            {
                int read = await stream.ReadAsync(chunk, token);
                if (read <= 0) break;

                buffer.Write(chunk, 0, read);

                // Sobald der Titel da ist, muss der Rest nicht mehr kommen.
                if (Encoding.UTF8.GetString(buffer.ToArray()).Contains("</title>", StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }
            }

            return Encoding.UTF8.GetString(buffer.ToArray());
        }

        private static WebIdentityResult BuildResult(
            string address, int port, bool tls, string? response, X509Certificate2? certificate)
        {
            string? title = ExtractTitle(response);
            string? server = ExtractHeader(response, "Server");

            return new WebIdentityResult
            {
                Address = address,
                Port = port,
                IsTls = tls,
                Title = title,
                Server = server,
                CertificateSubject = certificate is null ? null : Clean(certificate.Subject),
                CertificateIssuer = certificate is null ? null : Clean(certificate.Issuer),
                CertificateExpires = certificate?.NotAfter,

                // Selbst ausgestellt heisst: Aussteller und Inhaber sind
                // dieselbe Stelle. Das ist bei Geraeten die Regel, nicht die
                // Ausnahme - gemeldet wird es trotzdem, weil es zusammen mit
                // einem abgelaufenen Datum den Unterschied macht.
                IsSelfSigned = certificate is not null &&
                               string.Equals(certificate.Subject, certificate.Issuer, StringComparison.OrdinalIgnoreCase),
                AlternativeNames = ExtractAlternativeNames(certificate)
            };
        }

        private static string? ExtractTitle(string? response)
        {
            if (string.IsNullOrEmpty(response)) return null;

            Match match = Regex.Match(response, @"<title[^>]*>(.*?)</title>",
                RegexOptions.IgnoreCase | RegexOptions.Singleline);

            if (!match.Success) return null;

            string title = System.Net.WebUtility.HtmlDecode(match.Groups[1].Value).Trim();

            // Zeilenumbrueche im Titel kommen vor und wuerden die Detailansicht
            // auseinanderreissen.
            title = Regex.Replace(title, @"\s+", " ");

            return title.Length == 0 ? null : title;
        }

        private static string? ExtractHeader(string? response, string name)
        {
            if (string.IsNullOrEmpty(response)) return null;

            Match match = Regex.Match(response, $@"^{Regex.Escape(name)}:\s*(.+)$",
                RegexOptions.IgnoreCase | RegexOptions.Multiline);

            return match.Success ? match.Groups[1].Value.Trim() : null;
        }

        /// <summary>
        /// Die Namen aus dem Feld <c>Subject Alternative Name</c>. Dort stehen
        /// oft Hostnamen, die im DNS fehlen - fuer die Pruefung auf doppelt
        /// vergebene Namen sind sie genauso viel wert wie ein PTR-Eintrag.
        /// </summary>
        private static List<string> ExtractAlternativeNames(X509Certificate2? certificate)
        {
            List<string> names = [];
            if (certificate is null) return names;

            foreach (X509Extension extension in certificate.Extensions)
            {
                if (extension.Oid?.Value != "2.5.29.17") continue;

                foreach (string line in extension.Format(true)
                             .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    // Die Formatierung sieht so aus: "DNS Name=drucker.firma.de".
                    int separator = line.IndexOf('=');
                    if (separator < 0 || separator == line.Length - 1) continue;

                    string value = line[(separator + 1)..].Trim();
                    if (value.Length > 0 && !names.Contains(value, StringComparer.OrdinalIgnoreCase)) names.Add(value);
                }
            }

            return names;
        }

        /// <summary>
        /// Kuerzt einen Zertifikatsnamen auf das <c>CN=</c>-Feld. Der ganze
        /// Distinguished Name ist eine Zeile, die kein Detailpanel fasst.
        /// </summary>
        private static string Clean(string distinguishedName)
        {
            Match match = Regex.Match(distinguishedName, @"CN\s*=\s*([^,]+)", RegexOptions.IgnoreCase);
            return match.Success ? match.Groups[1].Value.Trim() : distinguishedName.Trim();
        }
    }

    /// <summary>Was hinter einem offenen Webport gefunden wurde.</summary>
    public sealed class WebIdentityResult
    {
        public required string Address { get; init; }
        public int Port { get; init; }
        public bool IsTls { get; init; }

        /// <summary>Der Seitentitel - meist der aussagekraeftigste Fund.</summary>
        public string? Title { get; init; }

        /// <summary>Die Serverkennung aus der Kopfzeile.</summary>
        public string? Server { get; init; }

        public string? CertificateSubject { get; init; }
        public string? CertificateIssuer { get; init; }
        public DateTime? CertificateExpires { get; init; }
        public bool IsSelfSigned { get; init; }

        /// <summary>Weitere Namen aus dem Zertifikat.</summary>
        public List<string> AlternativeNames { get; init; } = [];

        /// <summary>Die Zeilen fuer die Detailansicht.</summary>
        public string ToInfoText()
        {
            List<string> lines = [$"Reached on port {Port}{(IsTls ? " over TLS" : string.Empty)}"];

            if (!string.IsNullOrWhiteSpace(Title)) lines.Add($"Title: {Title}");
            if (!string.IsNullOrWhiteSpace(Server)) lines.Add($"Server: {Server}");
            if (!string.IsNullOrWhiteSpace(CertificateSubject)) lines.Add($"Certificate for: {CertificateSubject}");
            if (!string.IsNullOrWhiteSpace(CertificateIssuer)) lines.Add($"Issued by: {CertificateIssuer}");

            if (CertificateExpires is { } expires)
            {
                string state = expires < DateTime.Now ? " - EXPIRED" : string.Empty;
                lines.Add($"Valid until: {expires:yyyy-MM-dd}{state}");
            }

            if (IsSelfSigned) lines.Add("Self-signed certificate");
            if (AlternativeNames.Count > 0) lines.Add($"Also named: {string.Join(", ", AlternativeNames)}");

            return string.Join(Environment.NewLine, lines);
        }
    }
}
