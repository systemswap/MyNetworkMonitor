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
    /// Asks an open web interface what it is: page title, server header and the TLS certificate.
    /// <para>
    /// <b>The difference to the port scan:</b> the port scan says "port 443 is open". This scan
    /// adds, for example, "printer, self-signed certificate, expired years ago". Only that turns
    /// a list of addresses into a list of devices.
    /// </para>
    /// <para>
    /// The names in the <c>Subject Alternative Name</c> field are a second benefit: they often
    /// contain further host names of the device that do not appear in DNS. They go into the model
    /// as aliases and thus into the check for duplicate names.
    /// </para>
    /// </summary>
    public class ScanningMethod_WebIdentity
    {
        /// <summary>
        /// The ports checked when no open web ports are known for the device. Deliberately short:
        /// this is no port scan but a request at a known door.
        /// </summary>
        public static readonly int[] DefaultPorts = [80, 443, 8080, 8443];

        /// <summary>Which of these ports use TLS.</summary>
        private static readonly HashSet<int> TlsPorts = [443, 8443];

        /// <summary>Reports progress as (targets done, targets identified, total, status).</summary>
        public event Action<int, int, int, ScanStatus>? ProgressUpdated;

        /// <summary>Raised for every target whose web interface answered.</summary>
        public event Action<WebIdentityResult>? WebIdentityFound;

        private int current;
        private int responded;
        private int total;

        private CancellationTokenSource _cts = new();

        /// <summary>How long to wait for a connection and for an answer, in milliseconds.</summary>
        public int TimeoutMs { get; set; } = 3000;

        /// <summary>
        /// Cancels the running scan and reports <see cref="ScanStatus.stopped"/>.
        /// </summary>
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
        /// Checks the web ports of every target. <paramref name="portsPerTarget"/> lists the ports
        /// already known to be open on each target; without an entry, <see cref="DefaultPorts"/>
        /// are used.
        /// </summary>
        /// <param name="targets">The target addresses.</param>
        /// <param name="portsPerTarget">The known open web ports per address, or <see langword="null"/>.</param>
        /// <exception cref="ArgumentNullException"><paramref name="targets"/> is <see langword="null"/>.</exception>
        public async Task ScanAsync(
            IReadOnlyList<string> targets,
            IReadOnlyDictionary<string, List<int>>? portsPerTarget = null)
        {
            ArgumentNullException.ThrowIfNull(targets);

            StartNewScan();

            total = targets.Count;
            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running);

            // Twenty at a time: each probe holds a connection for up to three seconds, and more
            // gains nothing for web ports, because most targets have none open.
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
                // A cancellation is no error.
            }
        }

        /// <summary>
        /// Tries the ports one after the other and takes the first that answers. TLS ports come
        /// first: they also provide the certificate, so more information for the same connection.
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

                // Accept every certificate: the check is about what it says, not whether it can be
                // trusted. Rejecting a self-signed or expired certificate would discard exactly the
                // case of interest.
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
        /// Fetches the start page and returns the raw response, from which title and server
        /// header are read.
        /// <para>
        /// Deliberately hand-written HTTP instead of <c>HttpClient</c>: the target is often a
        /// device with an idiosyncratic web server that insists on a redirect or omits a field. A
        /// raw read sees more here than a library that insists on well-formed responses.
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

            // 64 KB is far more than enough for headers and title. Reading more would waste time
            // on a device page with an embedded image.
            while (buffer.Length < 65536)
            {
                int read = await stream.ReadAsync(chunk, token);
                if (read <= 0) break;

                buffer.Write(chunk, 0, read);

                // Once the title has arrived, the rest is not needed.
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

                // Self-signed means issuer and subject are the same. On devices that is the rule,
                // not the exception; it is still reported, because together with an expired date
                // it makes the difference.
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

            // Titles can contain line breaks, which would break up the detail view.
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
        /// The names from the <c>Subject Alternative Name</c> field (OID 2.5.29.17, RFC 5280,
        /// section 4.2.1.6). They often contain host names missing in DNS; for the check for
        /// duplicate names they are worth as much as a PTR record.
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
                    // The formatted line looks like "DNS Name=printer.example.com".
                    int separator = line.IndexOf('=');
                    if (separator < 0 || separator == line.Length - 1) continue;

                    string value = line[(separator + 1)..].Trim();
                    if (value.Length > 0 && !names.Contains(value, StringComparer.OrdinalIgnoreCase)) names.Add(value);
                }
            }

            return names;
        }

        /// <summary>
        /// Shortens a certificate name to its <c>CN=</c> field. The full distinguished name is a
        /// line no detail panel can hold.
        /// </summary>
        private static string Clean(string distinguishedName)
        {
            Match match = Regex.Match(distinguishedName, @"CN\s*=\s*([^,]+)", RegexOptions.IgnoreCase);
            return match.Success ? match.Groups[1].Value.Trim() : distinguishedName.Trim();
        }
    }

    /// <summary>What was found behind an open web port.</summary>
    public sealed class WebIdentityResult
    {
        /// <summary>The address of the target.</summary>
        public required string Address { get; init; }

        /// <summary>The port that answered.</summary>
        public int Port { get; init; }

        /// <summary>Whether the port uses TLS.</summary>
        public bool IsTls { get; init; }

        /// <summary>The page title, usually the most telling finding.</summary>
        public string? Title { get; init; }

        /// <summary>The value of the Server header.</summary>
        public string? Server { get; init; }

        /// <summary>The CN of the certificate subject.</summary>
        public string? CertificateSubject { get; init; }

        /// <summary>The CN of the certificate issuer.</summary>
        public string? CertificateIssuer { get; init; }

        /// <summary>The end of the validity period of the certificate.</summary>
        public DateTime? CertificateExpires { get; init; }

        /// <summary>Whether subject and issuer of the certificate are the same.</summary>
        public bool IsSelfSigned { get; init; }

        /// <summary>Further names from the certificate.</summary>
        public List<string> AlternativeNames { get; init; } = [];

        /// <summary>The lines for the detail view.</summary>
        /// <returns>The findings as multi-line text.</returns>
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
