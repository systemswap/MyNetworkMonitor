using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace MyNetworkMonitor
{
    /// <summary>
    /// WS-Discovery: fragt per Multicast "wer ist da?" und wertet aus, wer sich
    /// meldet.
    /// <para>
    /// <b>Warum das gebraucht wird:</b> alle uebrigen Verfahren finden nur, was
    /// auf eine gezielte Anfrage antwortet. Ein Windows-Rechner mit
    /// Standardfirewall antwortet nicht auf Ping, hat oft keinen PTR-Eintrag und
    /// zeigt keine offenen Ports - er ist damit unsichtbar. Auf WS-Discovery
    /// antwortet er, und Netzwerkdrucker und Scanner ebenso: es ist der
    /// Mechanismus, ueber den Windows selbst seine Netzwerkumgebung fuellt.
    /// </para>
    /// <para>
    /// <b>Warum zwei Anfragen:</b> es gibt zwei Fassungen des Protokolls, die
    /// verschiedene Namensraeume benutzen. Die aeltere von 2005 beantwortet
    /// ONVIF-Technik, die neuere von 2009 beantworten Windows-Geraete und
    /// Drucker. Wer nur eine sendet, findet die halbe Welt - genau das ist der
    /// Unterschied zu <see cref="ScanningMethod_ONVIF_IPCam"/>, das dieselbe
    /// Technik nutzt, aber gezielt nach Kameras fragt.
    /// </para>
    /// </summary>
    public class ScanningMethod_WSDiscovery
    {
        private const string MulticastAddress = "239.255.255.250";
        private const int DiscoveryPort = 3702;

        /// <summary>Der Namensraum der Fassung von 2005 - ONVIF und aeltere Geraete.</summary>
        private const string Discovery2005 = "http://schemas.xmlsoap.org/ws/2005/04/discovery";

        /// <summary>Der Namensraum der Fassung von 2009 - Windows, Drucker, Scanner.</summary>
        private const string Discovery2009 = "http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01";

        private const string Addressing2004 = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
        private const string Addressing2005 = "http://www.w3.org/2005/08/addressing";

        public event Action<int, int, int, ScanStatus>? ProgressUpdated;
        public event Action<WsDiscoveryResult>? WSDiscovery_DeviceFound;
        public event Action<ScanStatus>? WSDiscovery_Scan_Finished;

        private int current;
        private int responded;
        private int total;

        private CancellationTokenSource _cts = new();

        public void StopScan()
        {
            if (_cts != null && !_cts.IsCancellationRequested)
            {
                // Nur abbrechen, nicht ersetzen: die Schleifen lesen _cts ueber
                // das Feld. Ein frisches CTS meldete ihnen wieder "laeuft".
                _cts.Cancel();
            }

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
        /// Sendet die Anfragen und hoert die angegebene Zeit auf Antworten.
        /// </summary>
        /// <param name="localAddress">
        /// Die eigene IPv4-Adresse, an die der Empfangspunkt gebunden wird.
        /// Ohne Bindung schickt Windows die Anfrage ueber die Karte mit der
        /// niedrigsten Metrik - bei mehreren Netzkarten also womoeglich in das
        /// falsche Netz.
        /// </param>
        /// <param name="listenMs">Hoerdauer in Millisekunden.</param>
        public async Task DiscoverAsync(IPAddress localAddress, int listenMs = 5000)
        {
            ArgumentNullException.ThrowIfNull(localAddress);

            StartNewScan();

            // Jede Adresse zaehlt nur einmal, auch wenn ein Geraet auf beide
            // Fassungen und auf jede der drei Anfragen antwortet.
            HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

            using UdpClient client = new(new IPEndPoint(localAddress, 0));
            client.EnableBroadcast = true;
            client.MulticastLoopback = false;

            IPEndPoint target = new(IPAddress.Parse(MulticastAddress), DiscoveryPort);

            try
            {
                // Beide Fassungen, und jede dreimal: die Anfrage geht per UDP
                // raus und darf verlorengehen. Drei Versuche sind das, was auch
                // die Kamerasuche macht, und kosten unter einer Sekunde.
                foreach (string ns in new[] { Discovery2009, Discovery2005 })
                {
                    for (int attempt = 0; attempt < 3; attempt++)
                    {
                        if (_cts.Token.IsCancellationRequested) break;

                        byte[] probe = Encoding.UTF8.GetBytes(BuildProbe(ns));
                        await client.SendAsync(probe, probe.Length, target);

                        int sent = Interlocked.Increment(ref current);
                        ProgressUpdated?.Invoke(sent, responded, total, ScanStatus.running);

                        await Task.Delay(200, _cts.Token);
                    }
                }

                DateTime until = DateTime.UtcNow.AddMilliseconds(listenMs);

                while (DateTime.UtcNow < until && !_cts.Token.IsCancellationRequested)
                {
                    Task<UdpReceiveResult> receive = client.ReceiveAsync(_cts.Token).AsTask();
                    Task finished = await Task.WhenAny(receive, Task.Delay(200, _cts.Token));

                    if (finished != receive) continue;

                    UdpReceiveResult result = await receive;
                    string address = result.RemoteEndPoint.Address.ToString();

                    if (!seen.Add(address)) continue;

                    WsDiscoveryResult found = Parse(Encoding.UTF8.GetString(result.Buffer), address);

                    int respondedValue = Interlocked.Increment(ref responded);
                    ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running);

                    WSDiscovery_DeviceFound?.Invoke(found);
                }
            }
            catch (OperationCanceledException) { }
            catch (SocketException) { }
            finally
            {
                WSDiscovery_Scan_Finished?.Invoke(ScanStatus.finished);
            }
        }

        /// <summary>
        /// Die Anfrage. Bewusst <b>ohne</b> <c>Types</c>-Element: damit gilt sie
        /// jedem Geraet. Ein Typfilter waere genau das, was die Kamerasuche
        /// macht - und er wuerde hier die gesuchten Rechner und Drucker
        /// ausschliessen.
        /// </summary>
        private static string BuildProbe(string discoveryNamespace)
        {
            string addressing = discoveryNamespace == Discovery2009 ? Addressing2005 : Addressing2004;
            string action = $"{discoveryNamespace}/Probe";

            return $"""
                <?xml version="1.0" encoding="UTF-8"?>
                <e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
                            xmlns:w="{addressing}"
                            xmlns:d="{discoveryNamespace}">
                  <e:Header>
                    <w:MessageID>urn:uuid:{Guid.NewGuid()}</w:MessageID>
                    <w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
                    <w:Action e:mustUnderstand="true">{action}</w:Action>
                  </e:Header>
                  <e:Body>
                    <d:Probe/>
                  </e:Body>
                </e:Envelope>
                """;
        }

        /// <summary>
        /// Liest aus der Antwort heraus, um was fuer ein Geraet es sich handelt.
        /// <para>
        /// Ausgewertet wird <c>Types</c> - dort steht die Geraeteklasse - und
        /// <c>XAddrs</c>, die Adresse der Verwaltungsschnittstelle. Der
        /// Klarname steht in der Antwort <em>nicht</em> drin; ihn zu holen
        /// erforderte eine zweite Abfrage an die XAddrs-Adresse. Der eigentliche
        /// Gewinn ist ohnehin ein anderer: dass die Adresse ueberhaupt
        /// geantwortet hat.
        /// </para>
        /// </summary>
        private static WsDiscoveryResult Parse(string soap, string address)
        {
            try
            {
                XDocument document = XDocument.Parse(soap);

                // Ohne Namensraumbindung suchen: es kommen beide Fassungen
                // herein, und die Elementnamen sind in beiden dieselben.
                string? types = FindValue(document, "Types");
                string? xaddrs = FindValue(document, "XAddrs");
                string? scopes = FindValue(document, "Scopes");

                return new WsDiscoveryResult
                {
                    Address = address,
                    Kind = DescribeTypes(types),
                    Info = BuildInfoText(types, xaddrs, scopes)
                };
            }
            catch (Exception)
            {
                // Eine unverstaendliche Antwort ist trotzdem eine Antwort: die
                // Adresse lebt, und genau das ist der Fund.
                return new WsDiscoveryResult
                {
                    Address = address,
                    Info = "Replied, but the response could not be read."
                };
            }
        }

        private static string? FindValue(XDocument document, string localName) =>
            document.Descendants()
                .FirstOrDefault(e => string.Equals(e.Name.LocalName, localName, StringComparison.OrdinalIgnoreCase))
                ?.Value?.Trim();

        /// <summary>
        /// Setzt die Zeilen zusammen, die spaeter in der Detailansicht stehen.
        /// Die Geraeteklasse wird uebersetzt: <c>pub:Computer</c> sagt einem
        /// Netzwerker etwas, dem Rest der Welt nicht.
        /// </summary>
        private static string BuildInfoText(string? types, string? xaddrs, string? scopes)
        {
            List<string> lines = [];

            if (!string.IsNullOrWhiteSpace(types)) lines.Add($"Types: {types}");
            if (!string.IsNullOrWhiteSpace(xaddrs)) lines.Add($"Address: {xaddrs}");

            // Die Bereichsangaben enthalten bei Windows-Rechnern haeufig den
            // Domaenen- oder Arbeitsgruppennamen.
            if (!string.IsNullOrWhiteSpace(scopes)) lines.Add($"Scopes: {scopes}");

            return lines.Count > 0 ? string.Join(Environment.NewLine, lines) : "Replied.";
        }

        /// <summary>
        /// Uebersetzt die Typangaben in Klartext. Die Praefixe sind frei
        /// waehlbar, darum wird auf den lokalen Namen geprueft und nicht auf
        /// die ganze Zeichenkette.
        /// </summary>
        private static string? DescribeTypes(string? types)
        {
            if (string.IsNullOrWhiteSpace(types)) return null;

            List<string> kinds = [];

            if (types.Contains("PrintDeviceType", StringComparison.OrdinalIgnoreCase) ||
                types.Contains("Print", StringComparison.OrdinalIgnoreCase))
            {
                kinds.Add("printer");
            }

            if (types.Contains("ScanDeviceType", StringComparison.OrdinalIgnoreCase))
            {
                kinds.Add("scanner");
            }

            if (types.Contains("Computer", StringComparison.OrdinalIgnoreCase))
            {
                kinds.Add("Windows computer");
            }

            if (types.Contains("NetworkVideoTransmitter", StringComparison.OrdinalIgnoreCase))
            {
                kinds.Add("camera");
            }

            return kinds.Count > 0 ? string.Join(", ", kinds) : null;
        }
    }

    /// <summary>
    /// Was eine WS-Discovery-Antwort ueber ihren Absender verraet.
    /// <para>
    /// Bewusst ein eigener Typ statt eines weiteren Feldes an
    /// <see cref="IPToScan"/>: die alte Struktur traegt bereits vierzig Felder,
    /// von denen jedes Verfahren drei fuellt. Ein Verfahren, das ganz neu
    /// dazukommt, muss diesen Weg nicht auch noch gehen.
    /// </para>
    /// </summary>
    public sealed class WsDiscoveryResult
    {
        /// <summary>Die Adresse, von der die Antwort kam.</summary>
        public required string Address { get; init; }

        /// <summary>
        /// Die Geraeteklasse in Klartext - "Windows computer", "printer" -
        /// oder <c>null</c>, wenn die Typangabe nichts Bekanntes enthielt.
        /// </summary>
        public string? Kind { get; init; }

        /// <summary>Die vollstaendigen Angaben fuer die Detailansicht.</summary>
        public string Info { get; init; } = string.Empty;
    }
}
