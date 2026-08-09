using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    /// <summary>
    /// Prueft, welche UDP-Ports eines Ziels antworten.
    /// <para>
    /// Frueher fragte diese Klasse gar nicht das Ziel, sondern
    /// <see cref="System.Net.NetworkInformation.IPGlobalProperties.GetActiveUdpListeners"/>
    /// - die UDP-Sockets des <b>eigenen</b> Rechners. Gegen ein entferntes Ziel
    /// kam dabei immer "nichts offen" heraus, unabhaengig vom echten Zustand;
    /// nur wenn zufaellig die eigene Adresse gescannt wurde, stimmte etwas.
    /// </para>
    /// <para>
    /// <b>Warum "verbundene" UDP-Sockets.</b> UDP kennt keinen Handshake wie
    /// TCP - eine Antwort ist eine Antwort, aber Stille bedeutet nicht "zu",
    /// sie bedeutet nur "es kam nichts". Der einzige verlaessliche Weg, "zu"
    /// von "offen, aber auf dieses Paket antwortet niemand" zu unterscheiden,
    /// ist ICMP Port-unreachable - und ein per <see cref="UdpClient.Connect"/>
    /// verbundener Socket reicht dieses ICMP dem Betriebssystem als
    /// <see cref="SocketException"/> zurueck, statt es stillschweigend zu
    /// verwerfen. Das braucht keinen rohen Socket und damit keine
    /// Sonderrechte - anders als beim klassischen "raw ICMP mitlesen".
    /// </para>
    /// <para>
    /// <b>Bleibt trotzdem unvollstaendig.</b> Viele UDP-Dienste (DNS, SNMP,
    /// NTP, ...) antworten nur auf eine zu ihrem Protokoll passende Anfrage,
    /// nicht auf ein leeres Paket - ein offener, aber auf Zuruf stummer Port
    /// sieht dann genauso aus wie ein gefilterter, und beide bleiben
    /// unentdeckt. Gemeldet wird darum nur, was sich beweisen laesst: eine
    /// echte Antwort. Das ist weniger, als ein Werkzeug mit einer Datenbank
    /// protokollspezifischer Sonden faende, aber ehrlich - und unzaehlige
    /// Male mehr, als die vorherige Implementierung je gegen ein entferntes
    /// Ziel fand.
    /// </para>
    /// </summary>
    public class ScanningMethod_PortsUDP
    {
        public ScanningMethod_PortsUDP() { }

        public event EventHandler<ScanTask_Finished_EventArgs>? UDPPortScan_Task_Finished;
        public event Action<ScanStatus>? UDPPortScan_Finished;

        private CancellationTokenSource _cts = new();

        /// <summary>
        /// Wie viele Portpruefungen insgesamt gleichzeitig laufen duerfen - aus
        /// demselben Grund wie beim TCP-Portscan (siehe dort): ohne Grenze
        /// liefen bei vielen Zielen und Ports leicht tausende Sonden auf einmal.
        /// </summary>
        private const int MaxConcurrentPortScans = 128;

        public void StopScan()
        {
            if (!_cts.IsCancellationRequested)
            {
                _cts.Cancel();
            }
            UDPPortScan_Finished?.Invoke(ScanStatus.stopped);
        }

        public async Task ScanUDPPortsAsync(List<IPToScan> IPs, List<int> ports, TimeSpan timeout)
        {
            // Frischer Token je Scan, damit nach einem vorherigen StopScan
            // wieder sauber gescannt werden kann.
            _cts = new CancellationTokenSource();

            using SemaphoreSlim gate = new(MaxConcurrentPortScans);
            var tasks = new List<Task>();

            foreach (var ip in IPs.Where(ip => !string.IsNullOrEmpty(ip.IPorHostname)))
            {
                if (_cts.Token.IsCancellationRequested) break;

                tasks.Add(ScanIPAsync(ip, ports, timeout, gate));
                await Task.Delay(20, _cts.Token);
            }

            await Task.WhenAll(tasks);

            UDPPortScan_Finished?.Invoke(ScanStatus.finished);
        }

        private async Task ScanIPAsync(IPToScan ipToScan, List<int> ports, TimeSpan timeout, SemaphoreSlim gate)
        {
            if (_cts.Token.IsCancellationRequested) return;

            ipToScan.UsedScanMethod = ScanMethod.UDPPorts;

            var tasks = new List<Task>();

            foreach (int port in ports)
            {
                if (_cts.Token.IsCancellationRequested) return;

                await gate.WaitAsync(_cts.Token);

                tasks.Add(ProbePortAsync(ipToScan, port, timeout, gate));
            }

            await Task.WhenAll(tasks);

            if (ipToScan.UDP_OpenPorts.Count == 0) return;

            ipToScan.UDP_OpenPorts.Sort();

            UDPPortScan_Task_Finished?.Invoke(this, new ScanTask_Finished_EventArgs { ipToScan = ipToScan });
        }

        private async Task ProbePortAsync(IPToScan ipToScan, int port, TimeSpan timeout, SemaphoreSlim gate)
        {
            try
            {
                if (await IsOpenAsync(ipToScan.IPorHostname, port, timeout))
                {
                    lock (ipToScan.UDP_OpenPorts)
                    {
                        ipToScan.UDP_OpenPorts.Add(port);
                    }
                }
            }
            finally
            {
                gate.Release();
            }
        }

        /// <summary>
        /// Schickt ein leeres Paket und wartet auf eine Antwort. Siehe
        /// Klassenkommentar dazu, was "offen" hier heisst und was nicht
        /// erkannt wird.
        /// </summary>
        private async Task<bool> IsOpenAsync(string ip, int port, TimeSpan timeout)
        {
            try
            {
                using UdpClient client = new();
                client.Connect(ip, port);
                await client.SendAsync(Array.Empty<byte>(), 0).WaitAsync(_cts.Token);

                using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                linked.CancelAfter(timeout);

                await client.ReceiveAsync(linked.Token);

                // Irgendeine Antwort ist eine Antwort - der Port ist offen.
                return true;
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused)
            {
                // ICMP Port-unreachable, vom verbundenen Socket als Ausnahme
                // durchgereicht - der Port ist definitiv zu.
                return false;
            }
            catch (OperationCanceledException) when (!_cts.Token.IsCancellationRequested)
            {
                // Nur das eigene Zeitlimit abgelaufen, kein Abbruch von aussen -
                // keine Antwort kam, "offen" laesst sich damit nicht behaupten.
                return false;
            }
            catch (SocketException)
            {
                return false;
            }
        }
    }
}
