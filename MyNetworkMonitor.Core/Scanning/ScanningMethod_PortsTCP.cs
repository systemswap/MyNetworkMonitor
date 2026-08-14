using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

using System.Net;


namespace MyNetworkMonitor
{
    public class ScanningMethod_PortsTCP
    {
        //https://www.codeproject.com/Articles/1415/Introduction-to-TCP-client-server-in-C

        public ScanningMethod_PortsTCP() { }

        public event EventHandler<ScanTask_Finished_EventArgs>? TcpPortScan_Task_Finished;
        public event Action<ScanStatus>? TcpPortScan_Finished;

        /// <summary>
        /// Fortschritt waehrend des Laufs: geprueft, offen gefunden, gesamt -
        /// ueber alle Ziele und Ports. Ohne das stand die Anzeige still,
        /// solange ein Ziel lief; bei der eingestellten Auswahl faellt das nicht
        /// auf, bei allen 65535 Ports sitzt sie minutenlang fest, weil ein Ziel
        /// erst ganz am Ende gemeldet wird.
        /// </summary>
        public event Action<int, int, int>? ProgressUpdated;

        private int _checked;
        private int _open;
        private int _total;

        /// <summary>
        /// Wie oft der Fortschritt hoechstens gemeldet wird - jede geprueften
        /// so viele Ports einmal. Fein genug, dass sich die Anzeige spuerbar
        /// bewegt, grob genug, dass nicht jeder einzelne Port den
        /// Oberflaechen-Thread erreicht.
        /// </summary>
        private const int ProgressStep = 100;

        private CancellationTokenSource _cts = new CancellationTokenSource();
        public CancellationToken CancelPortScan
        {
            get => _cts.Token;
            set => _cts = CancellationTokenSource.CreateLinkedTokenSource(value);
        }

        public async Task ScanTCPPortsAsync(List<IPToScan> IPs, List<int> Ports, TimeSpan TimeOut)
        {
            // Frischer Token je Scan, damit nach einem vorherigen StopScan wieder
            // sauber gescannt werden kann.
            _cts = new CancellationTokenSource();

            //await _ScanTCPPortsAsync(IPs, new PortCollection().TCPPorts, TimeOut);
            await _ScanTCPPortsAsync(IPs, Ports, TimeOut);
        }

        public void StopScan()
        {
            // Der interne Token wird von den Scan-Tasks geprueft (siehe
            // ScanTCPPorts_Task) - Cancel beendet den laufenden Scan.
            if (_cts != null && !_cts.IsCancellationRequested)
            {
                _cts.Cancel();
            }
            TcpPortScan_Finished?.Invoke(ScanStatus.stopped);
        }

        /// <summary>
        /// Wie viele Portpruefungen insgesamt gleichzeitig laufen duerfen - ueber
        /// alle Ziel-IPs und Ports hinweg. Vorher gab es hier keine Grenze:
        /// jede IP startete im 20ms-Abstand, und je IP liefen wiederum alle
        /// Ports im 20ms-Abstand los. Bei "alle 65535 Ports" auf mehreren
        /// Zielen gleichzeitig waren so leicht mehrere tausend offene Sockets
        /// gleichzeitig unterwegs - derselbe Fehler wie beim Ping-Scan, nur
        /// ohne dessen Wiederholungen und darum weniger dramatisch, aber
        /// unnoetig und unbegrenzt.
        /// </summary>
        private const int MaxConcurrentPortScans = 128;

        private async Task _ScanTCPPortsAsync(List<IPToScan> IPs, List<int> TCP_Ports, TimeSpan TimeOut)
        {
            using SemaphoreSlim gate = new(MaxConcurrentPortScans);
            var tasks = new List<Task>();

            // Ausgangspunkt fuer die Fortschrittsanzeige: alle Portpruefungen
            // ueber alle gueltigen Ziele.
            int validIps = IPs.Count(ip => !string.IsNullOrEmpty(ip.IPorHostname));
            _checked = 0;
            _open = 0;
            _total = validIps * TCP_Ports.Count;

            foreach (var ip in IPs.Where(ip => !string.IsNullOrEmpty(ip.IPorHostname)))
            {
                tasks.Add(ScanTCPPorts_Task(ip, TCP_Ports, TimeOut, gate));
                await Task.Delay(20); // 20ms Verzögerung zwischen den IP-Scans
            }

            await Task.WhenAll(tasks);

            // Zum Abschluss der Vollstand, falls die letzte Meldung vor dem
            // Erreichen der naechsten Stufe lag.
            ProgressUpdated?.Invoke(Volatile.Read(ref _checked), Volatile.Read(ref _open), _total);

            TcpPortScan_Finished?.Invoke(ScanStatus.finished);
        }

        private async Task ScanTCPPorts_Task(IPToScan ipToScan, List<int> Ports, TimeSpan TimeOut, SemaphoreSlim gate)
        {
            if (_cts.Token.IsCancellationRequested)
                return;

            ipToScan.UsedScanMethod = ScanMethod.TCPPorts;

            List<Task<PortScanResult>> tasks = new List<Task<PortScanResult>>();

            foreach (int port in Ports)
            {
                if (_cts.Token.IsCancellationRequested)
                    return;

                await gate.WaitAsync(_cts.Token);

                tasks.Add(ScanPortGatedAsync(ipToScan.IPorHostname, port, TimeOut, gate));
            }

            var results = await Task.WhenAll(tasks);

            foreach (var result in results)
            {
                switch (result.PortState)
                {
                    case PortScanState.PortIsOpen:
                        ipToScan.TCP_OpenPorts.Add(result.Port.Value);
                        break;
                    case PortScanState.FirewallBlockedPort:
                        ipToScan.TCP_FirewallBlockedPorts.Add(result.Port.Value);
                        break;
                    case PortScanState.TargetDeniedAccessToPort:
                        ipToScan.TCP_TargetDeniedAccessToPorts.Add(result.Port.Value);
                        break;
                }
            }

            ipToScan.TCP_OpenPorts.Sort();
            ipToScan.TCP_FirewallBlockedPorts.Sort();
            ipToScan.TCP_TargetDeniedAccessToPorts.Sort();

            TcpPortScan_Task_Finished?.Invoke(this, new ScanTask_Finished_EventArgs { ipToScan = ipToScan });
        }

        public async Task<PortScanResult> ScanTCP_Port_via_Socket_Async(string IP, int Port, TimeSpan timeout)
        {
            var scanResult = new PortScanResult { IP = IP, Port = Port };

            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
            {
                Blocking = false
            };

            try
            {
                var connectTask = socket.ConnectAsync(new IPEndPoint(IPAddress.Parse(IP), Port));

                if (await Task.WhenAny(connectTask, Task.Delay(timeout, _cts.Token)) == connectTask)
                {
                    if (socket.Connected)
                    {
                        socket.Close();
                        scanResult.PortState = PortScanState.PortIsOpen;
                    }
                    else
                    {
                        scanResult.PortState = PortScanState.TargetNotReachable;
                    }
                }
                else
                {
                    scanResult.PortState = PortScanState.TargetNotReachable;
                }
            }
            catch (SocketException ex)
            {
                scanResult.PortState = ex.SocketErrorCode switch
                {
                    SocketError.AccessDenied => PortScanState.FirewallBlockedPort,
                    SocketError.TimedOut => PortScanState.TargetNotReachable,
                    SocketError.ConnectionRefused => PortScanState.TargetDeniedAccessToPort,
                    _ => PortScanState.TargetNotReachable
                };
            }

            return scanResult;
        }

        /// <summary>Reicht den Semaphor-Platz nach der Pruefung zuverlaessig weiter, auch bei einer Ausnahme.</summary>
        private async Task<PortScanResult> ScanPortGatedAsync(string ip, int port, TimeSpan timeout, SemaphoreSlim gate)
        {
            try
            {
                PortScanResult result = await ScanTCP_Port_via_Socket_Async(ip, port, timeout);

                if (result.PortState == PortScanState.PortIsOpen) Interlocked.Increment(ref _open);

                // Nur alle paar hundert Ports melden, nicht bei jedem einzelnen -
                // sonst erreichen 65535 Meldungen je Ziel den Oberflaechen-Thread.
                int done = Interlocked.Increment(ref _checked);
                if (done % ProgressStep == 0)
                {
                    ProgressUpdated?.Invoke(done, Volatile.Read(ref _open), _total);
                }

                return result;
            }
            finally
            {
                gate.Release();
            }
        }
    }

    public enum PortScanState
    {
        PortIsOpen,
        FirewallBlockedPort,
        TargetDeniedAccessToPort,
        TargetNotReachable
    }

    public class PortScanResult
    {
        public string IP { get; set; }
        public PortScanState PortState { get; set; }
        public int? Port { get; set; }
    }
}


