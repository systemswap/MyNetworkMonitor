// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
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
    /// <summary>
    /// Checks TCP ports of the targets by connection attempt.
    /// </summary>
    public class ScanningMethod_PortsTCP
    {
        /// <summary>Creates the TCP port scanner.</summary>
        public ScanningMethod_PortsTCP() { }

        /// <summary>Raised when all ports of one target have been checked.</summary>
        public event EventHandler<ScanTask_Finished_EventArgs>? TcpPortScan_Task_Finished;

        /// <summary>Raised when the scan has finished or was stopped.</summary>
        public event Action<ScanStatus>? TcpPortScan_Finished;

        /// <summary>
        /// Progress during the run as (checked, found open, total), across all targets and ports.
        /// A target is reported only at its very end; without this event the display stands still
        /// while a target runs, which with all 65535 ports means minutes.
        /// </summary>
        public event Action<int, int, int>? ProgressUpdated;

        private int _checked;
        private int _open;
        private int _total;

        /// <summary>
        /// Progress is reported once per this many checked ports: fine enough for the display to
        /// move noticeably, coarse enough that not every single port reaches the UI thread.
        /// </summary>
        private const int ProgressStep = 100;

        private CancellationTokenSource _cts = new CancellationTokenSource();
        /// <summary>
        /// The cancellation token of the scan; setting it links the scan to an external token.
        /// </summary>
        public CancellationToken CancelPortScan
        {
            get => _cts.Token;
            set => _cts = CancellationTokenSource.CreateLinkedTokenSource(value);
        }

        /// <summary>
        /// Checks the given TCP ports on every target and reports each target when done.
        /// </summary>
        /// <param name="IPs">The targets; each entry must be an IPv4 address.</param>
        /// <param name="Ports">The ports to check.</param>
        /// <param name="TimeOut">The time limit per connection attempt.</param>
        public async Task ScanTCPPortsAsync(List<IPToScan> IPs, List<int> Ports, TimeSpan TimeOut)
        {
            // A fresh token per scan, so that a scan works again after a previous StopScan.
            _cts = new CancellationTokenSource();

            await _ScanTCPPortsAsync(IPs, Ports, TimeOut);
        }

        /// <summary>
        /// Cancels the running scan and reports <see cref="ScanStatus.stopped"/>.
        /// </summary>
        public void StopScan()
        {
            // The scan tasks check the internal token (see ScanTCPPorts_Task); Cancel ends the
            // running scan.
            if (_cts != null && !_cts.IsCancellationRequested)
            {
                _cts.Cancel();
            }
            TcpPortScan_Finished?.Invoke(ScanStatus.stopped);
        }

        /// <summary>
        /// How many port checks may run at the same time in total, across all target addresses
        /// and ports. Without a limit the targets start 20 ms apart and their ports follow at short
        /// intervals; with all 65535 ports on several targets that easily means several thousand
        /// open sockets at once. The ping scan is limited for the same reason.
        /// </summary>
        private const int MaxConcurrentPortScans = 128;

        private async Task _ScanTCPPortsAsync(List<IPToScan> IPs, List<int> TCP_Ports, TimeSpan TimeOut)
        {
            using SemaphoreSlim gate = new(MaxConcurrentPortScans);
            var tasks = new List<Task>();

            // Basis for the progress display: all port checks across all valid targets.
            int validIps = IPs.Count(ip => !string.IsNullOrEmpty(ip.IPorHostname));
            _checked = 0;
            _open = 0;
            _total = validIps * TCP_Ports.Count;

            foreach (var ip in IPs.Where(ip => !string.IsNullOrEmpty(ip.IPorHostname)))
            {
                tasks.Add(ScanTCPPorts_Task(ip, TCP_Ports, TimeOut, gate));
                await Task.Delay(20); // 20 ms between the targets
            }

            await Task.WhenAll(tasks);

            // Report the final count, in case the last report came before the next step.
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

        /// <summary>
        /// Checks one TCP port by connection attempt.
        /// </summary>
        /// <param name="IP">The IPv4 address of the target.</param>
        /// <param name="Port">The port.</param>
        /// <param name="timeout">The time limit for the connection attempt.</param>
        /// <returns>
        /// The result: open on a completed connection, denied on a refused connection, blocked on
        /// access denied, otherwise not reachable.
        /// </returns>
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

        /// <summary>Releases the semaphore slot after the check in every case, also on an exception.</summary>
        private async Task<PortScanResult> ScanPortGatedAsync(string ip, int port, TimeSpan timeout, SemaphoreSlim gate)
        {
            try
            {
                PortScanResult result = await ScanTCP_Port_via_Socket_Async(ip, port, timeout);

                if (result.PortState == PortScanState.PortIsOpen) Interlocked.Increment(ref _open);

                // Report only every ProgressStep ports, not for every single one; otherwise 65535
                // reports per target reach the UI thread.
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

    /// <summary>
    /// The result of a TCP port check.
    /// </summary>
    public enum PortScanState
    {
        /// <summary>The connection was established.</summary>
        PortIsOpen,

        /// <summary>The connection attempt failed with "access denied", typically because of a firewall.</summary>
        FirewallBlockedPort,

        /// <summary>The target refused the connection.</summary>
        TargetDeniedAccessToPort,

        /// <summary>No answer within the time limit, or another error.</summary>
        TargetNotReachable
    }

    /// <summary>
    /// The result of checking one port on one target.
    /// </summary>
    public class PortScanResult
    {
        /// <summary>The address of the target.</summary>
        public string IP { get; set; }

        /// <summary>The state found.</summary>
        public PortScanState PortState { get; set; }

        /// <summary>The port.</summary>
        public int? Port { get; set; }
    }
}


