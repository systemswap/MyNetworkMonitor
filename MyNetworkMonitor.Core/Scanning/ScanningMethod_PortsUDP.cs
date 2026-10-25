// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    /// <summary>
    /// Checks which UDP ports of a target answer.
    /// <para>
    /// The class asks the target itself. The local UDP listeners
    /// (<see cref="System.Net.NetworkInformation.IPGlobalProperties.GetActiveUdpListeners"/>) are
    /// the sockets of the <b>local</b> computer and say nothing about a remote target. See
    /// docs/FEHLERGEDAECHTNIS.md, No. 4.
    /// </para>
    /// <para>
    /// <b>Why connected UDP sockets.</b> UDP has no handshake like TCP: an answer is an answer,
    /// but silence does not mean "closed", only "nothing came back". The only reliable way to
    /// tell "closed" from "open, but nobody answers this packet" is ICMP port unreachable, and a
    /// socket connected with <see cref="UdpClient.Connect(string, int)"/> passes that ICMP message
    /// back as a <see cref="SocketException"/> (<see cref="SocketError.ConnectionReset"/> or
    /// <see cref="SocketError.ConnectionRefused"/>) instead of dropping it silently. This needs no
    /// raw socket and therefore no special privileges, unlike reading raw ICMP.
    /// </para>
    /// <para>
    /// <b>Still incomplete.</b> Many UDP services (DNS, SNMP, NTP, ...) answer only a request
    /// that matches their protocol, not an empty packet. An open port that stays silent then looks
    /// the same as a filtered one, and both remain undetected. Only what can be proven is
    /// therefore reported: a real answer. That is less than protocol-specific probes would find,
    /// but it is reliable.
    /// </para>
    /// </summary>
    public class ScanningMethod_PortsUDP
    {
        /// <summary>Creates the UDP port scanner.</summary>
        public ScanningMethod_PortsUDP() { }

        /// <summary>Raised for every target with at least one answering port.</summary>
        public event EventHandler<ScanTask_Finished_EventArgs>? UDPPortScan_Task_Finished;

        /// <summary>Raised when the scan has finished or was stopped.</summary>
        public event Action<ScanStatus>? UDPPortScan_Finished;

        private CancellationTokenSource _cts = new();

        /// <summary>
        /// How many port checks may run at the same time in total, for the same reason as in the
        /// TCP port scan: without a limit, many targets and ports easily mean thousands of probes
        /// at once.
        /// </summary>
        private const int MaxConcurrentPortScans = 128;

        /// <summary>
        /// Cancels the running scan and reports <see cref="ScanStatus.stopped"/>.
        /// </summary>
        public void StopScan()
        {
            if (!_cts.IsCancellationRequested)
            {
                _cts.Cancel();
            }
            UDPPortScan_Finished?.Invoke(ScanStatus.stopped);
        }

        /// <summary>
        /// Checks the given UDP ports on every target and reports the targets with answering ports.
        /// </summary>
        /// <param name="IPs">The targets.</param>
        /// <param name="ports">The ports to check.</param>
        /// <param name="timeout">How long each port waits for an answer.</param>
        public async Task ScanUDPPortsAsync(List<IPToScan> IPs, List<int> ports, TimeSpan timeout)
        {
            // A fresh token per scan, so that a scan works again after a previous StopScan.
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
        /// Sends an empty packet and waits for an answer. See the class comment for what "open"
        /// means here and what is not detected.
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

                // Any answer is an answer: the port is open.
                return true;
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused)
            {
                // ICMP port unreachable, passed on by the connected socket as an exception: the
                // port is closed.
                return false;
            }
            catch (OperationCanceledException) when (!_cts.Token.IsCancellationRequested)
            {
                // Only the own time limit expired, no external cancellation: no answer came, so
                // the port cannot be reported as open.
                return false;
            }
            catch (SocketException)
            {
                return false;
            }
        }
    }
}
