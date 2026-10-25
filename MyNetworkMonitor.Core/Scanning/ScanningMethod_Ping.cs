// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    /// <summary>
    /// Pings the targets (ICMP echo) with up to three attempts and increasing timeouts.
    /// </summary>
    public class ScanningMethods_Ping
    {
        /// <summary>Creates the ping scanner.</summary>
        public ScanningMethods_Ping() { }

        /// <summary>Reports progress as (sent, responded, total, status).</summary>
        public event Action<int, int, int, ScanStatus> ProgressUpdated;

        /// <summary>Raised for every answering target, and with "show unused" also for silent ones.</summary>
        public event EventHandler<ScanTask_Finished_EventArgs>? Ping_Task_Finished;

        /// <summary>Raised when all pings of a run have finished.</summary>
        public event Action<ScanStatus>? PingFinished;


        private readonly PingOptions pingOptions = new PingOptions(200, true);
        private readonly byte[] buffer = Encoding.ASCII.GetBytes("nothing less than the world domination pinky, nothing less!");

        /// <summary>
        /// How many targets may be in the actual ping wait at the same time. Without this limit
        /// all 254 targets of a /24 start almost at once, and every silent target is stuck for up
        /// to three attempts with increasing timeouts (2.5 s / 5 s / 7.5 s). That overloads the
        /// thread pool and starves the 400 ms refresh timer of the result table, which then
        /// catches up only after the flood has passed and seems to fill only at the end. The
        /// value matches the limit the IPv6 methods use for the same purpose.
        /// </summary>
        private const int MaxConcurrentPings = 64;

        private readonly SemaphoreSlim _gate = new(MaxConcurrentPings);

        /// <summary>
        /// Whether the custom payload can be sent. On Linux any payload other than the default
        /// requires a raw socket; without <c>CAP_NET_RAW</c>/root <em>every</em> ping fails instead
        /// of reporting "no answer". Measured once per run (a ping to the local host) instead of
        /// assumed, so that 254 targets do not repeat the same failure three times before the
        /// fallback applies.
        /// </summary>
        private bool? _customPayloadSupported;

        private int current = 0;
        private int responded = 0;
        private int total = 0;

        private CancellationTokenSource _cts = new CancellationTokenSource(); // Allows the scan to be cancelled.

        /// <summary>
        /// Cancels the running scan and reports <see cref="ScanStatus.stopped"/>.
        /// </summary>
        public void StopScan()
        {
            if (_cts != null && !_cts.IsCancellationRequested)
            {
                _cts.Cancel();
                // Do NOT dispose and replace the source here: the loops read _cts through the
                // field. A fresh source at this point would report "not cancelled" to them and
                // the run would continue instead of ending. StartNewScan resets it for the next run.
            }
           
            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.stopped); // Resets the progress display.
        }

        private void StartNewScan()
        {
            if (_cts != null)
            {
                if (!_cts.IsCancellationRequested)
                {
                    _cts.Cancel();
                }
                _cts.Dispose();
            }
            _cts = new CancellationTokenSource();

            // Reset the counters.
            current = 0;
            responded = 0;
            total = 0;
        }





        /// <summary>
        /// Pings every target that is a valid IP address, with its own timeout.
        /// </summary>
        /// <param name="IPsToRefresh">The targets.</param>
        /// <param name="ShowUnused"><see langword="true"/> to report silent targets as well.</param>
        public async Task PingIPsAsync(List<IPToScan> IPsToRefresh, bool ShowUnused = false)
        {
            StartNewScan(); // Resets _cts.

            current = 0;
            responded = 0;
            total = IPsToRefresh.Count;

            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running);

            // Check once per run instead of repeating the same failure 254 times: otherwise all
            // three attempts of every target would fail on the missing permission before the
            // fallback applies.
            _customPayloadSupported = await CustomPayloadSupportedAsync();

            try
            {
                var tasks = new List<Task>();
                var ipListCopy = IPsToRefresh.ToList(); // Copy of the list

                foreach (var ip in ipListCopy.Where(ip => !string.IsNullOrEmpty(ip.IPorHostname)))
                {
                    if (_cts.Token.IsCancellationRequested) break;

                    tasks.Add(PingTask(ip, ip.TimeOut, ShowUnused));

                    try
                    {
                        await Task.Delay(20, _cts.Token);
                    }
                    catch (TaskCanceledException)
                    {
                        break;
                    }
                }

                await Task.WhenAll(tasks);
            }
            catch (OperationCanceledException)
            {
                Debug.WriteLine("Ping-Scan wurde abgebrochen!");
            }
            finally
            {
                PingFinished?.Invoke(ScanStatus.finished);
            }
        }



        private async Task PingTask(IPToScan ipToScan, int timeout, bool showUnused)
        {
            if (_cts.Token.IsCancellationRequested) return;

            if (!new SupportMethods().Is_Valid_IP(ipToScan.IPorHostname)) 
            { 
                return; 
            }


            // No more than MaxConcurrentPings in the actual wait at a time; otherwise a /24 quickly
            // has 200+ silent targets stuck in parallel, each for up to three attempts, and the
            // thread pool can no longer keep up with the display refresh (see MaxConcurrentPings).
            await _gate.WaitAsync(_cts.Token);

            try
            {
                // Count the sent request, not the finished probe. The display shows three numbers,
                // sent, responded and total, and "254 / 160 / 254" then means: everything sent,
                // 160 answers received, the rest still pending. With only two numbers this would
                // read as a misleading "finished".
                int sentCount = Interlocked.Increment(ref current);
                ProgressUpdated?.Invoke(sentCount, responded, total, ScanStatus.running);

                using Ping ping = new Ping();
                PingReply reply = null;
                bool success = false;

                // Up to three attempts with increasing timeouts.
                for (int attempt = 1; attempt <= 3; attempt++)
                {
                    _cts.Token.ThrowIfCancellationRequested();

                    // With the token: without it a started probe runs until its timeout, which is
                    // three times as long on the third attempt, and "Stop" takes many seconds to
                    // take effect.
                    reply = _customPayloadSupported == true
                        ? await ping.SendPingAsync(
                            ipToScan.IPorHostname,
                            TimeSpan.FromMilliseconds(timeout * attempt),
                            buffer,
                            pingOptions,
                            _cts.Token)
                        : await SendPlainPingAsync(ping, ipToScan.IPorHostname, timeout * attempt, _cts.Token);

                    if (reply != null && reply.Status == IPStatus.Success)
                    {
                        success = true;
                        break; // Answered; no further attempts needed.
                    }

                    if (attempt < 3)
                    {
                        try
                        {
                            await Task.Delay(100, _cts.Token); // Ends at once when stopped.
                        }
                        catch (TaskCanceledException)
                        {
                            return;
                        }
                    }
                }

                if (!success && !showUnused) return;

                ipToScan.ResponseTime = success ? reply?.RoundtripTime.ToString() : string.Empty;
                ipToScan.PingStatus = success;
                ipToScan.UsedScanMethod = ScanMethod.Ping;

                // The remaining TTL of the answer. It is in the packet anyway and hints at the
                // operating system at no cost; TtlFingerprint evaluates it.
                if (success) ipToScan.TTL = reply?.Options?.Ttl ?? 0;

                // Only a real answer counts as a response. With "show unused" a silent target also
                // gets here; counting it would make the middle number a copy of the first one and
                // the whole display worthless.
                if (success)
                {
                    int responsedCount = Interlocked.Increment(ref responded);
                    ProgressUpdated?.Invoke(current, responsedCount, total, ScanStatus.running);
                }

                // Report the result.
                Ping_Task_Finished?.Invoke(this, new ScanTask_Finished_EventArgs { ipToScan = ipToScan });
            }
            catch (OperationCanceledException)
            {
                Debug.WriteLine($"Ping für {ipToScan.IPorHostname} wurde abgebrochen.");
            }
            catch (Exception ex) when (ex is PingException || ex is SocketException)
            {
                Console.WriteLine($"Ping Fehler für {ipToScan.IPorHostname}: {ex.Message}");
            }
            finally
            {
                _gate.Release();
            }
        }

        /// <summary>
        /// A ping without a custom payload and without custom <see cref="PingOptions"/>, the
        /// simplest form, which works on Linux without <c>CAP_NET_RAW</c>/root. The simple
        /// overloads of <see cref="Ping.SendPingAsync(string, int)"/> take no
        /// <see cref="CancellationToken"/>; racing against
        /// <see cref="Task.Delay(int, CancellationToken)"/> makes "Stop" take effect at once here
        /// too instead of after the full timeout.
        /// </summary>
        private static async Task<PingReply> SendPlainPingAsync(
            Ping ping, string hostNameOrAddress, int timeoutMs, CancellationToken cancellationToken)
        {
            Task<PingReply> pingTask = ping.SendPingAsync(hostNameOrAddress, timeoutMs);
            Task delay = Task.Delay(Timeout.Infinite, cancellationToken);

            Task completed = await Task.WhenAny(pingTask, delay);
            if (completed != pingTask) throw new OperationCanceledException(cancellationToken);

            return await pingTask;
        }

        /// <summary>
        /// Checks once whether the custom payload can be sent: a quick ping to the loopback
        /// address instead of an assumption.
        /// <para>
        /// The payload text is meant to amuse network administrators who capture the traffic, not
        /// to break the scan. It is therefore used where it works and replaced by a plain ping only
        /// where it does not.
        /// </para>
        /// </summary>
        /// <returns><see langword="true"/> if a ping with the custom payload can be sent.</returns>
        private async Task<bool> CustomPayloadSupportedAsync()
        {
            try
            {
                using Ping probe = new();
                await probe.SendPingAsync(IPAddress.Loopback, 300, buffer, pingOptions);
                return true;
            }
            catch (Exception ex) when (ex is PingException or SocketException or PlatformNotSupportedException)
            {
                return false;
            }
        }
    }
}
