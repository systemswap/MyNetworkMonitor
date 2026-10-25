using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using MyNetworkMonitor.Core.Services;
namespace MyNetworkMonitor
{
    /// <summary>
    /// Resolves MAC addresses by ARP request and reads the ARP table of the system.
    /// </summary>
    public class ScanningMethod_ARP
    {
        private readonly IArpProvider _arp;

        /// <summary>
        /// Creates the ARP scanner.
        /// </summary>
        /// <param name="arpProvider">The platform ARP access; <see langword="null"/> uses <see cref="PlatformServices.Arp"/>.</param>
        /// <param name="routingProvider">
        /// Not evaluated: the targets are preselected by the networks of the active adapters, not by
        /// the routing table. The parameter keeps existing callers compiling.
        /// </param>
        public ScanningMethod_ARP(IArpProvider? arpProvider = null, IRoutingProvider? routingProvider = null)
        {
            // Without injection, the platform providers registered by the start-up project are used;
            // the scan logic is the same either way.
            _arp = arpProvider ?? PlatformServices.Arp;
        }
        
        
        
        /// <summary>
        /// Maximum number of concurrent resolutions. On Linux each one starts its own child
        /// processes, so the value is lower than the limit of the purely in-process methods.
        /// </summary>
        private const int MaxConcurrentResolutions = 32;

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
        




        SupportMethods support = new SupportMethods();

        /// <summary>Reports progress as (processed, responded, total, status).</summary>
        public event Action<int, int, int, ScanStatus> ProgressUpdated;

        /// <summary>Raised for every entry of the ARP table read by <see cref="ARP_A"/>.</summary>
        public event EventHandler<ScanTask_Finished_EventArgs>? ARP_A_newDevice;

        /// <summary>Raised when the ARP request for one target has finished.</summary>
        public event EventHandler<ScanTask_Finished_EventArgs> ARP_Request_Task_Finished;

        /// <summary>Raised when all ARP requests of a run have finished.</summary>
        public event Action<ScanStatus> ARP_Request_Finished;


        


        /// <summary>
        /// Sends an ARP request to every target in a locally attached network and reports MAC
        /// address and vendor of each answering device.
        /// </summary>
        /// <param name="ipsToRefresh">The targets; addresses outside the local networks are skipped.</param>
        public async Task SendARPRequestAsync(List<IPToScan> ipsToRefresh)
        {
            StartNewScan();

            if (_cts.Token.IsCancellationRequested) return;
            
            current = 0;
            responded = 0;
            total = 0;
            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running);

            List<IPToScan> filtered;
            try
            {
                filtered = await GetIPsInSameVLANAsync(ipsToRefresh).WaitAsync(_cts.Token);
            }
            catch (TaskCanceledException)
            {
                Debug.WriteLine("Task für GetIPsInSameVLANAsync wurde abgebrochen.");
                return;
            }

            // An empty or single-entry result is used as is and does not fall back to the full
            // list: restoring the list would lift the restriction exactly when it matters most,
            // when none of the targets is reachable locally. An empty result is an answer.
            total = filtered.Count;
            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running);

            try
            {
                // Limited: without a limit a /24 starts up to 254 resolutions at once. On Linux each
                // one runs its own "ping" and "ip neigh" child process (see LinuxArpProvider), which
                // means 500+ processes at a time. The ping scan has the same limit for threads.
                ParallelOptions options = new()
                {
                    MaxDegreeOfParallelism = MaxConcurrentResolutions,
                    CancellationToken = _cts.Token
                };

                await Parallel.ForEachAsync(filtered.Where(ip => !string.IsNullOrEmpty(ip.IPorHostname)), options,
                    async (ip, token) =>
                    {
                        token.ThrowIfCancellationRequested();
                        await ArpRequestTask(ip);
                    });
            }
            catch (OperationCanceledException)
            {
                Debug.WriteLine("Scan wurde abgebrochen!");
            }
            finally
            {
                // Always report the scan as finished.
                ARP_Request_Finished?.Invoke(ScanStatus.finished);
            }
        }


        private async Task ArpRequestTask(IPToScan ipToScan)
        {
            _cts.Token.ThrowIfCancellationRequested();

            if (_cts.Token.IsCancellationRequested) return;

            IPAddress ipAddress = IPAddress.Parse(ipToScan.IPorHostname);

            string? mac = await _arp.ResolveMacAsync(ipAddress, _cts.Token);

            // Count only once the request has been answered or has timed out; counting on
            // sending would fill the progress bar far too early.
            int currentValue = Interlocked.Increment(ref current);
            ProgressUpdated?.Invoke(currentValue, responded, total, ScanStatus.running);

            if (_cts.Token.IsCancellationRequested) return;

            if (mac == null)
            {
                ARP_Request_Task_Finished?.Invoke(this, new ScanTask_Finished_EventArgs()
                {
                    ipToScan = { UsedScanMethod = ScanMethod.failed }
                });
            }
            else
            {
                if (ARP_Request_Task_Finished != null)
                {
                    ipToScan.ARPStatus = true;
                    ipToScan.MAC = mac;
                    ipToScan.Vendor = support.GetVendorFromMac(mac).First();
                    ipToScan.UsedScanMethod = ScanMethod.ARPRequest;

                    int respondedValue = Interlocked.Increment(ref responded);
                    ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running);

                    ARP_Request_Task_Finished(this, new ScanTask_Finished_EventArgs() { ipToScan = ipToScan });
                }
            }
        }


















        /// <summary>
        /// Reads the ARP table of the system and reports every entry as a found device (with MAC address and vendor).
        /// </summary>
        /// <param name="IPs">The addresses of the scan; entries for other addresses are reported as new devices.</param>
        /// <exception cref="Exception">Reading the ARP table failed.</exception>
        public async Task ARP_A(List<IPToScan> IPs)
        {
            StartNewScan();

            try
            {
                var arpTable = await _arp.GetArpTableAsync(_cts.Token);

                foreach (var entry in arpTable)
                {
                    if (_cts.Token.IsCancellationRequested) break;

                    string ip = entry.IpAddress;
                    string mac = entry.MacAddress;
                    var vendor = support.GetVendorFromMac(mac);

                    if (ARP_A_newDevice != null)
                    {
                        IPToScan ipToScan;

                        try
                        {
                            ipToScan = IPs.Where(i => string.Equals(i.IPorHostname, ip)).ToList()[0];
                            ipToScan.ARPStatus = true;
                            ipToScan.MAC = mac;
                            ipToScan.Vendor = vendor[0];
                        }
                        catch (Exception)
                        {
                            ipToScan = new IPToScan();
                            ipToScan.ARPStatus = true;
                            ipToScan.IPorHostname = ip;
                            ipToScan.MAC = mac;
                            ipToScan.Vendor = vendor[0];
                            ipToScan.IPGroupDescription = "not specified";
                            ipToScan.DeviceDescription = "not specified";
                        }

                        ipToScan.UsedScanMethod = ScanMethod.ARP_A;

                        ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
                        scanTask_Finished.ipToScan = ipToScan;

                        Task.Run(() => ARP_A_newDevice(this, scanTask_Finished));
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Reading the ARP table failed", ex);
            }
        }

        /// <summary>
        /// Flushes the ARP cache of the system.
        /// </summary>
        /// <returns><see langword="true"/> if the cache was flushed.</returns>
        public bool DeleteARPCache()
        {
            return _arp.FlushArpCache();
        }


















        /// <summary>
        /// Restricts the target list to the addresses ARP can answer at all.
        /// <para>
        /// An ARP request stays in the local network segment: it is sent as a broadcast and only
        /// hosts attached to that segment receive it. Nothing behind a router can answer, so every
        /// such request only waits for the timeout. What counts is therefore where an
        /// <em>active</em> adapter is and which mask it carries, not where the routing table points.
        /// </para>
        /// </summary>
        /// <param name="ipsToRefresh">The targets to filter.</param>
        /// <returns>
        /// The targets in a network of an active adapter or already present in the ARP table; all
        /// targets if neither an adapter nor a table entry is known.
        /// </returns>
        public async Task<List<IPToScan>> GetIPsInSameVLANAsync(List<IPToScan> ipsToRefresh)
        {
            List<LocalSubnet> subnets = GetLocalSubnets();

            // Plus what is already resolved: an entry in the table proves that the address was
            // reachable.
            HashSet<string> knownIps = new(await GetLocalArpTableAsync(), StringComparer.OrdinalIgnoreCase);

            if (subnets.Count == 0 && knownIps.Count == 0)
            {
                // No active IPv4 adapter and no table: nothing is known, so try everything rather
                // than nothing.
                return ipsToRefresh;
            }

            List<IPToScan> reachable = [.. ipsToRefresh.Where(ip => IsReachableByArp(ip.IPorHostname, subnets, knownIps))];

            Debug.WriteLine($"ARP: {reachable.Count} von {ipsToRefresh.Count} Zielen liegen an einem aktiven Adapter.");

            return reachable;
        }

        /// <summary>A network an active adapter of this computer is attached to.</summary>
        private sealed record LocalSubnet(byte[] Address, byte[] Mask)
        {
            public bool Contains(byte[] candidate)
            {
                for (int i = 0; i < 4; i++)
                {
                    if ((candidate[i] & Mask[i]) != (Address[i] & Mask[i])) return false;
                }

                return true;
            }
        }

        /// <summary>
        /// The IPv4 networks of all operational adapters. Loopback and tunnel adapters are
        /// excluded; there is no one to reach by broadcast there.
        /// </summary>
        private static List<LocalSubnet> GetLocalSubnets()
        {
            List<LocalSubnet> subnets = [];

            foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (adapter.OperationalStatus != OperationalStatus.Up) continue;

                if (adapter.NetworkInterfaceType is NetworkInterfaceType.Loopback
                                                 or NetworkInterfaceType.Tunnel)
                {
                    continue;
                }

                foreach (UnicastIPAddressInformation address in adapter.GetIPProperties().UnicastAddresses)
                {
                    if (address.Address.AddressFamily != AddressFamily.InterNetwork) continue;

                    // Without a mask the network cannot be determined; a guessed /24 would
                    // reintroduce the error this filter prevents.
                    IPAddress? mask = address.IPv4Mask;
                    if (mask == null || mask.Equals(IPAddress.Any)) continue;

                    subnets.Add(new LocalSubnet(address.Address.GetAddressBytes(), mask.GetAddressBytes()));
                }
            }

            return subnets;
        }

        private static bool IsReachableByArp(string? address, List<LocalSubnet> subnets, HashSet<string> knownIps)
        {
            if (string.IsNullOrWhiteSpace(address)) return false;

            if (knownIps.Contains(address)) return true;

            // ARP exists only for IPv4. Host names and IPv6 addresses belong to other methods;
            // parsing them here would throw and abort the whole run.
            if (!IPAddress.TryParse(address, out IPAddress? parsed)
                || parsed.AddressFamily != AddressFamily.InterNetwork)
            {
                return false;
            }

            byte[] bytes = parsed.GetAddressBytes();

            return subnets.Any(subnet => subnet.Contains(bytes));
        }


        private async Task<List<string>> GetLocalArpTableAsync()
        {
            var table = await _arp.GetArpTableAsync();
            return table.Select(e => e.IpAddress).ToList();
        }


    }
}