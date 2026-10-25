// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using DnsClient;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    /// <summary>
    /// Resolves the host names of the targets forward (name to addresses) and compares the result
    /// with the scanned address.
    /// </summary>
    public class ScanningMethod_LookUp
    {
        /// <summary>Creates the forward lookup.</summary>
        public ScanningMethod_LookUp()
        {

        }

        /// <summary>Reports progress as (processed, responded, total, status).</summary>
        public event Action<int, int, int, ScanStatus> ProgressUpdated;

        /// <summary>Raised when a host name has been resolved.</summary>
        public event EventHandler<ScanTask_Finished_EventArgs>? Lookup_Task_Finished;

        /// <summary>Raised when all lookups of a run have finished.</summary>
        public event Action<ScanStatus>? Lookup_Finished;

        // The queries go directly to the DNS server known from the scope or, without one, to the
        // gateway, not to the system resolver (see docs/FEHLERGEDAECHTNIS.md, No. 8). A typical
        // gateway answers 32 concurrent queries in under 100 ms, so 16 leaves headroom.
        private static readonly SemaphoreSlim _semaphore = new SemaphoreSlim(16);

        /// <summary>How often a missing answer is requested again before the name counts as unresolvable.</summary>
        private const int QueryRetries = 3;

        /// <summary>How long each attempt waits for an answer; the reverse lookup uses the same values and explains them.</summary>
        private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(1);

        /// <summary>
        /// Total time budget per name across all retries; shorter than all retries together, the
        /// retries of the DNS client never run (see docs/FEHLERGEDAECHTNIS.md, No. 7).
        /// </summary>
        private static readonly TimeSpan QueryBudget =
            QueryTimeout * (QueryRetries + 1) + TimeSpan.FromMilliseconds(500);

        /// <summary>
        /// One client per set of name servers for the whole run, for the same reason as in
        /// <see cref="ScanningMethod_ReverseLookupToHostAndAlieases.ClientFor"/>.
        /// </summary>
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, LookupClient> _clients = new();

        private LookupClient ClientFor(IPToScan ipToScan)
        {
            List<string> servers = ipToScan.DNSServerList?
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim())
                .ToList() ?? [];

            return _clients.GetOrAdd(string.Join(",", servers), _ =>
            {
                LookupClientOptions options = servers.Count > 0 && servers.All(s => IPAddress.TryParse(s, out IPAddress? _))
                    ? new LookupClientOptions([.. servers.Select(s => new NameServer(IPAddress.Parse(s)))])
                    : new LookupClientOptions();

                options.Timeout = QueryTimeout;
                options.Retries = QueryRetries;
                options.UseCache = true;
                options.ThrowDnsErrors = false;

                // Ask in order, not at random: the list is a ranking. See the same setting in the
                // reverse lookup.
                options.UseRandomNameServer = false;

                return new LookupClient(options);
            });
        }

        /// <summary>
        /// Name servers that only timed out in this run, and the one that answered last. Both work
        /// as in the reverse lookup, which explains them in detail.
        /// </summary>
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> _silence = new();

        private const int SilentAfter = 3;

        private volatile string? _preferredServer;

        private bool IsKnownSilent(NameServer server) =>
            _silence.TryGetValue(server.Address.ToString(), out int misses) && misses >= SilentAfter;

        /// <summary>
        /// Asks exactly one server with its own time budget. A timeout is recorded; an answer
        /// makes the server the preferred one.
        /// </summary>
        private async Task<IPHostEntry?> AskOneAsync(NameServer server, string hostname)
        {
            try
            {
                using CancellationTokenSource oneCts =
                    CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                oneCts.CancelAfter(QueryBudget);

                IPHostEntry? entry = await SingleServerClientFor(server)
                    .GetHostEntryAsync(hostname)
                    .WaitAsync(oneCts.Token);

                _silence[server.Address.ToString()] = 0;

                if (entry is not null) _preferredServer = server.Address.ToString();

                return entry;
            }
            catch (OperationCanceledException) when (!_cts.Token.IsCancellationRequested)
            {
                _silence.AddOrUpdate(server.Address.ToString(), 1, (_, misses) => misses + 1);
                return null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>One client per single name server, reused like the clients above.</summary>
        private LookupClient SingleServerClientFor(NameServer dnsServer) =>
            _clients.GetOrAdd("single:" + dnsServer.Address, _ => new LookupClient(
                new LookupClientOptions([dnsServer])
                {
                    Timeout = QueryTimeout,
                    Retries = QueryRetries,
                    UseCache = true,
                    ThrowDnsErrors = false
                }));

        private int current = 0;
        private int responded = 0;
        private int total = 0;


        private CancellationTokenSource _cts = new CancellationTokenSource(); // Allows the scan to be cancelled.


        /// <summary>
        /// Cancels the running lookup and reports <see cref="ScanStatus.stopped"/>.
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
        /// Resolves the host name of every target that has one and reports the addresses found.
        /// </summary>
        /// <param name="IPs">The targets; entries without a host name are skipped.</param>
        public async Task LookupAsync(List<IPToScan> IPs)
        {
            StartNewScan();

            if (_cts.Token.IsCancellationRequested) return;

            current = 0;
            responded = 0;
            total = IPs.Count;
            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running);

            var tasks = new List<Task>();

            foreach (var ip in IPs)
            {
                if (_cts.Token.IsCancellationRequested) break;

                if (!string.IsNullOrEmpty(ip.HostName))
                {
                    tasks.Add(Task.Run(async () =>
                    {
                        await _semaphore.WaitAsync(); // Wait for a free slot.
                        try
                        {
                            await LookupTask(ip);                            
                        }
                        finally
                        {
                            _semaphore.Release();
                        }
                    }));
                }
            }

            try
            {
                await Task.WhenAll(tasks.Where(t => t != null));
            }
            catch (OperationCanceledException)
            {
                // Cancelled by StopScan.
            }

            
                Lookup_Finished?.Invoke(ScanStatus.finished);            
        }


        private async Task LookupTask(IPToScan ipToScan)
        {
            if (_cts.IsCancellationRequested) return;

            IPHostEntry _entry;
            try
            {
                LookupClient client = ClientFor(ipToScan);

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                cts.CancelAfter(QueryBudget);

                IPHostEntry? found = null;

                // First the server that resolved last.
                if (_preferredServer is { } preferredAddress)
                {
                    NameServer? preferred = client.NameServers
                        .FirstOrDefault(s => s.Address.ToString() == preferredAddress);

                    if (preferred is not null)
                    {
                        found = await AskOneAsync(preferred, ipToScan.HostnameWithDomain);
                    }
                }

                NameServer? leading = client.NameServers.FirstOrDefault();
                bool leadingSilent =
                    leading is not null && client.NameServers.Count > 1 && IsKnownSilent(leading);

                if (found is null && !leadingSilent)
                {
                    try
                    {
                        found = await client.GetHostEntryAsync(ipToScan.HostnameWithDomain)
                                            .WaitAsync(cts.Token);
                    }
                    catch (OperationCanceledException) when (!_cts.Token.IsCancellationRequested)
                    {
                        // The leading server is silent. The name is not lost: below, each server
                        // is asked on its own.
                        leadingSilent = true;
                        if (leading is not null)
                            _silence.AddOrUpdate(leading.Address.ToString(), 1, (_, misses) => misses + 1);
                    }
                }

                // Then each configured server on its own until one resolves the name; in a network
                // with several zones often only one of them knows it.
                if (found is null && client.NameServers.Count > 1)
                {
                    foreach (NameServer dnsServer in client.NameServers.Skip(leadingSilent ? 1 : 0))
                    {
                        if (_cts.Token.IsCancellationRequested) return;
                        if (IsKnownSilent(dnsServer)) continue;
                        if (dnsServer.Address.ToString() == _preferredServer) continue;

                        found = await AskOneAsync(dnsServer, ipToScan.HostnameWithDomain);
                        if (found is not null) break;
                    }
                }

                if (found is null) return;

                _entry = found;

                if (_cts.Token.IsCancellationRequested) return;

                bool _LookUpStatus = false;
                string _LookUpIPs = string.Empty;

                var addressList = _entry.AddressList.ToList();

                if (addressList.Count == 1)
                {
                    if (ipToScan.IPorHostname == addressList[0].ToString())
                    {
                        _LookUpStatus = true;
                    }
                    else
                    {
                        _LookUpStatus = false;
                        _LookUpIPs = addressList[0].ToString();
                    }
                }
                else if (addressList.Count > 1)
                {
                    _LookUpStatus = false;
                    _LookUpIPs = string.Join("\r\n", addressList);
                }
                else
                {
                    _LookUpIPs = "no IPs registered";
                }

                if (Lookup_Task_Finished != null)
                {
                    ipToScan.LookUpIPs = _LookUpIPs;
                    ipToScan.IP_HostEntry = _entry;
                    ipToScan.UsedScanMethod = ScanMethod.Lookup;

                    int respondedValue = Interlocked.Increment(ref responded);
                    ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running);

                    var scanTask_Finished = new ScanTask_Finished_EventArgs { ipToScan = ipToScan };
                    Lookup_Task_Finished(this, scanTask_Finished);
                }
            }
            catch (OperationCanceledException)
            {
                // Cancelled by StopScan.
            }
            catch (Exception)
            {
                // A failed lookup leaves the target without a result.
            }
            finally
            {
                // Count only once the query has been answered or has timed out; counting on
                // sending would fill the progress bar long before the actual end.
                int currentValue = Interlocked.Increment(ref current);
                ProgressUpdated?.Invoke(currentValue, responded, total, ScanStatus.running);
            }
        }


    }
}
