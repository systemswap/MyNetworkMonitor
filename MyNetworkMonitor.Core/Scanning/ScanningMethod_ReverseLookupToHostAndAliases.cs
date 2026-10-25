// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using DnsClient;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace MyNetworkMonitor
{
    /// <summary>
    /// Resolves the addresses of the targets backwards (PTR) into host name, domain and aliases.
    /// </summary>
    public class ScanningMethod_ReverseLookupToHostAndAlieases
    {
        /// <summary>Creates the reverse lookup.</summary>
        public ScanningMethod_ReverseLookupToHostAndAlieases()
        {

        }

        /// <summary>Reports progress as (sent, responded, total, status).</summary>
        public event Action<int, int, int, ScanStatus> ProgressUpdated;

        /// <summary>
        /// Raised for every resolved address; the event arguments are <see langword="null"/> if the
        /// address could not be resolved.
        /// </summary>
        public event EventHandler<ScanTask_Finished_EventArgs>? GetHostAliases_Task_Finished;

        /// <summary>Raised when all lookups of a run have finished.</summary>
        public event Action<ScanStatus>? GetHostAliases_Finished;



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
        /// Resolves every target address backwards and reports host name, domain and aliases.
        /// </summary>
        /// <param name="IPs">The targets.</param>
        /// <param name="isDeepDNSServerScan">
        /// <see langword="true"/> to additionally ask every configured DNS server on its own and
        /// record which one resolves the address.
        /// </param>
        public async Task GetHost_Aliases(List<IPToScan> IPs, bool isDeepDNSServerScan)
        {

            StartNewScan();


            current = 0;
            responded = 0;
            total = IPs.Count;

            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running);


            if (_cts.Token.IsCancellationRequested) return; // Stopped right after the start.


            if (IPs.Count == 0)
            {
                return;
            }

            var tasks = new List<Task>();


            // Limited concurrency: a small DNS server (router or NAS) loses most UDP packets under a
            // burst of 50 concurrent PTR queries before the timeout expires. Measured on a /24 with
            // about 33 devices: 50 concurrent queries returned 4 names, 8 (with the timing below)
            // returned all 32 reachable ones, in a fraction of the time of sequential queries.
            // See docs/FEHLERGEDAECHTNIS.md, No. 7.
            SemaphoreSlim semaphore = new SemaphoreSlim(MaxConcurrentLookups);

            foreach (IPToScan ip in IPs)
            {
                if (_cts.Token.IsCancellationRequested) return;



                var task = Task.Run(async () =>
                {
                    await semaphore.WaitAsync();
                    try
                    {
                        await ReverseLookupToHostAndAliases(ip, isDeepDNSServerScan);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }, _cts.Token);

                tasks.Add(task);
            }

            try
            {
                await Task.WhenAll(tasks.Where(t => t != null));
            }
            catch { }

            GetHostAliases_Finished?.Invoke(ScanStatus.finished);
        }





        /// <summary>
        /// How many addresses are queried concurrently; values below 1 are raised to 1. See the
        /// comment at the semaphore in <see cref="GetHost_Aliases"/>.
        /// <para>
        /// Configurable: the default of 8 is gentle on a home router, while a name server in a
        /// corporate network handles many times that. The value is set from the settings.
        /// </para>
        /// </summary>
        public int MaxConcurrentLookups
        {
            get => _maxConcurrentLookups;
            set => _maxConcurrentLookups = value > 0 ? value : 1;
        }

        private int _maxConcurrentLookups = 8;

        /// <summary>How often a missing answer is requested again before the address counts as "no PTR".</summary>
        private const int QueryRetries = 3;

        /// <summary>
        /// How long each attempt waits for an answer. Kept short: a reverse lookup that takes two
        /// seconds does not succeed after ten either. <see cref="QueryRetries"/> matters more than a
        /// long wait, because a small DNS server makes up for lost packets with a second chance
        /// shortly afterwards rather than with more patience on the first attempt.
        /// </summary>
        private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(1);

        /// <summary>
        /// Total time budget per address across all retries. The outer cancellation
        /// (<see cref="CancellationTokenSource.CancelAfter(TimeSpan)"/>) must allow more time than
        /// <see cref="QueryTimeout"/> alone; otherwise it aborts the query during the first attempt
        /// and the retries configured in the client never run (see docs/FEHLERGEDAECHTNIS.md, No. 7).
        /// </summary>
        private static readonly TimeSpan QueryBudget =
            QueryTimeout * (QueryRetries + 1) + TimeSpan.FromMilliseconds(500);

        /// <summary>
        /// One client per set of name servers for the whole run.
        /// <para>
        /// Each <see cref="LookupClient"/> has its own cache. A client created per query always
        /// starts with an empty cache, and the same zone is queried hundreds of times; a reused
        /// client keeps its cache for the whole run.
        /// </para>
        /// </summary>
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, LookupClient> _clients = new();

        /// <summary>
        /// Name servers that only timed out in this run, with the number of their failed attempts.
        /// <para>
        /// A server that is not a name server at all, such as a gateway entered as a fallback,
        /// would otherwise cost the full time budget for <em>every</em> address. After
        /// <see cref="SilentAfter"/> failed attempts without a single answer it is skipped for the
        /// rest of the run; an answer resets the counter at once, so a short outage does not lock
        /// out a usable server.
        /// </para>
        /// </summary>
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> _silence = new();

        /// <summary>Number of consecutive failed attempts after which a server counts as "not answering".</summary>
        private const int SilentAfter = 3;

        /// <summary>
        /// The server that last returned a name. It is asked first for the next address.
        /// <para>
        /// In a network with several name servers often only one knows the zone in question.
        /// Remembering it turns the search for the first address into a single query for all
        /// following ones. If it does <em>not</em> know a device, its rank stays the same: the full
        /// pass over all servers runs below, because that one device may well be in the zone of
        /// another server.
        /// </para>
        /// </summary>
        private volatile string? _preferredServer;

        private bool IsKnownSilent(NameServer server) =>
            _silence.TryGetValue(server.Address.ToString(), out int misses) && misses >= SilentAfter;

        private void NoteSilence(NameServer server) =>
            _silence.AddOrUpdate(server.Address.ToString(), 1, (_, misses) => misses + 1);

        private void NoteAnswered(NameServer server) =>
            _silence[server.Address.ToString()] = 0;

        /// <summary>
        /// Asks exactly one server with its own time budget. Returns the entry or <c>null</c>; a
        /// timeout is recorded, an answer resets the counter.
        /// </summary>
        private async Task<IPHostEntry?> AskOneAsync(NameServer server, string address)
        {
            try
            {
                using CancellationTokenSource oneCts =
                    CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                oneCts.CancelAfter(QueryBudget);

                IPHostEntry? entry = await SingleServerClientFor(server)
                    .GetHostEntryAsync(address)
                    .WaitAsync(oneCts.Token);

                NoteAnswered(server);

                if (entry is not null) _preferredServer = server.Address.ToString();

                return entry;
            }
            catch (OperationCanceledException) when (!_cts.Token.IsCancellationRequested)
            {
                NoteSilence(server);
                return null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        private LookupClient ClientFor(IPToScan ipToScan)
        {
            List<string> servers = ipToScan.DNSServerList?
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim())
                .ToList() ?? [];

            return _clients.GetOrAdd(string.Join(",", servers), _ =>
            {
                LookupClientOptions options;

                if (servers.Count > 0 && servers.All(s => IPAddress.TryParse(s, out IPAddress? _)))
                {
                    options = new LookupClientOptions([.. servers.Select(s => new NameServer(IPAddress.Parse(s)))]);
                }
                else
                {
                    // Without usable server addresses, the system's name servers are used.
                    // The scan normally supplies the scope's server or the gateway
                    // (see docs/FEHLERGEDAECHTNIS.md, No. 8).
                    options = new LookupClientOptions();
                }

                options.Timeout = QueryTimeout;
                options.Retries = QueryRetries;
                options.UseCache = true;

                // Ask in order, not at random: the list is a ranking, first the server of the scope
                // or the gateway, then the fallback behind it. With the default (random choice) the
                // order would be meaningless.
                options.UseRandomNameServer = false;

                // A missing entry is an answer, not an error; throwing it as an exception only
                // costs time.
                options.ThrowDnsErrors = false;

                return new LookupClient(options);
            });
        }

        /// <summary>
        /// One client per single name server, for the deep scan. Same reason as for
        /// <see cref="ClientFor"/>, keyed by server instead of by set of servers.
        /// </summary>
        private LookupClient SingleServerClientFor(NameServer dnsServer)
        {
            return _clients.GetOrAdd("single:" + dnsServer.Address, _ =>
            {
                LookupClientOptions options = new([dnsServer])
                {
                    Timeout = QueryTimeout,
                    Retries = QueryRetries,
                    UseCache = true,
                    ThrowDnsErrors = false
                };

                return new LookupClient(options);
            });
        }

        private async Task ReverseLookupToHostAndAliases(IPToScan ipToScan, bool isDeepDNSServerScan)
        {
            if (_cts.Token.IsCancellationRequested) return;

            try
            {
                LookupClient client = ClientFor(ipToScan);

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                // Must be QueryBudget, not QueryTimeout: otherwise this outer cancellation aborts the
                // query after the first attempt, before the client gets to its own retry, and the
                // configured retries have no effect (see docs/FEHLERGEDAECHTNIS.md, No. 7).
                cts.CancelAfter(QueryBudget);

                // Count the sent query. Together with "responded" and "total" this gives the
                // three-part display that shows how many queries are out and how many came back.
                int sentCount = Interlocked.Increment(ref current);
                ProgressUpdated?.Invoke(sentCount, responded, total, ScanStatus.running);

                // One query, no retry loop of its own: the client retries by itself and knows its
                // time limit. An additional loop would ask again and treat an address without a PTR
                // record, the normal case, as an error.
                IPHostEntry? _IPHostEntry = null;

                // First the server that last returned a name. For most addresses this is the only
                // query; the rest below applies only when this server does not know the device.
                if (_preferredServer is { } preferredAddress)
                {
                    NameServer? preferred = client.NameServers
                        .FirstOrDefault(s => s.Address.ToString() == preferredAddress);

                    if (preferred is not null)
                    {
                        _IPHostEntry = await AskOneAsync(preferred, ipToScan.IPorHostname);
                    }
                }

                // If the leading server has already been silent several times in this run, the
                // combined query is skipped; it would run into the same timeout. The remaining
                // servers are asked one by one below anyway.
                NameServer? leading = client.NameServers.FirstOrDefault();
                bool firstServerSilent =
                    leading is not null && client.NameServers.Count > 1 && IsKnownSilent(leading);

                try
                {
                    if (_IPHostEntry is null && !firstServerSilent)
                    {
                        _IPHostEntry = await client.GetHostEntryAsync(ipToScan.IPorHostname)
                                                   .WaitAsync(cts.Token);

                        if (leading is not null) NoteAnswered(leading);
                    }
                }
                catch (OperationCanceledException) when (!_cts.Token.IsCancellationRequested)
                {
                    firstServerSilent = true;
                    if (leading is not null) NoteSilence(leading);

                    // Only the budget of this one query has expired, so the first server did not
                    // answer. That is no reason to give up: below, every server gets its own
                    // attempt with its own budget.
                    //
                    // This timeout must not abort the whole resolution; otherwise a silent first
                    // server (such as a gateway that is no name server) costs every name in the run.
                }

                // If the first query returns no name, each configured server is asked on its own
                // until one resolves the address.
                //
                // Needed because the first query passes on to the next server only on a
                // *failure*; if a server answers "unknown", it stops. In a network with several
                // zones often only one of the servers knows the name, and without this pass the
                // result would depend on which server happens to be first.
                if (_IPHostEntry is null && client.NameServers.Count > 1)
                {
                    // A first server that was silent is not asked again here: it has just used up
                    // its budget, and a second attempt only doubles the wait per address. The order
                    // is fixed (UseRandomNameServer is off), so the first in the list is the one
                    // that just stayed silent.
                    foreach (NameServer dnsServer in client.NameServers.Skip(firstServerSilent ? 1 : 0))
                    {
                        if (_cts.Token.IsCancellationRequested) return;

                        // Skip servers that only stay silent and the preferred server that was
                        // just asked.
                        if (IsKnownSilent(dnsServer)) continue;
                        if (dnsServer.Address.ToString() == _preferredServer) continue;

                        IPHostEntry? single = await AskOneAsync(dnsServer, ipToScan.IPorHostname);

                        if (single is not null)
                        {
                            _IPHostEntry = single;
                            break;
                        }
                    }
                }

                    var results = new List<string>();

                if (isDeepDNSServerScan)
                {
                    // Check each DNS server on its own for whether it resolves this address. Each
                    // server gets its own time budget instead of sharing one with the query above
                    // and all other servers: with a shared budget, nothing is left for the later
                    // servers once more than one or two are configured, and they fail silently on
                    // the expired time rather than on a missing entry. The client is reused instead
                    // of being created per address, for the same reason as in ClientFor().
                    foreach (var dnsServer in client.NameServers)
                    {
                        try
                        {
                            LookupClient singleLookup = SingleServerClientFor(dnsServer);

                            using CancellationTokenSource serverCts =
                                CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                            serverCts.CancelAfter(QueryBudget);

                            var result = await singleLookup.GetHostEntryAsync(ipToScan.IPorHostname).WaitAsync(serverCts.Token);

                            if (result != null)
                            {
                                results.Add(dnsServer.Address.ToString().PadRight(17, ' ') + "\t-> " + result.HostName);
                            }
                            else
                            {
                                results.Add(dnsServer.Address.ToString().PadRight(17, ' ') + "\t-> nothing");
                            }


                        }
                        catch (Exception ex)
                        {

                        }
                    }
                }


                // Deliberately the cancellation of the run, not the time budget of this query:
                // because the servers after the first one have their own budgets, "cts" has often
                // expired here although a later server has already answered. Checking cts.Token
                // would throw away exactly that result.
                if (_cts.Token.IsCancellationRequested) return;


                if (_IPHostEntry == null)
                {
                    throw new Exception("IPHostEntry is null");
                }

                if (GetHostAliases_Task_Finished != null)
                {
                    // Split from two labels on, not only from three: a name such as "router.example"
                    // has only two and belongs split into host and domain, not entirely into the
                    // HostName field. See docs/FEHLERGEDAECHTNIS.md, No. 6.
                    if (_IPHostEntry.HostName.Split('.').ToList().Count > 1)
                    {
                        List<string> HostDomainSplit = new List<string>();
                        HostDomainSplit.AddRange(_IPHostEntry.HostName.ToString().Split(".", 2, StringSplitOptions.None).ToList());
                        ipToScan.HostName = (HostDomainSplit.Count >= 1) ? HostDomainSplit[0] : string.Empty;
                        ipToScan.Domain = (HostDomainSplit.Count >= 2) ? HostDomainSplit[1] : string.Empty;
                    }
                    else
                    {
                        ipToScan.HostName = _IPHostEntry.HostName;
                        ipToScan.Domain = string.Empty;
                    }

                    ipToScan.Aliases = (_IPHostEntry.Aliases != null) ? string.Join("\r\n", _IPHostEntry.Aliases) : string.Empty;

                    
                    ipToScan.DNSServerList = results;

                    ipToScan.UsedScanMethod = ScanMethod.ReverseLookup;

                    ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
                    scanTask_Finished.ipToScan = ipToScan;

                    int respondedValue = Interlocked.Increment(ref responded);
                    ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running);

                    GetHostAliases_Task_Finished(this, scanTask_Finished);
                }
            }
            catch (Exception ex)
            {
               GetHostAliases_Task_Finished(this, null);
            }
        }
    }
}
