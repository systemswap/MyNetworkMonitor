// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net;
using DnsClient;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// What a single name server reported for an address.
    /// </summary>
    /// <param name="Server">The name server queried.</param>
    /// <param name="HostName">The name it returns for the address - empty if none.</param>
    /// <param name="Addresses">The addresses it returns for that name.</param>
    /// <param name="Error">Why the query failed, if it did; otherwise empty.</param>
    public sealed record DnsServerAnswer(
        string Server, string HostName, IReadOnlyList<string> Addresses, string Error)
    {
        /// <summary>The server did not answer at all.</summary>
        public bool Failed => Error.Length > 0;

        /// <summary>The server answered but does not know the address.</summary>
        public bool IsEmpty => !Failed && HostName.Length == 0;

        /// <summary>
        /// The reverse lookup leads to a name, but the forward lookup of that name
        /// does not lead back to the address. This case is only visible when both
        /// directions are checked.
        /// </summary>
        public bool RoundTripBroken { get; init; }

        /// <summary>The answer as one line of text, prefixed with the server.</summary>
        public string Text =>
            Failed ? $"{Server}: no answer ({Error})"
            : IsEmpty ? $"{Server}: does not know this address"
            : RoundTripBroken
                ? $"{Server}: {HostName}, but the name points back to " +
                  (Addresses.Count == 0 ? "nothing" : string.Join(", ", Addresses))
                : $"{Server}: {HostName}";
    }

    /// <summary>
    /// The result of a cross-check of one address across all name servers.
    /// </summary>
    /// <param name="Address">The address that was checked.</param>
    /// <param name="Answers">One answer per name server queried.</param>
    public sealed record DnsCrossCheckResult(
        string Address, IReadOnlyList<DnsServerAnswer> Answers)
    {
        /// <summary>
        /// The distinct names returned by the answering servers.
        /// More than one means they contradict each other.
        /// </summary>
        public IReadOnlyList<string> DistinctNames =>
            [.. Answers.Where(a => !a.Failed && !a.IsEmpty)
                       .Select(a => a.HostName)
                       .Distinct(StringComparer.OrdinalIgnoreCase)
                       .Order(StringComparer.OrdinalIgnoreCase)];

        /// <summary>Servers that answered but did not know the address.</summary>
        public IReadOnlyList<DnsServerAnswer> Silent => [.. Answers.Where(a => a.IsEmpty)];

        /// <summary>Servers that were not reachable at all.</summary>
        public IReadOnlyList<DnsServerAnswer> Unreachable => [.. Answers.Where(a => a.Failed)];

        /// <summary>Servers whose returned name does not point back to the address.</summary>
        public IReadOnlyList<DnsServerAnswer> Broken => [.. Answers.Where(a => a.RoundTripBroken)];

        /// <summary>
        /// There is something to report. Not every difference counts: if
        /// <em>no</em> server knows the address, that is no contradiction between
        /// them but simply a missing record - and the normal case on a home
        /// network.
        /// </summary>
        public bool HasMismatch =>
            DistinctNames.Count > 1
            || Broken.Count > 0
            || Unreachable.Count > 0
            || (DistinctNames.Count == 1 && Silent.Count > 0);

        /// <summary>The finding in one sentence - for the findings list.</summary>
        public string Summary
        {
            get
            {
                if (DistinctNames.Count > 1)
                {
                    return "The DNS servers disagree: " +
                           string.Join("; ", Answers.Where(a => !a.Failed && !a.IsEmpty)
                                                    .Select(a => $"{a.Server} says {a.HostName}"));
                }

                List<string> parts = [];

                if (DistinctNames.Count == 1 && Silent.Count > 0)
                {
                    parts.Add($"{string.Join(", ", Silent.Select(a => a.Server))} " +
                              $"{(Silent.Count == 1 ? "does" : "do")} not know the address, " +
                              $"while the others resolve it to {DistinctNames[0]}");
                }

                if (Broken.Count > 0)
                {
                    parts.Add($"{string.Join(", ", Broken.Select(a => a.Server))} " +
                              "returns a name that does not point back to this address");
                }

                if (Unreachable.Count > 0)
                {
                    parts.Add($"{string.Join(", ", Unreachable.Select(a => a.Server))} " +
                              $"did not answer at all");
                }

                return parts.Count == 0
                    ? "All DNS servers agree."
                    : string.Join(". ", parts) + ".";
            }
        }

        /// <summary>All answers, one per line - for the detail panel.</summary>
        public string Report => string.Join("\r\n", Answers.Select(a => a.Text));
    }

    /// <summary>
    /// Queries the same address at every known name server individually and
    /// presents the answers side by side.
    /// <para>
    /// The purpose is troubleshooting: as long as all servers agree, there is
    /// nothing to do. If they differ, <b>that difference is the finding</b> - and
    /// because every answer carries its server, it also shows which of them does
    /// not resolve cleanly.
    /// </para>
    /// <para>
    /// <b>Both directions</b> are checked. The reverse lookup alone misses the
    /// case in which all servers return the same name but that name points back
    /// to a different address - a stale forward record that looks correct on
    /// every server when viewed in isolation.
    /// </para>
    /// </summary>
    public static class DnsCrossCheck
    {
        /// <summary>
        /// How long to wait for a single server. Kept short: the queries run
        /// against several servers, and a silent server must not hold up the
        /// comparison - being silent is itself the answer.
        /// </summary>
        private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(2);

        /// <summary>
        /// Cross-checks one address across the given name servers. If none are
        /// given, the system's name servers are used.
        /// </summary>
        /// <param name="address">The IP address to look up.</param>
        /// <param name="servers">Name server addresses as text; invalid entries are ignored.</param>
        /// <param name="cancellationToken">Cancels all queries.</param>
        /// <returns>The answers of all servers; empty if no name server is known.</returns>
        /// <exception cref="ArgumentException"><paramref name="address"/> is null, empty or whitespace.</exception>
        public static async Task<DnsCrossCheckResult> RunAsync(
            string address, IReadOnlyList<string> servers, CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(address);

            List<IPAddress> resolvers = [.. servers
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Select(s => IPAddress.TryParse(s, out IPAddress? parsed) ? parsed : null)
                .Where(a => a is not null)
                .Select(a => a!)];

            if (resolvers.Count == 0) resolvers = [.. SystemResolvers()];

            if (resolvers.Count == 0)
            {
                return new DnsCrossCheckResult(address, []);
            }

            // Query the servers in parallel. Sequentially the timeouts add up:
            // five silent servers would mean ten seconds of a frozen user
            // interface.
            DnsServerAnswer[] answers = await Task.WhenAll(
                resolvers.Select(server => AskAsync(address, server, cancellationToken)));

            return new DnsCrossCheckResult(address, answers);
        }

        /// <summary>Runs the same check for several addresses, one after another.</summary>
        /// <param name="addresses">The IP addresses to look up.</param>
        /// <param name="servers">Name server addresses as text; invalid entries are ignored.</param>
        /// <param name="cancellationToken">Cancels the remaining checks.</param>
        /// <returns>One result per address, in input order.</returns>
        public static async Task<List<DnsCrossCheckResult>> RunAsync(
            IEnumerable<string> addresses, IReadOnlyList<string> servers,
            CancellationToken cancellationToken = default)
        {
            List<DnsCrossCheckResult> results = [];

            foreach (string address in addresses)
            {
                cancellationToken.ThrowIfCancellationRequested();
                results.Add(await RunAsync(address, servers, cancellationToken));
            }

            return results;
        }

        /// <summary>
        /// One server, both directions. First the address to the name, then the
        /// name back to the addresses - both at the same server, otherwise two
        /// different sources of information would be compared.
        /// </summary>
        private static async Task<DnsServerAnswer> AskAsync(
            string address, IPAddress server, CancellationToken cancellationToken)
        {
            string text = server.ToString();

            try
            {
                LookupClient client = new(new LookupClientOptions(new NameServer(server))
                {
                    Timeout = QueryTimeout,
                    Retries = 1,

                    // Every server gets its own query. A hit from the cache
                    // would defeat the purpose of the check.
                    UseCache = false,

                    // A missing record is an answer, not an error.
                    ThrowDnsErrors = false
                });

                using CancellationTokenSource cts =
                    CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(QueryTimeout);

                IPHostEntry? reverse = await client.GetHostEntryAsync(address).WaitAsync(cts.Token);

                string hostName = reverse?.HostName ?? string.Empty;
                if (hostName.Length == 0)
                {
                    return new DnsServerAnswer(text, string.Empty, [], string.Empty);
                }

                // The way back: does the name point to this address again?
                IPHostEntry? forward = await client.GetHostEntryAsync(hostName).WaitAsync(cts.Token);

                List<string> addresses = [.. (forward?.AddressList ?? [])
                    .Select(a => a.ToString())
                    .Distinct(StringComparer.OrdinalIgnoreCase)];

                bool pointsBack = addresses.Any(a =>
                    string.Equals(a, address, StringComparison.OrdinalIgnoreCase));

                return new DnsServerAnswer(text, hostName, addresses, string.Empty)
                {
                    RoundTripBroken = !pointsBack
                };
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                // A server that does not answer is a finding, not a reason to
                // drop the comparison of the remaining servers.
                return new DnsServerAnswer(text, string.Empty, [], Short(ex.Message));
            }
        }

        /// <summary>The name servers the machine itself uses.</summary>
        private static IEnumerable<IPAddress> SystemResolvers()
        {
            try
            {
                // NameServer.Address is the address as text - the query needs
                // it as an IPAddress again.
                return NameServer.ResolveNameServers()
                    .Select(n => n.Address)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Select(a => IPAddress.TryParse(a, out IPAddress? parsed) ? parsed : null)
                    .Where(a => a is not null)
                    .Select(a => a!);
            }
            catch (Exception)
            {
                return [];
            }
        }

        /// <summary>
        /// Error messages of the library span several lines. In a table that
        /// breaks the row without saying more than the first sentence.
        /// </summary>
        private static string Short(string message)
        {
            string first = message.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                                  .FirstOrDefault() ?? "timeout";

            return first.Length > 90 ? first[..90] + "..." : first;
        }
    }
}
