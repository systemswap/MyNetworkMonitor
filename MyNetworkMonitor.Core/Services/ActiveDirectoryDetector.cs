// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using DnsClient;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Determines whether an Active Directory domain controller is reachable on the
    /// current network - the only cross-platform, protocol-based answer to the
    /// question "is this machine currently on a corporate network".
    /// <para>
    /// Queries DNS for the well-known AD service record
    /// <c>_ldap._tcp.dc._msdcs.&lt;domain&gt;</c> (RFC 2782 SRV record, defined by
    /// Microsoft for domain controller location) - the same path every domain-joined
    /// Windows machine uses to locate its own domain controller. If it resolves, a
    /// real DC is on the network; otherwise not. Known IP ranges ("10.", "172.") are
    /// not used: they occur on home networks (mesh routers, Docker, VPN, WSL) just as
    /// in corporate networks and are no reliable distinguishing feature. A resolvable
    /// DC SRV record, by contrast, practically never occurs on a private network.
    /// See docs/FEHLERGEDAECHTNIS.md, No. 1.
    /// </para>
    /// <para>
    /// Privacy: the query goes to the name servers of the adapters, but not to
    /// the large public resolvers (<see cref="IsPublicResolver"/>), which never
    /// know an internal domain controller and would only learn the domain name;
    /// and it is not made for suffixes that home routers and the standards
    /// reserve for local names (<see cref="IsLocalSuffix"/>). Company networks
    /// are still checked whatever addresses their name servers have - some run
    /// them on public address ranges of their own. See
    /// docs/FEHLERGEDAECHTNIS.md, No. 26.
    /// </para>
    /// <para>
    /// Deliberately does not rely on the device's own domain membership
    /// (<c>Domain.GetComputerDomain()</c> on Windows): that only answers "has this
    /// device ever joined a domain", not "is it on that network right now" - a
    /// domain-joined laptop in a home office would produce the same false positive
    /// as an IP-range heuristic, just for a different reason. The SRV query requires
    /// a currently reachable peer and therefore answers the right question.
    /// </para>
    /// </summary>
    public static class ActiveDirectoryDetector
    {
        /// <summary>
        /// Timeout per candidate domain. Kept short: a name server that does not
        /// know this record either answers quickly with NXDOMAIN or not at all -
        /// and "not at all" must not noticeably delay application startup.
        /// </summary>
        private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(1.5);

        /// <summary>
        /// Upper bound for the entire check, regardless of how many candidate
        /// domains exist. This clock counts, not the sum of the individual
        /// timeouts - otherwise several slow name servers in a row could still
        /// delay startup.
        /// </summary>
        private static readonly TimeSpan OverallTimeout = TimeSpan.FromSeconds(2.5);

        /// <summary>
        /// Synchronous facade for callers such as <see cref="IEnterpriseEnvironment"/>
        /// whose interface does not provide an asynchronous check.
        /// <para>
        /// Runs through <see cref="Task.Run(Func{Task})"/> instead of blocking directly,
        /// so the check has no SynchronizationContext it would have to return to.
        /// Blocking on work that resumes on a captured context deadlocks startup
        /// (the web engine initialization is known to hang this way).
        /// </para>
        /// </summary>
        /// <returns><c>true</c> if a domain controller answered within the time limit.</returns>
        public static bool DomainControllerReachable()
        {
            try
            {
                return Task.Run(() => DomainControllerReachableAsync(CancellationToken.None))
                    .GetAwaiter().GetResult();
            }
            catch (Exception)
            {
                // A timeout or any other error means "no corporate network" -
                // and must certainly not crash startup.
                return false;
            }
        }

        /// <summary>
        /// Queries the DC SRV record for every candidate domain in parallel, bounded
        /// by an overall time limit.
        /// </summary>
        /// <param name="cancellationToken">Cancels the check from the outside.</param>
        /// <returns><c>true</c> if at least one candidate domain has a reachable domain controller.</returns>
        public static async Task<bool> DomainControllerReachableAsync(CancellationToken cancellationToken)
        {
            List<NetworkInterface> adapters = [.. RealAdapters()];
            List<string> candidates = [.. CandidateDomains(adapters)];
            List<IPAddress> nameServers = [.. NameServers()];
            if (candidates.Count == 0 || nameServers.Count == 0) return false;

            using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            limit.CancelAfter(OverallTimeout);

            try
            {
                IEnumerable<Task<bool>> lookups = candidates.Select(domain => HasDomainControllerAsync(domain, nameServers, limit.Token));
                bool[] results = await Task.WhenAll(lookups);
                return results.Any(found => found);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                // Only the internal time limit expired, no external cancellation -
                // "no DC found" is the correct answer.
                return false;
            }
        }

        /// <summary>
        /// A single SRV query. No match, no server or a timeout -
        /// all count equally as "no domain controller here".
        /// </summary>
        private static async Task<bool> HasDomainControllerAsync(string domain, IReadOnlyList<IPAddress> nameServers, CancellationToken cancellationToken)
        {
            try
            {
                LookupClient client = new(new LookupClientOptions([.. nameServers])
                {
                    Timeout = QueryTimeout,
                    Retries = 0,
                    UseCache = false,
                    ThrowDnsErrors = false
                });

                using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(QueryTimeout);

                IDnsQueryResponse response = await client.QueryAsync(
                    $"_ldap._tcp.dc._msdcs.{domain}", QueryType.SRV, cancellationToken: cts.Token);

                return !response.HasError && response.Answers.SrvRecords().Any();
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// The active physical adapters. Virtual adapters (Docker, libvirt, VPN,
        /// WSL) are skipped - they carry no DHCP-assigned domain, at most an
        /// inherited or empty suffix that only slows the check down and never
        /// confirms it.
        /// </summary>
        private static IEnumerable<NetworkInterface> RealAdapters()
        {
            NetworkInterface[] interfaces;
            try
            {
                interfaces = NetworkInterface.GetAllNetworkInterfaces();
            }
            catch (NetworkInformationException)
            {
                yield break;
            }

            foreach (NetworkInterface nic in interfaces)
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
                if (IsVirtualAdapter(nic.Name)) continue;
                yield return nic;
            }
        }

        /// <summary>
        /// The domain names to check: the machine's global DNS domain and the
        /// DNS suffixes of the adapters, without the local suffixes of
        /// <see cref="IsLocalSuffix"/>.
        /// </summary>
        private static IEnumerable<string> CandidateDomains(IEnumerable<NetworkInterface> adapters)
        {
            HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

            string globalDomain = IPGlobalProperties.GetIPGlobalProperties().DomainName;
            if (!string.IsNullOrWhiteSpace(globalDomain) && !IsLocalSuffix(globalDomain) && seen.Add(globalDomain))
            {
                yield return globalDomain;
            }

            foreach (NetworkInterface nic in adapters)
            {
                string suffix;
                try
                {
                    suffix = nic.GetIPProperties().DnsSuffix;
                }
                catch (NetworkInformationException) { continue; }
                catch (PlatformNotSupportedException) { continue; }

                if (!string.IsNullOrWhiteSpace(suffix) && !IsLocalSuffix(suffix) && seen.Add(suffix))
                {
                    yield return suffix;
                }
            }
        }

        /// <summary>
        /// The name servers of all active adapters, without the public resolvers
        /// of <see cref="IsPublicResolver"/>. Virtual adapters count here: the
        /// name server of a company VPN is what finds the domain controller from
        /// a home office.
        /// </summary>
        private static IEnumerable<IPAddress> NameServers()
        {
            NetworkInterface[] interfaces;
            try
            {
                interfaces = NetworkInterface.GetAllNetworkInterfaces();
            }
            catch (NetworkInformationException)
            {
                yield break;
            }

            HashSet<IPAddress> seen = [];
            foreach (NetworkInterface nic in interfaces)
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;

                IPAddressCollection servers;
                try
                {
                    servers = nic.GetIPProperties().DnsAddresses;
                }
                catch (NetworkInformationException) { continue; }
                catch (PlatformNotSupportedException) { continue; }

                foreach (IPAddress server in servers)
                {
                    if (!IsPublicResolver(server) && seen.Add(server)) yield return server;
                }
            }
        }

        /// <summary>
        /// The anycast addresses of the large public resolvers (Google Public DNS,
        /// Cloudflare, Quad9, OpenDNS, as published by their operators). None of
        /// them can know the domain controller of an internal domain, so asking
        /// them never finds one and only hands them the domain name.
        /// </summary>
        private static readonly HashSet<IPAddress> PublicResolvers =
        [
            .. new[]
            {
                "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
                "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",
                "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9",
                "208.67.222.222", "208.67.220.220", "2620:119:35::35", "2620:119:53::53",
            }.Select(IPAddress.Parse),
        ];

        /// <summary>Whether a name server is one of the large public resolvers, which are not asked.</summary>
        /// <param name="address">The name server address.</param>
        /// <returns><c>true</c> if the server is not asked.</returns>
        internal static bool IsPublicResolver(IPAddress address) =>
            PublicResolvers.Contains(address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address);

        /// <summary>
        /// Suffixes under which no company runs its domain: the names home
        /// routers hand out as a whole (<c>fritz.box</c>, <c>speedport.ip</c>,
        /// <c>lan</c>, <c>home</c>, <c>localdomain</c>, <c>local</c>),
        /// <c>home.arpa</c> and below it (RFC 8375), and the top-level domains
        /// reserved for tests and documentation (<c>localhost</c>,
        /// <c>invalid</c>, <c>test</c>, <c>example</c>, RFC 6761).
        /// <para>
        /// Only whole names: many companies run their Active Directory under
        /// <c>.local</c> or <c>.lan</c> (for example <c>company.local</c>), and
        /// skipping those endings would hide exactly these networks.
        /// </para>
        /// </summary>
        /// <param name="suffix">The DNS suffix or domain.</param>
        /// <returns><c>true</c> if the suffix is not checked.</returns>
        internal static bool IsLocalSuffix(string suffix)
        {
            string name = suffix.Trim().TrimEnd('.').ToLowerInvariant();
            if (name.Length == 0) return true;
            if (name is "fritz.box" or "speedport.ip" or "lan" or "home" or "localdomain" or "local" or "home.arpa") return true;
            if (name.EndsWith(".home.arpa", StringComparison.Ordinal)) return true;

            string last = name[(name.LastIndexOf('.') + 1)..];
            return last is "localhost" or "invalid" or "test" or "example";
        }

        /// <summary>
        /// Adapter names that never carry a DHCP-assigned corporate suffix:
        /// container and hypervisor bridges, VPN and tunnel interfaces. Their
        /// presence is what makes IP-range heuristics produce false positives
        /// (for example <c>docker0</c> with <c>172.17.0.1</c> matches any
        /// "172." check on every home machine running Docker).
        /// </summary>
        private static bool IsVirtualAdapter(string name)
        {
            string lower = name.ToLowerInvariant();

            return lower.StartsWith("docker") || lower.StartsWith("veth")
                || lower.StartsWith("virbr") || lower.StartsWith("br-")
                || lower.StartsWith("vmnet") || lower.StartsWith("vboxnet")
                || lower.StartsWith("tun") || lower.StartsWith("tap")
                || lower.StartsWith("wg") || lower.StartsWith("utun")
                || lower.StartsWith("zt");
        }
    }
}
