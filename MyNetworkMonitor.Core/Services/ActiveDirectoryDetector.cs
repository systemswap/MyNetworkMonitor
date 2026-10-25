using System.Net.NetworkInformation;
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
            List<string> candidates = [.. CandidateDomains()];
            if (candidates.Count == 0) return false;

            using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            limit.CancelAfter(OverallTimeout);

            try
            {
                IEnumerable<Task<bool>> lookups = candidates.Select(domain => HasDomainControllerAsync(domain, limit.Token));
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
        private static async Task<bool> HasDomainControllerAsync(string domain, CancellationToken cancellationToken)
        {
            try
            {
                LookupClient client = new(new LookupClientOptions
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
        /// The domain names to check: the machine's global DNS domain and the
        /// DNS suffixes of active physical adapters. Virtual adapters (Docker,
        /// libvirt, VPN, WSL) are skipped - they carry no DHCP-assigned domain,
        /// at most an inherited or empty suffix that only slows the check down
        /// and never confirms it.
        /// </summary>
        private static IEnumerable<string> CandidateDomains()
        {
            HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

            string globalDomain = IPGlobalProperties.GetIPGlobalProperties().DomainName;
            if (!string.IsNullOrWhiteSpace(globalDomain) && seen.Add(globalDomain))
            {
                yield return globalDomain;
            }

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

                string suffix;
                try
                {
                    suffix = nic.GetIPProperties().DnsSuffix;
                }
                catch (NetworkInformationException) { continue; }
                catch (PlatformNotSupportedException) { continue; }

                if (!string.IsNullOrWhiteSpace(suffix) && seen.Add(suffix))
                {
                    yield return suffix;
                }
            }
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
