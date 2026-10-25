// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Globalization;
using System.Net;
using MyNetworkMonitor.Core.Model;

namespace MyNetworkMonitor.Core.SatelliteLink
{
    /// <summary>
    /// A scan job as text.
    /// <para>
    /// Deliberately one line instead of a serialized settings tree: no option
    /// has to be transferred and maintained across versions individually, the
    /// job is readable in the log, and whatever the job does not mention stays
    /// at the satellite's default.
    /// </para>
    /// <para>
    /// Format:
    /// <code>
    /// scan ranges=10.0.0.1-10.0.0.254;198.51.100.0/24 methods=ping,arp
    ///      tcp=22,80,443 udp=161 timeout=2500 dns=10.0.0.1 gateway=10.0.0.1
    ///      group=IDF2
    /// </code>
    /// Only <c>scan</c> and <c>ranges</c> are required. Several ranges are
    /// separated by semicolons, lists within a field by commas.
    /// </para>
    /// </summary>
    public sealed class JobRequest
    {
        /// <summary>The ranges to scan.</summary>
        public List<ScanScope> Scopes { get; } = [];

        /// <summary>Identifiers of the scan methods. Empty means the satellite's default.</summary>
        public List<string> MethodIds { get; } = [];

        /// <summary>
        /// The methods that only query what has already been found.
        /// <para>
        /// Must be transferred, otherwise the satellite works differently from
        /// the same run done locally: port scan, service detection, NetBIOS and
        /// SMB would cover <em>all</em> addresses of the range instead of only
        /// the devices found. With 128 addresses and 83 devices, that is 45
        /// targets where every port runs into the timeout, the most expensive
        /// part of a run, for nothing.
        /// </para>
        /// </summary>
        public List<string> OnlyKnownFor { get; } = [];

        /// <summary>
        /// Whether the DNS cross-check only checks devices that answered in this
        /// run. <c>null</c> means the job does not say, so the satellite's
        /// default applies.
        /// </summary>
        public bool? CrossCheckOnlyKnown { get; private set; }

        /// <summary>TCP ports to scan. Empty means the satellite's default.</summary>
        public List<int> TcpPorts { get; } = [];

        /// <summary>UDP ports to scan. Empty means the satellite's default.</summary>
        public List<int> UdpPorts { get; } = [];

        /// <summary>Timeout per port in milliseconds, if specified.</summary>
        public int? TimeoutMs { get; private set; }

        /// <summary>Plain-text reason if the job could not be read; otherwise <c>null</c>.</summary>
        public string? Problem { get; private set; }

        /// <summary>True if the job was read without problems and names at least one range.</summary>
        public bool IsValid => Problem is null && Scopes.Count > 0;

        /// <summary>
        /// Builds a job text from ranges and settings; the inverse of
        /// <see cref="Parse"/>.
        /// </summary>
        /// <param name="scopes">The ranges; adapter scopes are skipped. DNS, gateway and group are taken from the first scope that has them.</param>
        /// <param name="methodIds">Scan method identifiers, or <c>null</c> for the satellite's default.</param>
        /// <param name="tcpPorts">TCP ports, or <c>null</c> for the satellite's default.</param>
        /// <param name="udpPorts">UDP ports, or <c>null</c> for the satellite's default.</param>
        /// <param name="timeoutMs">Timeout per port in milliseconds, or <c>null</c>.</param>
        /// <param name="onlyKnownFor">Methods that only query devices already found.</param>
        /// <param name="crossCheckOnlyKnown">Scope of the DNS cross-check, or <c>null</c> for the satellite's default.</param>
        /// <returns>The job as one line of text.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="scopes"/> is null.</exception>
        public static string Format(
            IEnumerable<ScanScope> scopes,
            IEnumerable<string>? methodIds = null,
            IEnumerable<int>? tcpPorts = null,
            IEnumerable<int>? udpPorts = null,
            int? timeoutMs = null,
            IEnumerable<string>? onlyKnownFor = null,
            bool? crossCheckOnlyKnown = null)
        {
            ArgumentNullException.ThrowIfNull(scopes);

            List<string> parts = ["scan"];

            List<string> ranges = [];
            string? dns = null;
            string? gateway = null;
            string? group = null;

            foreach (ScanScope scope in scopes)
            {
                switch (scope.Kind)
                {
                    case ScanScopeKind.IPv4Range:
                        ranges.Add($"{scope.FirstIP}-{scope.LastIP}");
                        break;

                    case ScanScopeKind.TargetList:
                        ranges.AddRange(scope.Targets);
                        break;

                    case ScanScopeKind.IPv6Prefix:
                        ranges.Add($"{scope.Prefix}/{scope.PrefixLength}");
                        break;

                    // An adapter scope makes no sense on the satellite, which
                    // has adapters of its own. Only what can be expressed as an
                    // address range is transferred.
                    default:
                        break;
                }

                dns ??= string.IsNullOrWhiteSpace(scope.DnsServers) ? null : scope.DnsServers;
                gateway ??= string.IsNullOrWhiteSpace(scope.GatewayIP) ? null : scope.GatewayIP;
                group ??= string.IsNullOrWhiteSpace(scope.GroupDescription) ? null : scope.GroupDescription;
            }

            if (ranges.Count > 0) parts.Add("ranges=" + string.Join(';', ranges));

            List<string> methods = [.. methodIds ?? []];
            if (methods.Count > 0) parts.Add("methods=" + string.Join(',', methods));

            List<int> tcp = [.. tcpPorts ?? []];
            if (tcp.Count > 0) parts.Add("tcp=" + string.Join(',', tcp));

            List<int> udp = [.. udpPorts ?? []];
            if (udp.Count > 0) parts.Add("udp=" + string.Join(',', udp));

            // Only those that occur in this job at all: a list of methods that
            // do not run says nothing and only lengthens the job text in the
            // log.
            List<string> known = [.. (onlyKnownFor ?? [])
                .Where(id => methods.Count == 0 || methods.Contains(id, StringComparer.OrdinalIgnoreCase))];

            if (known.Count > 0) parts.Add("known=" + string.Join(',', known));

            // Only when switched off: the default is "on", and whatever the job
            // does not mention stays at the satellite's default.
            if (crossCheckOnlyKnown is false) parts.Add("crosscheck=all");

            if (timeoutMs is > 0) parts.Add("timeout=" + timeoutMs.Value.ToString(CultureInfo.InvariantCulture));
            if (dns is not null) parts.Add("dns=" + dns.Replace(" ", string.Empty));
            if (gateway is not null) parts.Add("gateway=" + gateway);
            if (group is not null) parts.Add("group=" + group.Replace(' ', '_'));

            return string.Join(' ', parts);
        }

        /// <summary>
        /// Reads a job text. An unintelligible job yields a result with
        /// <see cref="Problem"/> set instead of an exception: the satellite must
        /// be able to report the reason back, not crash.
        /// </summary>
        /// <param name="text">The job text, as produced by <see cref="Format"/>.</param>
        /// <returns>The parsed job; check <see cref="IsValid"/>.</returns>
        public static JobRequest Parse(string text)
        {
            JobRequest job = new();

            if (string.IsNullOrWhiteSpace(text))
            {
                job.Problem = "The job is empty.";
                return job;
            }

            string[] tokens = text.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            if (!tokens[0].Equals("scan", StringComparison.OrdinalIgnoreCase))
            {
                job.Problem = $"Unknown job \"{tokens[0]}\" - expected \"scan\".";
                return job;
            }

            string ranges = string.Empty;
            string dns = string.Empty;
            string gateway = string.Empty;
            string group = "Satellite";

            foreach (string token in tokens.Skip(1))
            {
                int split = token.IndexOf('=');
                if (split <= 0)
                {
                    job.Problem = $"\"{token}\" is not a key=value pair.";
                    return job;
                }

                string key = token[..split].ToLowerInvariant();
                string value = token[(split + 1)..];

                switch (key)
                {
                    case "ranges": ranges = value; break;
                    case "methods": job.MethodIds.AddRange(SplitList(value)); break;
                    case "known": job.OnlyKnownFor.AddRange(SplitList(value)); break;

                    // "all" means: also check the older rows of the table.
                    // Anything else means: only what answered in this run.
                    case "crosscheck":
                        job.CrossCheckOnlyKnown = !value.Equals("all", StringComparison.OrdinalIgnoreCase);
                        break;

                    case "tcp": job.TcpPorts.AddRange(ParsePorts(value)); break;
                    case "udp": job.UdpPorts.AddRange(ParsePorts(value)); break;
                    case "dns": dns = value; break;
                    case "gateway": gateway = value; break;
                    case "group": group = value.Replace('_', ' '); break;

                    case "timeout":
                        if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int ms) && ms > 0)
                        {
                            job.TimeoutMs = ms;
                        }
                        break;

                    default:
                        // Unknown fields are skipped rather than rejected: a
                        // newer main scanner may send more than this satellite
                        // understands without the job failing.
                        break;
                }
            }

            if (string.IsNullOrWhiteSpace(ranges))
            {
                job.Problem = "The job names no ranges.";
                return job;
            }

            foreach (string part in ranges.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                ScanScope? scope = ParseRange(part, dns, gateway, group);

                if (scope is null)
                {
                    job.Problem = $"\"{part}\" is not a range, a prefix or an address.";
                    return job;
                }

                job.Scopes.Add(scope);
            }

            return job;
        }

        /// <summary>
        /// A single range: "a-b" as an IPv4 span, "address/length" as a prefix
        /// (IPv6, or IPv4 converted to a span), anything else as a single target.
        /// </summary>
        private static ScanScope? ParseRange(string part, string dns, string gateway, string group)
        {
            ScanScope scope = new()
            {
                GroupDescription = group,
                DnsServers = dns,
                GatewayIP = gateway,
                IsSelected = true
            };

            int dash = part.IndexOf('-');
            if (dash > 0)
            {
                string first = part[..dash];
                string last = part[(dash + 1)..];

                if (!IPAddress.TryParse(first, out _) || !IPAddress.TryParse(last, out _)) return null;

                scope.Kind = ScanScopeKind.IPv4Range;
                scope.FirstIP = first;
                scope.LastIP = last;
                return scope;
            }

            int slash = part.IndexOf('/');
            if (slash > 0)
            {
                string prefix = part[..slash];

                if (!IPAddress.TryParse(prefix, out IPAddress? address)) return null;
                if (!int.TryParse(part[(slash + 1)..], out int length)) return null;

                if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    scope.Kind = ScanScopeKind.IPv6Prefix;
                    scope.Prefix = prefix;
                    scope.PrefixLength = length;
                    return scope;
                }

                // IPv4 with prefix length: converted to first and last address,
                // because that is how the range type works.
                if (length is < 0 or > 32) return null;

                byte[] bytes = address.GetAddressBytes();
                uint raw = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
                uint mask = length == 0 ? 0 : uint.MaxValue << (32 - length);

                uint start = raw & mask;
                uint end = start | ~mask;

                // Skips network and broadcast address if the network is large enough.
                if (length <= 30) { start++; end--; }

                scope.Kind = ScanScopeKind.IPv4Range;
                scope.FirstIP = ToAddress(start);
                scope.LastIP = ToAddress(end);
                return scope;
            }

            if (!IPAddress.TryParse(part, out _)) return null;

            scope.Kind = ScanScopeKind.TargetList;
            scope.Targets.Add(part);
            return scope;
        }

        private static string ToAddress(uint value) =>
            $"{(value >> 24) & 0xFF}.{(value >> 16) & 0xFF}.{(value >> 8) & 0xFF}.{value & 0xFF}";

        private static IEnumerable<string> SplitList(string value) =>
            value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        private static IEnumerable<int> ParsePorts(string value)
        {
            foreach (string part in SplitList(value))
            {
                if (int.TryParse(part, NumberStyles.Integer, CultureInfo.InvariantCulture, out int port) &&
                    port is > 0 and <= 65535)
                {
                    yield return port;
                }
            }
        }
    }
}
