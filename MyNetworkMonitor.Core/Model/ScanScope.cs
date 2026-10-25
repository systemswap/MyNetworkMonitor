// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using CommunityToolkit.Mvvm.ComponentModel;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Model
{
    /// <summary>
    /// Kind of scan scope. The from/to range is one of four kinds, so IPv6 fits
    /// into the same list without IPv4 losing anything.
    /// </summary>
    public enum ScanScopeKind
    {
        /// <summary>From/to range or CIDR.</summary>
        IPv4Range,

        /// <summary>
        /// Fixed addresses and host names, IPv4 and IPv6 mixed. In practice the
        /// most important kind for IPv6, because a /64 cannot be enumerated.
        /// </summary>
        TargetList,

        /// <summary>
        /// An IPv6 prefix together with the methods used to examine it. Not
        /// enumerated - see <see cref="Ipv6Discovery"/>.
        /// </summary>
        IPv6Prefix,

        /// <summary>
        /// Bound to a network adapter. Determines the IPv4 subnet and IPv6
        /// prefixes from the adapter itself.
        /// </summary>
        NetworkInterface
    }

    /// <summary>
    /// Methods used to examine an IPv6 prefix. A /64 contains about 18
    /// quintillion addresses - enumeration is out of the question; the only
    /// options are targeted queries or listening.
    /// </summary>
    [Flags]
    public enum Ipv6Discovery
    {
        /// <summary>No discovery method.</summary>
        None = 0,

        /// <summary>Read the neighbor table of the operating system (the IPv6 counterpart of arp -a).</summary>
        NeighborCache = 1 << 0,

        /// <summary>Echo to ff02::1 - practically every device in the segment answers.</summary>
        MulticastPing = 1 << 1,

        /// <summary>Listen for router advertisements.</summary>
        ListenRouterAdvertisements = 1 << 2,

        /// <summary>Evaluate MLD reports - reveals services without sending a single packet.</summary>
        ListenMulticastGroups = 1 << 3,

        /// <summary>Probe ::1 to ::ff - where manually assigned addresses are located.</summary>
        LowByteSweep = 1 << 4,

        /// <summary>Build EUI-64 addresses from known MAC addresses and probe them.</summary>
        Eui64FromKnownMacs = 1 << 5,

        /// <summary>The usual set: everything passive plus multicast ping.</summary>
        Default = NeighborCache | MulticastPing | ListenRouterAdvertisements | ListenMulticastGroups
    }

    /// <summary>
    /// A scan scope. Carries every field of the stored
    /// <see cref="Models.IpGroup"/> - group, device description, domain, own DNS
    /// servers, order, automatic scan and the gateway for remote segments -
    /// plus <see cref="Kind"/>.
    /// <para>
    /// <see cref="IsSelected"/> corresponds to the stored "IsActive" column. It
    /// is set through the selection in the command bar, not in the scope
    /// editor, and is persisted so that the selection survives a restart.
    /// </para>
    /// </summary>
    public partial class ScanScope : ObservableObject
    {
        /// <summary>Stays stable across reordering and renaming.</summary>
        public Guid Id { get; init; } = Guid.NewGuid();

        /// <summary>Sequence number; determines the order during the scan.</summary>
        [ObservableProperty] private int _index;

        /// <summary>Included in the next scan. Stored as "IsActive".</summary>
        [ObservableProperty] private bool _isSelected;

        /// <summary>The kind of scope; determines which of the fields below apply.</summary>
        [ObservableProperty] private ScanScopeKind _kind = ScanScopeKind.IPv4Range;

        /// <summary>Name of the group the scope belongs to.</summary>
        [ObservableProperty] private string _groupDescription = string.Empty;
        /// <summary>Description of the devices in this scope.</summary>
        [ObservableProperty] private string _deviceDescription = string.Empty;

        // --- IPv4Range -----------------------------------------------------
        /// <summary>First address of the range.</summary>
        [ObservableProperty] private string _firstIP = string.Empty;
        /// <summary>Last address of the range.</summary>
        [ObservableProperty] private string _lastIP = string.Empty;

        // --- TargetList ----------------------------------------------------
        /// <summary>Addresses and host names, IPv4 and IPv6 mixed.</summary>
        public List<string> Targets { get; init; } = [];

        // --- IPv6Prefix ----------------------------------------------------
        /// <summary>The IPv6 prefix.</summary>
        [ObservableProperty] private string _prefix = string.Empty;
        /// <summary>The prefix length in bits.</summary>
        [ObservableProperty] private int _prefixLength = 64;
        /// <summary>The methods used to examine the prefix.</summary>
        [ObservableProperty] private Ipv6Discovery _ipv6Discovery = Ipv6Discovery.Default;

        // --- NetworkInterface ----------------------------------------------
        /// <summary>Id of the adapter as reported by <see cref="System.Net.NetworkInformation.NetworkInterface"/>.</summary>
        [ObservableProperty] private string _interfaceId = string.Empty;

        // --- Name resolution, applies to all kinds --------------------------
        /// <summary>DNS domain of the scope.</summary>
        [ObservableProperty] private string _domain = string.Empty;
        /// <summary>Own DNS servers, separated by comma or semicolon.</summary>
        [ObservableProperty] private string _dnsServers = string.Empty;

        /// <summary>
        /// The router of this network.
        /// <para>
        /// An override, not a replacement: if the field is empty, the run uses
        /// the gateway of the adapter the scan runs through
        /// (<c>LegacyScanMethod.GatewayDnsFallback</c>). Intended for a scope
        /// behind a different router than this adapter.
        /// </para>
        /// <para>
        /// The field holds the router, not the address of a remote instance -
        /// remote instances are managed separately by the satellite mode, see
        /// SATELLIT.md. In the stored XML it is the <c>NMGatewayIP</c> column.
        /// </para>
        /// </summary>
        [ObservableProperty] private string _gatewayIP = string.Empty;

        /// <summary>
        /// Name of the satellite that scans this scope; empty means this
        /// machine scans it. See SATELLIT.md.
        /// </summary>
        [ObservableProperty] private string _scannedBy = string.Empty;

        // --- Automatic scan --------------------------------------------------
        /// <summary>The scope is scanned automatically.</summary>
        [ObservableProperty] private bool _automaticScan;
        /// <summary>Interval of the automatic scan in minutes.</summary>
        [ObservableProperty] private int _scanIntervalMinutes;

        /// <summary>
        /// Time of the last run.
        /// <para>
        /// Persisted because the automatic scan catches up on missed runs: on
        /// start the main scanner compares this value with the interval and
        /// triggers what is overdue. Without a stored value everything would
        /// count as freshly scanned after each program start.
        /// </para>
        /// </summary>
        [ObservableProperty] private DateTimeOffset? _lastScanned;

        /// <summary>The DNS servers of this scope, split at comma or semicolon.</summary>
        public IReadOnlyList<string> DnsServerList =>
            string.IsNullOrWhiteSpace(DnsServers)
                ? []
                : DnsServers.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        /// <summary>
        /// Entries in the DNS field that are not IP addresses; empty if
        /// everything is in order.
        /// <para>
        /// Name resolution uses the configured servers only if <b>every</b>
        /// entry parses as an IP address. A single name such as
        /// "dns.corp.example" therefore silently discards the whole list - the
        /// run then queries the gateway instead (see docs/FEHLERGEDAECHTNIS.md,
        /// No. 8), and nothing shows why names are missing. The user interface
        /// warns about exactly this.
        /// </para>
        /// </summary>
        public IReadOnlyList<string> InvalidDnsServers =>
            [.. DnsServerList.Where(s => !IPAddress.TryParse(s, out _))];

        /// <summary>The warning for the DNS field, or empty if there is nothing to report.</summary>
        public string DnsServerWarning
        {
            get
            {
                IReadOnlyList<string> bad = InvalidDnsServers;
                if (bad.Count == 0) return string.Empty;

                string list = string.Join(", ", bad);
                return bad.Count == 1
                    ? $"\"{list}\" is not an IP address. Name servers have to be given as IP addresses - " +
                      "as long as this entry stays, none of the servers of this range are used and names " +
                      "are resolved elsewhere."
                    : $"These are not IP addresses: {list}. Name servers have to be given as IP addresses - " +
                      "as long as they stay, none of the servers of this range are used and names are " +
                      "resolved elsewhere.";
            }
        }

        // The warning depends on the text field and must be re-raised with it;
        // otherwise the warning stays after the entry has been corrected.
        partial void OnDnsServersChanged(string value)
        {
            OnPropertyChanged(nameof(DnsServerList));
            OnPropertyChanged(nameof(InvalidDnsServers));
            OnPropertyChanged(nameof(DnsServerWarning));
            OnPropertyChanged(nameof(HasDnsServerWarning));
        }

        /// <summary>There is a warning for the DNS field.</summary>
        public bool HasDnsServerWarning => InvalidDnsServers.Count > 0;

        /// <summary>A router of its own is configured for this scope.</summary>
        public bool HasOwnGateway => !string.IsNullOrWhiteSpace(GatewayIP);

        /// <summary>The scope is scanned by a satellite instead of this machine.</summary>
        public bool IsScannedRemotely => !string.IsNullOrWhiteSpace(ScannedBy);

        /// <summary>
        /// The warning for the gateway field, or empty if there is nothing to
        /// report. A name is useless here: the value serves as reference point
        /// for TTL, topology and name resolution and is never resolved.
        /// </summary>
        public string GatewayWarning =>
            !HasOwnGateway || IPAddress.TryParse(GatewayIP.Trim(), out _)
                ? string.Empty
                : $"\"{GatewayIP}\" is not an IP address. The gateway is used as it stands and is " +
                  "never resolved, so a name cannot be used here. Leave the field empty to use the " +
                  "gateway of the adapter this range is scanned through.";

        /// <summary>There is a warning for the gateway field.</summary>
        public bool HasGatewayWarning => GatewayWarning.Length > 0;

        // As with the DNS field: the warning depends on the input and must be
        // re-raised with it.
        partial void OnGatewayIPChanged(string value)
        {
            OnPropertyChanged(nameof(HasOwnGateway));
            OnPropertyChanged(nameof(GatewayWarning));
            OnPropertyChanged(nameof(HasGatewayWarning));
        }

        partial void OnScannedByChanged(string value) => OnPropertyChanged(nameof(IsScannedRemotely));

        // --------------------------------------------------------- Validation

        /// <summary>
        /// Checks whether the scope is complete enough to be scanned.
        /// </summary>
        /// <param name="problem">A sentence describing what is missing; <c>null</c> if valid.</param>
        /// <returns><c>true</c> if the scope can be scanned.</returns>
        public bool TryValidate(out string? problem)
        {
            problem = null;

            switch (Kind)
            {
                case ScanScopeKind.IPv4Range:
                    if (!IPAddress.TryParse(FirstIP, out IPAddress? first) ||
                        first.AddressFamily != AddressFamily.InterNetwork)
                    {
                        problem = "The first address is not a valid IPv4 address.";
                        return false;
                    }
                    if (!IPAddress.TryParse(LastIP, out IPAddress? last) ||
                        last.AddressFamily != AddressFamily.InterNetwork)
                    {
                        problem = "The last address is not a valid IPv4 address.";
                        return false;
                    }
                    if (ToUInt32(last) < ToUInt32(first))
                    {
                        problem = "The last address comes before the first.";
                        return false;
                    }
                    return true;

                case ScanScopeKind.TargetList:
                    if (Targets.Count == 0)
                    {
                        problem = "The target list is empty.";
                        return false;
                    }
                    return true;

                case ScanScopeKind.IPv6Prefix:
                    if (!IPAddress.TryParse(Prefix, out IPAddress? prefix) ||
                        prefix.AddressFamily != AddressFamily.InterNetworkV6)
                    {
                        problem = "The prefix is not a valid IPv6 address.";
                        return false;
                    }
                    if (PrefixLength is < 1 or > 128)
                    {
                        problem = "The prefix length must be between 1 and 128.";
                        return false;
                    }
                    if (Ipv6Discovery == Ipv6Discovery.None)
                    {
                        problem = "An IPv6 prefix needs at least one discovery method.";
                        return false;
                    }
                    return true;

                case ScanScopeKind.NetworkInterface:
                    if (string.IsNullOrWhiteSpace(InterfaceId))
                    {
                        problem = "No network adapter is assigned.";
                        return false;
                    }
                    return true;

                default:
                    problem = "Unknown scope kind.";
                    return false;
            }
        }

        // --------------------------------------------------------------- Size

        /// <summary>
        /// How many targets the scope contains. For
        /// <see cref="ScanScopeKind.IPv6Prefix"/> only an estimate, because the
        /// number depends on what the neighbor cache and multicast reveal - in
        /// that case <paramref name="isEstimate"/> is set.
        /// </summary>
        /// <param name="isEstimate">Set if the count is only an estimate.</param>
        /// <returns>The number of targets; 0 if unknown before the scan.</returns>
        public long CountTargets(out bool isEstimate)
        {
            isEstimate = false;

            switch (Kind)
            {
                case ScanScopeKind.IPv4Range:
                    if (!IPAddress.TryParse(FirstIP, out IPAddress? f) ||
                        !IPAddress.TryParse(LastIP, out IPAddress? l)) return 0;
                    long span = (long)ToUInt32(l) - ToUInt32(f) + 1;
                    return span < 0 ? 0 : span;

                case ScanScopeKind.TargetList:
                    return Targets.Count;

                case ScanScopeKind.IPv6Prefix:
                    isEstimate = true;
                    // Only the low-byte sweep has a fixed size. Everything else
                    // finds what is there - not quantifiable in advance.
                    return Ipv6Discovery.HasFlag(Ipv6Discovery.LowByteSweep) ? 255 : 0;

                case ScanScopeKind.NetworkInterface:
                    isEstimate = true;
                    return 0; // determined from the adapter during the scan

                default:
                    return 0;
            }
        }

        // ------------------------------------------------------------ Targets

        /// <summary>
        /// Enumerates the addresses of an IPv4 range - linearly, not octet by
        /// octet. 10.0.4.200 to 10.0.5.50 thus really covers the 107 addresses
        /// in between.
        /// <para>
        /// Deliberately not counted per octet: that gives a wrong result for a
        /// range crossing an octet boundary.
        /// </para>
        /// </summary>
        /// <returns>The addresses; empty if the scope is not a valid IPv4 range.</returns>
        public IEnumerable<IPAddress> EnumerateIPv4Range()
        {
            if (Kind != ScanScopeKind.IPv4Range) yield break;
            if (!IPAddress.TryParse(FirstIP, out IPAddress? first) ||
                !IPAddress.TryParse(LastIP, out IPAddress? last)) yield break;
            if (first.AddressFamily != AddressFamily.InterNetwork ||
                last.AddressFamily != AddressFamily.InterNetwork) yield break;

            uint from = ToUInt32(first);
            uint to = ToUInt32(last);
            if (to < from) yield break;

            for (uint value = from; ; value++)
            {
                yield return FromUInt32(value);
                if (value == to) break; // checked after yielding so that 255.255.255.255 does not overflow
            }
        }

        /// <summary>
        /// Splits the target list into addresses and host names. Host names stay
        /// as text and are resolved only during the scan - hence two result
        /// lists.
        /// </summary>
        /// <returns>The entries that parse as addresses, and the remaining entries as host names.</returns>
        public (List<IpAddressInfo> Addresses, List<string> Hostnames) SplitTargetList()
        {
            List<IpAddressInfo> addresses = [];
            List<string> hostnames = [];

            foreach (string entry in Targets)
            {
                if (string.IsNullOrWhiteSpace(entry)) continue;

                if (IpAddressAnalyzer.TryAnalyze(entry, out IpAddressInfo? info) && info is not null)
                {
                    addresses.Add(info);
                }
                else
                {
                    hostnames.Add(entry.Trim());
                }
            }

            return (addresses, hostnames);
        }

        // -------------------------------------------------------- Description

        /// <summary>One-line address description for list and selection, for example "192.0.2.1 - 192.0.2.254".</summary>
        /// <returns>The address part of the scope.</returns>
        public string DescribeAddressPart() => Kind switch
        {
            ScanScopeKind.IPv4Range => string.IsNullOrWhiteSpace(FirstIP) ? "-" : $"{FirstIP} - {LastIP}",
            ScanScopeKind.TargetList => $"{Targets.Count} entries",
            ScanScopeKind.IPv6Prefix => string.IsNullOrWhiteSpace(Prefix) ? "-" : $"{Prefix}/{PrefixLength}",
            // Without a fixed assignment the scan uses the adapter through
            // which the machine is connected - that belongs here, not a "-".
            ScanScopeKind.NetworkInterface =>
                string.IsNullOrWhiteSpace(InterfaceId) ? "subnet of the active adapter" : "from adapter",
            _ => "-"
        };

        /// <summary>
        /// The same as a bindable property - the scope selection shows the
        /// address part next to the name, because "Office 2nd floor" alone does
        /// not tell what is scanned.
        /// </summary>
        public string RangeText => DescribeAddressPart();

        partial void OnFirstIPChanged(string value) => OnPropertyChanged(nameof(RangeText));
        partial void OnLastIPChanged(string value) => OnPropertyChanged(nameof(RangeText));
        partial void OnPrefixChanged(string value) => OnPropertyChanged(nameof(RangeText));
        partial void OnKindChanged(ScanScopeKind value) => OnPropertyChanged(nameof(RangeText));

        public override string ToString() =>
            $"{Index}. {GroupDescription} [{Kind}] {DescribeAddressPart()}";

        // ---------------------------------------------------------- Free input

        /// <summary>
        /// Parses a manually entered scope. Accepted is what one expects for a
        /// quick check:
        /// <list type="bullet">
        ///   <item><c>192.0.2.20</c> - a single address</item>
        ///   <item><c>192.0.2.1-192.0.2.254</c> - from/to</item>
        ///   <item><c>192.0.2.1-254</c> - short form with the last octet</item>
        ///   <item><c>192.0.2.0/24</c> - CIDR</item>
        ///   <item><c>192.0.2.5, server1, 2001:db8::1</c> - list, mixed</item>
        /// </list>
        /// Everything that is not an address is kept as a host name and resolved
        /// during the scan.
        /// </summary>
        /// <param name="text">The entered text.</param>
        /// <param name="scope">The parsed scope, selected for the next scan; <c>null</c> if nothing was recognized.</param>
        /// <param name="problem">A sentence describing the problem, if any.</param>
        /// <returns><c>true</c> if a valid scope was recognized.</returns>
        public static bool TryParseCustom(string? text, out ScanScope? scope, out string? problem)
        {
            scope = null;
            problem = null;

            if (string.IsNullOrWhiteSpace(text)) return false;

            string input = text.Trim();

            if (!input.Contains(',') && TryParseRange(input, out string? first, out string? last))
            {
                scope = new ScanScope
                {
                    Kind = ScanScopeKind.IPv4Range,
                    GroupDescription = "Own entry",
                    DeviceDescription = input,
                    FirstIP = first!,
                    LastIP = last!,
                    IsSelected = true
                };

                return scope.TryValidate(out problem);
            }

            List<string> entries =
            [
                .. input.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            ];

            if (entries.Count == 0)
            {
                problem = "Nothing recognised in the entry.";
                return false;
            }

            scope = new ScanScope
            {
                Kind = ScanScopeKind.TargetList,
                GroupDescription = "Own entry",
                DeviceDescription = input,
                Targets = entries,
                IsSelected = true
            };

            return true;
        }

        /// <summary>
        /// Recognizes the three notations of an IPv4 range. Returns true only if
        /// both ends yield valid IPv4 addresses - otherwise it is not a range
        /// but a host name with a hyphen.
        /// </summary>
        private static bool TryParseRange(string input, out string? first, out string? last)
        {
            first = last = null;

            int slash = input.IndexOf('/');
            if (slash > 0)
            {
                if (!IPAddress.TryParse(input[..slash], out IPAddress? network) ||
                    network.AddressFamily != AddressFamily.InterNetwork) return false;

                if (!int.TryParse(input[(slash + 1)..], out int bits) || bits is < 0 or > 32) return false;

                uint mask = bits == 0 ? 0u : uint.MaxValue << (32 - bits);
                uint start = ToUInt32(network) & mask;
                uint end = start | ~mask;

                // Skip network and broadcast address as long as the network is
                // large enough for them to have a meaning of their own
                // (/31 and /32 have none, RFC 3021).
                if (bits <= 30)
                {
                    start++;
                    end--;
                }

                first = FromUInt32(start).ToString();
                last = FromUInt32(end).ToString();
                return true;
            }

            int dash = input.IndexOf('-');
            if (dash <= 0) return false;

            string left = input[..dash].Trim();
            string right = input[(dash + 1)..].Trim();

            if (!IPAddress.TryParse(left, out IPAddress? from) ||
                from.AddressFamily != AddressFamily.InterNetwork) return false;

            // Short form: the right side holds only the last octet.
            if (!right.Contains('.') && byte.TryParse(right, out byte lastOctet))
            {
                byte[] bytes = from.GetAddressBytes();
                bytes[3] = lastOctet;
                right = new IPAddress(bytes).ToString();
            }

            if (!IPAddress.TryParse(right, out IPAddress? to) ||
                to.AddressFamily != AddressFamily.InterNetwork) return false;

            first = from.ToString();
            last = to.ToString();
            return true;
        }

        // -------------------------------------------------- Stored format

        /// <summary>
        /// Creates a scope from a stored <see cref="Models.IpGroup"/>. It always
        /// becomes a <see cref="ScanScopeKind.IPv4Range"/>, which is all the XML
        /// format can describe. Stored XML files are thus read without any
        /// conversion step, and no scopes are lost.
        /// <para>
        /// <c>IsActive</c> becomes <see cref="IsSelected"/>.
        /// </para>
        /// </summary>
        /// <param name="group">The stored IP group.</param>
        /// <returns>The equivalent scope.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="group"/> is <c>null</c>.</exception>
        public static ScanScope FromIpGroup(Models.IpGroup group)
        {
            ArgumentNullException.ThrowIfNull(group);

            return new ScanScope
            {
                Kind = ScanScopeKind.IPv4Range,
                Index = group.Index,
                IsSelected = group.IsActive,
                GroupDescription = group.IpGroupDescription,
                DeviceDescription = group.DeviceDescription,
                FirstIP = group.FirstIP,
                LastIP = group.LastIP,
                Domain = group.Domain,
                DnsServers = group.DnsServers,
                GatewayIP = group.NmGatewayIP,
                ScannedBy = group.ScannedBy,
                AutomaticScan = group.AutomaticScan,
                ScanIntervalMinutes = int.TryParse(group.ScanIntervalMinutes, out int minutes) ? minutes : 0,
                LastScanned = DateTimeOffset.TryParse(group.LastScanned, CultureInfo.InvariantCulture,
                                                      DateTimeStyles.RoundtripKind, out DateTimeOffset last)
                    ? last
                    : null
            };
        }

        /// <summary>
        /// Converts back into the stored XML format, for saving. Scopes that are
        /// not a <see cref="ScanScopeKind.IPv4Range"/> cannot be represented
        /// there and yield <c>null</c>.
        /// </summary>
        /// <returns>The equivalent IP group, or <c>null</c>.</returns>
        public Models.IpGroup? ToIpGroup()
        {
            if (Kind != ScanScopeKind.IPv4Range) return null;

            return new Models.IpGroup
            {
                Index = Index,
                IsActive = IsSelected,
                IpGroupDescription = GroupDescription,
                DeviceDescription = DeviceDescription,
                FirstIP = FirstIP,
                LastIP = LastIP,
                Domain = Domain,
                DnsServers = DnsServers,
                NmGatewayIP = GatewayIP,
                ScannedBy = ScannedBy,
                AutomaticScan = AutomaticScan,
                ScanIntervalMinutes = ScanIntervalMinutes > 0 ? ScanIntervalMinutes.ToString() : string.Empty,
                // Round-trip format ("O") so that the value read back is exactly
                // the same point in time - whether a scope counts as overdue
                // depends on it.
                LastScanned = LastScanned?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty
            };
        }

        // ------------------------------------------------------------ Helpers

        private static uint ToUInt32(IPAddress address)
        {
            byte[] b = address.GetAddressBytes();
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }

        private static IPAddress FromUInt32(uint value) => new(new[]
        {
            (byte)(value >> 24),
            (byte)(value >> 16),
            (byte)(value >> 8),
            (byte)value
        });
    }
}
