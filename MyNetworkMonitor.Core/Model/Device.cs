// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Collections.ObjectModel;
using System.Net.NetworkInformation;
using CommunityToolkit.Mvvm.ComponentModel;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Model
{
    /// <summary>
    /// What a device is recognized by - from the most reliable property
    /// downwards. The order is the ranking: higher entries win when merging.
    /// </summary>
    public enum IdentityKey
    {
        /// <summary>Nothing reliable available.</summary>
        None,

        /// <summary>
        /// DHCPv6 DUID. Survives address changes, prefix changes and in some
        /// cases even MAC randomization - the most stable identifier available.
        /// </summary>
        Duid,

        /// <summary>MAC address, from ARP, the neighbor cache or an EUI-64 interface identifier.</summary>
        Mac,

        /// <summary>Fully qualified host name.</summary>
        Hostname,

        /// <summary>
        /// Only an address is known. Weak: under IPv6 the same address may
        /// belong to another device tomorrow.
        /// </summary>
        Address
    }

    /// <summary>
    /// A device on the network. Not a flat record but an aggregate: identity
    /// cascade, several addresses and an observation history.
    /// <para>
    /// Unlike <see cref="IPToScan"/>, which combines scan job, result and
    /// identity in one class with the IP as key, the address is not the
    /// identity here: under IPv6 a device regularly carries four to six
    /// addresses, several of which change daily.
    /// </para>
    /// </summary>
    public partial class Device : ObservableObject
    {
        /// <summary>Internal identifier of the entry.</summary>
        public Guid Id { get; init; } = Guid.NewGuid();

        /// <summary>
        /// While set, the device raises no change notifications.
        /// <para>
        /// During a run the scan threads write into the device through
        /// <c>DeviceStore.Apply</c> - host name, vendor, MAC and the other
        /// generated properties would each raise a notification. A bound row
        /// would process that notification on the foreign thread, which
        /// Avalonia rejects.
        /// </para>
        /// <para>
        /// Quiet mode ends in <see cref="NotifyDisplayChanged"/>, which the list
        /// calls for the marked devices on its own thread. It therefore first
        /// reports "everything has changed", covering whatever was suppressed
        /// while quiet.
        /// </para>
        /// </summary>
        internal bool IsQuiet { get; set; }

        /// <summary>Raises the notification unless <see cref="IsQuiet"/> is set.</summary>
        /// <param name="e">The event data.</param>
        protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (IsQuiet) return;

            base.OnPropertyChanged(e);
        }

        // --------------------------------------------------------- Identity

        /// <summary>DHCPv6 DUID in hexadecimal notation, if observed.</summary>
        [ObservableProperty] private string? _duid;

        /// <summary>MAC address of the device.</summary>
        [ObservableProperty] private PhysicalAddress? _mac;

        /// <summary>Vendor, determined from the MAC address.</summary>
        [ObservableProperty] private string _vendor = string.Empty;

        /// <summary>Host name without domain.</summary>
        [ObservableProperty] private string _hostName = string.Empty;
        /// <summary>DNS domain of the host.</summary>
        [ObservableProperty] private string _domain = string.Empty;
        /// <summary>NetBIOS name of the host.</summary>
        [ObservableProperty] private string _netBiosName = string.Empty;

        /// <summary>Name assigned in the internal name table. Overrides every detected name.</summary>
        [ObservableProperty] private string _internalName = string.Empty;

        /// <summary>The IP range the device comes from - for grouping.</summary>
        [ObservableProperty] private string _groupDescription = string.Empty;

        /// <summary>What the device is currently recognized by.</summary>
        public IdentityKey IdentityKey =>
            !string.IsNullOrWhiteSpace(Duid) ? IdentityKey.Duid :
            Mac is not null ? IdentityKey.Mac :
            !string.IsNullOrWhiteSpace(HostName) ? IdentityKey.Hostname :
            Addresses.Count > 0 ? IdentityKey.Address :
            IdentityKey.None;

        /// <summary>
        /// Display name. The internal name takes precedence, then the host
        /// name, then NetBIOS, then the best address.
        /// </summary>
        public string DisplayName
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(InternalName)) return InternalName;
                if (!string.IsNullOrWhiteSpace(HostName)) return HostName;
                if (!string.IsNullOrWhiteSpace(NetBiosName)) return NetBiosName;
                return PrimaryAddress?.Info.Canonical ?? "- unnamed -";
            }
        }

        // -------------------------------------------------------- Addresses

        /// <summary>All known addresses of the device.</summary>
        public ObservableCollection<DeviceAddress> Addresses { get; } = [];

        /// <summary>
        /// The address shown in the overview. Preference goes to what changes
        /// least: first IPv4, then a global IPv6 address with a stable
        /// interface identifier, finally link-local.
        /// </summary>
        public DeviceAddress? PrimaryAddress =>
            Addresses.Where(a => a.Info.Family == IpFamily.IPv4).OrderBy(a => a.Info.SortKey, ByteArrayComparer.Instance).FirstOrDefault()
            ?? BestIpv6Address;

        /// <summary>
        /// The most meaningful IPv6 address: global before local, stable before
        /// random. A privacy address would be the worst choice because it will
        /// be different tomorrow.
        /// </summary>
        public DeviceAddress? BestIpv6Address =>
            Addresses
                .Where(a => a.Info.Family == IpFamily.IPv6 && !a.IsExpired)
                .OrderBy(a => a.Info.Scope switch
                {
                    IpAddressScope.Global => 0,
                    IpAddressScope.UniqueLocal => 1,
                    IpAddressScope.LinkLocal => 2,
                    _ => 3
                })
                .ThenBy(a => a.Info.InterfaceIdKind == InterfaceIdKind.Random ? 1 : 0)
                .ThenBy(a => a.Info.SortKey, ByteArrayComparer.Instance)
                .FirstOrDefault();

        /// <summary>The IPv4 addresses of the device.</summary>
        public IEnumerable<DeviceAddress> Ipv4Addresses =>
            Addresses.Where(a => a.Info.Family == IpFamily.IPv4);

        /// <summary>The IPv6 addresses of the device.</summary>
        public IEnumerable<DeviceAddress> Ipv6Addresses =>
            Addresses.Where(a => a.Info.Family == IpFamily.IPv6);

        /// <summary>The device is reachable over IPv6 - not only via link-local.</summary>
        public bool IsIpv6Capable =>
            Ipv6Addresses.Any(a => a.Info.Scope is IpAddressScope.Global or IpAddressScope.UniqueLocal);

        /// <summary>
        /// The device was found exclusively over IPv6. These are the devices
        /// an IPv4-only scan never sees.
        /// </summary>
        public bool IsIpv6Only => Addresses.Count > 0 && !Ipv4Addresses.Any();

        /// <summary>
        /// At least one address is reachable from the internet without NAT.
        /// Basis for assessing open ports.
        /// </summary>
        public bool HasGloballyRoutableAddress =>
            Addresses.Any(a => a.Info.IsGloballyRoutable && !a.IsExpired);

        // ------------------------------------------------------- Name service

        /// <summary>
        /// Addresses the host name points to in DNS. More than one means the
        /// same name is assigned more than once.
        /// </summary>
        public List<string> LookupAddresses { get; } = [];

        /// <summary>Further names for the address, from the reverse lookup.</summary>
        public List<string> Aliases { get; } = [];

        /// <summary>The forward lookup was performed at all.</summary>
        [ObservableProperty] private bool _wasLookedUp;

        /// <summary>
        /// The name points to an address at which this device does not answer.
        /// Either a stale DNS entry or a second device that took the same name.
        /// </summary>
        public bool HasLookupMismatch =>
            WasLookedUp && LookupAddresses.Count > 0 &&
            !LookupAddresses.Any(a => Addresses.Any(x =>
                string.Equals(x.Info.Canonical, a, StringComparison.OrdinalIgnoreCase)));

        /// <summary><see cref="LookupAddresses"/> as a comma-separated list.</summary>
        public string LookupAddressText => string.Join(", ", LookupAddresses);

        /// <summary><see cref="Aliases"/> as a comma-separated list.</summary>
        public string AliasText => string.Join(", ", Aliases);

        // ----------------------------------------------------------- Findings

        /// <summary>What is assigned more than once on this device.</summary>
        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(HasConflict))]
        [NotifyPropertyChangedFor(nameof(ConflictRank))]
        private DeviceConflict _conflicts;

        /// <summary>The finding in plain text, for tooltip and detail view.</summary>
        [ObservableProperty] private string _conflictDetails = string.Empty;

        /// <summary>The device has at least one finding.</summary>
        public bool HasConflict => Conflicts != DeviceConflict.None;

        /// <summary>
        /// How serious the finding is - the higher, the more urgent. Used for
        /// sorting so that duplicates appear at the top instead of hiding among
        /// hundreds of rows.
        /// </summary>
        public int ConflictRank =>
            Conflicts.HasFlag(DeviceConflict.Address) ? 5 :
            Conflicts.HasFlag(DeviceConflict.DnsMultipleAddresses) ? 4 :
            Conflicts.HasFlag(DeviceConflict.HostName) ? 3 :
            Conflicts.HasFlag(DeviceConflict.DuplicateAlias) ? 3 :
            Conflicts.HasFlag(DeviceConflict.DnsMismatch) ? 2 :
            Conflicts != DeviceConflict.None ? 1 :
            0;

        // ------------------------------------------------------- Observations

        /// <summary>When the device was first seen.</summary>
        [ObservableProperty] private DateTimeOffset _firstSeen;
        /// <summary>When the device was last seen.</summary>
        [ObservableProperty] private DateTimeOffset _lastSeen;

        /// <summary>At least one address responded most recently.</summary>
        public bool IsOnline => Addresses.Any(a => a.IsResponding);

        /// <summary>The scan methods that reported this device.</summary>
        public HashSet<string> SeenBy { get; } = new(StringComparer.OrdinalIgnoreCase);

        // ------------------------------------------------------------ Results

        /// <summary>
        /// Services and ports, separated by address family. Comparing both
        /// sides yields the finding "behind NAT on IPv4, globally open on
        /// IPv6".
        /// </summary>
        public List<DeviceServiceResult> Services { get; } = [];

        /// <summary>Free-form details from the modules: SNMP, mDNS, SSDP, SMB, ONVIF.</summary>
        public Dictionary<string, string> Details { get; } = new(StringComparer.OrdinalIgnoreCase);

        // -------------------------------------------- Origin and location

        /// <summary>
        /// Remaining TTL of the last ping reply. 0 means "not measured".
        /// </summary>
        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(OsGuess))]
        [NotifyPropertyChangedFor(nameof(HasOsGuess))]
        private int _ttl;

        /// <summary>
        /// The presumed operating system, derived from the TTL. Deliberately
        /// computed rather than stored: the rule behind it can change, the
        /// measured TTL cannot.
        /// </summary>
        public string? OsGuess => Network.TtlFingerprint.Describe(Ttl);

        /// <summary>An operating system guess is available.</summary>
        public bool HasOsGuess => OsGuess is not null;

        /// <summary>The switch the device is connected to - from the SNMP query.</summary>
        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(HasSwitchInfo))]
        private string _switchName = string.Empty;

        /// <summary>The port on that switch, for example "GigabitEthernet1/0/12".</summary>
        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(HasSwitchInfo))]
        private string _switchPort = string.Empty;

        /// <summary>The VLAN of the switch port.</summary>
        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(HasSwitchInfo))]
        private string _vlan = string.Empty;

        /// <summary>Switch, port or VLAN is known.</summary>
        public bool HasSwitchInfo =>
            SwitchName.Length > 0 || SwitchPort.Length > 0 || Vlan.Length > 0;

        // ------------------------------------------------------ Web interface

        /// <summary>The title of the page behind the open web port.</summary>
        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(HasWebInfo))]
        private string _webTitle = string.Empty;

        /// <summary>The subject the TLS certificate is issued to.</summary>
        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(HasWebInfo))]
        private string _certificateSubject = string.Empty;

        /// <summary>The issuer of the certificate.</summary>
        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(HasWebInfo))]
        private string _certificateIssuer = string.Empty;

        /// <summary>When it expires. <c>null</c> if no certificate was read.</summary>
        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(HasWebInfo))]
        [NotifyPropertyChangedFor(nameof(CertificateIsExpired))]
        private DateTimeOffset? _certificateExpires;

        /// <summary>The certificate is self-signed.</summary>
        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(HasWebInfo))]
        private bool _certificateIsSelfSigned;

        /// <summary>The certificate has expired.</summary>
        public bool CertificateIsExpired =>
            CertificateExpires is { } until && until < DateTimeOffset.Now;

        /// <summary>A web title or certificate subject is known.</summary>
        public bool HasWebInfo =>
            WebTitle.Length > 0 || CertificateSubject.Length > 0;

        /// <summary>
        /// What the individual name servers reported about this device, if the
        /// cross-check has run. Deliberately not persisted: it is a snapshot of
        /// the name service, and an outdated version would be worse than none.
        /// </summary>
        public Services.DnsCrossCheckResult? DnsCrossCheck { get; set; }

        // ------------------------------------------------------------ Display

        /// <summary>
        /// The IPv4 address for the table column, or a note that there is none.
        /// A device without IPv4 is not an exception under IPv6 but the
        /// interesting case.
        /// </summary>
        public string Ipv4Text =>
            Ipv4Addresses.FirstOrDefault()?.Info.Canonical ?? "none";

        /// <summary>The device has at least one IPv4 address.</summary>
        public bool HasIpv4 => Ipv4Addresses.Any();

        /// <summary>
        /// The most meaningful IPv6 address. Instead of "none" the text says
        /// <em>why</em> there is nothing - link-local only, expired, or nothing
        /// at all. That difference matters.
        /// </summary>
        public string Ipv6Text
        {
            get
            {
                DeviceAddress? best = BestIpv6Address;
                if (best is not null) return best.Info.Canonical;

                if (!Ipv6Addresses.Any()) return "none";

                return Ipv6Addresses.All(a => a.IsExpired) ? "expired" : "link-local only";
            }
        }

        /// <summary>A usable IPv6 address exists.</summary>
        public bool HasIpv6 => BestIpv6Address is not null;

        /// <summary>How many IPv6 addresses exist besides the displayed one.</summary>
        public int Ipv6ExtraCount => Math.Max(0, Ipv6Addresses.Count() - 1);

        /// <summary><see cref="Ipv6ExtraCount"/> as "+n"; empty if zero.</summary>
        public string Ipv6ExtraText => Ipv6ExtraCount > 0 ? $"+{Ipv6ExtraCount}" : string.Empty;

        /// <summary>The MAC address in lowercase colon notation; empty if unknown.</summary>
        public string MacText =>
            Mac is null ? string.Empty : string.Join(":", Mac.GetAddressBytes().Select(b => b.ToString("x2")));

        /// <summary>
        /// Only the services that actually respond. The scan checks against
        /// several hundred service definitions - closed ports are noise, not a
        /// finding, and do not belong in display, filters or counts.
        /// <para>
        /// Sorted by service name, then by lowest port. Findings arrive in the
        /// order of their scan method - first the scan, later the port search
        /// of a single service - and without a fixed order late arrivals would
        /// be appended at the end instead of being sorted in.
        /// </para>
        /// </summary>
        public IEnumerable<DeviceServiceResult> OpenServices =>
            Services.Where(s => s.IsOpen)
                    .OrderBy(s => s.ServiceName, StringComparer.CurrentCultureIgnoreCase)
                    .ThenBy(s => s.Ports.Count == 0 ? int.MaxValue : s.Ports.Min());

        /// <summary>
        /// The responding services as names, without duplicates. Basis of the
        /// chips in the table column.
        /// </summary>
        public IReadOnlyList<string> OpenServiceNames =>
            [.. OpenServices.Select(s => s.ServiceName).Distinct(StringComparer.OrdinalIgnoreCase)];

        /// <summary>
        /// The chips shown in the "Services" column. Without a finding the list
        /// is empty - and so is the cell. "Not checked" and "nothing found" are
        /// shown in the status line instead, where they belong.
        /// <para>
        /// By default <b>all</b> running services appear here. Which ones are
        /// folded into a "+n" instead is decided by <see cref="ServiceDisplay"/>,
        /// that is, by the display settings rather than a fixed limit.
        /// </para>
        /// </summary>
        public IReadOnlyList<string> ServiceChips
        {
            get
            {
                IReadOnlyList<string> names = OpenServiceNames;
                if (names.Count == 0) return [];

                // Open ports without a detected service are named "TCP {Port}"
                // or "UDP {Port}" (see LegacyScanMethod.BuildServices) - exactly
                // the cases that overflow the column on a device with many open
                // ports. They are taken out before grouping by name and folded
                // into a single chip, so that "TCP 22", "TCP 8080", "TCP 8443"
                // ... take no more space than one named service.
                List<string> remaining = [];
                int tcpPorts = 0, udpPorts = 0;

                foreach (string name in names)
                {
                    if (ServiceDisplay.GroupTcpPorts && name.StartsWith("TCP ", StringComparison.Ordinal))
                    {
                        tcpPorts++;
                    }
                    else if (ServiceDisplay.GroupUdpPorts && name.StartsWith("UDP ", StringComparison.Ordinal))
                    {
                        udpPorts++;
                    }
                    else
                    {
                        remaining.Add(name);
                    }
                }

                (IReadOnlyList<string> shown, int folded) = ServiceDisplay.Split(remaining);

                List<string> chips = [.. shown];
                if (tcpPorts > 0) chips.Add(tcpPorts == 1 ? "TCP Ports" : $"TCP Ports ({tcpPorts})");
                if (udpPorts > 0) chips.Add(udpPorts == 1 ? "UDP Ports" : $"UDP Ports ({udpPorts})");
                if (folded > 0) chips.Add($"+{folded}");

                return chips;
            }
        }

        /// <summary>The responding services as short text - for export and search.</summary>
        public string RunningServicesText => string.Join(", ", OpenServiceNames);

        /// <summary>The number of distinct open ports.</summary>
        public int OpenPortCount =>
            OpenServices.SelectMany(s => s.Ports).Distinct().Count();

        /// <summary>For sections that should not appear at all without content.</summary>
        public bool HasServices => Services.Any(s => s.IsOpen);

        /// <summary><see cref="Details"/> contains entries.</summary>
        public bool HasDetails => Details.Count > 0;

        /// <summary>
        /// The details as a list - the source the detail view binds to.
        /// <para>
        /// Deliberately created anew on every access. <see cref="Details"/> is a
        /// dictionary: its instance stays the same for the whole run, and it
        /// raises no notifications when its content changes. A bound
        /// <c>ItemsControl</c>, however, rebuilds its rows only when the source
        /// is a different object - with the dictionary itself, the view would
        /// stay at the state of the first binding, and the information reported
        /// and stored by a service would appear only after restarting the
        /// application.
        /// </para>
        /// </summary>
        public IReadOnlyList<KeyValuePair<string, string>> DetailPairs => [.. Details];

        /// <summary>When the device was last seen, in words.</summary>
        public string LastSeenText
        {
            get
            {
                if (LastSeen == default) return "-";

                TimeSpan ago = DateTimeOffset.Now - LastSeen;

                return ago.TotalSeconds switch
                {
                    < 30 => "now",
                    < 90 => "1 m ago",
                    < 3600 => $"{ago.TotalMinutes:F0} m ago",
                    < 86400 => $"{ago.TotalHours:F0} h ago",
                    _ => $"{ago.TotalDays:F0} d ago"
                };
            }
        }

        /// <summary>
        /// Notifies the computed display properties that something has changed.
        /// They depend on addresses and services whose changes the binding
        /// would otherwise not notice. Ends <see cref="IsQuiet"/>; call on the
        /// UI thread.
        /// </summary>
        public void NotifyDisplayChanged()
        {
            // Quiet mode ends here - on the thread that calls this method. The
            // empty name means "re-read all properties" and catches up on what
            // was suppressed during the run; the explicit notifications below
            // remain necessary for computed properties without fields of their
            // own.
            IsQuiet = false;
            OnPropertyChanged(new System.ComponentModel.PropertyChangedEventArgs(string.Empty));

            OnPropertyChanged(nameof(DisplayName));
            OnPropertyChanged(nameof(IdentityKey));
            OnPropertyChanged(nameof(Ipv4Text));
            OnPropertyChanged(nameof(HasIpv4));
            OnPropertyChanged(nameof(Ipv6Text));
            OnPropertyChanged(nameof(HasIpv6));
            OnPropertyChanged(nameof(Ipv6ExtraCount));
            OnPropertyChanged(nameof(Ipv6ExtraText));
            OnPropertyChanged(nameof(MacText));
            OnPropertyChanged(nameof(RunningServicesText));
            OnPropertyChanged(nameof(OpenServices));
            OnPropertyChanged(nameof(OpenServiceNames));
            OnPropertyChanged(nameof(ServiceChips));
            OnPropertyChanged(nameof(OpenPortCount));
            OnPropertyChanged(nameof(HasServices));
            OnPropertyChanged(nameof(HasDetails));
            OnPropertyChanged(nameof(DetailPairs));
            OnPropertyChanged(nameof(LastSeenText));
            OnPropertyChanged(nameof(IsOnline));
            OnPropertyChanged(nameof(IsIpv6Capable));
            OnPropertyChanged(nameof(IsIpv6Only));
            OnPropertyChanged(nameof(HasGloballyRoutableAddress));
            OnPropertyChanged(nameof(PrimaryAddress));
            OnPropertyChanged(nameof(BestIpv6Address));
            OnPropertyChanged(nameof(LookupAddressText));
            OnPropertyChanged(nameof(AliasText));
            OnPropertyChanged(nameof(HasLookupMismatch));
            OnPropertyChanged(nameof(OsGuess));
            OnPropertyChanged(nameof(HasOsGuess));
            OnPropertyChanged(nameof(HasSwitchInfo));
            OnPropertyChanged(nameof(HasWebInfo));
            OnPropertyChanged(nameof(CertificateIsExpired));
            OnPropertyChanged(nameof(HasConflict));
            OnPropertyChanged(nameof(ConflictRank));
        }

        public override string ToString() =>
            $"{DisplayName} [{IdentityKey}] {Addresses.Count} Adresse(n)";
    }

    /// <summary>
    /// A detected service on the device, with the port state per address
    /// family.
    /// </summary>
    public sealed class DeviceServiceResult
    {
        /// <summary>The service name, usually a <see cref="ServiceType"/> name or "TCP {Port}"/"UDP {Port}".</summary>
        public required string ServiceName { get; init; }

        /// <summary>Category for grouping, see <see cref="ServiceCategories"/>.</summary>
        public string Category { get; init; } = string.Empty;

        /// <summary>The ports of the service.</summary>
        public List<int> Ports { get; init; } = [];

        /// <summary>State over IPv4. <c>null</c> if not checked.</summary>
        public PortStatus? StatusIPv4 { get; set; }

        /// <summary>State over IPv6. <c>null</c> if not checked.</summary>
        public PortStatus? StatusIPv6 { get; set; }

        /// <summary>Raw answer of the target, for the detail view.</summary>
        public string? PortLog { get; set; }

        /// <summary>
        /// The service runs over IPv6 but is not reachable over IPv4. Almost
        /// always a gap in the rule set, because firewalls often cover only
        /// IPv4.
        /// </summary>
        public bool IsExposedOnlyViaIpv6 =>
            StatusIPv6 is PortStatus.IsRunning or PortStatus.Open &&
            StatusIPv4 is PortStatus.Filtered or PortStatus.Closed or PortStatus.NoResponse;

        /// <summary>The service was identified on at least one address family.</summary>
        public bool IsRunning =>
            StatusIPv4 == PortStatus.IsRunning || StatusIPv6 == PortStatus.IsRunning;

        /// <summary>
        /// The port answered - open or with a detected service. Everything else
        /// (closed, filtered, no response) is the outcome of an attempt, not a
        /// finding, and is not displayed anywhere.
        /// </summary>
        public bool IsOpen =>
            StatusIPv4 is PortStatus.Open or PortStatus.IsRunning ||
            StatusIPv6 is PortStatus.Open or PortStatus.IsRunning;

        /// <summary>The ports as short text after the service name, for example "80, 443". Ascending.</summary>
        public string PortsText => Ports.Count == 0 ? string.Empty : string.Join(", ", Ports.OrderBy(p => p));

        public override string ToString() =>
            $"{ServiceName} [{string.Join(",", Ports)}] v4={StatusIPv4?.ToString() ?? "-"} v6={StatusIPv6?.ToString() ?? "-"}";
    }

    /// <summary>Compares address sort keys byte by byte.</summary>
    public sealed class ByteArrayComparer : IComparer<byte[]>
    {
        /// <summary>The shared instance.</summary>
        public static readonly ByteArrayComparer Instance = new();

        /// <summary>Compares two byte arrays lexicographically; <c>null</c> sorts first.</summary>
        /// <param name="x">The first array.</param>
        /// <param name="y">The second array.</param>
        /// <returns>Less than zero, zero or greater than zero, as for <see cref="IComparer{T}.Compare"/>.</returns>
        public int Compare(byte[]? x, byte[]? y)
        {
            if (ReferenceEquals(x, y)) return 0;
            if (x is null) return -1;
            if (y is null) return 1;
            return x.AsSpan().SequenceCompareTo(y);
        }
    }
}
