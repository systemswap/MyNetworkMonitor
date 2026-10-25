using System.Net.NetworkInformation;
using CommunityToolkit.Mvvm.ComponentModel;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine
{
    /// <summary>
    /// Phase of a scan. The order is also the execution order: discover first,
    /// then identify, then check services. It matches the columns of the
    /// method drawer in the UI.
    /// </summary>
    public enum ScanPhase
    {
        /// <summary>Which devices exist? Ping, ARP, neighbor cache, SSDP, mDNS.</summary>
        Discovery = 0,

        /// <summary>What kind of device is it? Host name, SNMP, NetBIOS, ONVIF.</summary>
        Identification = 1,

        /// <summary>What runs on it? Ports, service detection, SMB version.</summary>
        Services = 2
    }

    /// <summary>Address families a method can handle.</summary>
    [Flags]
    public enum FamilySupport
    {
        /// <summary>No address family.</summary>
        None = 0,

        /// <summary>IPv4 targets.</summary>
        IPv4 = 1 << 0,

        /// <summary>IPv6 targets.</summary>
        IPv6 = 1 << 1,

        /// <summary>IPv4 and IPv6 targets.</summary>
        Both = IPv4 | IPv6
    }

    /// <summary>Whether a method runs, and if not, why.</summary>
    public enum ScanMethodState
    {
        /// <summary>The method runs.</summary>
        Available,

        /// <summary>
        /// Not applicable: no suitable target. Not an error but the normal
        /// case, for example NetBIOS with IPv6-only targets.
        /// </summary>
        NotApplicable,

        /// <summary>
        /// Possible in principle but blocked here: missing privileges, IPv6
        /// disabled, missing platform support. Reported in the UI instead of
        /// being skipped silently.
        /// </summary>
        Blocked
    }

    /// <summary>
    /// Whether a method can run in the given situation, and if not, why. The
    /// reason is intended for the UI, where it appears in the tooltip of the
    /// greyed-out checkbox.
    /// </summary>
    public sealed class ScanMethodAvailability
    {
        /// <summary>The availability state.</summary>
        public required ScanMethodState State { get; init; }

        /// <summary>Empty when the method runs.</summary>
        public string Reason { get; init; } = string.Empty;

        /// <summary>True if <see cref="State"/> is <see cref="ScanMethodState.Available"/>.</summary>
        public bool CanRun => State == ScanMethodState.Available;

        /// <summary>Shared instance for an available method.</summary>
        public static ScanMethodAvailability Available { get; } =
            new() { State = ScanMethodState.Available };

        /// <summary>Creates a "not applicable" result.</summary>
        /// <param name="reason">Reason shown in the UI.</param>
        /// <returns>An availability with state <see cref="ScanMethodState.NotApplicable"/>.</returns>
        public static ScanMethodAvailability NotApplicable(string reason) =>
            new() { State = ScanMethodState.NotApplicable, Reason = reason };

        /// <summary>Creates a "blocked" result.</summary>
        /// <param name="reason">Reason shown in the UI.</param>
        /// <returns>An availability with state <see cref="ScanMethodState.Blocked"/>.</returns>
        public static ScanMethodAvailability Blocked(string reason) =>
            new() { State = ScanMethodState.Blocked, Reason = reason };

        /// <inheritdoc />
        public override string ToString() =>
            State == ScanMethodState.Available ? "verfuegbar" : $"{State}: {Reason}";
    }

    /// <summary>
    /// A single scan target: a concrete address together with the scope it
    /// comes from. The scope is carried along because domain, DNS servers and
    /// gateway differ per scope; the same address in two scopes is resolved
    /// differently.
    /// </summary>
    public sealed class ScanTargetEntry
    {
        /// <summary>Set when the target is an address.</summary>
        public IpAddressInfo? Address { get; init; }

        /// <summary>Set when the target is given as a host name (resolved or not).</summary>
        public string? HostName { get; init; }

        /// <summary>The scope the target belongs to.</summary>
        public required ScopeRuntime Scope { get; init; }

        /// <summary>Address family of <see cref="Address"/>; null for an unresolved host name.</summary>
        public IpFamily? Family => Address?.Family;

        /// <summary>What is passed to the method: address or host name.</summary>
        public string TargetText => Address?.Canonical ?? HostName ?? string.Empty;

        /// <inheritdoc />
        public override string ToString() => TargetText;
    }

    /// <summary>
    /// A scope with everything that belongs to it at runtime: the assigned
    /// network interface and how far IPv6 is usable there.
    /// <para>
    /// The IPv6 check deliberately lives here and not globally. A selection
    /// can span several scopes on different interfaces; a scan over four
    /// scopes may use IPv6 in two of them and skip it in the other two.
    /// </para>
    /// </summary>
    public sealed class ScopeRuntime
    {
        /// <summary>The configured scope.</summary>
        public required ScanScope Scope { get; init; }

        /// <summary>The interface the scope runs over; null if none was found.</summary>
        public NetworkInterface? Interface { get; init; }

        /// <summary>IPv6 state of <see cref="Interface"/>.</summary>
        public required Ipv6Readiness Ipv6 { get; init; }

        /// <inheritdoc />
        public override string ToString() => $"{Scope.GroupDescription} [{Ipv6.Availability}]";
    }

    /// <summary>Progress of a running method.</summary>
    public sealed class ScanProgress
    {
        /// <summary>Identifier of the reporting method.</summary>
        public required string MethodId { get; init; }

        /// <summary>Display name of the reporting method.</summary>
        public required string MethodName { get; init; }

        /// <summary>Phase of the reporting method.</summary>
        public required ScanPhase Phase { get; init; }

        /// <summary>Number of targets processed so far.</summary>
        public int Current { get; init; }

        /// <summary>Total number of targets.</summary>
        public int Total { get; init; }

        /// <summary>Number of targets that have answered.</summary>
        public int Responded { get; init; }

        /// <summary>Status of the method.</summary>
        public ScanStatus Status { get; init; } = ScanStatus.running;

        /// <summary>
        /// The sub-step within the method; for service detection, the service
        /// currently being checked. Empty for methods that consist of a single
        /// step, which applies to all others.
        /// </summary>
        public string? Detail { get; init; }

        /// <summary>Number of the current sub-step (see <see cref="StepCount"/>). 0 means none.</summary>
        public int Step { get; init; }

        /// <summary>Total number of sub-steps. 0 means none.</summary>
        public int StepCount { get; init; }

        /// <summary>True if the method reports more than one named sub-step.</summary>
        public bool HasSteps => StepCount > 1 && !string.IsNullOrEmpty(Detail);

        /// <summary>
        /// Text shown in the command bar. Without sub-steps the method name,
        /// with sub-steps also the current step: otherwise a run over 24
        /// services shows only "Services" for a minute.
        /// </summary>
        public string Label => HasSteps ? $"{MethodName} · {Detail} ({Step} of {StepCount})" : MethodName;

        /// <summary>Progress as a fraction between 0 and 1.</summary>
        public double Fraction => Total <= 0 ? 0 : Math.Clamp((double)Current / Total, 0, 1);

        /// <inheritdoc />
        public override string ToString() => $"{Label} {Current}/{Total}";
    }

    /// <summary>
    /// Settings that apply to the entire run, set through the sliders and
    /// checkboxes of the main window.
    /// </summary>
    public sealed partial class ScanSettings : ObservableObject
    {
        /// <summary>
        /// Timeout per port, in milliseconds.
        /// <para>
        /// Defaults to 2500: one second suffices on the local segment, but not
        /// across a WAN link or for a device that is just waking up; there the
        /// scan would report "closed" where the answer merely came too late. A
        /// false "closed" goes unnoticed and is therefore more costly than the
        /// waiting time.
        /// </para>
        /// </summary>
        [ObservableProperty] private int _portTimeoutMs = 2500;

        /// <summary>TCP ports to scan.</summary>
        public List<int> TcpPorts { get; init; } = [];

        /// <summary>UDP ports to scan.</summary>
        public List<int> UdpPorts { get; init; } = [];

        /// <summary>Scan all 65,536 ports instead of the selection.</summary>
        [ObservableProperty] private bool _scanAllPorts;

        /// <summary>
        /// The SNMP community string used to query switches and managed
        /// devices.
        /// <para>
        /// "public" is the factory default and is still set for read access in
        /// many networks. Where it is not, the switch port query returns
        /// nothing, which deliberately stays silent: an error message per
        /// non-responding device would be constant noise.
        /// </para>
        /// </summary>
        [ObservableProperty] private string _snmpCommunity = "public";

        /// <summary>Services to check. Empty means all enabled services.</summary>
        public List<ServiceType> Services { get; init; } = [];

        /// <summary>
        /// Check only targets already listed in the table. A scan over 254
        /// addresses then becomes a follow-up on the twelve that actually
        /// exist.
        /// </summary>
        [ObservableProperty] private bool _onlyKnownTargets;

        /// <summary>
        /// Methods that should query only devices already found, as a set of
        /// <see cref="IScanMethod.Id"/> keys.
        /// <para>
        /// The restriction applies per method rather than to the whole run
        /// because both are needed: ping, ARP and SNMP should sweep the whole
        /// scope, since that is where most devices answer, while the subsequent
        /// port and service scans should query only those that responded. A
        /// single setting for everything cannot express this.
        /// </para>
        /// <para>
        /// Evaluated anew before each method, not once at the start: the list
        /// grows during the run, and the staging depends on exactly that.
        /// </para>
        /// </summary>
        public HashSet<string> OnlyKnownTargetsFor { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Whether a method queries only devices already found.</summary>
        /// <param name="methodId">The method identifier.</param>
        /// <returns>True if <see cref="OnlyKnownTargets"/> is set or the method is listed in <see cref="OnlyKnownTargetsFor"/>.</returns>
        public bool IsRestrictedToKnown(string methodId) =>
            OnlyKnownTargets || OnlyKnownTargetsFor.Contains(methodId);

        /// <summary>
        /// Alternative DNS server for name resolution. Overrides the servers
        /// configured for the scope, for checking against a specific server.
        /// </summary>
        [ObservableProperty] private string? _overrideDnsServer;

        /// <summary>
        /// Number of addresses the reverse lookup queries concurrently.
        /// <para>
        /// The default of 8 suits a home router: under a burst of concurrent
        /// PTR queries it drops most UDP packets before the timeout expires.
        /// With 50 concurrent queries, only 4 of 32 devices on a /24 return a
        /// name; with 8, all do. See docs/FEHLERGEDAECHTNIS.md, No. 7.
        /// </para>
        /// <para>
        /// A proper name server in a corporate network handles 32 or 64
        /// easily, and there the default becomes a bottleneck: an address that
        /// gets no answer consumes the full budget of timeout times retries,
        /// and only eight of them run side by side. Hence configurable rather
        /// than fixed.
        /// </para>
        /// </summary>
        [ObservableProperty] private int _reverseLookupConcurrency = 8;

        /// <summary>
        /// After name resolution, check every address against <b>each</b> known
        /// name server individually and compare the answers.
        /// <para>
        /// A sub-function of the DNS scan, not a method of its own: it needs
        /// the scan's result and has nothing to work on without it. If the
        /// servers disagree, a finding is created that names the server that
        /// does not resolve cleanly.
        /// </para>
        /// <para>
        /// Costs time: one query per address to every server, in both
        /// directions. Hence optional and off by default.
        /// </para>
        /// </summary>
        [ObservableProperty] private bool _crossCheckDnsServers;

        /// <summary>
        /// The cross-check queries only devices that answered during the run,
        /// instead of every row of the table.
        /// <para>
        /// On by default, which is where the time saving lies: each address is
        /// queried against <em>every</em> name server, twice. Over a table that
        /// has accumulated hundreds of stale entries (devices that no longer
        /// exist) this amounts to thousands of queries for information of no
        /// interest.
        /// </para>
        /// <para>
        /// When off, the check includes stale entries as well. That has its
        /// purpose: a name that still resolves although the device is gone is
        /// exactly the entry to clean up in the name service.
        /// </para>
        /// </summary>
        [ObservableProperty] private bool _crossCheckOnlyKnownTargets = true;

        /// <summary>Flush the ARP cache before the scan.</summary>
        [ObservableProperty] private bool _clearArpCacheFirst;

        // --- Satellite mode, see SATELLIT.md --------------------------------
        //
        // The ports are settings rather than constants: some networks allow
        // only specific ports, and then a different one must be configurable.

        /// <summary>Listen for satellites. Without it, no satellite can connect.</summary>
        [ObservableProperty] private bool _satelliteListenEnabled;

        /// <summary>Port the main scanner listens on.</summary>
        [ObservableProperty] private int _satelliteListenPort = 27411;

        /// <summary>
        /// Run this instance as a satellite that connects out to the main
        /// scanner.
        /// </summary>
        [ObservableProperty] private bool _satelliteModeEnabled;

        /// <summary>
        /// The main scanner this instance connects to as a satellite, as name
        /// or address. A name is preferable: it survives an address change,
        /// for example when the main scanner is a laptop.
        /// </summary>
        [ObservableProperty] private string _mainScannerHost = string.Empty;

        /// <summary>Port of the main scanner.</summary>
        [ObservableProperty] private int _mainScannerPort = 27411;

        /// <summary>
        /// As a satellite: any approved main scanner may cancel a running job,
        /// not only the one that started it.
        /// <para>
        /// On by default, because a hanging job blocks the satellite for
        /// everyone, and whoever is at the main scanner should be able to free
        /// it. Off means: only the scanner that issued the job.
        /// </para>
        /// </summary>
        [ObservableProperty] private bool _allowCancelFromAnyReceiver = true;

        /// <summary>
        /// Load the 3D topology library from the CDN instead of the program
        /// folder. The generated page can then be passed on on its own, but it
        /// needs an internet connection.
        /// </summary>
        [ObservableProperty] private bool _useOnlineTopologyLibrary;
    }
}
