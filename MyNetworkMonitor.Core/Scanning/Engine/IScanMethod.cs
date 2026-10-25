// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using MyNetworkMonitor.Core.Model;

namespace MyNetworkMonitor.Core.Scanning.Engine
{
    /// <summary>
    /// What a method has available during its run: the targets, the settings,
    /// a way to report results and one to report progress.
    /// <para>
    /// A method does <b>not</b> maintain the device list itself. It reports
    /// observations through <see cref="Report"/>; the
    /// <see cref="DeviceStore"/> handles the mapping. This is what allows
    /// active scans and passive sources such as the RA capture to be treated
    /// alike.
    /// </para>
    /// </summary>
    public sealed class ScanContext
    {
        /// <summary>The selected scopes with their runtime information.</summary>
        public required IReadOnlyList<ScopeRuntime> Scopes { get; init; }

        /// <summary>The targets for this method.</summary>
        public required IReadOnlyList<ScanTargetEntry> Targets { get; init; }

        /// <summary>Settings of the run.</summary>
        public required ScanSettings Settings { get; init; }

        /// <summary>The device store of the run; new findings go through <see cref="Report"/>.</summary>
        public required DeviceStore Store { get; init; }

        /// <summary>Reports an observation. Thread-safe through the caller's lock.</summary>
        public required Action<DeviceObservation> Report { get; init; }

        /// <summary>
        /// Reports progress including the current sub-step. Only service
        /// detection has sub-steps: it proceeds service by service, and
        /// "Services" alone says nothing for a minute about where the run
        /// stands.
        /// </summary>
        /// <remarks>
        /// Arguments: current, responded, total, detail, step, step count
        /// (see <see cref="ScanProgress"/>).
        /// </remarks>
        public required Action<int, int, int, string?, int, int> ReportStepProgress { get; init; }

        /// <summary>
        /// Reports progress of a method that consists of a single step, which
        /// is the normal case.
        /// </summary>
        /// <param name="current">Number of targets processed so far.</param>
        /// <param name="responded">Number of targets that have answered.</param>
        /// <param name="total">Total number of targets.</param>
        public void ReportProgress(int current, int responded, int total) =>
            ReportStepProgress(current, responded, total, null, 0, 0);

        /// <summary>The targets of one address family.</summary>
        /// <param name="family">The address family.</param>
        /// <returns>Targets with an address of <paramref name="family"/>; unresolved host names are excluded.</returns>
        public IEnumerable<ScanTargetEntry> TargetsOf(Network.IpFamily family) =>
            Targets.Where(t => t.Family == family);

        /// <summary>
        /// Whether there is at least one target of this family.
        /// <para>
        /// A target given only as a host name counts for <em>every</em>
        /// family: which one it becomes is only decided by name resolution
        /// during the run. Until then the family is unknown.
        /// </para>
        /// <para>
        /// Without this exception every method is blocked as soon as the
        /// target list contains only a host name and no scope is checked: ping
        /// appears greyed out with "No IPv4 targets selected" although the
        /// name points to an IPv4 address. Not offering a method that could
        /// run is the worse error; if it finds nothing, the result says so
        /// clearly.
        /// </para>
        /// </summary>
        /// <param name="family">The address family.</param>
        /// <returns>True if a target of <paramref name="family"/> or an unresolved host name exists.</returns>
        public bool HasTargetsOf(Network.IpFamily family) =>
            Targets.Any(t => t.Family == family || (t.Family is null && t.HostName is not null));

        /// <summary>
        /// At least one scope allows IPv6 on the local segment. Relevant for
        /// methods that work with link-local addresses: neighbor discovery,
        /// ff02::1, RA capture, MLD.
        /// </summary>
        public bool AnyScopeAllowsLocalIpv6 => Scopes.Any(s => s.Ipv6.CanScanLocalSegment);

        /// <summary>At least one scope allows IPv6 across segment boundaries.</summary>
        public bool AnyScopeAllowsRoutedIpv6 => Scopes.Any(s => s.Ipv6.CanScanRoutedTargets);

        /// <summary>
        /// The reason IPv6 is unavailable everywhere, for display in the UI.
        /// Takes the reason of the first scope, because it normally applies
        /// to all.
        /// </summary>
        public string Ipv6BlockReason =>
            Scopes.FirstOrDefault()?.Ipv6.Reason ?? "No range selected.";
    }

    /// <summary>
    /// A scan method. All scan modules, IPv4 and IPv6, are handled uniformly
    /// through this interface. Adding a method means implementing and
    /// registering it.
    /// <para>
    /// The scan modules themselves stay independent of the engine. They are
    /// wrapped by adapters that translate their events into
    /// <see cref="ScanContext.Report"/>.
    /// </para>
    /// </summary>
    public interface IScanMethod
    {
        /// <summary>
        /// Immutable key, such as "ping" or "ndp.neighborcache". It is
        /// persisted; display names may change, this key must not.
        /// </summary>
        string Id { get; }

        /// <summary>Name shown in the UI.</summary>
        string DisplayName { get; }

        /// <summary>
        /// What the method finds and what it is used for, written for the
        /// person deciding in front of the list whether to check it.
        /// <para>
        /// The method name alone does not answer this: "SNMP" does not tell
        /// anyone whether it is worthwhile. The text therefore states two
        /// things: <b>which devices typically speak it</b> and <b>what it
        /// yields</b>. No protocol details, no abbreviations that are not
        /// explained first.
        /// </para>
        /// </summary>
        string Explanation { get; }

        /// <summary>Phase the method runs in.</summary>
        ScanPhase Phase { get; }

        /// <summary>Address families the method handles.</summary>
        FamilySupport Families { get; }

        /// <summary>
        /// The method listens instead of asking: router advertisements, MLD,
        /// the neighbor cache. Passive methods keep running after the scan
        /// ends and are what turns the scanner into a monitor.
        /// </summary>
        bool IsPassive { get; }

        /// <summary>
        /// The method walks through a target list instead of sending a single
        /// query to everyone.
        /// <para>
        /// Only such methods can be restricted to devices already found; SSDP,
        /// mDNS and the ARP cache have no target list that could be shortened.
        /// This property decides whether the UI offers a checkbox for the
        /// method under "scan only devices in table".
        /// </para>
        /// </summary>
        bool EnumeratesTargets { get; }

        /// <summary>
        /// Requires raw sockets and thus elevated privileges, or CAP_NET_RAW on
        /// Linux. The UI can check and report this in advance instead of
        /// letting the method fail.
        /// </summary>
        bool RequiresElevation { get; }

        /// <summary>
        /// Shown indented below the preceding method in the UI, for variants
        /// that belong to it, such as the full port scan below the regular
        /// one. Presentation only, no effect on the run. Default: not
        /// indented.
        /// </summary>
        bool Indented => false;

        /// <summary>
        /// Checks before the run whether the method can achieve anything here.
        /// Must be cheap: no network access.
        /// </summary>
        /// <param name="context">The run context.</param>
        /// <returns>Whether the method can run, and if not, why.</returns>
        ScanMethodAvailability CheckAvailability(ScanContext context);

        /// <summary>
        /// Executes the method. On cancellation through
        /// <paramref name="cancellationToken"/> it returns promptly; an
        /// <see cref="OperationCanceledException"/> is permitted and is treated
        /// by the engine as cancellation, not as an error.
        /// </summary>
        /// <param name="context">The run context.</param>
        /// <param name="cancellationToken">Cancels the method.</param>
        /// <returns>A task that completes when the method has finished.</returns>
        Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken);
    }
}
