using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// Integrates <see cref="ScanningMethods_Ping"/> into the engine. The
    /// module itself stays independent of the engine; the adapter only
    /// translates its events into <see cref="ScanContext.Report"/> and
    /// forwards cancellation.
    /// <para>
    /// <b>Deliberately IPv4 only.</b> <c>ScanningMethods_Ping.PingTask</c>
    /// validates every target with <c>SupportMethods.Is_Valid_IP</c>, an
    /// IPv4-only regular expression; IPv6 targets are dropped there silently.
    /// The adapter therefore declares <see cref="FamilySupport.IPv4"/> instead
    /// of claiming a capability the module lacks. The ICMPv6 counterpart is a
    /// separate method (<see cref="Ipv6MulticastPingScanMethod"/>, echo to
    /// ff02::1), which works differently anyway: one packet to everyone
    /// instead of one per address.
    /// </para>
    /// </summary>
    public sealed class PingScanMethod : IScanMethod
    {
        public string Id => "ping";
        public string DisplayName => "Ping";

        public string Explanation =>
            "Asks every address in the range whether anyone is there. The oldest and " +
            "most reliable check: almost every device answers, from servers to phones. " +
            "You get to know which addresses are in use at all - no names, no details. " +
            "Some devices are told to stay quiet and will be missed here; a firewall on " +
            "the target is the usual reason. Start with this one, then let the other " +
            "methods fill in the blanks.";
        public ScanPhase Phase => ScanPhase.Discovery;
        public FamilySupport Families => FamilySupport.IPv4;
        public bool IsPassive => false;
        public bool RequiresElevation => false;
        public bool EnumeratesTargets => true;

        public ScanMethodAvailability CheckAvailability(ScanContext context)
        {
            if (!context.HasTargetsOf(IpFamily.IPv4))
            {
                return ScanMethodAvailability.NotApplicable(
                    "No IPv4 targets selected. For IPv6 the multicast ping to ff02::1 does this instead.");
            }

            return ScanMethodAvailability.Available;
        }

        public async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            List<ScanTargetEntry> targets = context.TargetsOf(IpFamily.IPv4).ToList();
            if (targets.Count == 0) return;

            // Maps the engine's model to the module's model. The mapping is
            // kept so that the module's response can be assigned to the
            // correct scope.
            Dictionary<string, ScanTargetEntry> byText = [];
            List<IPToScan> legacy = [];

            foreach (ScanTargetEntry target in targets)
            {
                string text = target.TargetText;
                if (string.IsNullOrEmpty(text) || !byText.TryAdd(text, target)) continue;

                legacy.Add(new IPToScan
                {
                    IPorHostname = text,
                    TimeOut = context.Settings.PortTimeoutMs,
                    IPGroupDescription = target.Scope.Scope.GroupDescription
                });
            }

            ScanningMethods_Ping ping = new();

            void OnProgress(int current, int responded, int total, ScanStatus status) =>
                context.ReportProgress(current, responded, total);

            void OnFinished(object? sender, ScanTask_Finished_EventArgs e)
            {
                IPToScan result = e.ipToScan;
                if (!IpAddressAnalyzer.TryAnalyze(result.IPorHostname, out IpAddressInfo? info) || info is null) return;

                byText.TryGetValue(result.IPorHostname, out ScanTargetEntry? origin);

                Dictionary<string, string>? details = null;
                if (!string.IsNullOrWhiteSpace(result.ResponseTime))
                {
                    details = new Dictionary<string, string> { ["Response time"] = $"{result.ResponseTime} ms" };
                }

                context.Report(new DeviceObservation
                {
                    Source = DisplayName,
                    Address = info,
                    IsResponding = result.PingStatus,

                    // The name under which the target was entered.
                    //
                    // A host name entered in the target list is expected to
                    // appear in the table, not just the address it resolved
                    // to. For a single target, ping is often the only method
                    // that runs; without this line the "Device" column would
                    // show the address until a reverse lookup supplied a name,
                    // or never.
                    HostName = string.IsNullOrWhiteSpace(origin?.HostName) ? null : origin!.HostName,

                    GroupDescription = origin?.Scope.Scope.GroupDescription,
                    Domain = string.IsNullOrWhiteSpace(origin?.Scope.Scope.Domain) ? null : origin!.Scope.Scope.Domain,
                    Details = details,

                    // Every reply carries the remaining TTL. It is the only
                    // hint at the operating system available without sending
                    // another packet.
                    Ttl = result.TTL
                });
            }

            ping.ProgressUpdated += OnProgress;
            ping.Ping_Task_Finished += OnFinished;

            // The module manages its own cancellation and only offers
            // StopScan(). The registration bridges that to the engine's token.
            using CancellationTokenRegistration registration = cancellationToken.Register(ping.StopScan);

            try
            {
                await ping.PingIPsAsync(legacy);
            }
            finally
            {
                ping.ProgressUpdated -= OnProgress;
                ping.Ping_Task_Finished -= OnFinished;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
    }
}
