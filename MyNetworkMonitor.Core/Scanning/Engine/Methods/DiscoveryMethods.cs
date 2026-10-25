using MyNetworkMonitor.Core.Network;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// ARP request to every target. IPv6 has no ARP; there, neighbor
    /// discovery takes its place, covered by the IPv6 methods.
    /// </summary>
    public sealed class ArpRequestScanMethod : LegacyScanMethod
    {
        public override string Id => "arp.request";
        public override string DisplayName => "ARP request";

        public override string Explanation =>
            "Calls out on the local cable: \"who has this address?\" Every device on the " +
            "same network segment has to answer - that is how the network works, and a " +
            "firewall cannot suppress it. So this finds machines that stay silent on Ping. " +
            "You also get the hardware address (MAC), which says who built the network " +
            "card - often the first hint at what kind of device it is. Only works within " +
            "your own segment: anything behind a router cannot hear the call.";
        public override ScanPhase Phase => ScanPhase.Discovery;
        public override FamilySupport Families => FamilySupport.IPv4;

        public override ScanMethodAvailability CheckAvailability(ScanContext context)
        {
            if (PlatformServices.ArpOrNull is null)
            {
                return ScanMethodAvailability.Blocked(ArpProviderMissing);
            }

            return context.HasTargetsOf(IpFamily.IPv4)
                ? ScanMethodAvailability.Available
                : ScanMethodAvailability.NotApplicable(
                    "No IPv4 targets. Under IPv6, Neighbor Discovery takes the place of ARP.");
        }

        /// <summary>
        /// ARP is platform-specific and requires the provider registered by the
        /// startup project. Without it, the method is reported as blocked
        /// instead of throwing.
        /// </summary>
        internal const string ArpProviderMissing =
            "No ARP provider registered. This platform is not supported yet.";

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            LegacyTargets targets = BuildTargets(context);
            if (targets.Count == 0) return;

            ScanningMethod_ARP arp = new();

            void OnProgress(int c, int r, int t, ScanStatus s) => context.ReportProgress(c, r, t);
            void OnFound(object? _, ScanTask_Finished_EventArgs e) => ReportResult(context, e.ipToScan, targets);

            arp.ProgressUpdated += OnProgress;
            arp.ARP_Request_Task_Finished += OnFound;
            using CancellationTokenRegistration reg = BridgeCancellation(cancellationToken, arp.StopScan);

            try { await arp.SendARPRequestAsync(targets.Items); }
            finally
            {
                arp.ProgressUpdated -= OnProgress;
                arp.ARP_Request_Task_Finished -= OnFound;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    /// <summary>
    /// Reads the operating system's ARP table. Also finds devices that do not
    /// answer themselves, as long as the local machine has exchanged data with
    /// them. The IPv6 counterpart is the neighbor cache.
    /// </summary>
    public sealed class ArpCacheScanMethod : LegacyScanMethod
    {
        public override string Id => "arp.cache";
        public override string DisplayName => "ARP table";

        public override string Explanation =>
            "Looks into a list your own computer already keeps: every device it has " +
            "recently exchanged data with, together with its hardware address (MAC). " +
            "Costs nothing and disturbs nobody - no packet leaves the machine. It can " +
            "turn up devices that are switched off by now, because the entry survives " +
            "them for a while, and it says nothing about devices your computer has " +
            "never talked to. A good free extra, not a substitute for a real scan.";
        public override ScanPhase Phase => ScanPhase.Discovery;
        public override FamilySupport Families => FamilySupport.IPv4;

        // Reads the local machine's table; its content is determined by the
        // operating system, not by a target list.
        public override bool EnumeratesTargets => false;

        public override ScanMethodAvailability CheckAvailability(ScanContext context) =>
            PlatformServices.ArpOrNull is null
                ? ScanMethodAvailability.Blocked(ArpRequestScanMethod.ArpProviderMissing)
                : ScanMethodAvailability.Available;

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            LegacyTargets targets = BuildTargets(context);

            ScanningMethod_ARP arp = new();

            void OnProgress(int c, int r, int t, ScanStatus s) => context.ReportProgress(c, r, t);

            // Only entries that belong to the selection are reported.
            //
            // Reporting the whole table, although devices outside the scope
            // may be of interest, is surprising in practice: checking a single
            // machine with all scopes deselected would put half the interface
            // subnet into the table and suggest that everything had been
            // scanned. None of it was scanned (the entries come from the
            // operating system's own cache), but the table does not show
            // that.
            void OnFound(object? _, ScanTask_Finished_EventArgs e)
            {
                if (targets.Find(e.ipToScan?.IPorHostname) is null) return;

                ReportResult(context, e.ipToScan!, targets);
            }

            arp.ProgressUpdated += OnProgress;
            arp.ARP_A_newDevice += OnFound;
            using CancellationTokenRegistration reg = BridgeCancellation(cancellationToken, arp.StopScan);

            try { await arp.ARP_A(targets.Items); }
            finally
            {
                arp.ProgressUpdated -= OnProgress;
                arp.ARP_A_newDevice -= OnFound;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
    }
}
