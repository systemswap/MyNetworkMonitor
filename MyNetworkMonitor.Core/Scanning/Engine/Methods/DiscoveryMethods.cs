using MyNetworkMonitor.Core.Network;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// ARP-Request an jedes Ziel. Unter IPv6 gibt es kein ARP - dort
    /// uebernimmt Neighbor Discovery, das als eigenes Verfahren kommt.
    /// </summary>
    public sealed class ArpRequestScanMethod : LegacyScanMethod
    {
        public override string Id => "arp.request";
        public override string DisplayName => "ARP-Request";
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
                    "Keine IPv4-Ziele. Unter IPv6 tritt an die Stelle von ARP die Neighbor Discovery.");
        }

        /// <summary>
        /// ARP ist plattformabhaengig und braucht die Registrierung des
        /// Startprojekts. Ohne sie wird das Verfahren gemeldet statt zu werfen.
        /// </summary>
        internal const string ArpProviderMissing =
            "Kein ARP-Anbieter registriert. Diese Plattform wird noch nicht unterstuetzt.";

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
    /// Liest die ARP-Tabelle des Betriebssystems aus. Findet auch Geraete, die
    /// selbst nicht antworten, solange jemand anders mit ihnen gesprochen hat.
    /// Das IPv6-Gegenstueck ist der Neighbor Cache.
    /// </summary>
    public sealed class ArpCacheScanMethod : LegacyScanMethod
    {
        public override string Id => "arp.cache";
        public override string DisplayName => "ARP-Tabelle";
        public override ScanPhase Phase => ScanPhase.Discovery;
        public override FamilySupport Families => FamilySupport.IPv4;

        public override ScanMethodAvailability CheckAvailability(ScanContext context) =>
            PlatformServices.ArpOrNull is null
                ? ScanMethodAvailability.Blocked(ArpRequestScanMethod.ArpProviderMissing)
                : ScanMethodAvailability.Available;

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            // Bewusst ueber alle Ziele, nicht nur die ausgewaehlten: die
            // Tabelle enthaelt auch Geraete ausserhalb des Bereichs, und
            // gerade die sind interessant.
            LegacyTargets targets = BuildTargets(context);

            ScanningMethod_ARP arp = new();

            void OnProgress(int c, int r, int t, ScanStatus s) => context.ReportProgress(c, r, t);
            void OnFound(object? _, ScanTask_Finished_EventArgs e) => ReportResult(context, e.ipToScan, targets);

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
