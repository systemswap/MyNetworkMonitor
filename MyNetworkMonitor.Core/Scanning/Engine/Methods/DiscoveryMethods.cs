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
        /// ARP ist plattformabhaengig und braucht die Registrierung des
        /// Startprojekts. Ohne sie wird das Verfahren gemeldet statt zu werfen.
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
    /// Liest die ARP-Tabelle des Betriebssystems aus. Findet auch Geraete, die
    /// selbst nicht antworten, solange jemand anders mit ihnen gesprochen hat.
    /// Das IPv6-Gegenstueck ist der Neighbor Cache.
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

        // Liest die Tabelle des eigenen Rechners aus - was darin steht,
        // bestimmt das Betriebssystem, nicht eine Zielliste.
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

            // Nur melden, was auch zur Auswahl gehoert.
            //
            // Frueher wurde die ganze Tabelle gemeldet - mit der Begruendung,
            // dass gerade die Geraete ausserhalb des Bereichs interessant
            // seien. In der Praxis ueberrascht das: wer einen einzelnen
            // Rechner nachsieht und alle Bereiche abwaehlt, bekam den halben
            // Adapterbereich in die Tabelle und musste annehmen, es sei doch
            // alles gescannt worden. Gescannt war nichts davon - die
            // Eintraege stammen aus dem Zwischenspeicher des eigenen
            // Betriebssystems -, aber das sieht man der Tabelle nicht an.
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
