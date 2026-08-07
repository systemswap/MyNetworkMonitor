using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>Loest Hostnamen ueber DNS auf.</summary>
    public sealed class HostnameLookupScanMethod : LegacyScanMethod
    {
        public override string Id => "dns.lookup";
        public override string DisplayName => "Hostname";
        public override ScanPhase Phase => ScanPhase.Identification;

        // DNS kennt AAAA-Eintraege; das Modul reicht den Zieltext durch,
        // ohne ihn auf IPv4 zu pruefen.
        public override FamilySupport Families => FamilySupport.Both;

        public override ScanMethodAvailability CheckAvailability(ScanContext context) =>
            context.Targets.Count > 0
                ? ScanMethodAvailability.Available
                : ScanMethodAvailability.NotApplicable("No targets selected.");

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            LegacyTargets targets = BuildTargets(context, only: null);
            if (targets.Count == 0) return;

            ScanningMethod_LookUp lookup = new();

            void OnProgress(int c, int r, int t, ScanStatus s) => context.ReportProgress(c, r, t);
            void OnFound(object? _, ScanTask_Finished_EventArgs e) => ReportResult(context, e.ipToScan, targets);

            lookup.ProgressUpdated += OnProgress;
            lookup.Lookup_Task_Finished += OnFound;
            using CancellationTokenRegistration reg = BridgeCancellation(cancellationToken, lookup.StopScan);

            try { await lookup.LookupAsync(targets.Items); }
            finally
            {
                lookup.ProgressUpdated -= OnProgress;
                lookup.Lookup_Task_Finished -= OnFound;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    /// <summary>
    /// Rueckwaertsaufloesung samt Aliasen. Unter IPv6 laeuft sie ueber
    /// ip6.arpa - das Modul reicht die Adresse durch, die Aufloesung uebernimmt
    /// der Resolver.
    /// </summary>
    public sealed class ReverseLookupScanMethod : LegacyScanMethod
    {
        /// <summary>Alle hinterlegten DNS-Server abfragen statt nur den ersten.</summary>
        public bool DeepScan { get; set; }

        public override string Id => "dns.reverse";
        public override string DisplayName => "Reverse lookup";
        public override ScanPhase Phase => ScanPhase.Identification;
        public override FamilySupport Families => FamilySupport.Both;

        public override ScanMethodAvailability CheckAvailability(ScanContext context) =>
            context.Targets.Count > 0
                ? ScanMethodAvailability.Available
                : ScanMethodAvailability.NotApplicable("No targets selected.");

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            LegacyTargets targets = BuildTargets(context, only: null);
            if (targets.Count == 0) return;

            ScanningMethod_ReverseLookupToHostAndAlieases reverse = new();

            void OnProgress(int c, int r, int t, ScanStatus s) => context.ReportProgress(c, r, t);

            // Das Modul meldet einen Fehlschlag, indem es die Ereignisdaten
            // selbst auf null setzt - eine Adresse ohne PTR-Eintrag ist der
            // Normalfall, nicht die Ausnahme. Ungeprueft zugegriffen, reisst
            // das den Task mit und der Rest des Laufs bleibt liegen.
            void OnFound(object? _, ScanTask_Finished_EventArgs? e)
            {
                if (e?.ipToScan is null) return;

                ReportResult(context, e.ipToScan, targets);
            }

            reverse.ProgressUpdated += OnProgress;
            reverse.GetHostAliases_Task_Finished += OnFound;
            using CancellationTokenRegistration reg = BridgeCancellation(cancellationToken, reverse.StopScan);

            try { await reverse.GetHost_Aliases(targets.Items, DeepScan); }
            finally
            {
                reverse.ProgressUpdated -= OnProgress;
                reverse.GetHostAliases_Task_Finished -= OnFound;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    /// <summary>
    /// NetBIOS-Namensabfrage. Es gibt kein NetBIOS ueber IPv6 - das Verfahren
    /// bleibt dauerhaft auf IPv4 beschraenkt, das ist keine Luecke im Adapter.
    /// </summary>
    public sealed class NetBiosScanMethod : LegacyScanMethod
    {
        public override string Id => "netbios";
        public override string DisplayName => "NetBIOS";
        public override ScanPhase Phase => ScanPhase.Identification;
        public override FamilySupport Families => FamilySupport.IPv4;

        public override ScanMethodAvailability CheckAvailability(ScanContext context) =>
            context.HasTargetsOf(IpFamily.IPv4)
                ? ScanMethodAvailability.Available
                : ScanMethodAvailability.NotApplicable(
                    "No IPv4 targets. NetBIOS over TCP/IP does not exist for IPv6.");

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            LegacyTargets targets = BuildTargets(context);
            if (targets.Count == 0) return;

            ScanningMethod_NetBios netbios = new();

            void OnProgress(int c, int r, int t, ScanStatus s) => context.ReportProgress(c, r, t);
            void OnFound(IPToScan ip) => ReportResult(context, ip, targets);

            netbios.ProgressUpdated += OnProgress;
            netbios.NetbiosIPScanFinished += OnFound;
            using CancellationTokenRegistration reg = BridgeCancellation(cancellationToken, netbios.StopScan);

            try { await netbios.ScanMultipleIPsAsync(targets.Items); }
            finally
            {
                netbios.ProgressUpdated -= OnProgress;
                netbios.NetbiosIPScanFinished -= OnFound;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    /// <summary>
    /// SNMP-Abfrage. Liefert Systemname, Seriennummer, Standort und MAC -
    /// besonders bei Druckern und aktiven Netzkomponenten ergiebig.
    /// <para>
    /// Nur IPv4: <c>ScanningMethod_SNMP</c> prueft jedes Ziel mit
    /// <c>SupportMethods.Is_Valid_IP</c>, einer reinen IPv4-Regex.
    /// </para>
    /// </summary>
    public sealed class SnmpScanMethod : LegacyScanMethod
    {
        public override string Id => "snmp";
        public override string DisplayName => "SNMP";
        public override ScanPhase Phase => ScanPhase.Identification;
        public override FamilySupport Families => FamilySupport.IPv4;

        public override ScanMethodAvailability CheckAvailability(ScanContext context) =>
            context.HasTargetsOf(IpFamily.IPv4)
                ? ScanMethodAvailability.Available
                : ScanMethodAvailability.NotApplicable(NoIpv4Targets);

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            LegacyTargets targets = BuildTargets(context);
            if (targets.Count == 0) return;

            ScanningMethod_SNMP snmp = new();

            void OnProgress(int c, int r, int t, ScanStatus s) => context.ReportProgress(c, r, t);
            void OnFound(IPToScan ip) => ReportResult(context, ip, targets);

            snmp.ProgressUpdated += OnProgress;
            snmp.SNMB_Task_Finished += OnFound;
            using CancellationTokenRegistration reg = BridgeCancellation(cancellationToken, snmp.StopScan);

            try { await snmp.ScanAsync(targets.Items); }
            finally
            {
                snmp.ProgressUpdated -= OnProgress;
                snmp.SNMB_Task_Finished -= OnFound;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
    }
}
