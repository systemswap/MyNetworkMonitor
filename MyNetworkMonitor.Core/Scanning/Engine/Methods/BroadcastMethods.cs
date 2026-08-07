using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// SSDP/UPnP-Suche. Fragt nicht jedes Ziel einzeln, sondern schickt eine
    /// Anfrage an alle und wartet auf Meldungen - findet darum auch Geraete
    /// ausserhalb der gewaehlten Bereiche.
    /// <para>
    /// Das Modul bindet seinen Empfangspunkt an
    /// <c>SupportMethods.SelectedNetworkInterfaceInfos.IPv4</c>. Ist dort noch
    /// nichts gesetzt, wirft es - darum die Vorbedingung in
    /// <see cref="CheckAvailability"/>.
    /// </para>
    /// </summary>
    public sealed class SsdpScanMethod : LegacyScanMethod
    {
        /// <summary>Wie lange auf Meldungen gewartet wird.</summary>
        public int ScanDurationMs { get; set; } = 5000;

        public override string Id => "ssdp";
        public override string DisplayName => "SSDP / UPnP";
        public override ScanPhase Phase => ScanPhase.Discovery;
        public override FamilySupport Families => FamilySupport.IPv4;

        // Eine Frage an alle, dann zuhoeren - es gibt keine Zielliste, die
        // sich auf die bekannten Geraete kuerzen liesse.
        public override bool EnumeratesTargets => false;

        public override ScanMethodAvailability CheckAvailability(ScanContext context) =>
            SupportMethods.SelectedNetworkInterfaceInfos.IPv4 is null
                ? ScanMethodAvailability.Blocked(
                    "No network adapter selected. SSDP has to bind its listener to a local IPv4 address.")
                : ScanMethodAvailability.Available;

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            LegacyTargets targets = BuildTargets(context);

            ScanningMethod_SSDP_UPNP ssdp = new();

            void OnProgress(int c, int r, int t, ScanStatus s) => context.ReportProgress(c, r, t);
            void OnFound(object? _, ScanTask_Finished_EventArgs e) => ReportResult(context, e.ipToScan, targets);

            ssdp.ProgressUpdated += OnProgress;
            ssdp.SSDP_foundNewDevice += OnFound;
            using CancellationTokenRegistration reg = BridgeCancellation(cancellationToken, ssdp.StopScan);

            try
            {
                await ssdp.Scan_for_SSDP_devices_async(ScanDurationMs);
            }
            finally
            {
                ssdp.ProgressUpdated -= OnProgress;
                ssdp.SSDP_foundNewDevice -= OnFound;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    /// <summary>
    /// mDNS/Bonjour-Suche ueber einen Adapter.
    /// <para>
    /// Das Modul kennt kein <c>StopScan()</c> - es laeuft, bis seine Hoerzeit
    /// abgelaufen ist. Bei Abbruch kehrt der Adapter darum zurueck, ohne auf
    /// das Modul zu warten; dessen Aufgabe laeuft im Hintergrund aus.
    /// </para>
    /// <para>
    /// Unter IPv6 lauscht mDNS auf ff02::fb. Das Modul bindet seinen Socket
    /// jedoch mit <c>AddressFamily.InterNetwork</c> und deckt damit nur IPv4
    /// ab; die IPv6-Seite kommt mit den passiven Verfahren.
    /// </para>
    /// </summary>
    public sealed class MdnsScanMethod : LegacyScanMethod
    {
        public int ListenTimeMs { get; set; } = 5000;

        public override string Id => "mdns";
        public override string DisplayName => "mDNS";
        public override ScanPhase Phase => ScanPhase.Discovery;
        public override FamilySupport Families => FamilySupport.IPv4;

        // Zuhoeren auf der Multicast-Gruppe, keine Zielliste.
        public override bool EnumeratesTargets => false;

        public override ScanMethodAvailability CheckAvailability(ScanContext context)
        {
            ScopeRuntime? withInterface = context.Scopes.FirstOrDefault(s => s.Interface is not null);

            return withInterface is null
                ? ScanMethodAvailability.Blocked("No network adapter assigned.")
                : ScanMethodAvailability.Available;
        }

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            ScopeRuntime? runtime = context.Scopes.FirstOrDefault(s => s.Interface is not null);
            if (runtime?.Interface is null) return;

            LegacyTargets targets = BuildTargets(context);

            ScanningMethod_mDNS mdns = new();

            void OnProgress(int c, int r, int t, ScanStatus s) => context.ReportProgress(c, r, t);
            void OnFound(IPToScan ip) => ReportResult(context, ip, targets);

            mdns.ProgressUpdated += OnProgress;
            mdns.found_mDNS_Device += OnFound;

            try
            {
                Task discovery = mdns.DiscoverAsync(runtime.Interface.Name, ListenTimeMs);

                // Kein StopScan vorhanden - bei Abbruch nicht laenger warten.
                Task cancelled = Task.Delay(Timeout.Infinite, cancellationToken);
                await Task.WhenAny(discovery, cancelled);
            }
            catch (OperationCanceledException)
            {
                // Abbruch ist kein Fehler.
            }
            finally
            {
                mdns.ProgressUpdated -= OnProgress;
                mdns.found_mDNS_Device -= OnFound;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    /// <summary>
    /// ONVIF-Suche nach IP-Kameras. Wie SSDP eine Rundfrage an alle statt
    /// einer Abfrage je Ziel.
    /// </summary>
    public sealed class OnvifScanMethod : LegacyScanMethod
    {
        public override string Id => "onvif";
        public override string DisplayName => "ONVIF cameras";
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

            ScanningMethod_ONVIF_IPCam onvif = new();

            void OnProgress(int c, int r, int t, ScanStatus s) => context.ReportProgress(c, r, t);
            void OnFound(object? _, ScanTask_Finished_EventArgs e) => ReportResult(context, e.ipToScan, targets);

            onvif.ProgressUpdated += OnProgress;
            onvif.new_ONVIF_IP_Camera_Found_Task_Finished += OnFound;
            using CancellationTokenRegistration reg = BridgeCancellation(cancellationToken, onvif.StopScan);

            try
            {
                await onvif.Discover(targets.Items);
            }
            finally
            {
                onvif.ProgressUpdated -= OnProgress;
                onvif.new_ONVIF_IP_Camera_Found_Task_Finished -= OnFound;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
    }
}
