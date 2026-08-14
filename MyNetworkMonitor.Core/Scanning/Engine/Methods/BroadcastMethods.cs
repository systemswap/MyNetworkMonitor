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

        public override string Explanation =>
            "Asks into the room \"who is offering something?\" and listens for a few " +
            "seconds. Devices meant to be found by themselves answer: smart TVs, media " +
            "boxes, game consoles, routers, network storage, printers. They usually " +
            "announce their model name and manufacturer along the way, so you learn what " +
            "a device is, not just that it exists. Because it is a call to everyone, it " +
            "also turns up devices outside the ranges you picked.";
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

        public override string Explanation =>
            "The way devices introduce themselves by name without any name server being " +
            "involved. Apple devices, iPhones, printers, network storage, Chromecasts and " +
            "many smart-home boxes announce themselves this way. It is the method that " +
            "gives you readable names like \"kitchen-printer\" instead of bare numbers, " +
            "and it often tells you what a device offers - printing, file shares, media. " +
            "Listens for a few seconds; only reaches your own network segment.";
        public override ScanPhase Phase => ScanPhase.Discovery;
        public override FamilySupport Families => FamilySupport.IPv4;

        // Zuhoeren auf der Multicast-Gruppe, keine Zielliste.
        public override bool EnumeratesTargets => false;

        // Wie SSDP an der global gewaehlten Schnittstelle festgemacht, nicht am
        // Adapter eines Bereichs: <c>EnsureLocalInterfaceSelected</c> fuellt die
        // auch dann, wenn kein Bereich angehakt ist. Vorher war mDNS ausgegraut,
        // sobald kein Bereich gewaehlt war - obwohl der Rechner sehr wohl einen
        // Adapter hat, auf dem sich lauschen laesst.
        public override ScanMethodAvailability CheckAvailability(ScanContext context) =>
            SupportMethods.SelectedNetworkInterfaceInfos.IPv4 is null
                ? ScanMethodAvailability.Blocked(
                    "No network adapter selected. mDNS has to bind its listener to a local IPv4 address.")
                : ScanMethodAvailability.Available;

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            // Der Adapter des Bereichs, wenn es einen gibt; sonst der lokale
            // Standard - damit mDNS auch beim erneuten Scannen einzelner Geraete
            // laeuft, wo kein Bereich mit Adapter dahintersteht.
            string? interfaceName =
                context.Scopes.FirstOrDefault(s => s.Interface is not null)?.Interface?.Name
                ?? SupportMethods.SelectedNetworkInterfaceInfos.Name;

            if (string.IsNullOrEmpty(interfaceName)) return;

            LegacyTargets targets = BuildTargets(context);

            ScanningMethod_mDNS mdns = new();

            void OnProgress(int c, int r, int t, ScanStatus s) => context.ReportProgress(c, r, t);
            void OnFound(IPToScan ip) => ReportResult(context, ip, targets);

            mdns.ProgressUpdated += OnProgress;
            mdns.found_mDNS_Device += OnFound;

            try
            {
                // DiscoverAsync nimmt den Abbruch inzwischen selbst entgegen -
                // der fruehere Task.WhenAny-Umweg (ohne echtes StopScan lief
                // die Empfangsschleife im Hintergrund weiter, auch nachdem
                // hier laengst nicht mehr gewartet wurde) ist damit ueberfluessig.
                await mdns.DiscoverAsync(interfaceName, ListenTimeMs, cancellationToken);
            }
            finally
            {
                mdns.ProgressUpdated -= OnProgress;
                mdns.found_mDNS_Device -= OnFound;
            }
        }
    }

    /// <summary>
    /// WS-Discovery: die Rundfrage, auf die Windows-Rechner und Netzwerkdrucker
    /// antworten.
    /// <para>
    /// Der Grund, warum es dieses Verfahren gibt: alle uebrigen finden nur
    /// Geraete, die auf eine gezielte Anfrage antworten. Ein Windows-Rechner mit
    /// Standardfirewall tut das nicht - er blockt ICMP, hat oft keinen
    /// PTR-Eintrag und zeigt von aussen keine offenen Ports. Hier antwortet er,
    /// weil Windows selbst darueber seine Netzwerkumgebung fuellt.
    /// </para>
    /// <para>
    /// Meldet die Adresse als antwortend und traegt die Geraeteklasse ein.
    /// Bindet den Empfangspunkt wie SSDP an die gewaehlte Netzkarte - darum
    /// dieselbe Vorbedingung.
    /// </para>
    /// </summary>
    public sealed class WsDiscoveryScanMethod : LegacyScanMethod
    {
        /// <summary>Wie lange auf Antworten gewartet wird.</summary>
        public int ListenTimeMs { get; set; } = 5000;

        public override string Id => "wsdiscovery";
        public override string DisplayName => "WS-Discovery";

        public override string Explanation =>
            "Calls into the network the way Windows itself does when it fills its network " +
            "neighbourhood, and notes who answers. This is the one method that finds the " +
            "machines all the others miss: a Windows PC with its standard firewall does " +
            "not answer a ping, has no name in DNS and shows no open ports - it is simply " +
            "invisible to a normal scan. Here it answers. Network printers and scanners " +
            "answer too, and say which of the two they are. Tick this when the device " +
            "count looks too low for the size of the network.";

        public override ScanPhase Phase => ScanPhase.Discovery;
        public override FamilySupport Families => FamilySupport.IPv4;

        // Eine Frage an alle, dann zuhoeren - es gibt keine Zielliste.
        public override bool EnumeratesTargets => false;

        public override ScanMethodAvailability CheckAvailability(ScanContext context) =>
            SupportMethods.SelectedNetworkInterfaceInfos.IPv4 is null
                ? ScanMethodAvailability.Blocked(
                    "No network adapter selected. WS-Discovery has to send from a local IPv4 address.")
                : ScanMethodAvailability.Available;

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            System.Net.IPAddress? local = SupportMethods.SelectedNetworkInterfaceInfos.IPv4;
            if (local is null) return;

            ScanningMethod_WSDiscovery discovery = new();

            void OnProgress(int c, int r, int t, ScanStatus s) => context.ReportProgress(c, r, t);

            void OnFound(WsDiscoveryResult found)
            {
                if (!IpAddressAnalyzer.TryAnalyze(found.Address, out IpAddressInfo? info) || info is null) return;

                Dictionary<string, string> details = new() { ["WS-Discovery"] = found.Info };

                context.Report(new DeviceObservation
                {
                    Source = DisplayName,
                    Address = info,

                    // Der eigentliche Fund: die Adresse lebt. Genau das war
                    // vorher nicht zu sehen.
                    IsResponding = true,
                    Details = details,
                    Services = BuildService(found, info.Family)
                });
            }

            discovery.ProgressUpdated += OnProgress;
            discovery.WSDiscovery_DeviceFound += OnFound;
            using CancellationTokenRegistration reg = BridgeCancellation(cancellationToken, discovery.StopScan);

            try
            {
                await discovery.DiscoverAsync(local, ListenTimeMs);
            }
            finally
            {
                discovery.ProgressUpdated -= OnProgress;
                discovery.WSDiscovery_DeviceFound -= OnFound;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }

        /// <summary>
        /// Traegt den Fund auch in die Dienstspalte ein - Port 3702, wie SMB
        /// und SNMP es an ihrer Stelle tun. Sonst stuende ein Geraet, das nur
        /// hierueber gefunden wurde, ohne einen einzigen Dienst in der Tabelle
        /// und saehe aus wie ein leerer Eintrag.
        /// </summary>
        private static List<DeviceServiceResult> BuildService(WsDiscoveryResult found, IpFamily family)
        {
            DeviceServiceResult entry = new()
            {
                ServiceName = "WS-Discovery",
                Category = "Network",
                Ports = [3702],
                PortLog = found.Kind is null ? found.Info : $"{found.Kind}{Environment.NewLine}{found.Info}"
            };

            if (family == IpFamily.IPv6) entry.StatusIPv6 = PortStatus.IsRunning;
            else entry.StatusIPv4 = PortStatus.IsRunning;

            return [entry];
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

        public override string Explanation =>
            "Looks specifically for surveillance cameras and video recorders. Nearly every " +
            "professional IP camera answers here, whatever the brand, and reports its " +
            "model and where its video stream can be reached. Worth ticking when you want " +
            "to know how many cameras are hanging in a network and whether one of them is " +
            "there that nobody has on their list - cameras are often installed once and " +
            "then forgotten.";
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
