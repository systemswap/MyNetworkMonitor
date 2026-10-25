// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// SSDP/UPnP discovery. Instead of querying each target, it sends one
    /// request to everyone and waits for announcements, and therefore also
    /// finds devices outside the selected scopes.
    /// <para>
    /// The module binds its receive endpoint to
    /// <c>SupportMethods.SelectedNetworkInterfaceInfos.IPv4</c>. If nothing is
    /// set there, it throws; hence the precondition in
    /// <see cref="CheckAvailability"/>.
    /// </para>
    /// </summary>
    public sealed class SsdpScanMethod : LegacyScanMethod
    {
        /// <summary>How long to wait for announcements, in milliseconds.</summary>
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

        // One query to everyone, then listen: there is no target list that
        // could be restricted to known devices.
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
    /// mDNS/Bonjour discovery over one network interface.
    /// <para>
    /// The module has no <c>StopScan()</c>; it listens until its listening
    /// time has elapsed or the cancellation token passed to
    /// <c>DiscoverAsync</c> is cancelled.
    /// </para>
    /// <para>
    /// Over IPv6, mDNS listens on ff02::fb. The module binds its socket with
    /// <c>AddressFamily.InterNetwork</c> and therefore covers IPv4 only; IPv6
    /// is covered by the passive IPv6 methods.
    /// </para>
    /// </summary>
    public sealed class MdnsScanMethod : LegacyScanMethod
    {
        /// <summary>How long to listen for answers, in milliseconds.</summary>
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

        // Listens on the multicast group; no target list.
        public override bool EnumeratesTargets => false;

        // Like SSDP, tied to the globally selected interface rather than to
        // the interface of a scope: <c>EnsureLocalInterfaceSelected</c> sets it
        // even when no scope is checked. Tied to a scope instead, mDNS would be
        // greyed out whenever no scope is selected, although the machine has
        // an interface it can listen on.
        public override ScanMethodAvailability CheckAvailability(ScanContext context) =>
            SupportMethods.SelectedNetworkInterfaceInfos.IPv4 is null
                ? ScanMethodAvailability.Blocked(
                    "No network adapter selected. mDNS has to bind its listener to a local IPv4 address.")
                : ScanMethodAvailability.Available;

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            // The scope's interface if there is one, otherwise the local
            // default, so that mDNS also runs when rescanning individual
            // devices, where no scope with an interface is involved.
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
                // DiscoverAsync observes the cancellation token itself, so its
                // receive loop ends on cancellation instead of continuing in
                // the background after the caller has stopped waiting.
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
    /// WS-Discovery: the multicast probe that Windows machines and network
    /// printers answer.
    /// <para>
    /// The reason this method exists: all others only find devices that
    /// answer a directed request. A Windows machine with the default firewall
    /// does not: it blocks ICMP, often has no PTR record and shows no open
    /// ports from outside. It answers here, because Windows itself uses this
    /// protocol to populate its network neighbourhood.
    /// </para>
    /// <para>
    /// Reports the address as responding and records the device class. Binds
    /// the receive endpoint to the selected network interface like SSDP, hence
    /// the same precondition.
    /// </para>
    /// </summary>
    public sealed class WsDiscoveryScanMethod : LegacyScanMethod
    {
        /// <summary>How long to wait for answers, in milliseconds.</summary>
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

        // One query to everyone, then listen: there is no target list.
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

                    // The actual finding: the address is alive, which no
                    // other method can show for such a device.
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
        /// Also records the finding in the services column (port 3702), as SMB
        /// and SNMP do for theirs. Otherwise a device found only this way would
        /// appear in the table without a single service and look like an empty
        /// entry.
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
    /// ONVIF discovery of IP cameras. Like SSDP, a multicast probe to everyone
    /// instead of one query per target.
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
