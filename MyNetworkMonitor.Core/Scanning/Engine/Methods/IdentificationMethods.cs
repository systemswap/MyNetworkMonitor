// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// Asks the switches which device is connected to which port.
    /// <para>
    /// <b>The question no other method answers:</b> all other methods tell
    /// <em>that</em> a device exists. This one tells <em>where</em> it is
    /// connected: on which switch, which port, which VLAN. That is the
    /// information needed to actually go there and pull a cable.
    /// </para>
    /// <para>
    /// The query uses SNMP rather than capturing LLDP frames. Capturing would
    /// require npcap or <c>CAP_NET_RAW</c> and would only reveal where the
    /// local machine is connected; the switch, by contrast, keeps the mapping
    /// for all of its ports and returns it once the community string is
    /// correct.
    /// </para>
    /// </summary>
    public sealed class SwitchPortScanMethod : LegacyScanMethod
    {
        public override string Id => "switch.ports";
        public override string DisplayName => "Switch port and VLAN";

        public override string Explanation =>
            "Asks the switches themselves which device is plugged into which port, and " +
            "which VLAN that port belongs to. Every other method tells you that a device " +
            "exists; this one tells you where it physically sits - the answer you need " +
            "when something has to be unplugged, traced or moved. It also shows up devices " +
            "sitting in a VLAN they were never meant to be in. Needs SNMP access to the " +
            "switch, so set the community string under Settings if it is not \"public\".";

        public override ScanPhase Phase => ScanPhase.Identification;
        public override FamilySupport Families => FamilySupport.IPv4;

        // The switches are queried, not the devices, so there is no target
        // list of found devices to restrict.
        public override bool EnumeratesTargets => false;

        public override ScanMethodAvailability CheckAvailability(ScanContext context) =>
            SwitchAddresses(context).Count == 0
                ? ScanMethodAvailability.NotApplicable(
                    "No gateway known. The switch is asked at the gateway address of the selected ranges.")
                : ScanMethodAvailability.Available;

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            List<string> switches = SwitchAddresses(context);
            if (switches.Count == 0) return;

            ScanningMethod_SwitchPorts module = new()
            {
                Community = context.Settings.SnmpCommunity,
                TimeoutMs = context.Settings.PortTimeoutMs
            };

            void OnProgress(int c, int r, int t, ScanStatus s) => context.ReportProgress(c, r, t);
            void OnFound(SwitchPortResult found) => Report(context, found);

            module.ProgressUpdated += OnProgress;
            module.SwitchPortFound += OnFound;
            using CancellationTokenRegistration reg = BridgeCancellation(cancellationToken, module.StopScan);

            try
            {
                await module.ScanAsync(switches);
            }
            finally
            {
                module.ProgressUpdated -= OnProgress;
                module.SwitchPortFound -= OnFound;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }

        /// <summary>
        /// The addresses queried as switches: the gateways of the interfaces
        /// that belong to the selected scopes.
        /// <para>
        /// The gateway is not always the switch the device is connected to,
        /// but in small networks it almost always is, and in larger ones it is
        /// the starting point for further searching. Querying every found
        /// address with SNMP instead would amount to a port scan on 161 and
        /// take many times longer.
        /// </para>
        /// </summary>
        private static List<string> SwitchAddresses(ScanContext context)
        {
            List<string> addresses = [];

            foreach (ScopeRuntime runtime in context.Scopes)
            {
                if (runtime.Interface is null) continue;

                IEnumerable<string> gateways = runtime.Interface
                    .GetIPProperties().GatewayAddresses
                    .Where(g => g.Address is not null)
                    .Select(g => g.Address.ToString());

                foreach (string gateway in gateways)
                {
                    // IPv4 only: the Bridge MIB is queried through the
                    // switch's IPv4 address.
                    if (!IpAddressAnalyzer.TryAnalyze(gateway, out IpAddressInfo? info) || info is null) continue;
                    if (info.Family != IpFamily.IPv4) continue;

                    if (!addresses.Contains(info.Canonical, StringComparer.OrdinalIgnoreCase))
                    {
                        addresses.Add(info.Canonical);
                    }
                }
            }

            return addresses;
        }

        /// <summary>
        /// Reports the finding by MAC address.
        /// <para>
        /// Deliberately without an IP address: the switch only knows MAC
        /// addresses, and the store maps them to devices through its
        /// identifier cascade better than could be done here. A device not yet
        /// found is created, with its switch port as the first information.
        /// That is intended: it is connected to the network, even if it
        /// answers nothing.
        /// </para>
        /// </summary>
        private static void Report(ScanContext context, SwitchPortResult found)
        {
            if (found.ParsedMac is not { } mac) return;

            List<string> lines =
            [
                $"Switch: {found.SwitchName} ({found.SwitchAddress})",
                $"Port: {found.Port}"
            ];

            if (!string.IsNullOrWhiteSpace(found.Vlan)) lines.Add($"VLAN: {found.Vlan}");

            context.Report(new DeviceObservation
            {
                Source = "Switch port and VLAN",
                Mac = mac,

                // No IsResponding: that the switch lists the MAC in its table
                // only means it has recently sent traffic, not that it has
                // answered this scanner.
                SwitchName = found.SwitchName,
                SwitchPort = found.Port,
                Vlan = found.Vlan,
                Details = new Dictionary<string, string> { ["Switch port"] = string.Join(Environment.NewLine, lines) }
            });
        }
    }

    /// <summary>
    /// Resolves host names through DNS. Without a DNS server configured for
    /// the scope, the gateway is queried; see docs/FEHLERGEDAECHTNIS.md, No. 8.
    /// </summary>
    public sealed class HostnameLookupScanMethod : LegacyScanMethod
    {
        public override string Id => "dns.lookup";
        public override string DisplayName => "Hostname";

        public override string Explanation =>
            "Asks the name server which address belongs to a name - the same step your " +
            "browser takes when you type in a web address. Use it when you know the names " +
            "of your machines and want to check where they actually point. In a company " +
            "network this is also how you spot stale entries: a name that resolves to an " +
            "address where nothing answers any more usually means the device is long gone " +
            "and only the record stayed behind.";
        public override ScanPhase Phase => ScanPhase.Identification;

        // DNS has AAAA records; the module passes the target text through
        // without checking it for IPv4.
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
    /// Reverse lookup including aliases. Over IPv6 it runs through ip6.arpa;
    /// the module passes the address through and the DNS client builds the
    /// query. Concurrency and time budget: see docs/FEHLERGEDAECHTNIS.md,
    /// No. 7; DNS server selection: No. 8.
    /// </summary>
    public sealed class ReverseLookupScanMethod : LegacyScanMethod
    {
        /// <summary>Query all configured DNS servers instead of only the first.</summary>
        public bool DeepScan { get; set; }

        public override string Id => "dns.reverse";
        public override string DisplayName => "Reverse lookup";

        public override string Explanation =>
            "The other direction: you have an address and want the name behind it. This is " +
            "what turns a list of bare numbers into something readable, and it also brings " +
            "in second names a device carries. Only works where someone has kept the name " +
            "server tidy - in a home network mostly nothing comes back, in a company " +
            "network almost everything. Where the answer is missing or wrong, the record " +
            "has not been maintained.";
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

            ScanningMethod_ReverseLookupToHostAndAlieases reverse = new()
            {
                MaxConcurrentLookups = context.Settings.ReverseLookupConcurrency
            };

            void OnProgress(int c, int r, int t, ScanStatus s) => context.ReportProgress(c, r, t);

            // The module reports a failure by passing null event data; an
            // address without a PTR record is the normal case, not the
            // exception. Accessed unchecked, this takes down the task and the
            // rest of the run stalls.
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
    /// NetBIOS node status query (RFC 1002, section 4.2.17/4.2.18; see
    /// docs/FEHLERGEDAECHTNIS.md, No. 15). NetBIOS over TCP/IP does not exist
    /// for IPv6; the method is restricted to IPv4 by design, not because of a
    /// gap in the adapter.
    /// </summary>
    public sealed class NetBiosScanMethod : LegacyScanMethod
    {
        public override string Id => "netbios";
        public override string DisplayName => "NetBIOS";

        public override string Explanation =>
            "The old Windows way of asking a machine \"what is your name?\" directly, " +
            "without any name server. Windows PCs and servers answer, as do network " +
            "storage boxes and anything else that offers Windows file shares. You get the " +
            "computer name, often the workgroup or domain, and the hardware address (MAC). " +
            "Especially useful where the name server knows nothing - the machine answers " +
            "for itself.";
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
    /// SNMP query. Returns system name, serial number, location and MAC,
    /// which is particularly informative for printers and active network
    /// components.
    /// <para>
    /// IPv4 only: <c>ScanningMethod_SNMP</c> validates every target with
    /// <c>SupportMethods.Is_Valid_IP</c>, an IPv4-only regular expression.
    /// </para>
    /// </summary>
    public sealed class SnmpScanMethod : LegacyScanMethod
    {
        public override string Id => "snmp";
        public override string DisplayName => "SNMP";

        public override string Explanation =>
            "The language network equipment speaks about itself. Printers, switches, " +
            "routers, uninterruptible power supplies and many storage boxes answer here. " +
            "Without logging in you get device name, model, serial number, location as " +
            "the administrator typed it in, and how long the device has been running - by " +
            "far the richest information of any method, and the fastest way to find out " +
            "what a device in the rack actually is. Ordinary PCs usually stay silent.";
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
