using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// Fragt die Switches, an welchem Port welches Geraet haengt.
    /// <para>
    /// <b>Die Frage, die sonst niemand beantwortet:</b> alle uebrigen Verfahren
    /// sagen, <em>dass</em> ein Geraet da ist. Dieses sagt, <em>wo</em> es
    /// steckt - an welchem Switch, an welchem Port, in welchem VLAN. Das ist die
    /// Angabe, mit der man tatsaechlich hingehen und ein Kabel ziehen kann.
    /// </para>
    /// <para>
    /// Gefragt wird ueber SNMP und nicht durch Mithoeren von LLDP-Frames.
    /// Mithoeren braeuchte npcap beziehungsweise <c>CAP_NET_RAW</c> und
    /// verriete nur, woran der eigene Rechner haengt; der Switch dagegen fuehrt
    /// die Zuordnung fuer alle seine Ports und gibt sie heraus, sobald die
    /// Gemeinschaftskennung stimmt.
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

        // Gefragt werden die Switches, nicht die Geraete - eine Zielliste der
        // gefundenen Geraete gibt es hier also nicht zu kuerzen.
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
        /// Welche Adressen als Switch befragt werden: die Gateways der Adapter,
        /// die zu den gewaehlten Bereichen gehoeren.
        /// <para>
        /// Das Gateway ist nicht immer der Switch, an dem das Geraet haengt -
        /// in kleinen Netzen aber fast immer, und in groesseren ist es der
        /// Ausgangspunkt, von dem aus man weitersucht. Ein Verfahren, das
        /// stattdessen jede gefundene Adresse mit SNMP anspraeche, waere ein
        /// Portscan auf 161 und dauerte ein Vielfaches.
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
                    // Nur IPv4: die Bridge-MIB wird ueber die v4-Adresse des
                    // Switches abgefragt, und der Umbau auf v6 steht erst mit
                    // den uebrigen Verfahren an.
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
        /// Meldet den Fund ueber die MAC-Adresse.
        /// <para>
        /// Bewusst ohne IP-Adresse: der Switch kennt nur MAC-Adressen, und die
        /// Zuordnung zum Geraet macht der Speicher ueber seine Kennungskaskade
        /// ohnehin besser, als es hier gelaenge. Ein Geraet, das noch gar nicht
        /// gefunden wurde, entsteht dabei neu - mit seinem Switchport als
        /// erster Angabe. Das ist gewollt: es haengt am Netz, auch wenn es auf
        /// nichts antwortet.
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

                // Kein IsResponding: dass der Switch die MAC in seiner Tabelle
                // fuehrt, heisst nur, dass sie kuerzlich gesprochen hat - nicht,
                // dass sie uns geantwortet haette.
                SwitchName = found.SwitchName,
                SwitchPort = found.Port,
                Vlan = found.Vlan,
                Details = new Dictionary<string, string> { ["Switch port"] = string.Join(Environment.NewLine, lines) }
            });
        }
    }

    /// <summary>Loest Hostnamen ueber DNS auf.</summary>
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
