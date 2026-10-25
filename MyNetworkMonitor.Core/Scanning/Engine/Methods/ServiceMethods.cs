// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;
using MyNetworkMonitor.Core.Scanning.ServiceScans;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// TCP port scan over the configured port selection.
    /// <para>
    /// <b>IPv4 only, because of the socket:</b>
    /// <c>ScanningMethod_PortsTCP</c> opens a socket with
    /// <c>AddressFamily.InterNetwork</c> in
    /// <c>ScanTCP_Port_via_Socket_Async</c>. An IPv6 target would raise an
    /// exception there, not merely return no result. A per-port IPv4/IPv6
    /// comparison requires a dual-stack socket in that module.
    /// </para>
    /// </summary>
    public sealed class TcpPortScanMethod : LegacyScanMethod
    {
        public override string Id => "ports.tcp";
        public override string DisplayName => "TCP ports";

        public override string Explanation =>
            "Knocks on the doors of a device and notes which ones open. Each open door " +
            "stands for something the device offers - a web page, file shares, remote " +
            "desktop, a database. This is how you find out what a machine is for, and " +
            "just as importantly what it offers that nobody intended: an open remote " +
            "desktop or an old web interface on a device that should only be printing. " +
            "Which doors are tried is set under Ports.";
        public override ScanPhase Phase => ScanPhase.Services;
        public override FamilySupport Families => FamilySupport.IPv4;

        public override ScanMethodAvailability CheckAvailability(ScanContext context)
        {
            if (!context.HasTargetsOf(IpFamily.IPv4))
            {
                return ScanMethodAvailability.NotApplicable(NoIpv4Targets);
            }

            if (!context.Settings.ScanAllPorts && context.Settings.TcpPorts.Count == 0)
            {
                return ScanMethodAvailability.NotApplicable(
                    "No ports selected. Pick ports under Manage, or switch on \"all ports\".");
            }

            return ScanMethodAvailability.Available;
        }

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            LegacyTargets targets = BuildTargets(context);
            if (targets.Count == 0) return;

            List<int> ports = context.Settings.ScanAllPorts
                ? [.. Enumerable.Range(1, 65535)]
                : [.. context.Settings.TcpPorts];

            ScanningMethod_PortsTCP tcp = new();

            void OnFound(object? _, ScanTask_Finished_EventArgs e) => ReportResult(context, e.ipToScan, targets);
            void OnProgress(int c, int r, int t) => context.ReportProgress(c, r, t);

            tcp.TcpPortScan_Task_Finished += OnFound;
            tcp.ProgressUpdated += OnProgress;
            using CancellationTokenRegistration reg = BridgeCancellation(cancellationToken, tcp.StopScan);

            try
            {
                await tcp.ScanTCPPortsAsync(targets.Items, ports,
                    TimeSpan.FromMilliseconds(context.Settings.PortTimeoutMs));
            }
            finally
            {
                tcp.TcpPortScan_Task_Finished -= OnFound;
                tcp.ProgressUpdated -= OnProgress;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    /// <summary>
    /// Like <see cref="TcpPortScanMethod"/>, but over all 65535 ports instead
    /// of the configured selection, reporting the ones that are open.
    /// <para>
    /// Shown indented below the regular port scan in the UI and never
    /// preselected: the full pass takes considerably longer and is a
    /// deliberate choice, not a default. It is the method for finding out
    /// which ports are open at all, regardless of which ports are configured.
    /// </para>
    /// </summary>
    public sealed class AllTcpPortScanMethod : LegacyScanMethod
    {
        public override string Id => "ports.tcp.all";
        public override string DisplayName => "All TCP ports";
        public override bool Indented => true;

        public override string Explanation =>
            "The same knock as the TCP port check, but on every one of the 65535 doors " +
            "instead of the configured list - and it reports the ones that open. This is " +
            "the way to find a service on an unusual port that no preset would ever try: a " +
            "web interface on 8443, a remote desktop moved off its default. It takes " +
            "noticeably longer than the configured check, so no preset turns it on - tick " +
            "it yourself when you want the full picture.";

        public override ScanPhase Phase => ScanPhase.Services;
        public override FamilySupport Families => FamilySupport.IPv4;

        public override ScanMethodAvailability CheckAvailability(ScanContext context) =>
            context.HasTargetsOf(IpFamily.IPv4)
                ? ScanMethodAvailability.Available
                : ScanMethodAvailability.NotApplicable(NoIpv4Targets);

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            LegacyTargets targets = BuildTargets(context);
            if (targets.Count == 0) return;

            // Deliberately the full range, regardless of the port selection and
            // the "all ports" switch: choosing this method is the selection.
            List<int> ports = [.. Enumerable.Range(1, 65535)];

            ScanningMethod_PortsTCP tcp = new();

            void OnFound(object? _, ScanTask_Finished_EventArgs e) => ReportResult(context, e.ipToScan, targets);
            void OnProgress(int c, int r, int t) => context.ReportProgress(c, r, t);

            tcp.TcpPortScan_Task_Finished += OnFound;
            tcp.ProgressUpdated += OnProgress;
            using CancellationTokenRegistration reg = BridgeCancellation(cancellationToken, tcp.StopScan);

            try
            {
                await tcp.ScanTCPPortsAsync(targets.Items, ports,
                    TimeSpan.FromMilliseconds(context.Settings.PortTimeoutMs));
            }
            finally
            {
                tcp.TcpPortScan_Task_Finished -= OnFound;
                tcp.ProgressUpdated -= OnProgress;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    /// <summary>
    /// Checks the configured port selection over UDP. Sends an empty datagram
    /// per port and evaluates what comes back; see
    /// <see cref="ScanningMethod_PortsUDP"/> for what this finds and what it
    /// inherently cannot. See docs/FEHLERGEDAECHTNIS.md, No. 4.
    /// </summary>
    public sealed class UdpPortScanMethod : LegacyScanMethod
    {
        public override string Id => "ports.udp";
        public override string DisplayName => "UDP ports";

        public override string Explanation =>
            "The same idea as the TCP check, but for services that answer without setting " +
            "up a connection first: name resolution, time servers, network management, " +
            "video and voice transmission. Slower and less certain than the TCP check - " +
            "silence can mean \"closed\" just as well as \"nobody felt like answering\", and " +
            "a service that only replies to a properly formed request stays invisible to an " +
            "empty probe. Worth ticking when you are specifically after such services, not " +
            "as a routine first pass.";
        public override ScanPhase Phase => ScanPhase.Services;
        public override FamilySupport Families => FamilySupport.IPv4;

        public override ScanMethodAvailability CheckAvailability(ScanContext context)
        {
            if (!context.HasTargetsOf(IpFamily.IPv4))
            {
                return ScanMethodAvailability.NotApplicable(NoIpv4Targets);
            }

            if (!context.Settings.ScanAllPorts && context.Settings.UdpPorts.Count == 0)
            {
                return ScanMethodAvailability.NotApplicable(
                    "No ports selected. Pick ports under Manage, or switch on \"all ports\".");
            }

            return ScanMethodAvailability.Available;
        }

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            LegacyTargets targets = BuildTargets(context);
            if (targets.Count == 0) return;

            List<int> ports = context.Settings.ScanAllPorts
                ? [.. Enumerable.Range(1, 65535)]
                : [.. context.Settings.UdpPorts];

            ScanningMethod_PortsUDP udp = new();

            void OnFound(object? _, ScanTask_Finished_EventArgs e) => ReportResult(context, e.ipToScan, targets);

            udp.UDPPortScan_Task_Finished += OnFound;
            using CancellationTokenRegistration reg = BridgeCancellation(cancellationToken, udp.StopScan);

            try
            {
                await udp.ScanUDPPortsAsync(targets.Items, ports,
                    TimeSpan.FromMilliseconds(context.Settings.PortTimeoutMs));
            }
            finally
            {
                udp.UDPPortScan_Task_Finished -= OnFound;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    /// <summary>
    /// Determines the SMB version of the target, including whether SMB1 is
    /// still enabled (as stated by the server's answer; see
    /// docs/FEHLERGEDAECHTNIS.md, No. 3).
    /// </summary>
    public sealed class SmbVersionScanMethod : LegacyScanMethod
    {
        public override string Id => "smb.version";
        public override string DisplayName => "SMB version";

        public override string Explanation =>
            "Checks which generation of Windows file sharing a device still speaks. " +
            "Windows PCs, servers and network storage boxes answer. This matters because " +
            "the oldest generation, SMB 1, is considered unsafe and has been switched off " +
            "for years - where it is still on, it is usually an old storage box or a " +
            "printer nobody has touched since. The finding is reported so you can see it " +
            "without hunting through the table.";
        public override ScanPhase Phase => ScanPhase.Services;
        public override FamilySupport Families => FamilySupport.IPv4;

        public override ScanMethodAvailability CheckAvailability(ScanContext context) =>
            context.HasTargetsOf(IpFamily.IPv4)
                ? ScanMethodAvailability.Available
                : ScanMethodAvailability.NotApplicable(NoIpv4Targets);

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            LegacyTargets targets = BuildTargets(context);
            if (targets.Count == 0) return;

            ScanningMethod_SMBVersionCheck smb = new();

            void OnProgress(int c, int r, int t, ScanStatus s) => context.ReportProgress(c, r, t);
            void OnFound(IPToScan ip) => ReportResult(context, ip, targets);

            smb.ProgressUpdated += OnProgress;
            smb.SMBIPScanFinished += OnFound;
            using CancellationTokenRegistration reg = BridgeCancellation(cancellationToken, smb.StopScan);

            try { await smb.ScanMultipleIPsAsync(targets.Items); }
            finally
            {
                smb.ProgressUpdated -= OnProgress;
                smb.SMBIPScanFinished -= OnFound;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    /// <summary>
    /// Asks an open web interface who it is: page title, server header and
    /// TLS certificate.
    /// <para>
    /// Deliberately runs in the services phase and therefore <b>after</b> the
    /// port scan: when the target's open ports are already known, exactly
    /// those are queried instead of trying four ports speculatively.
    /// </para>
    /// </summary>
    public sealed class WebIdentityScanMethod : LegacyScanMethod
    {
        public override string Id => "web.identity";
        public override string DisplayName => "Web page and certificate";

        public override string Explanation =>
            "Opens the web page a device serves and reads who it says it is - the page " +
            "title, the server software, and for encrypted pages the certificate. This is " +
            "the difference between \"port 443 is open\" and \"this is a HP LaserJet whose " +
            "certificate expired in 2019\". The certificate is worth it twice over: it " +
            "often carries further host names for the device that do not appear in DNS at " +
            "all, and an expired or self-signed one is reported as a finding.";

        public override ScanPhase Phase => ScanPhase.Services;
        public override FamilySupport Families => FamilySupport.IPv4;

        public override ScanMethodAvailability CheckAvailability(ScanContext context) =>
            context.HasTargetsOf(IpFamily.IPv4)
                ? ScanMethodAvailability.Available
                : ScanMethodAvailability.NotApplicable(NoIpv4Targets);

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            LegacyTargets targets = BuildTargets(context);
            if (targets.Count == 0) return;

            List<string> addresses = [.. targets.Items.Select(t => t.IPorHostname).Where(t => !string.IsNullOrEmpty(t))];
            if (addresses.Count == 0) return;

            ScanningMethod_WebIdentity web = new() { TimeoutMs = context.Settings.PortTimeoutMs };

            void OnProgress(int c, int r, int t, ScanStatus s) => context.ReportProgress(c, r, t);
            void OnFound(WebIdentityResult found) => Report(context, found);

            web.ProgressUpdated += OnProgress;
            web.WebIdentityFound += OnFound;
            using CancellationTokenRegistration reg = BridgeCancellation(cancellationToken, web.StopScan);

            try
            {
                await web.ScanAsync(addresses, KnownWebPorts(context, addresses));
            }
            finally
            {
                web.ProgressUpdated -= OnProgress;
                web.WebIdentityFound -= OnFound;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }

        /// <summary>
        /// The web ports already known to be open, per target.
        /// <para>
        /// Without this step the method would only try four fixed ports, and
        /// an interface on 8081 would stay undetected although the port scan
        /// found it one phase earlier.
        /// </para>
        /// </summary>
        private static Dictionary<string, List<int>> KnownWebPorts(
            ScanContext context, List<string> addresses)
        {
            Dictionary<string, List<int>> known = new(StringComparer.OrdinalIgnoreCase);

            lock (context.Store.SyncRoot)
            {
                foreach (string address in addresses)
                {
                    if (!IpAddressAnalyzer.TryAnalyze(address, out IpAddressInfo? info) || info is null) continue;

                    Device? device = context.Store.FindByAddress(info);
                    if (device is null) continue;

                    List<int> ports = [.. device.OpenServices
                        .SelectMany(s => s.Ports)
                        .Where(LooksLikeWebPort)
                        .Distinct()
                        .Order()];

                    if (ports.Count > 0) known[address] = ports;
                }
            }

            return known;
        }

        /// <summary>
        /// Ports that qualify as web ports. The unusual numbers are
        /// intentional: device interfaces rarely sit on port 80 but on 8080,
        /// 8443, 8000 and similar.
        /// </summary>
        private static bool LooksLikeWebPort(int port) =>
            port is 80 or 443 or 280 or 591 or 593 or 981 or 1311 or 2480 or 4443 or 4444
                or 7000 or 7001 or 8000 or 8008 or 8080 or 8081 or 8088 or 8090 or 8443
                or 8888 or 9000 or 9090 or 9443 or 10000;

        private static void Report(ScanContext context, WebIdentityResult found)
        {
            if (!IpAddressAnalyzer.TryAnalyze(found.Address, out IpAddressInfo? info) || info is null) return;

            Dictionary<string, string> details = new() { ["Web interface"] = found.ToInfoText() };

            context.Report(new DeviceObservation
            {
                Source = "Web page and certificate",
                Address = info,
                IsResponding = true,
                Details = details,

                WebTitle = found.Title,
                CertificateSubject = found.CertificateSubject,
                CertificateIssuer = found.CertificateIssuer,

                // As a DateTimeOffset in the local time zone: the certificate
                // value is a local time, and a wrong conversion turns
                // "expires today" into "expired".
                CertificateExpires = found.CertificateExpires is { } expires
                    ? new DateTimeOffset(expires)
                    : null,

                CertificateIsSelfSigned = found.CertificateExpires is null ? null : found.IsSelfSigned,

                // The names in the certificate are name assignments like any
                // other; they belong in the same duplicate check.
                Aliases = found.AlternativeNames.Count > 0 ? found.AlternativeNames : null
            });
        }
    }

    /// <summary>
    /// Service detection: addresses the ports directly and assigns the answer
    /// to a service. Provides the service list by which the result table is
    /// filtered. A service counts as detected only if its answer matches the
    /// protocol; see docs/FEHLERGEDAECHTNIS.md, No. 2.
    /// <para>
    /// Needs the path to the service XML, because the module loads its
    /// definitions from there.
    /// </para>
    /// </summary>
    /// <param name="serviceXmlPath">Path of the service definitions.</param>
    public sealed class ServiceDetectionScanMethod(string serviceXmlPath) : LegacyScanMethod
    {
        public override string Id => "services";
        public override string DisplayName => "Services";

        public override string Explanation =>
            "Does not just check whether a door is open, but talks to whatever is behind " +
            "it and asks what it is. That is the difference between \"port 21 is open\" " +
            "and \"an FTP server is running here, and this is its version\". Covers the " +
            "usual suspects - web servers, file transfer, mail, databases, remote access. " +
            "Use it when you want to know what is really running in the network rather " +
            "than which numbers are reachable. Which services are looked for is set under " +
            "Services.";
        public override ScanPhase Phase => ScanPhase.Services;
        public override FamilySupport Families => FamilySupport.IPv4;

        /// <summary>
        /// A missing service XML is <b>not</b> an obstacle:
        /// <c>SetServicePorts</c> creates every service type with its default
        /// ports and reads the file only as an overlay for custom changes. The
        /// file does not have to exist.
        /// </summary>
        public override ScanMethodAvailability CheckAvailability(ScanContext context) =>
            context.HasTargetsOf(IpFamily.IPv4)
                ? ScanMethodAvailability.Available
                : ScanMethodAvailability.NotApplicable(NoIpv4Targets);

        /// <summary>
        /// Runs through <see cref="ServiceScanRunner"/>, service by service
        /// rather than target by target. The service definitions come from the
        /// XML: what is searched for and on which ports is decided by the
        /// service management, not by the run.
        /// </summary>
        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            LegacyTargets targets = BuildTargets(context);
            if (targets.Count == 0) return;

            ScanningMethod_Services definitions = new(serviceXmlPath);

            (List<ServiceType> wanted,
             Dictionary<ServiceType, List<int>> ports,
             HashSet<ServiceType> activeInquiry) =
                SelectServices(definitions, context.Settings.Services);

            if (wanted.Count == 0) return;

            List<string> addresses =
                [.. targets.Items.Select(t => t.IPorHostname).Where(a => !string.IsNullOrEmpty(a))];

            if (addresses.Count == 0) return;

            ServiceScanRunner runner = new() { ActiveInquiryServices = activeInquiry };

            void OnProgress(ServiceScanProgress p) =>
                context.ReportStepProgress(p.Current, p.Responded, p.Total, p.Service, p.Step, p.StepCount);

            void OnFound(ServiceFinding finding) =>
                ReportResult(context, ToLegacyResult(finding), targets);

            runner.ProgressUpdated += OnProgress;
            runner.Found += OnFound;

            try
            {
                await runner.RunAsync(addresses, wanted, ports, cancellationToken);
            }
            finally
            {
                runner.ProgressUpdated -= OnProgress;
                runner.Found -= OnFound;
            }

            cancellationToken.ThrowIfCancellationRequested();

            // Only after all services are done: at this point the store holds
            // the firmware reported by S7, BACnet and Modbus, and exactly that
            // decides whether the OPC UA session is needed.
            await AddOpcUaFirmwareAsync(context, addresses, cancellationToken);
        }

        /// <summary>The usual OPC UA port, used here only to identify running services.</summary>
        private const int OpcUaPort = 4840;

        /// <summary>
        /// Follow-up pass for firmware over OPC UA, the only step that
        /// <em>establishes</em> a session instead of merely querying.
        /// <para>
        /// A session is opened only where needed: the device must speak OPC UA,
        /// and no firmware may be known yet from another service. S7, BACnet
        /// and the WAGO registers deliver it without a session; for these
        /// devices the login is skipped. What remains are devices for which
        /// OPC UA is the only way, such as a pure OPC UA controller. The
        /// session is always anonymous.
        /// </para>
        /// </summary>
        private async Task AddOpcUaFirmwareAsync(
            ScanContext context, List<string> addresses, CancellationToken token)
        {
            List<(string Address, IpAddressInfo Info)> candidates = [];

            lock (context.Store.SyncRoot)
            {
                foreach (string address in addresses)
                {
                    if (!IpAddressAnalyzer.TryAnalyze(address, out IpAddressInfo? info) || info is null) continue;

                    Device? device = context.Store.FindByAddress(info);
                    if (device is null) continue;

                    bool opcUaRunning = device.Services.Any(s => s.IsRunning && s.Ports.Contains(OpcUaPort));
                    if (!opcUaRunning) continue;

                    if (FirmwareAlreadyKnown(device)) continue;

                    candidates.Add((address, info));
                }
            }

            if (candidates.Count == 0) return;

            ProbeContext probeContext = new() { TimeoutMs = context.Settings.PortTimeoutMs };
            using SemaphoreSlim slots = new(4);

            IEnumerable<Task> reads = candidates.Select(async candidate =>
            {
                await slots.WaitAsync(token);

                try
                {
                    string? build = await OpcUaProbe.ReadBuildInfoAsync(
                        probeContext, candidate.Address, OpcUaPort, token);

                    if (string.IsNullOrWhiteSpace(build)) return;

                    context.Report(new DeviceObservation
                    {
                        Source = DisplayName,
                        Address = candidate.Info,
                        IsResponding = true,
                        Details = new Dictionary<string, string> { ["OPC UA build info"] = build }
                    });
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception)
                {
                    // A server that rejects anonymous sessions or aborts midway
                    // stays without firmware; the remaining findings stand.
                }
                finally
                {
                    slots.Release();
                }
            });

            await Task.WhenAll(reads);
        }

        /// <summary>
        /// Whether firmware is already known for this device, from the details
        /// or the log of a running service. All probes that report firmware
        /// write the word "Firmware" into their output.
        /// </summary>
        private static bool FirmwareAlreadyKnown(Device device)
        {
            foreach (string value in device.Details.Values)
            {
                if (value.Contains("Firmware", StringComparison.OrdinalIgnoreCase)) return true;
            }

            foreach (DeviceServiceResult service in device.Services)
            {
                if (service.PortLog is { } log && log.Contains("Firmware", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Wraps a finding in the form the result path expects.
        /// <para>
        /// Deliberately a fresh, minimal instance per finding instead of the
        /// target from the list: results are reported after <em>each</em>
        /// service rather than once at the end, and if the target carried its
        /// previous findings along, the same service rows would pass through
        /// the merge up to 24 times. Address and scope suffice; the store
        /// already holds everything else.
        /// </para>
        /// </summary>
        private static IPToScan ToLegacyResult(ServiceFinding finding)
        {
            IPToScan result = new()
            {
                IPorHostname = finding.Address,
                UsedScanMethod = ScanMethod.Services
            };

            result.Services.Services.Add(finding.Result);

            return result;
        }

        /// <summary>
        /// Determines which services are searched for, and on which ports.
        /// <para>
        /// Three stages: what the settings name explicitly, otherwise what the
        /// service table marks as <c>toScan</c>, otherwise all. The last stage
        /// matters when no selection exists: without it, service detection
        /// would be checked and still do nothing, which nobody would
        /// understand.
        /// </para>
        /// </summary>
        private static (List<ServiceType>, Dictionary<ServiceType, List<int>>, HashSet<ServiceType>) SelectServices(
            ScanningMethod_Services module, List<ServiceType> fromSettings)
        {
            Dictionary<ServiceType, List<int>> ports = [];
            List<ServiceType> marked = [];
            List<ServiceType> all = [];
            HashSet<ServiceType> activeInquiry = [];

            foreach (System.Data.DataRow row in module.Services.Rows)
            {
                string name = row["Service"]?.ToString() ?? string.Empty;
                if (!Enum.TryParse(name, out ServiceType type)) continue;

                all.Add(type);
                ports[type] = ParsePorts(row["Ports"]?.ToString());

                if (row["toScan"] != DBNull.Value && row["toScan"] is true) marked.Add(type);

                // Service tables saved before the ActiveInquiry column existed
                // lack it; then the value stays "off".
                if (module.Services.Columns.Contains("ActiveInquiry") &&
                    row["ActiveInquiry"] != DBNull.Value && row["ActiveInquiry"] is true)
                {
                    activeInquiry.Add(type);
                }
            }

            List<ServiceType> wanted =
                fromSettings.Count > 0 ? fromSettings :
                marked.Count > 0 ? marked :
                all;

            return (wanted, ports, activeInquiry);
        }

        private static List<int> ParsePorts(string? text)
        {
            if (string.IsNullOrWhiteSpace(text)) return [];

            List<int> ports = [];

            foreach (string part in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (int.TryParse(part, out int port) && port is > 0 and <= 65535) ports.Add(port);
            }

            return ports;
        }
    }
}
