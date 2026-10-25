// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net.NetworkInformation;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;
using MyNetworkMonitor.Core.Scanning.ServiceScans;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// Common base of all adapters that integrate a scan module into the
    /// engine. The modules themselves stay independent of the engine.
    /// <para>
    /// All modules follow the same pattern: they take an
    /// <see cref="IPToScan"/> list, modify it in place and report through
    /// events. The wiring lives here once instead of in every adapter, in
    /// particular the mapping from <see cref="IPToScan"/> to
    /// <see cref="DeviceObservation"/>, which would otherwise differ slightly
    /// in each adapter.
    /// </para>
    /// </summary>
    public abstract class LegacyScanMethod : IScanMethod
    {
        public abstract string Id { get; }
        public abstract string DisplayName { get; }

        // Deliberately abstract without an empty default: a method without an
        // explanation cannot be judged in the UI, and that should become
        // apparent when the method is added, not in operation.
        public abstract string Explanation { get; }

        public abstract ScanPhase Phase { get; }

        public virtual FamilySupport Families => FamilySupport.IPv4;
        public virtual bool IsPassive => false;
        public virtual bool RequiresElevation => false;
        public virtual bool Indented => false;

        // The vast majority of modules work through a target list; the
        // exceptions (SSDP, mDNS, ARP cache) override this.
        public virtual bool EnumeratesTargets => true;

        public abstract ScanMethodAvailability CheckAvailability(ScanContext context);
        public abstract Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken);

        /// <summary>
        /// Reason for methods that support IPv4 only. Several modules validate
        /// their targets with <c>SupportMethods.Is_Valid_IP</c>, an IPv4-only
        /// regular expression, and drop IPv6 targets silently.
        /// </summary>
        protected const string NoIpv4Targets =
            "No IPv4 targets selected. This method works over IPv4 only.";

        /// <summary>
        /// Builds the target list in the <see cref="IPToScan"/> format of the
        /// scan modules and records which entry belongs to which scope; domain,
        /// DNS servers and gateway differ per scope.
        /// </summary>
        /// <param name="context">The run context.</param>
        /// <param name="only">Address family to include; null includes all targets.</param>
        /// <returns>The module target list with the mapping back to the scan targets.</returns>
        protected static LegacyTargets BuildTargets(ScanContext context, IpFamily? only = IpFamily.IPv4)
        {
            Dictionary<string, ScanTargetEntry> byText = new(StringComparer.OrdinalIgnoreCase);
            List<IPToScan> legacy = [];

            IEnumerable<ScanTargetEntry> source = only is null
                ? context.Targets
                : context.Targets.Where(t => t.Family == only);

            foreach (ScanTargetEntry target in source)
            {
                string text = target.TargetText;
                if (string.IsNullOrEmpty(text) || !byText.TryAdd(text, target)) continue;

                ScanScope scope = target.Scope.Scope;

                // A DNS server set in the settings overrides those of the
                // scope; that is its purpose: checking against a specific
                // server without touching every scope.
                string? overrideDns = context.Settings.OverrideDnsServer;

                List<string> dnsServers = string.IsNullOrWhiteSpace(overrideDns)
                    ? [.. scope.DnsServerList]
                    : [overrideDns.Trim()];

                // Without a DNS server of its own in the scope, the gateway is
                // asked. Falling back to the system resolver instead means a
                // local stub on Linux in almost all cases (for example
                // systemd-resolved), which itself forwards to the actual
                // server, with its own cache and noticeable losses under load.
                // On most home routers the gateway of the scanning interface
                // answers the same namespace itself and directly: measured, 32
                // of 254 addresses of a /24 in under 60 ms against the gateway,
                // compared to tens of seconds through a downstream server. If
                // the gateway does not know the names, the address stays
                // without a PTR result; deliberately no fallback to the system
                // resolver. See docs/FEHLERGEDAECHTNIS.md, No. 8.
                //
                // The router configured for the scope overrides that of the
                // interface, for scopes behind a different router than the one
                // the scan runs through. If none is configured, the interface's
                // gateway is used, even though it is the same for all scopes.
                if (dnsServers.Count == 0)
                {
                    string? gateway = scope.HasOwnGateway
                        ? scope.GatewayIP.Trim()
                        : GatewayDnsFallback(target.Scope.Interface);

                    if (gateway is not null) dnsServers = [gateway];

                    // Behind the *inferred* gateway, the system's name servers
                    // (queried directly, not through the stub resolver) serve
                    // as a backup. The gateway keeps priority, as the
                    // measurement above still applies, but where it is no name
                    // server at all, the name is not lost.
                    //
                    // In a corporate network whose gateway answers no query at
                    // all, every address otherwise runs into its time budget
                    // and the device list shows only addresses, although the
                    // system's servers return the name immediately.
                    //
                    // Only for the inferred gateway: a router configured for
                    // the scope is an explicit choice and remains the only
                    // server used.
                    if (!scope.HasOwnGateway)
                    {
                        dnsServers.AddRange(SystemDnsServers()
                            .Where(s => !dnsServers.Contains(s, StringComparer.OrdinalIgnoreCase)));
                    }
                }

                legacy.Add(new IPToScan
                {
                    IPorHostname = text,

                    // A name entered in the target list overrides the one in
                    // the store.
                    //
                    // Host names are resolved before the run, so TargetText is
                    // the address; KnownHostName alone would look it up in the
                    // still empty store and find nothing. The entered name
                    // would be lost and the column would stay empty although
                    // the device was found.
                    HostName = NullIfBlank(target.HostName) ?? KnownHostName(context, text),
                    TimeOut = context.Settings.PortTimeoutMs,
                    IPGroupDescription = scope.GroupDescription,
                    DeviceDescription = scope.DeviceDescription,
                    Domain = scope.Domain,
                    DNSServerList = dnsServers,
                    NMGatewayIP = scope.GatewayIP,
                    TCPPortsToScan = [.. context.Settings.TcpPorts],
                    UDPPortsToScan = [.. context.Settings.UdpPorts]
                });
            }

            return new LegacyTargets(legacy, byText);
        }

        /// <summary>
        /// The name servers the operating system itself uses, as a backup
        /// behind the inferred gateway; see the call site.
        /// <para>
        /// Takes all operational interfaces except loopback and tunnel, in
        /// their order and without duplicates.
        /// </para>
        /// </summary>
        private static List<string> SystemDnsServers()
        {
            try
            {
                return
                [
                    .. NetworkInterface.GetAllNetworkInterfaces()
                        .Where(i => i.OperationalStatus == OperationalStatus.Up &&
                                    i.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel))
                        .SelectMany(i => i.GetIPProperties().DnsAddresses)
                        .Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        .Select(a => a.ToString())
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                ];
            }
            catch (NetworkInformationException)
            {
                return [];
            }
        }

        /// <summary>The IPv4 gateway address of the interface, if any; see the comment at the call site.</summary>
        private static string? GatewayDnsFallback(NetworkInterface? nic)
        {
            if (nic is null) return null;

            try
            {
                return nic.GetIPProperties().GatewayAddresses
                    .Select(g => g.Address)
                    .FirstOrDefault(a => a is not null &&
                                          a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                                          !System.Net.IPAddress.Any.Equals(a))
                    ?.ToString();
            }
            catch (NetworkInformationException)
            {
                return null;
            }
        }

        /// <summary>
        /// The host name already found for this target during the run.
        /// <para>
        /// Without it the forward lookup cannot achieve anything: it queries
        /// <c>HostnameWithDomain</c>, and without the name only the bare domain
        /// remains, a query that returns the same or nothing for every target.
        /// The name comes from the reverse lookup, which therefore has to run
        /// first.
        /// </para>
        /// </summary>
        private static string KnownHostName(ScanContext context, string text)
        {
            if (!IpAddressAnalyzer.TryAnalyze(text, out IpAddressInfo? info) || info is null)
            {
                // The target itself is a name, so it is already present.
                return text;
            }

            lock (context.Store.SyncRoot)
            {
                return context.Store.FindByAddress(info)?.HostName ?? string.Empty;
            }
        }

        /// <summary>
        /// Forwards the engine's cancellation to the module. The modules manage
        /// their own cancellation source and only offer <c>StopScan()</c>.
        /// </summary>
        /// <param name="token">The engine's cancellation token.</param>
        /// <param name="stopScan">The module's stop method.</param>
        /// <returns>The registration; dispose it when the module has finished.</returns>
        protected static CancellationTokenRegistration BridgeCancellation(
            CancellationToken token, Action stopScan) => token.Register(stopScan);

        /// <summary>
        /// Converts an <see cref="IPToScan"/> modified by the module into an
        /// observation and reports it. Only fields that are actually set are
        /// transferred; each module fills a different subset.
        /// </summary>
        /// <param name="context">The run context.</param>
        /// <param name="result">The entry updated by the module.</param>
        /// <param name="targets">Target list used to find the originating scope.</param>
        /// <param name="sourceOverride">Source name to report instead of <see cref="DisplayName"/>.</param>
        protected void ReportResult(ScanContext context, IPToScan result, LegacyTargets targets, string? sourceOverride = null)
        {
            if (result is null) return;
            if (!IpAddressAnalyzer.TryAnalyze(result.IPorHostname, out IpAddressInfo? info) || info is null) return;

            ScanTargetEntry? origin = targets.Find(result.IPorHostname);
            ScanScope? scope = origin?.Scope.Scope;

            Dictionary<string, string> details = [];
            void Detail(string key, string? value)
            {
                if (!string.IsNullOrWhiteSpace(value)) details[key] = value;
            }

            Detail("Response time", string.IsNullOrWhiteSpace(result.ResponseTime) ? null : $"{result.ResponseTime} ms");
            Detail("Detected services", result.detectedServices);

            if (result.SMBVersions.Count > 0) Detail("SMB versions", string.Join(", ", result.SMBVersions));

            // The name is the actual result of the NetBIOS query. Without this
            // line the services would only show that NetBIOS is running, and
            // the name itself would appear nowhere.
            Detail("NetBIOS", NetBiosDetail(result));

            // What the industrial protocols report about themselves: vendor,
            // model, firmware, application name. The probes query this anyway;
            // without these lines the details would only state that the
            // service is running.
            foreach ((ServiceType service, string label) in ServiceNames.WithDeviceInfo)
            {
                Detail(label, ServiceLog(result, service));
            }

            if (!string.IsNullOrWhiteSpace(result.SNMP_SysName)) Detail("SNMP", result.SNMPInfos);
            if (result.IsIPCam) Detail("Camera", $"{result.IPCamName} {result.IPCamXAddress}".Trim());
            Detail("mDNS", result.mDNS_toMultiLineString);

            context.Report(new DeviceObservation
            {
                Source = sourceOverride ?? DisplayName,
                Address = info,
                // The MAC from SNMP counts only as a soft hint. Taken as a
                // hard identifier, it contradicts the one seen via ARP and
                // splits the same device into two entries.
                Mac = ParseMac(result.MAC),
                SoftMac = ParseMac(result.SNMP_MAC),
                Vendor = NullIfBlank(result.Vendor),
                HostName = NullIfBlank(result.HostName) ?? NullIfBlank(result.SNMP_SysName),
                Domain = NullIfBlank(result.Domain) ?? NullIfBlank(scope?.Domain),
                NetBiosName = NullIfBlank(result.NetBiosHostname),
                GroupDescription = NullIfBlank(result.IPGroupDescription) ?? NullIfBlank(scope?.GroupDescription),
                IsResponding = IsResponding(result),
                Details = details.Count > 0 ? details : null,
                LookupAddresses = LookupAddresses(result),
                Aliases = SplitLines(result.Aliases),
                Services = BuildServices(result, info.Family)
            });
        }

        /// <summary>
        /// The addresses the name points to in DNS.
        /// <para>
        /// Uses the whole <see cref="IPHostEntry"/>, not the
        /// <c>LookUpIPs</c> field: the module fills that field only when the
        /// lookup <em>differs</em> and leaves it empty otherwise. Empty would
        /// then mean both "matches" and "not checked", two cases that must be
        /// kept apart for a finding to be derived.
        /// </para>
        /// </summary>
        private static List<string>? LookupAddresses(IPToScan result)
        {
            if (result.UsedScanMethod != ScanMethod.Lookup) return null;
            if (result.IP_HostEntry?.AddressList is not { } addresses) return null;

            // Normalized to the same notation as the device's addresses;
            // otherwise fe80:0:0::1 differs from fe80::1 and every comparison
            // fails.
            return [.. addresses
                .Select(a => IpAddressAnalyzer.TryAnalyze(a.ToString(), out IpAddressInfo? info) && info is not null
                    ? info.Canonical
                    : a.ToString())
                .Distinct(StringComparer.OrdinalIgnoreCase)];
        }

        /// <summary>Splits a multi-line field of the scan modules into a list.</summary>
        private static List<string>? SplitLines(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return null;

            List<string> lines = [.. value
                .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.OrdinalIgnoreCase)];

            return lines.Count > 0 ? lines : null;
        }

        /// <summary>
        /// A target counts as reachable as soon as any method has seen an
        /// answer, not only ping.
        /// </summary>
        private static bool IsResponding(IPToScan r) =>
            r.PingStatus || r.ARPStatus || r.SSDPStatus || r.IsIPCam ||
            r.TCP_OpenPorts.Count > 0 || r.UDP_OpenPorts.Count > 0 ||
            !string.IsNullOrWhiteSpace(r.SNMP_SysName);

        /// <summary>The port the SMB check works on.</summary>
        private const int SmbPort = 445;

        private const int NetBiosPort = 137;

        /// <summary>
        /// Name and, if the answer contained it, workgroup or domain, in one
        /// line.
        /// </summary>
        private static string? NetBiosDetail(IPToScan r)
        {
            if (string.IsNullOrWhiteSpace(r.NetBiosHostname)) return null;

            return string.IsNullOrWhiteSpace(r.NetBiosWorkgroup)
                ? r.NetBiosHostname
                : $"{r.NetBiosHostname} (workgroup/domain: {r.NetBiosWorkgroup})";
        }

        private const int SnmpPort = 161;
        private const int OnvifPort = 3702;

        /// <summary>
        /// Adds a service found by a dedicated module.
        /// <para>
        /// NetBIOS, SNMP, ONVIF and SMB do not run through service detection
        /// but each have a method of their own. They are services nonetheless
        /// and belong in the same column as the others. Listed only as plain
        /// text in the details, they are visible only to someone who already
        /// knows they exist.
        /// </para>
        /// </summary>
        private static void AddFoundService(
            List<DeviceServiceResult> services, IpFamily family,
            string name, string category, int port, string? log = null)
        {
            DeviceServiceResult entry = new()
            {
                ServiceName = name,
                Category = category,
                Ports = [port],
                PortLog = NullIfBlank(log)
            };

            if (family == IpFamily.IPv6) entry.StatusIPv6 = PortStatus.IsRunning;
            else entry.StatusIPv4 = PortStatus.IsRunning;

            services.Add(entry);
        }

        /// <summary>
        /// The log of the port on which the given service was detected. Only
        /// from a running service: for "open, but nothing detected" the log
        /// holds a note about the attempt, not information about the device.
        /// <para>
        /// The bare confirmation line of a successful detection is skipped as
        /// well. It appears wherever a probe has nothing further to report,
        /// for example an FTP server whose greeting carries no name, and as a
        /// detail line under "FTP server" it would only state that FTP is
        /// running.
        /// </para>
        /// </summary>
        private static string? ServiceLog(IPToScan r, ServiceType service)
        {
            if (r.Services?.Services is null) return null;

            foreach (ServiceScanData.ServiceResult entry in r.Services.Services)
            {
                if (entry.Service != service || entry.Ports is null) continue;

                foreach (ServiceScanData.PortResult port in entry.Ports)
                {
                    if (port.Status == PortStatus.IsRunning && IsDeviceInfo(port.PortLog))
                    {
                        return port.PortLog;
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Whether a log text is information about the device rather than mere
        /// bookkeeping of the attempt.
        /// </summary>
        internal static bool IsDeviceInfo(string? portLog) =>
            !string.IsNullOrWhiteSpace(portLog) &&
            !portLog.Trim().Equals(ServiceProbeBase.ProtocolMatched, StringComparison.Ordinal) &&
            !portLog.Trim().Equals(ServiceProbeBase.ProtocolMatchedGerman, StringComparison.Ordinal);

        /// <summary>
        /// Maps ports and detected services. The state is set only for the
        /// address family checked; the other family stays open, so that a
        /// later run can fill it in.
        /// </summary>
        private static List<DeviceServiceResult>? BuildServices(IPToScan r, IpFamily family)
        {
            List<DeviceServiceResult> services = [];

            foreach (ServiceScanData.ServiceResult service in r.Services.Services)
            {
                foreach (ServiceScanData.PortResult port in service.Ports)
                {
                    List<int> ports = port.Ports is null ? [] : [.. port.Ports];

                    // Only a port that returned its protocol's signature
                    // carries the service name. A port that merely accepts the
                    // connection is an open port and is named like the other
                    // unidentified ones further down.
                    //
                    // Otherwise port 3306 of a MariaDB server would also show
                    // "MySQL", because the MySQL probe gets a connection there
                    // too and its row would keep the probe's name despite the
                    // non-matching answer. This way several failed probes on
                    // the same port collapse into a single row. See
                    // docs/FEHLERGEDAECHTNIS.md, No. 2.
                    bool unidentifiedOpen = port.Status == PortStatus.Open && ports.Count == 1;

                    DeviceServiceResult entry = new()
                    {
                        ServiceName = unidentifiedOpen ? $"TCP {ports[0]}" : ServiceNames.Of(service.Service),
                        Category = unidentifiedOpen ? "Open ports" : CategoryOf(service.Service),
                        Ports = ports,
                        PortLog = NullIfBlank(port.PortLog)
                    };

                    if (family == IpFamily.IPv6) entry.StatusIPv6 = port.Status;
                    else entry.StatusIPv4 = port.Status;

                    services.Add(entry);
                }
            }

            // SMB comes from a dedicated module, not from service detection;
            // it is a service nonetheless and belongs next to the others in
            // the "Running services" column. The versions go into the log:
            // that a target still speaks SMB 1.0 is the actual news.
            if (r.SMBVersions.Count > 0)
            {
                AddFoundService(services, family, "SMB", "File services", SmbPort,
                    "SMB versions: " + string.Join(", ", r.SMBVersions));
            }

            if (!string.IsNullOrWhiteSpace(r.NetBiosHostname))
            {
                AddFoundService(services, family, "NetBIOS", "Network", NetBiosPort,
                    $"NetBIOS name: {NetBiosDetail(r)}");
            }

            if (!string.IsNullOrWhiteSpace(r.SNMP_SysName))
            {
                AddFoundService(services, family, "SNMP", "Network", SnmpPort,
                    NullIfBlank(r.SNMPInfos) ?? $"System name: {r.SNMP_SysName}");
            }

            if (r.IsIPCam)
            {
                AddFoundService(services, family, "ONVIF", "Cameras", OnvifPort,
                    $"{r.IPCamName} {r.IPCamXAddress}".Trim());
            }

            // Open ports without a detected service are kept; they matter to
            // the port filter just as much as named services.
            foreach (int open in r.TCP_OpenPorts.Where(p => !services.Any(s => s.Ports.Contains(p))))
            {
                DeviceServiceResult entry = new()
                {
                    ServiceName = $"TCP {open}",
                    Category = "Open ports",
                    Ports = [open]
                };

                if (family == IpFamily.IPv6) entry.StatusIPv6 = PortStatus.Open;
                else entry.StatusIPv4 = PortStatus.Open;

                services.Add(entry);
            }

            // The same for UDP; without this, open UDP ports would appear only
            // in the CSV export, not in the services column or the port
            // filter.
            foreach (int open in r.UDP_OpenPorts.Where(p => !services.Any(s => s.Ports.Contains(p))))
            {
                DeviceServiceResult entry = new()
                {
                    ServiceName = $"UDP {open}",
                    Category = "Open ports",
                    Ports = [open]
                };

                if (family == IpFamily.IPv6) entry.StatusIPv6 = PortStatus.Open;
                else entry.StatusIPv4 = PortStatus.Open;

                services.Add(entry);
            }

            return services.Count > 0 ? services : null;
        }

        /// <summary>
        /// Assigns a service to its category. The mapping lives in
        /// <see cref="ServiceCategories"/> because the all-ports scan needs it
        /// too.
        /// </summary>
        private static string CategoryOf(ServiceType service) => ServiceCategories.Of(service);

        private static string? NullIfBlank(string? value) =>
            string.IsNullOrWhiteSpace(value) ? null : value.Trim();

        /// <summary>
        /// Parses a MAC address in the notations used by the modules: with
        /// colons, with hyphens or without separators.
        /// </summary>
        /// <param name="text">The MAC address text.</param>
        /// <returns>The parsed address, or null if the text is not a valid MAC address.</returns>
        protected static PhysicalAddress? ParseMac(string? text)
        {
            if (string.IsNullOrWhiteSpace(text)) return null;

            string cleaned = text.Replace(":", "").Replace("-", "").Replace(".", "").Replace(" ", "").Trim();
            if (cleaned.Length != 12) return null;

            return PhysicalAddress.TryParse(cleaned, out PhysicalAddress? mac) ? mac : null;
        }
    }

    /// <summary>
    /// The target list in the <see cref="IPToScan"/> format of the scan
    /// modules, with the way back to the scope an entry comes from.
    /// </summary>
    /// <param name="items">The module target list.</param>
    /// <param name="byText">Scan targets keyed by target text (address or host name).</param>
    public sealed class LegacyTargets(List<IPToScan> items, Dictionary<string, ScanTargetEntry> byText)
    {
        /// <summary>The module target list.</summary>
        public List<IPToScan> Items { get; } = items;

        /// <summary>Number of entries in <see cref="Items"/>.</summary>
        public int Count => Items.Count;

        /// <summary>Finds the scan target for a module entry.</summary>
        /// <param name="targetText">Address or host name as used by the module.</param>
        /// <returns>The scan target, or null if unknown.</returns>
        public ScanTargetEntry? Find(string? targetText) =>
            string.IsNullOrEmpty(targetText) ? null : byText.GetValueOrDefault(targetText);
    }
}
