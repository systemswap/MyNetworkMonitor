using System.Net.NetworkInformation;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// Gemeinsame Grundlage aller Adapter, die ein bestehendes Scan-Modul in
    /// die Engine einbinden. Die Module selbst bleiben unveraendert.
    /// <para>
    /// Alle 16 arbeiten nach demselben Muster: sie nehmen eine
    /// <see cref="IPToScan"/>-Liste entgegen, aendern sie an Ort und Stelle und
    /// melden ueber Ereignisse. Hier steht die Verdrahtung einmal, statt in
    /// jedem Adapter erneut - insbesondere die Abbildung von
    /// <see cref="IPToScan"/> auf <see cref="DeviceObservation"/>, die sonst
    /// 16-mal leicht unterschiedlich ausfiele.
    /// </para>
    /// </summary>
    public abstract class LegacyScanMethod : IScanMethod
    {
        public abstract string Id { get; }
        public abstract string DisplayName { get; }
        public abstract ScanPhase Phase { get; }

        public virtual FamilySupport Families => FamilySupport.IPv4;
        public virtual bool IsPassive => false;
        public virtual bool RequiresElevation => false;

        // Die grosse Mehrheit der Module arbeitet eine Zielliste ab; die
        // Ausnahmen - SSDP, mDNS, ARP-Cache - sagen es selbst.
        public virtual bool EnumeratesTargets => true;

        public abstract ScanMethodAvailability CheckAvailability(ScanContext context);
        public abstract Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken);

        /// <summary>
        /// Begruendung fuer Verfahren, die nur IPv4 koennen. Mehrere Module
        /// pruefen ihre Ziele mit <c>SupportMethods.Is_Valid_IP</c>, einer
        /// reinen IPv4-Regex, und verwerfen IPv6-Ziele ohne Meldung.
        /// </summary>
        protected const string NoIpv4Targets =
            "No IPv4 targets selected. This method works over IPv4 only.";

        /// <summary>
        /// Baut die Zielliste im alten Format auf und merkt sich, welcher
        /// Eintrag zu welchem Bereich gehoert - Domain, DNS-Server und Gateway
        /// unterscheiden sich je Bereich.
        /// </summary>
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

                // Ein in den Einstellungen gesetzter DNS-Server sticht die des
                // Bereichs - genau dafuer ist er da: gegen einen bestimmten
                // Server pruefen, ohne jeden Bereich anzufassen.
                string? overrideDns = context.Settings.OverrideDnsServer;

                List<string> dnsServers = string.IsNullOrWhiteSpace(overrideDns)
                    ? [.. scope.DnsServerList]
                    : [overrideDns.Trim()];

                legacy.Add(new IPToScan
                {
                    IPorHostname = text,
                    HostName = KnownHostName(context, text),
                    TimeOut = context.Settings.PortTimeoutMs,
                    IPGroupDescription = scope.GroupDescription,
                    DeviceDescription = scope.DeviceDescription,
                    Domain = scope.Domain,
                    DNSServerList = dnsServers,
                    NMGatewayIP = scope.GatewayIP,
                    NMGatewayPort = scope.GatewayPort,
                    TCPPortsToScan = [.. context.Settings.TcpPorts],
                    UDPPortsToScan = [.. context.Settings.UdpPorts]
                });
            }

            return new LegacyTargets(legacy, byText);
        }

        /// <summary>
        /// Der Hostname, der im Lauf bereits zu diesem Ziel gefunden wurde.
        /// <para>
        /// Ohne ihn kann der Vorwaertslookup nichts ausrichten: er fragt nach
        /// <c>HostnameWithDomain</c>, und wenn der Name fehlt, bleibt davon die
        /// blosse Domain uebrig - eine Abfrage, die fuer jedes Ziel dasselbe
        /// oder gar nichts liefert. Der Name entsteht in der Rueckwaerts-
        /// aufloesung, die darum vorher laufen muss.
        /// </para>
        /// </summary>
        private static string KnownHostName(ScanContext context, string text)
        {
            if (!IpAddressAnalyzer.TryAnalyze(text, out IpAddressInfo? info) || info is null)
            {
                // Das Ziel ist selbst ein Name - dann steht er schon da.
                return text;
            }

            lock (context.Store.SyncRoot)
            {
                return context.Store.FindByAddress(info)?.HostName ?? string.Empty;
            }
        }

        /// <summary>
        /// Leitet den Abbruch der Engine an das Modul weiter. Die Module
        /// verwalten ihre Abbruchquelle selbst und kennen nur
        /// <c>StopScan()</c>.
        /// </summary>
        protected static CancellationTokenRegistration BridgeCancellation(
            CancellationToken token, Action stopScan) => token.Register(stopScan);

        /// <summary>
        /// Wandelt ein vom Modul geaendertes <see cref="IPToScan"/> in eine
        /// Sichtung um und meldet sie. Uebertragen wird nur, was tatsaechlich
        /// gefuellt ist - jedes Modul fuellt einen anderen Ausschnitt.
        /// </summary>
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
            if (!string.IsNullOrWhiteSpace(result.SNMP_SysName)) Detail("SNMP", result.SNMPInfos);
            if (result.IsIPCam) Detail("Camera", $"{result.IPCamName} {result.IPCamXAddress}".Trim());
            Detail("mDNS", result.mDNS_toMultiLineString);

            context.Report(new DeviceObservation
            {
                Source = sourceOverride ?? DisplayName,
                Address = info,
                Mac = ParseMac(result.MAC) ?? ParseMac(result.SNMP_MAC),
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
        /// Die Adressen, auf die der Name im DNS zeigt.
        /// <para>
        /// Genommen wird der ganze <see cref="IPHostEntry"/>, nicht das Feld
        /// <c>LookUpIPs</c>: das Modul fuellt es nur, wenn der Lookup
        /// <em>abweicht</em>, und laesst es sonst leer. Leer hiesse damit
        /// zugleich "stimmt ueberein" und "nicht geprueft" - zwei Dinge, die
        /// auseinandergehalten werden muessen, wenn daraus ein Befund werden
        /// soll.
        /// </para>
        /// </summary>
        private static List<string>? LookupAddresses(IPToScan result)
        {
            if (result.UsedScanMethod != ScanMethod.Lookup) return null;
            if (result.IP_HostEntry?.AddressList is not { } addresses) return null;

            // Auf dieselbe Schreibweise bringen wie die Adressen am Geraet -
            // sonst gilt fe80:0:0::1 als etwas anderes als fe80::1 und jeder
            // Vergleich schlaegt fehl.
            return [.. addresses
                .Select(a => IpAddressAnalyzer.TryAnalyze(a.ToString(), out IpAddressInfo? info) && info is not null
                    ? info.Canonical
                    : a.ToString())
                .Distinct(StringComparer.OrdinalIgnoreCase)];
        }

        /// <summary>Zerlegt ein mehrzeiliges Feld der alten Module in eine Liste.</summary>
        private static List<string>? SplitLines(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return null;

            List<string> lines = [.. value
                .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.OrdinalIgnoreCase)];

            return lines.Count > 0 ? lines : null;
        }

        /// <summary>
        /// Ein Ziel gilt als erreichbar, sobald irgendein Verfahren eine
        /// Antwort gesehen hat - nicht nur der Ping.
        /// </summary>
        private static bool IsResponding(IPToScan r) =>
            r.PingStatus || r.ARPStatus || r.SSDPStatus || r.IsIPCam ||
            r.TCP_OpenPorts.Count > 0 || r.UDP_OpenPorts.Count > 0 ||
            !string.IsNullOrWhiteSpace(r.SNMP_SysName);

        /// <summary>
        /// Bildet Ports und erkannte Dienste ab. Der Zustand wird nur fuer die
        /// gepruefte Adressfamilie gesetzt; die andere Seite bleibt offen,
        /// damit ein spaeterer Lauf sie ergaenzen kann.
        /// </summary>
        private static List<DeviceServiceResult>? BuildServices(IPToScan r, IpFamily family)
        {
            List<DeviceServiceResult> services = [];

            foreach (ServiceScanData.ServiceResult service in r.Services.Services)
            {
                foreach (ServiceScanData.PortResult port in service.Ports)
                {
                    DeviceServiceResult entry = new()
                    {
                        ServiceName = service.Service.ToString(),
                        Category = CategoryOf(service.Service),
                        Ports = port.Ports is null ? [] : [.. port.Ports],
                        PortLog = NullIfBlank(port.PortLog)
                    };

                    if (family == IpFamily.IPv6) entry.StatusIPv6 = port.Status;
                    else entry.StatusIPv4 = port.Status;

                    services.Add(entry);
                }
            }

            // Offene Ports ohne erkannten Dienst gehen nicht verloren - sie
            // sind fuer den Portfilter genauso wichtig wie benannte Dienste.
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

            return services.Count > 0 ? services : null;
        }

        /// <summary>
        /// Ordnet einen Dienst seiner Gruppe zu - dieselbe Gliederung, die das
        /// <c>ServiceType</c>-Enum bereits durch seine Reihenfolge vorgibt.
        /// </summary>
        private static string CategoryOf(ServiceType service) => service switch
        {
            ServiceType.WebServices or ServiceType.DNS_TCP or ServiceType.DNS_UDP
                or ServiceType.DHCP or ServiceType.SSH or ServiceType.FTP => "Network",

            ServiceType.RDP or ServiceType.UltraVNC or ServiceType.BigFixRemote
                or ServiceType.TeamViewer or ServiceType.Anydesk
                or ServiceType.RustdeskServer or ServiceType.RustdeskClient => "Remote",

            ServiceType.MSSQLServer or ServiceType.PostgreSQL or ServiceType.MariaDB
                or ServiceType.MySQL or ServiceType.OracleDB or ServiceType.MongoDB
                or ServiceType.InfluxDB2 => "Databases",

            _ => "Other"
        };

        private static string? NullIfBlank(string? value) =>
            string.IsNullOrWhiteSpace(value) ? null : value.Trim();

        /// <summary>
        /// Liest eine MAC in den Schreibweisen, die in den Modulen vorkommen:
        /// mit Doppelpunkt, mit Bindestrich oder ohne Trenner.
        /// </summary>
        protected static PhysicalAddress? ParseMac(string? text)
        {
            if (string.IsNullOrWhiteSpace(text)) return null;

            string cleaned = text.Replace(":", "").Replace("-", "").Replace(".", "").Replace(" ", "").Trim();
            if (cleaned.Length != 12) return null;

            return PhysicalAddress.TryParse(cleaned, out PhysicalAddress? mac) ? mac : null;
        }
    }

    /// <summary>
    /// Die Zielliste im alten Format samt Rueckweg zum Bereich, aus dem ein
    /// Eintrag stammt.
    /// </summary>
    public sealed class LegacyTargets(List<IPToScan> items, Dictionary<string, ScanTargetEntry> byText)
    {
        public List<IPToScan> Items { get; } = items;

        public int Count => Items.Count;

        public ScanTargetEntry? Find(string? targetText) =>
            string.IsNullOrEmpty(targetText) ? null : byText.GetValueOrDefault(targetText);
    }
}
