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

        // Bewusst abstrakt und nicht mit einem leeren Standard versehen: ein
        // Verfahren ohne Erklaerung ist eines, das der Nutzer nicht einordnen
        // kann - das soll beim Hinzufuegen auffallen und nicht im Betrieb.
        public abstract string Explanation { get; }

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

                // Ohne eigenen DNS-Server im Bereich sonst auf den
                // System-Resolver zurueckzufallen bedeutet auf Linux fast immer
                // einen lokalen Stub (z.B. systemd-resolved), der selbst erst an
                // den eigentlichen Server weiterleitet - mit eigenem Zwischen-
                // speicher und, unter Last, spuerbarem Verlust. Das Gateway des
                // scannenden Interfaces beantwortet bei den meisten
                // Heimroutern denselben Namensraum selbst und direkt: live
                // gemessen 32 von 254 Adressen eines /24 in unter 60ms gegen
                // das Gateway, gegenueber zig Sekunden ueber einen
                // nachgelagerten Server. Kennt das Gateway die Namen nicht,
                // bleibt die Adresse einfach ohne PTR-Ergebnis - bewusst kein
                // weiterer Rueckfall auf den System-Resolver.
                // Der am Bereich hinterlegte Router sticht den des Adapters -
                // fuer den Fall, dass ein Bereich hinter einem anderen Router
                // haengt als der, ueber den gescannt wird. Ist dort nichts
                // eingetragen, bleibt es beim Adapter, auch wenn derselbe fuer
                // alle Bereiche gilt.
                if (dnsServers.Count == 0)
                {
                    string? gateway = scope.HasOwnGateway
                        ? scope.GatewayIP.Trim()
                        : GatewayDnsFallback(target.Scope.Interface);

                    if (gateway is not null) dnsServers = [gateway];
                }

                legacy.Add(new IPToScan
                {
                    IPorHostname = text,

                    // Der Name, den jemand selbst eingetippt hat, sticht den
                    // aus dem Bestand.
                    //
                    // Seit ein Hostname vor dem Lauf aufgeloest wird, ist
                    // TargetText die Adresse - KnownHostName suchte sie dann im
                    // noch leeren Bestand und fand nichts. Der eingegebene Name
                    // ging damit verloren und die Spalte blieb leer, obwohl das
                    // Geraet gefunden wurde.
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

        /// <summary>Die IPv4-Gateway-Adresse des Interfaces, falls vorhanden - siehe Kommentar an der Aufrufstelle.</summary>
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
        /// <summary>Der Port, auf dem die SMB-Pruefung arbeitet.</summary>
        private const int SmbPort = 445;

        private const int NetBiosPort = 137;
        private const int SnmpPort = 161;
        private const int OnvifPort = 3702;

        /// <summary>
        /// Traegt einen Dienst nach, den ein eigenes Modul gefunden hat.
        /// <para>
        /// NetBIOS, SNMP, ONVIF und SMB laufen nicht ueber die Diensterkennung,
        /// sondern haben je ein eigenes Verfahren - Dienste sind es trotzdem,
        /// und sie gehoeren in dieselbe Spalte wie die uebrigen. Vorher waren
        /// sie nur im Klartext unter den Details zu finden, wo man sie nur
        /// sieht, wenn man ohnehin schon weiss, dass es sie gibt.
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

            // SMB kommt aus einem eigenen Modul und nicht aus der
            // Diensterkennung - ein Dienst ist es trotzdem, und in der Spalte
            // "Running services" gehoert er neben die anderen. Die Versionen
            // stehen im Protokoll: dass ein Ziel noch SMB 1.0 spricht, ist die
            // eigentliche Nachricht.
            if (r.SMBVersions.Count > 0)
            {
                AddFoundService(services, family, "SMB", "File services", SmbPort,
                    "SMB versions: " + string.Join(", ", r.SMBVersions));
            }

            if (!string.IsNullOrWhiteSpace(r.NetBiosHostname))
            {
                AddFoundService(services, family, "NetBIOS", "Network", NetBiosPort,
                    $"NetBIOS name: {r.NetBiosHostname}");
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

            // Dasselbe fuer UDP - bisher gingen offene UDP-Ports hier
            // verloren und tauchten nur im CSV-Export auf, nicht in der
            // Dienstspalte oder im Portfilter.
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
        /// Ordnet einen Dienst seiner Gruppe zu. Die Zuordnung steht in
        /// <see cref="ServiceCategories"/>, weil auch die Portsuche ueber alle
        /// Ports sie braucht.
        /// </summary>
        private static string CategoryOf(ServiceType service) => ServiceCategories.Of(service);

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
