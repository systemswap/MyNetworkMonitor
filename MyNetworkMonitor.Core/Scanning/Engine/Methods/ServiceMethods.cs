using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// TCP-Portscan ueber die eingestellte Portauswahl.
    /// <para>
    /// <b>Nur IPv4, und zwar wegen des Sockets:</b>
    /// <c>ScanningMethod_PortsTCP</c> oeffnet in
    /// <c>ScanTCP_Port_via_Socket_Async</c> einen Socket mit
    /// <c>AddressFamily.InterNetwork</c>. Ein IPv6-Ziel wuerde dort eine
    /// Ausnahme ausloesen, nicht nur kein Ergebnis liefern. Der Dual-Stack-Umbau
    /// dieses Moduls ist Schritt 5 der Reihenfolge - erst danach entsteht die
    /// Gegenueberstellung v4/v6 je Port.
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

            tcp.TcpPortScan_Task_Finished += OnFound;
            using CancellationTokenRegistration reg = BridgeCancellation(cancellationToken, tcp.StopScan);

            try
            {
                await tcp.ScanTCPPortsAsync(targets.Items, ports,
                    TimeSpan.FromMilliseconds(context.Settings.PortTimeoutMs));
            }
            finally
            {
                tcp.TcpPortScan_Task_Finished -= OnFound;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    /// <summary>
    /// UDP-Lauscher am Ziel ermitteln. Das Modul arbeitet ohne eigene
    /// Abbruchmoeglichkeit und synchron - der Lauf wird darum auf einen
    /// Hintergrund-Thread gelegt, damit die Oberflaeche nicht stehenbleibt.
    /// </summary>
    public sealed class UdpPortScanMethod : LegacyScanMethod
    {
        public override string Id => "ports.udp";
        public override string DisplayName => "UDP ports";

        public override string Explanation =>
            "The same idea as the TCP check, but for services that answer without setting " +
            "up a connection first: name resolution, time servers, network management, " +
            "video and voice transmission. Slower and less certain than the TCP check - " +
            "silence can mean \"closed\" just as well as \"nobody felt like answering\". " +
            "Worth ticking when you are specifically after such services, not as a " +
            "routine first pass.";
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

            ScanningMethod_PortsUDP udp = new();

            void OnFound(object? _, ScanTask_Finished_EventArgs e) => ReportResult(context, e.ipToScan, targets);

            udp.UDPPortScan_Task_Finished += OnFound;

            try
            {
                await Task.Run(() => udp.Get_All_UPD_Listener_as_List(targets.Items), cancellationToken);
            }
            finally
            {
                udp.UDPPortScan_Task_Finished -= OnFound;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    /// <summary>
    /// SMB-Version des Ziels bestimmen. Meldet auch, wenn noch SMBv1 aktiv ist.
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
    /// Diensterkennung: spricht die Ports gezielt an und ordnet die Antwort
    /// einem Dienst zu. Liefert die Dienstliste, nach der die Ergebnistabelle
    /// gefiltert wird.
    /// <para>
    /// Braucht den Pfad zur Dienst-XML, weil das Modul seine Definitionen
    /// von dort laedt. Die Erkennungspakete selbst werden nicht angetastet.
    /// </para>
    /// </summary>
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
        /// Eine fehlende Dienst-XML ist <b>kein</b> Hindernis:
        /// <c>SetServicePorts</c> legt jeden Diensttyp mit seinen Standardports
        /// an und liest die Datei nur als Ueberlagerung fuer eigene
        /// Anpassungen darueber. Sie muss also gar nicht vorhanden sein.
        /// </summary>
        public override ScanMethodAvailability CheckAvailability(ScanContext context) =>
            context.HasTargetsOf(IpFamily.IPv4)
                ? ScanMethodAvailability.Available
                : ScanMethodAvailability.NotApplicable(NoIpv4Targets);

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            LegacyTargets targets = BuildTargets(context);
            if (targets.Count == 0) return;

            ScanningMethod_Services services = new(serviceXmlPath);

            (List<ServiceType> wanted, Dictionary<ServiceType, List<int>> ports) =
                SelectServices(services, context.Settings.Services);

            if (wanted.Count == 0) return;

            void OnProgress(int c, int r, int t) => context.ReportProgress(c, r, t);
            void OnFound(IPToScan ip) => ReportResult(context, ip, targets);

            services.ProgressUpdated += OnProgress;
            services.ServiceIPScanFinished += OnFound;
            using CancellationTokenRegistration reg = BridgeCancellation(cancellationToken, services.StopScan);

            try
            {
                await services.ScanIPsAsync(targets.Items, wanted, ports);
            }
            finally
            {
                services.ProgressUpdated -= OnProgress;
                services.ServiceIPScanFinished -= OnFound;
            }

            cancellationToken.ThrowIfCancellationRequested();
        }

        /// <summary>
        /// Bestimmt, welche Dienste gesucht werden - und mit welchen Ports.
        /// <para>
        /// Drei Stufen: was die Einstellungen ausdruecklich nennen, sonst was
        /// in der Dienstetabelle als <c>toScan</c> markiert ist, sonst alle.
        /// Die letzte Stufe ist wichtig, weil die Dienstauswahl in der neuen
        /// Oberflaeche noch fehlt - ohne sie waere "Diensterkennung" angehakt
        /// und wuerde trotzdem nichts tun, was niemand versteht.
        /// </para>
        /// </summary>
        private static (List<ServiceType>, Dictionary<ServiceType, List<int>>) SelectServices(
            ScanningMethod_Services module, List<ServiceType> fromSettings)
        {
            Dictionary<ServiceType, List<int>> ports = [];
            List<ServiceType> marked = [];
            List<ServiceType> all = [];

            foreach (System.Data.DataRow row in module.Services.Rows)
            {
                string name = row["Service"]?.ToString() ?? string.Empty;
                if (!Enum.TryParse(name, out ServiceType type)) continue;

                all.Add(type);
                ports[type] = ParsePorts(row["Ports"]?.ToString());

                if (row["toScan"] != DBNull.Value && row["toScan"] is true) marked.Add(type);
            }

            List<ServiceType> wanted =
                fromSettings.Count > 0 ? fromSettings :
                marked.Count > 0 ? marked :
                all;

            return (wanted, ports);
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
