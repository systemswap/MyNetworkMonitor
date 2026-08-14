namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Alle vorhandenen Sonden. Eine neue hinzuzufuegen heisst: Datei anlegen
    /// und hier eine Zeile eintragen - so wie ein neues Scan-Verfahren eine
    /// Zeile in <c>ScanEngineFactory</c> bekommt.
    /// <para>
    /// Waehrend des Umbaus ist die Liste noch unvollstaendig. Was hier fehlt,
    /// laeuft weiter ueber den alten Schalter in
    /// <c>ScanningMethod_Services</c>; darum <see cref="Has"/> statt der
    /// Annahme, dass es zu jedem <c>ServiceType</c> eine Sonde gibt.
    /// </para>
    /// </summary>
    public static class ServiceProbes
    {
        /// <summary>
        /// Angelegt wird je Lauf neu, nicht einmal fuer immer: eine Sonde darf
        /// sich in <see cref="IServiceProbe.PrepareAsync"/> etwas merken - DHCP
        /// tut es -, und zwei gleichzeitige Laeufe (oertlich und als Satellit)
        /// duerfen sich dabei nicht ins Gehege kommen.
        /// </summary>
        private static readonly Dictionary<ServiceType, Func<IServiceProbe>> Factories = new()
        {
            // Netzwerk-Dienste
            [ServiceType.WebServices] = () => new WebServicesProbe(),
            [ServiceType.DNS_TCP] = () => new DnsTcpProbe(),
            [ServiceType.DNS_UDP] = () => new DnsUdpProbe(),
            [ServiceType.DHCP] = () => new DhcpProbe(),
            [ServiceType.SSH] = () => new SshProbe(),
            [ServiceType.FTP] = () => new FtpProbe(),

            // Remote-Desktop und Fernwartung
            [ServiceType.RDP] = () => new RdpProbe(),
            [ServiceType.UltraVNC] = () => new UltraVncProbe(),
            [ServiceType.BigFixRemote] = () => new BigFixRemoteProbe(),
            [ServiceType.TeamViewer] = () => new TeamViewerProbe(),
            [ServiceType.Anydesk] = () => new AnydeskProbe(),
            [ServiceType.RustdeskServer] = () => new RustdeskServerProbe(),
            [ServiceType.RustdeskClient] = () => new RustdeskClientProbe(),

            // Datenbanken
            [ServiceType.MSSQLServer] = () => new MsSqlServerProbe(),
            [ServiceType.PostgreSQL] = () => new PostgreSqlProbe(),
            [ServiceType.MariaDB] = () => new MariaDbProbe(),
            [ServiceType.MySQL] = () => new MySqlProbe(),
            [ServiceType.OracleDB] = () => new OracleDbProbe(),
            [ServiceType.MongoDB] = () => new MongoDbProbe(),
            [ServiceType.InfluxDB2] = () => new InfluxDb2Probe(),

            // Industrieprotokolle
            [ServiceType.OPCUA] = () => new OpcUaProbe(),
            [ServiceType.ModBus] = () => new ModBusProbe(),
            [ServiceType.S7] = () => new S7Probe(),
            [ServiceType.BacNet] = () => new BacNetProbe(),
            [ServiceType.Wago] = () => new WagoProbe()
        };

        /// <summary>
        /// Exemplare fuer die reinen Angaben - Ports, Gruppe, Paket, Pruefung.
        /// Die sind zustandslos, und die Dienstverwaltung fragt sie oft.
        /// </summary>
        private static readonly Lazy<IReadOnlyList<IServiceProbe>> Shared =
            new(() => [.. Factories.Values.Select(create => create())]);

        /// <summary>Es gibt eine Sonde fuer diesen Dienst.</summary>
        public static bool Has(ServiceType service) => Factories.ContainsKey(service);

        /// <summary>Eine frische Sonde fuer einen Lauf.</summary>
        public static IServiceProbe Create(ServiceType service) =>
            Factories.TryGetValue(service, out Func<IServiceProbe>? create)
                ? create()
                : throw new KeyNotFoundException($"Fuer {service} gibt es keine Sonde.");

        /// <summary>Die Sonde fuer Angaben - nicht fuer einen Lauf, siehe <see cref="Create"/>.</summary>
        public static IServiceProbe For(ServiceType service) =>
            Shared.Value.FirstOrDefault(p => p.Service == service)
            ?? throw new KeyNotFoundException($"Fuer {service} gibt es keine Sonde.");

        /// <summary>Alle Sonden, fuer Angaben.</summary>
        public static IReadOnlyList<IServiceProbe> All => Shared.Value;

        /// <summary>
        /// Frische Sonden fuer die gewuenschten Dienste, in der Reihenfolge, in
        /// der sie auch in der Dienstverwaltung stehen: erst nach Gruppe, dann
        /// nach Name. Wer die Liste dort vor sich hat, sieht den Lauf in
        /// derselben Ordnung durchgehen.
        /// <para>
        /// Dienste ohne eigene Sonde werden uebergangen - waehrend des Umbaus
        /// laufen sie noch ueber den alten Weg.
        /// </para>
        /// </summary>
        public static IReadOnlyList<IServiceProbe> InScanOrder(IEnumerable<ServiceType> wanted)
        {
            ArgumentNullException.ThrowIfNull(wanted);

            return
            [
                .. wanted.Distinct()
                         .Where(Has)
                         .Select(Create)
                         .OrderBy(p => p.Group, StringComparer.CurrentCulture)
                         .ThenBy(p => p.Service.ToString(), StringComparer.CurrentCulture)
            ];
        }
    }
}
