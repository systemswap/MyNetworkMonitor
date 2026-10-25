// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// All available probes. Adding one means creating its file and adding one
    /// line here, just as a new scan method gets one line in
    /// <c>ScanEngineFactory</c>.
    /// <para>
    /// Callers use <see cref="Has"/> instead of assuming that every
    /// <c>ServiceType</c> has a probe.
    /// </para>
    /// </summary>
    public static class ServiceProbes
    {
        /// <summary>
        /// Probes are created anew for every run: a probe may keep state from
        /// <see cref="IServiceProbe.PrepareAsync"/> (DHCP does), and two
        /// simultaneous runs (local and as a satellite) must not interfere.
        /// </summary>
        private static readonly Dictionary<ServiceType, Func<IServiceProbe>> Factories = new()
        {
            // Network services
            [ServiceType.WebServices] = () => new WebServicesProbe(),
            [ServiceType.DNS_TCP] = () => new DnsTcpProbe(),
            [ServiceType.DNS_UDP] = () => new DnsUdpProbe(),
            [ServiceType.DHCP] = () => new DhcpProbe(),
            [ServiceType.SSH] = () => new SshProbe(),
            [ServiceType.FTP] = () => new FtpProbe(),

            // Remote desktop and remote maintenance
            [ServiceType.RDP] = () => new RdpProbe(),
            [ServiceType.UltraVNC] = () => new UltraVncProbe(),
            [ServiceType.BigFixRemote] = () => new BigFixRemoteProbe(),
            [ServiceType.TeamViewer] = () => new TeamViewerProbe(),
            [ServiceType.Anydesk] = () => new AnydeskProbe(),
            [ServiceType.RustdeskServer] = () => new RustdeskServerProbe(),
            [ServiceType.RustdeskClient] = () => new RustdeskClientProbe(),

            // Databases
            [ServiceType.MSSQLServer] = () => new MsSqlServerProbe(),
            [ServiceType.PostgreSQL] = () => new PostgreSqlProbe(),
            [ServiceType.MariaDB] = () => new MariaDbProbe(),
            [ServiceType.MySQL] = () => new MySqlProbe(),
            [ServiceType.OracleDB] = () => new OracleDbProbe(),
            [ServiceType.MongoDB] = () => new MongoDbProbe(),
            [ServiceType.InfluxDB2] = () => new InfluxDb2Probe(),

            // Industrial protocols
            [ServiceType.OPCUA] = () => new OpcUaProbe(),
            [ServiceType.ModBus] = () => new ModBusProbe(),
            [ServiceType.S7] = () => new S7Probe(),
            [ServiceType.BacNet] = () => new BacNetProbe(),
            [ServiceType.Wago] = () => new WagoProbe(),
            [ServiceType.SecsGem] = () => new SecsGemProbe()
        };

        /// <summary>
        /// Instances for metadata only: ports, group, packet, answer check.
        /// These are stateless, and the service manager queries them often.
        /// </summary>
        private static readonly Lazy<IReadOnlyList<IServiceProbe>> Shared =
            new(() => [.. Factories.Values.Select(create => create())]);

        /// <summary>Checks whether a probe exists for a service.</summary>
        /// <param name="service">The service.</param>
        /// <returns><c>true</c> if a probe exists.</returns>
        public static bool Has(ServiceType service) => Factories.ContainsKey(service);

        /// <summary>Creates a fresh probe for a run.</summary>
        /// <param name="service">The service.</param>
        /// <returns>A new probe instance.</returns>
        /// <exception cref="KeyNotFoundException">No probe exists for <paramref name="service"/>.</exception>
        public static IServiceProbe Create(ServiceType service) =>
            Factories.TryGetValue(service, out Func<IServiceProbe>? create)
                ? create()
                : throw new KeyNotFoundException($"There is no probe for {service}.");

        /// <summary>The shared probe for metadata, not for a run; see <see cref="Create"/>.</summary>
        /// <param name="service">The service.</param>
        /// <returns>The shared, stateless probe instance.</returns>
        /// <exception cref="KeyNotFoundException">No probe exists for <paramref name="service"/>.</exception>
        public static IServiceProbe For(ServiceType service) =>
            Shared.Value.FirstOrDefault(p => p.Service == service)
            ?? throw new KeyNotFoundException($"There is no probe for {service}.");

        /// <summary>All probes, for metadata.</summary>
        public static IReadOnlyList<IServiceProbe> All => Shared.Value;

        /// <summary>
        /// Fresh probes for the requested services, in the order of the service
        /// manager: first by group, then by name. The run therefore proceeds in
        /// the same order as the list shown there.
        /// <para>
        /// Services without a probe are skipped.
        /// </para>
        /// </summary>
        /// <param name="wanted">The requested services; duplicates are ignored.</param>
        /// <returns>New probe instances in scan order.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="wanted"/> is <c>null</c>.</exception>
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
