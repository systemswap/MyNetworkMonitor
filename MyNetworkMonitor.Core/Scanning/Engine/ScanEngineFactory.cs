// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using MyNetworkMonitor.Core.Scanning.Engine.Methods;

namespace MyNetworkMonitor.Core.Scanning.Engine
{
    /// <summary>
    /// Builds an engine with all available methods.
    /// <para>
    /// Lives in Core rather than in the window because there are two callers:
    /// the UI and the satellite service, which runs without a window. Two
    /// registration lists would diverge: a method known only to the UI would
    /// be silently missing on the satellite, and the requesting scanner would
    /// only notice that a finding never arrives.
    /// </para>
    /// </summary>
    public static class ScanEngineFactory
    {
        /// <summary>
        /// Registers all available methods. Adding a method means adding one
        /// line here; the method drawer in the UI and the availability check
        /// follow from it automatically.
        /// </summary>
        /// <param name="engine">The engine to register the methods with.</param>
        /// <param name="serviceXmlPath">
        /// Path of the service definitions used by service detection.
        /// </param>
        /// <exception cref="ArgumentNullException"><paramref name="engine"/> is null.</exception>
        public static void RegisterAllMethods(ScanEngine engine, string serviceXmlPath)
        {
            ArgumentNullException.ThrowIfNull(engine);

            engine.Register(new PingScanMethod());
            engine.Register(new ArpRequestScanMethod());
            engine.Register(new ArpCacheScanMethod());
            engine.Register(new SsdpScanMethod());
            engine.Register(new MdnsScanMethod());
            engine.Register(new WsDiscoveryScanMethod());

            // The IPv6 discovery methods, ordered by network load: first the
            // method that only reads the cache, then the single packet to all
            // nodes. Both run without elevated privileges.
            engine.Register(new Ipv6NeighborCacheScanMethod());
            engine.Register(new Ipv6MulticastPingScanMethod());

            // Router advertisements provide the valid prefixes, on which the
            // two guessing methods below base their addresses. Registered
            // before them for that reason.
            engine.Register(new Ipv6RouterAdvertisementScanMethod());
            engine.Register(new Ipv6MulticastGroupScanMethod());

            engine.Register(new Ipv6LowByteSweepScanMethod());

            // Must come after everything that finds MAC addresses (ARP, ping,
            // neighbor cache). It derives addresses from their findings and has
            // nothing to work with before them.
            engine.Register(new Ipv6Eui64ScanMethod());

            // Order within a phase equals the order here. Reverse lookup must
            // come before forward lookup: it first supplies the name for the
            // address, then forward lookup asks which addresses this name has
            // in DNS. The other way round, the forward lookup has no name to
            // query yet.
            engine.Register(new ReverseLookupScanMethod());
            engine.Register(new HostnameLookupScanMethod());
            engine.Register(new NetBiosScanMethod());
            engine.Register(new SnmpScanMethod());
            engine.Register(new OnvifScanMethod());
            engine.Register(new SwitchPortScanMethod());
            engine.Register(new TcpPortScanMethod());

            // Directly below the regular port scan: the all-ports variant is
            // shown indented beneath it in the UI. Never preselected, in any
            // profile.
            engine.Register(new AllTcpPortScanMethod());

            engine.Register(new UdpPortScanMethod());
            engine.Register(new SmbVersionScanMethod());
            engine.Register(new ServiceDetectionScanMethod(serviceXmlPath));

            // After the port scan and service detection: this method queries
            // the ports those two have reported as open.
            engine.Register(new WebIdentityScanMethod());
        }

        /// <summary>Creates an engine with all methods registered.</summary>
        /// <param name="serviceXmlPath">Path of the service definitions used by service detection.</param>
        /// <returns>The ready-to-use engine.</returns>
        public static ScanEngine Create(string serviceXmlPath)
        {
            ScanEngine engine = new();
            RegisterAllMethods(engine, serviceXmlPath);
            return engine;
        }
    }
}
