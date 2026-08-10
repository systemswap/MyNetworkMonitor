using MyNetworkMonitor.Core.Scanning.Engine.Methods;

namespace MyNetworkMonitor.Core.Scanning.Engine
{
    /// <summary>
    /// Baut eine Engine mit allen vorhandenen Verfahren.
    /// <para>
    /// Steht in Core und nicht mehr im Fenster, weil es inzwischen zwei
    /// Aufrufer gibt: die Oberflaeche und den Satellitendienst, der ohne
    /// Fenster laeuft. Zwei Registrierungslisten waeren zwei Wirklichkeiten -
    /// ein Verfahren, das nur die Oberflaeche kennt, fehlte dem Satelliten
    /// still, und der Auftraggeber saehe nur, dass ein Befund ausbleibt.
    /// </para>
    /// </summary>
    public static class ScanEngineFactory
    {
        /// <summary>
        /// Alle heute vorhandenen Verfahren. Ein neues hinzuzufuegen heisst:
        /// eine Zeile hier - die Schublade der Oberflaeche und die
        /// Verfuegbarkeitspruefung ergeben sich daraus von selbst.
        /// </summary>
        /// <param name="serviceXmlPath">
        /// Die Dienstdefinitionen fuer die Diensterkennung.
        /// </param>
        public static void RegisterAllMethods(ScanEngine engine, string serviceXmlPath)
        {
            ArgumentNullException.ThrowIfNull(engine);

            engine.Register(new PingScanMethod());
            engine.Register(new ArpRequestScanMethod());
            engine.Register(new ArpCacheScanMethod());
            engine.Register(new SsdpScanMethod());
            engine.Register(new MdnsScanMethod());
            engine.Register(new WsDiscoveryScanMethod());

            // Die IPv6-Suchverfahren. Reihenfolge nach Aufwand fuer das Netz: erst
            // das Verfahren, das nur nachliest, dann das eine Paket an alle. Beide
            // laufen ohne erhoehte Rechte.
            engine.Register(new Ipv6NeighborCacheScanMethod());
            engine.Register(new Ipv6MulticastPingScanMethod());

            // Die Router-Ankuendigung liefert die gueltigen Praefixe - und auf die
            // setzen die beiden Rateverfahren darunter ihre Adressen. Steht darum
            // vor ihnen.
            engine.Register(new Ipv6RouterAdvertisementScanMethod());
            engine.Register(new Ipv6MulticastGroupScanMethod());

            engine.Register(new Ipv6LowByteSweepScanMethod());

            // Muss nach allem stehen, was MAC-Adressen findet - ARP, Ping,
            // Neighbor Cache. Es rechnet aus deren Funden Adressen aus und hat
            // vorher nichts, womit es rechnen koennte.
            engine.Register(new Ipv6Eui64ScanMethod());

            // Reihenfolge innerhalb der Phase = Reihenfolge hier. Die
            // Rueckwaertsaufloesung muss vor der Vorwaertsaufloesung stehen: erst
            // liefert sie zur Adresse den Namen, dann fragt die Vorwaerts-
            // aufloesung, welche Adressen dieser Name im DNS hat. Andersherum
            // fragt die zweite ins Leere, weil der Name noch fehlt.
            engine.Register(new ReverseLookupScanMethod());
            engine.Register(new HostnameLookupScanMethod());
            engine.Register(new NetBiosScanMethod());
            engine.Register(new SnmpScanMethod());
            engine.Register(new OnvifScanMethod());
            engine.Register(new SwitchPortScanMethod());
            engine.Register(new TcpPortScanMethod());
            engine.Register(new UdpPortScanMethod());
            engine.Register(new SmbVersionScanMethod());
            engine.Register(new ServiceDetectionScanMethod(serviceXmlPath));

            // Nach dem Portscan und der Diensterkennung: dieses Verfahren fragt an
            // den Ports nach, die die beiden vorher als offen gemeldet haben.
            engine.Register(new WebIdentityScanMethod());
        }

        /// <summary>Eine fertige Engine mit allen Verfahren.</summary>
        public static ScanEngine Create(string serviceXmlPath)
        {
            ScanEngine engine = new();
            RegisterAllMethods(engine, serviceXmlPath);
            return engine;
        }
    }
}
