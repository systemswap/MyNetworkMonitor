using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// Was das Betriebssystem aus den Router-Ankuendigungen bereits gelernt
    /// hat - ausgelesen statt mitgehoert.
    /// <para>
    /// <b>Warum es diesen zweiten Weg gibt.</b> Am 2026-08-09 nachgemessen:
    /// Windows liefert ICMPv6 <em>grundsaetzlich nicht</em> an Rohsockets aus,
    /// auch nicht mit Administratorrechten und auch nicht nach Beitritt zu den
    /// Multicast-Gruppen (vier Bindungs- und Beitrittsvarianten geprueft, alle
    /// null Pakete). Der Netzwerkstapel verbraucht sie selbst; sie zu sehen
    /// setzt einen Mitschnitttreiber wie Npcap voraus, und der soll
    /// ausdruecklich nicht noetig sein.
    /// </para>
    /// <para>
    /// Der Ausweg dreht die Sache um: Windows <em>hat</em> die Ankuendigungen
    /// empfangen und ausgewertet - sonst haette der Rechner keine
    /// IPv6-Adresse. Das Ergebnis steht in ganz gewoehnlichen APIs, die keine
    /// Sonderrechte brauchen. Was dabei verloren geht, ist die Momentaufnahme
    /// ("welcher Router hat gerade was angekuendigt"); was bleibt, ist der
    /// Inhalt - Router, Praefixe, Namensserver und die Frage, ob DHCPv6 im
    /// Spiel ist. Fuer die Bestandsaufnahme eines Netzes ist das dasselbe.
    /// </para>
    /// </summary>
    public sealed class Ipv6StackInfo
    {
        /// <summary>Die Router, die dieser Adapter als Standardgateway kennt.</summary>
        public List<IPAddress> Routers { get; } = [];

        /// <summary>Praefixe, auf denen der Adapter eine Adresse gebildet hat.</summary>
        public List<AdvertisedPrefix> Prefixes { get; } = [];

        /// <summary>Die IPv6-Namensserver dieses Adapters.</summary>
        public List<IPAddress> DnsServers { get; } = [];

        public string? SearchDomain { get; init; }

        /// <summary>
        /// Mindestens eine Adresse stammt von einem DHCPv6-Server. Entspricht
        /// dem M-Bit der Ankuendigung, nur von der anderen Seite betrachtet:
        /// statt "der Router sagt, es gibt DHCPv6" heisst es hier "wir haben
        /// tatsaechlich eine Adresse von dort".
        /// </summary>
        public bool UsesDhcpv6 { get; private set; }

        /// <summary>
        /// Mindestens eine Adresse hat sich der Rechner selbst gebildet, auf
        /// Grundlage eines angekuendigten Praefixes (SLAAC).
        /// </summary>
        public bool UsesSlaac { get; private set; }

        /// <summary>Es gibt etwas zu berichten.</summary>
        public bool HasAnything => Routers.Count > 0 || Prefixes.Count > 0 || DnsServers.Count > 0;

        /// <summary>
        /// Liest zusammen, was der Stapel ueber diesen Adapter weiss. Wirft
        /// nicht - ein Adapter, der waehrenddessen verschwindet, ergibt ein
        /// leeres Ergebnis.
        /// </summary>
        public static Ipv6StackInfo ForInterface(NetworkInterface nic, int interfaceIndex)
        {
            ArgumentNullException.ThrowIfNull(nic);

            IPInterfaceProperties properties;
            try { properties = nic.GetIPProperties(); }
            catch (NetworkInformationException) { return new Ipv6StackInfo(); }
            catch (PlatformNotSupportedException) { return new Ipv6StackInfo(); }

            Ipv6StackInfo info = new()
            {
                SearchDomain = string.IsNullOrWhiteSpace(properties.DnsSuffix) ? null : properties.DnsSuffix
            };

            info.ReadGateways(properties, interfaceIndex);
            info.ReadDnsServers(properties, interfaceIndex);
            info.ReadPrefixes(properties, interfaceIndex);

            return info;
        }

        private void ReadGateways(IPInterfaceProperties properties, int interfaceIndex)
        {
            try
            {
                HashSet<string> seen = [];

                foreach (GatewayIPAddressInformation gateway in properties.GatewayAddresses)
                {
                    if (gateway.Address?.AddressFamily != AddressFamily.InterNetworkV6) continue;
                    if (IPAddress.IPv6Any.Equals(gateway.Address)) continue;

                    IPAddress scoped = WithZone(gateway.Address, interfaceIndex);

                    // Windows fuehrt dasselbe Gateway mehrfach auf, wenn es
                    // ueber mehrere Routen erreichbar ist. Zweimal derselbe
                    // Router waere zweimal dasselbe Geraet.
                    if (!seen.Add(scoped.ToString())) continue;

                    Routers.Add(scoped);
                }
            }
            catch (PlatformNotSupportedException) { /* Gateways nicht abfragbar */ }
        }

        private void ReadDnsServers(IPInterfaceProperties properties, int interfaceIndex)
        {
            try
            {
                HashSet<string> seen = [];

                foreach (IPAddress server in properties.DnsAddresses)
                {
                    if (server.AddressFamily != AddressFamily.InterNetworkV6) continue;
                    if (IsWindowsPlaceholder(server)) continue;

                    IPAddress scoped = WithZone(server, interfaceIndex);

                    // Derselbe Server steht doppelt in der Liste, wenn er
                    // sowohl ueber die Router-Ankuendigung (RDNSS) als auch
                    // ueber DHCPv6 bekanntgegeben wird - am 2026-08-09 an
                    // einer FRITZ!Box mit beidem gesehen. Fuer den Befund
                    // "zu viele DNS-Server je Adapter" waere das eine
                    // Falschmeldung.
                    if (!seen.Add(scoped.ToString())) continue;

                    DnsServers.Add(scoped);
                }
            }
            catch (PlatformNotSupportedException) { /* keine DNS-Angaben */ }
        }

        /// <summary>
        /// Leitet die Praefixe aus den eigenen Adressen ab - und liest dabei
        /// die eigentlich interessante Angabe mit: <see cref="PrefixOrigin"/>
        /// sagt, <em>woher</em> das Praefix stammt.
        /// <para>
        /// <see cref="PrefixOrigin.RouterAdvertisement"/> heisst: genau dieses
        /// Praefix hat ein Router angekuendigt. <see cref="PrefixOrigin.Dhcp"/>
        /// heisst: die Adresse kam von einem DHCPv6-Server. Damit steht die
        /// Auskunft zur Adressvergabe fest, ohne ein Bit aus einem Paket lesen
        /// zu muessen.
        /// </para>
        /// </summary>
        private void ReadPrefixes(IPInterfaceProperties properties, int interfaceIndex)
        {
            HashSet<string> seen = [];

            foreach (UnicastIPAddressInformation unicast in properties.UnicastAddresses)
            {
                if (unicast.Address.AddressFamily != AddressFamily.InterNetworkV6) continue;
                if (unicast.Address.IsIPv6LinkLocal) continue;

                PrefixOrigin origin;
                int length;

                try
                {
                    origin = unicast.PrefixOrigin;
                    length = unicast.PrefixLength;
                }
                catch (PlatformNotSupportedException)
                {
                    // Unter Linux gibt .NET diese Angaben nicht immer her.
                    // Dort ist ohnehin der Rohsocket der bessere Weg.
                    continue;
                }

                if (origin == PrefixOrigin.Dhcp) UsesDhcpv6 = true;
                if (origin == PrefixOrigin.RouterAdvertisement) UsesSlaac = true;

                if (length is <= 0 or > 64) continue;

                IPAddress network = Ipv6Prefixes.Mask(unicast.Address, length);
                if (!seen.Add($"{network}/{length}")) continue;

                Prefixes.Add(new AdvertisedPrefix
                {
                    Prefix = network,
                    Length = length,

                    // Der Rechner hat sich hier selbst eine Adresse gebildet -
                    // das ist genau die Bedeutung des A-Bits.
                    Autonomous = origin == PrefixOrigin.RouterAdvertisement,
                    OnLink = true,
                    ValidLifetimeSeconds = 0
                });
            }
        }

        /// <summary>
        /// <c>fec0:0:0:ffff::1</c> bis <c>::3</c> sind keine Namensserver,
        /// sondern die Platzhalter, die Windows an jedem Adapter auffuehrt,
        /// solange keiner eingerichtet ist.
        /// <para>
        /// Am 2026-08-09 an einem Rechner ohne IPv6 im Netz gesehen: vier von
        /// sechs Adaptern meldeten diese drei Adressen. Sie ungeprueft zu
        /// uebernehmen hiesse, an einem Netz ganz ohne IPv6 drei Namensserver
        /// zu behaupten - und der Befund "zu viele DNS-Server je Adapter"
        /// spraenge bei jedem zweiten Adapter an. Der Bereich
        /// <c>fec0::/10</c> ist ohnehin seit RFC 3879 abgekuendigt und kommt
        /// als echter Server nicht mehr vor.
        /// </para>
        /// </summary>
        private static bool IsWindowsPlaceholder(IPAddress address)
        {
            byte[] b = address.GetAddressBytes();

            // fec0::/10
            if (b[0] != 0xFE || (b[1] & 0xC0) != 0xC0) return false;

            return b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0 &&
                   b[6] == 0xFF && b[7] == 0xFF &&
                   b[8] == 0 && b[9] == 0 && b[10] == 0 && b[11] == 0 &&
                   b[12] == 0 && b[13] == 0 && b[14] == 0 && b[15] is >= 1 and <= 3;
        }

        /// <summary>
        /// Haengt die Adapterzone an, wo sie fehlt. Ein Gateway ist regelmaessig
        /// link-local, und ohne Zone ist es nicht ansprechbar.
        /// </summary>
        private static IPAddress WithZone(IPAddress address, int interfaceIndex) =>
            address.IsIPv6LinkLocal && address.ScopeId == 0 && interfaceIndex > 0
                ? new IPAddress(address.GetAddressBytes(), interfaceIndex)
                : address;
    }
}
