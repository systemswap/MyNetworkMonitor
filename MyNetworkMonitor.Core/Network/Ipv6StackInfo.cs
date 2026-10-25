using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// What the operating system has already learned from router advertisements -
    /// read out instead of overheard.
    /// <para>
    /// <b>Why this second path exists.</b> Verified by measurement: Windows
    /// <em>never</em> delivers ICMPv6 to raw sockets, not even with administrator
    /// rights and not after joining the multicast groups (four binding and join
    /// variants tested, all zero packets). The network stack consumes them
    /// itself; seeing them requires a capture driver such as Npcap, which is
    /// deliberately not a requirement.
    /// </para>
    /// <para>
    /// The workaround turns the problem around: Windows <em>has</em> received and
    /// evaluated the advertisements - otherwise the machine would have no IPv6
    /// address. The result is available through ordinary APIs that need no
    /// special privileges. What is lost is the snapshot ("which router announced
    /// what just now"); what remains is the content - routers, prefixes, name
    /// servers and whether DHCPv6 is involved. For an inventory of a network
    /// that is the same.
    /// </para>
    /// </summary>
    public sealed class Ipv6StackInfo
    {
        /// <summary>The routers this adapter knows as default gateway.</summary>
        public List<IPAddress> Routers { get; } = [];

        /// <summary>Prefixes on which the adapter has formed an address.</summary>
        public List<AdvertisedPrefix> Prefixes { get; } = [];

        /// <summary>The IPv6 name servers of this adapter.</summary>
        public List<IPAddress> DnsServers { get; } = [];

        /// <summary>The DNS suffix of the adapter, or null if none is set.</summary>
        public string? SearchDomain { get; init; }

        /// <summary>
        /// At least one address comes from a DHCPv6 server. Corresponds to the M
        /// flag of the advertisement, only viewed from the other side: instead of
        /// "the router says there is DHCPv6" it means "an address was actually
        /// obtained from there".
        /// </summary>
        public bool UsesDhcpv6 { get; private set; }

        /// <summary>
        /// At least one address was formed by the machine itself, based on an
        /// announced prefix (SLAAC).
        /// </summary>
        public bool UsesSlaac { get; private set; }

        /// <summary>There is something to report.</summary>
        public bool HasAnything => Routers.Count > 0 || Prefixes.Count > 0 || DnsServers.Count > 0;

        /// <summary>
        /// Collects what the stack knows about this adapter. Does not throw - an
        /// adapter that disappears meanwhile yields an empty result.
        /// </summary>
        /// <param name="nic">The adapter.</param>
        /// <param name="interfaceIndex">The adapter index used as zone for link-local addresses.</param>
        /// <returns>Routers, prefixes and name servers of the adapter.</returns>
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

                    // Windows lists the same gateway several times if it is
                    // reachable via several routes. The same router twice
                    // would be the same device twice.
                    if (!seen.Add(scoped.ToString())) continue;

                    Routers.Add(scoped);
                }
            }
            catch (PlatformNotSupportedException) { /* gateways cannot be queried */ }
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

                    // The same server appears twice in the list if it is
                    // announced both via the router advertisement (RDNSS) and
                    // via DHCPv6 - observed on a home router doing both. For
                    // the finding "too many DNS servers per adapter" that
                    // would be a false report.
                    if (!seen.Add(scoped.ToString())) continue;

                    DnsServers.Add(scoped);
                }
            }
            catch (PlatformNotSupportedException) { /* no DNS information */ }
        }

        /// <summary>
        /// Derives the prefixes from the own addresses - and reads the actually
        /// interesting information along the way: <see cref="PrefixOrigin"/>
        /// tells <em>where</em> the prefix comes from.
        /// <para>
        /// <see cref="PrefixOrigin.RouterAdvertisement"/> means: exactly this
        /// prefix was announced by a router. <see cref="PrefixOrigin.Dhcp"/>
        /// means: the address came from a DHCPv6 server. This settles how
        /// addresses are assigned without reading a single bit from a packet.
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
                    // On Linux, .NET does not always provide this information.
                    // There the raw socket is the better path anyway.
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

                    // The machine has formed an address of its own here -
                    // exactly the meaning of the A flag.
                    Autonomous = origin == PrefixOrigin.RouterAdvertisement,
                    OnLink = true,
                    ValidLifetimeSeconds = 0
                });
            }
        }

        /// <summary>
        /// <c>fec0:0:0:ffff::1</c> to <c>::3</c> are not name servers but the
        /// placeholders Windows lists on every adapter as long as none is
        /// configured.
        /// <para>
        /// Observed on a machine without IPv6 on the network: four of six
        /// adapters reported these three addresses. Taking them unchecked would
        /// claim three name servers on a network without any IPv6 - and the
        /// finding "too many DNS servers per adapter" would trigger on every
        /// second adapter. The range <c>fec0::/10</c> is deprecated by RFC 3879
        /// anyway and no longer occurs as a real server.
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
        /// Appends the adapter zone where it is missing. A gateway is regularly
        /// link-local, and without a zone it cannot be addressed.
        /// </summary>
        private static IPAddress WithZone(IPAddress address, int interfaceIndex) =>
            address.IsIPv6LinkLocal && address.ScopeId == 0 && interfaceIndex > 0
                ? new IPAddress(address.GetAddressBytes(), interfaceIndex)
                : address;
    }
}
