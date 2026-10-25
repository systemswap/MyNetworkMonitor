using System.Net;
using System.Net.NetworkInformation;

namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// A network adapter of this machine as shown in the network view.
    /// </summary>
    public sealed class AdapterInfo
    {
        /// <summary>The adapter name as the operating system reports it.</summary>
        public required string Name { get; init; }
        /// <summary>The adapter description (usually the driver or device name).</summary>
        public required string Description { get; init; }
        /// <summary>The adapter type.</summary>
        public required NetworkInterfaceType Type { get; init; }
        /// <summary>Whether the adapter is operational.</summary>
        public required bool IsUp { get; init; }

        /// <summary>The MAC address, lower case and colon-separated; empty if none.</summary>
        public string MacText { get; init; } = string.Empty;

        /// <summary>The IPv4 addresses of the adapter.</summary>
        public IReadOnlyList<string> Ipv4Addresses { get; init; } = [];
        /// <summary>The IPv6 addresses of the adapter.</summary>
        public IReadOnlyList<string> Ipv6Addresses { get; init; } = [];
        /// <summary>The default gateways of the adapter.</summary>
        public IReadOnlyList<string> Gateways { get; init; } = [];

        /// <summary>
        /// The name servers of this adapter, in the order in which they are
        /// queried.
        /// </summary>
        public IReadOnlyList<string> DnsServers { get; init; } = [];

        /// <summary>The address comes from a DHCP server, not from the configuration.</summary>
        public bool DhcpEnabled { get; init; }

        /// <summary>The DNS suffix of the adapter; empty if none.</summary>
        public string DnsSuffix { get; init; } = string.Empty;

        /// <summary>
        /// Conspicuously many name servers. Two to three are common, four still
        /// explainable - anything above that the adapter has collected somewhere,
        /// usually through repeated DHCP leases, and every failing server costs
        /// waiting time.
        /// </summary>
        public bool HasTooManyDnsServers => DnsServers.Count > MaxPlausibleDnsServers;

        /// <summary>The highest number of name servers that does not yet count as a finding.</summary>
        public const int MaxPlausibleDnsServers = 4;

        /// <summary>The IPv4 addresses as one comma-separated line.</summary>
        public string Ipv4Text => string.Join(", ", Ipv4Addresses);
        /// <summary>The IPv6 addresses as one comma-separated line.</summary>
        public string Ipv6Text => string.Join(", ", Ipv6Addresses);
        /// <summary>The gateways as one comma-separated line.</summary>
        public string GatewayText => string.Join(", ", Gateways);
        /// <summary>The name servers as one comma-separated line.</summary>
        public string DnsText => string.Join(", ", DnsServers);

        /// <summary>Number of name servers.</summary>
        public int DnsServerCount => DnsServers.Count;

        /// <summary>Where the configuration comes from - for the adjacent column.</summary>
        public string ConfigurationText => DhcpEnabled ? "DHCP" : "static";

        public override string ToString() => $"{Name} [{DnsServers.Count} DNS]";
    }

    /// <summary>
    /// Reads the adapters of this machine with their name servers.
    /// <para>
    /// The name servers are deliberately kept per adapter and not as one list:
    /// only this way does it become visible when a single adapter has collected,
    /// for example, twenty-five servers via DHCP. A merged list would hide that.
    /// </para>
    /// </summary>
    public static class NetworkAdapters
    {
        /// <summary>
        /// All adapters that carry an address. Loopback and tunnel adapters are
        /// excluded - they appear in every enumeration and say nothing.
        /// </summary>
        /// <param name="includeDown">Also include adapters that are not operational.</param>
        /// <returns>The adapters in the order of the operating system.</returns>
        public static List<AdapterInfo> Read(bool includeDown = false)
        {
            List<AdapterInfo> adapters = [];

            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;

                bool isUp = nic.OperationalStatus == OperationalStatus.Up;
                if (!isUp && !includeDown) continue;

                IPInterfaceProperties properties;

                try
                {
                    properties = nic.GetIPProperties();
                }
                catch (NetworkInformationException)
                {
                    // An adapter can disappear between enumeration and
                    // query - VPN clients do that constantly.
                    continue;
                }

                // Windows lists every bound filter driver as an adapter of its
                // own - "...-QoS Packet Scheduler-0000" and half a dozen more
                // per real card. They never carry an address, which is how
                // they are recognized: without an address, an adapter is of no
                // use for this view.
                List<string> v4 = [.. Unicast(properties, System.Net.Sockets.AddressFamily.InterNetwork)];
                List<string> v6 = [.. Unicast(properties, System.Net.Sockets.AddressFamily.InterNetworkV6)];

                if (v4.Count == 0 && v6.Count == 0) continue;

                adapters.Add(new AdapterInfo
                {
                    Name = nic.Name,
                    Description = nic.Description,
                    Type = nic.NetworkInterfaceType,
                    IsUp = isUp,
                    MacText = FormatMac(nic),
                    Ipv4Addresses = v4,
                    Ipv6Addresses = v6,
                    Gateways = [.. properties.GatewayAddresses
                        .Where(g => g.Address is not null && !IsUnspecified(g.Address))
                        .Select(g => g.Address.ToString())],
                    DnsServers = [.. properties.DnsAddresses.Select(d => d.ToString())],
                    DhcpEnabled = IsDhcp(properties),
                    DnsSuffix = properties.DnsSuffix ?? string.Empty
                });
            }

            return adapters;
        }

        private static IEnumerable<string> Unicast(IPInterfaceProperties properties, System.Net.Sockets.AddressFamily family) =>
            properties.UnicastAddresses
                .Where(u => u.Address.AddressFamily == family)
                .Select(u => u.Address.ToString());

        /// <summary>
        /// Whether the adapter obtains its address via DHCP. On Linux the query
        /// throws instead of declining to answer - there it cannot be determined
        /// this way.
        /// </summary>
        private static bool IsDhcp(IPInterfaceProperties properties)
        {
            try
            {
                return properties.GetIPv4Properties()?.IsDhcpEnabled ?? false;
            }
            catch (PlatformNotSupportedException)
            {
                return false;
            }
            catch (NetworkInformationException)
            {
                return false;
            }
        }

        private static bool IsUnspecified(IPAddress address) =>
            address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);

        private static string FormatMac(NetworkInterface nic)
        {
            byte[] bytes = nic.GetPhysicalAddress().GetAddressBytes();

            return bytes.Length == 0 ? string.Empty : string.Join(":", bytes.Select(b => b.ToString("x2")));
        }
    }
}
