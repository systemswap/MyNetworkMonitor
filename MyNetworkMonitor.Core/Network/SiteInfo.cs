// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// An address of this machine together with the network it belongs to.
    /// </summary>
    public sealed class SiteAddress
    {
        /// <summary>The address as text.</summary>
        public required string Address { get; init; }

        /// <summary>Prefix length, for example 24 for a mask of 255.255.255.0.</summary>
        public required int PrefixLength { get; init; }

        /// <summary>
        /// Whether the adapter of this address has a default gateway.
        /// <para>
        /// This distinguishes the card on the real network from the virtual
        /// adapters created by Hyper-V, WSL, Docker and VPN clients. These also
        /// carry an address and are also "up", but are useless as a location.
        /// </para>
        /// </summary>
        public required bool HasGateway { get; init; }

        /// <summary>Whether the address is IPv4 (otherwise IPv6).</summary>
        public required bool IsIpv4 { get; init; }

        /// <summary>The adapter name - for display when several are candidates.</summary>
        public string AdapterName { get; init; } = string.Empty;

        /// <summary>
        /// The network in CIDR notation, for example <c>192.0.2.0/24</c>. Exactly
        /// what the main scanner needs to see which satellite is responsible
        /// for a range.
        /// </summary>
        public string Network => SiteInfo.ToCidr(Address, PrefixLength);

        public override string ToString() => $"{Address}/{PrefixLength}";
    }

    /// <summary>
    /// Who this machine is and which networks it belongs to.
    /// <para>
    /// The satellite sends this with every registration. Without this
    /// information, the main scanner cannot tell which segment a satellite
    /// actually sits in - it would only show a name, leaving it to guess
    /// whether the satellite is the right one for a range.
    /// </para>
    /// </summary>
    public sealed class SiteInfo
    {
        /// <summary>The machine name.</summary>
        public string HostName { get; init; } = string.Empty;

        /// <summary>The domain of this machine. Empty if it belongs to none.</summary>
        public string Domain { get; init; } = string.Empty;

        /// <summary>The usable addresses, adapters with gateway first, IPv4 before IPv6.</summary>
        public IReadOnlyList<SiteAddress> Addresses { get; init; } = [];

        /// <summary>The IPv4 addresses.</summary>
        public IEnumerable<SiteAddress> Ipv4 => Addresses.Where(a => a.IsIpv4);
        /// <summary>The IPv6 addresses.</summary>
        public IEnumerable<SiteAddress> Ipv6 => Addresses.Where(a => !a.IsIpv4);

        /// <summary>The IPv4 addresses as one comma-separated line; "-" if none.</summary>
        public string Ipv4Text => Join(Ipv4.Select(a => a.Address));
        /// <summary>The IPv6 addresses as one comma-separated line; "-" if none.</summary>
        public string Ipv6Text => Join(Ipv6.Select(a => a.Address));

        /// <summary>
        /// The network that best describes this machine: the first IPv4 network
        /// of an adapter with a gateway. Exactly this one appears in the
        /// selection after the satellite's name.
        /// </summary>
        public string PrimaryNetwork =>
            Ipv4.FirstOrDefault(a => a.HasGateway)?.Network
            ?? Ipv4.FirstOrDefault()?.Network
            ?? string.Empty;

        /// <summary>All networks, without duplicates - for tooltip and form.</summary>
        public IReadOnlyList<string> Networks =>
            [.. Addresses.Select(a => a.Network)
                        .Where(n => n.Length > 0)
                        .Distinct(StringComparer.OrdinalIgnoreCase)];

        /// <summary>All networks as one comma-separated line; "-" if none.</summary>
        public string NetworksText => Join(Networks);

        private static string Join(IEnumerable<string> values)
        {
            string text = string.Join(", ", values);
            return text.Length == 0 ? "-" : text;
        }

        /// <summary>
        /// Reads name, domain and addresses of this machine.
        /// <para>
        /// Loopback and link-local addresses are excluded: they are never
        /// reachable from another segment, and as a location they would simply
        /// be wrong.
        /// </para>
        /// </summary>
        /// <returns>The site information; empty lists if the adapters cannot be read.</returns>
        public static SiteInfo Read()
        {
            string domain;
            try
            {
                domain = IPGlobalProperties.GetIPGlobalProperties().DomainName ?? string.Empty;
            }
            catch (Exception)
            {
                domain = string.Empty;
            }

            List<SiteAddress> addresses = [];

            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;

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

                    bool hasGateway = properties.GatewayAddresses
                        .Any(g => g.Address is not null && !IsUnspecified(g.Address));

                    foreach (UnicastIPAddressInformation unicast in properties.UnicastAddresses)
                    {
                        IPAddress ip = unicast.Address;
                        if (!IsUsable(ip)) continue;

                        int prefix = PrefixOf(unicast, ip);

                        addresses.Add(new SiteAddress
                        {
                            Address = ip.ToString(),
                            PrefixLength = prefix,
                            HasGateway = hasGateway,
                            IsIpv4 = ip.AddressFamily == AddressFamily.InterNetwork,
                            AdapterName = nic.Name
                        });
                    }
                }
            }
            catch (Exception)
            {
                // Without an adapter list the overview stays empty - it is
                // informational and must not cause anything to fail.
            }

            // Adapters with gateway first, IPv4 before IPv6: what comes first
            // is what ends up in the selection on the main scanner.
            return new SiteInfo
            {
                HostName = Environment.MachineName,
                Domain = domain,
                Addresses = [.. addresses
                    .OrderByDescending(a => a.HasGateway)
                    .ThenByDescending(a => a.IsIpv4)
                    .ThenBy(a => a.Address, StringComparer.OrdinalIgnoreCase)]
            };
        }

        /// <summary>
        /// Whether an address is suitable as a location. Not loopback and not
        /// link-local - nobody from another segment arrives there.
        /// </summary>
        private static bool IsUsable(IPAddress ip)
        {
            if (IPAddress.IsLoopback(ip)) return false;

            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                return !ip.IsIPv6LinkLocal && !ip.IsIPv6Multicast;
            }

            byte[] b = ip.GetAddressBytes();
            return !(b[0] == 169 && b[1] == 254);
        }

        /// <summary>
        /// The prefix length. On Linux the query throws for some adapters
        /// instead of declining to answer - then the usual values are used as
        /// fallback so that at least something is shown.
        /// </summary>
        private static int PrefixOf(UnicastIPAddressInformation unicast, IPAddress ip)
        {
            try
            {
                int p = unicast.PrefixLength;
                if (p > 0) return p;
            }
            catch (Exception) { }

            return ip.AddressFamily == AddressFamily.InterNetwork ? 24 : 64;
        }

        private static bool IsUnspecified(IPAddress address) =>
            address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);

        /// <summary>
        /// Converts address and prefix length into network notation, that is
        /// <c>192.0.2.22</c> with 24 to <c>192.0.2.0/24</c>.
        /// </summary>
        /// <param name="address">The address as text.</param>
        /// <param name="prefixLength">The prefix length in bits.</param>
        /// <returns>The network in CIDR notation, or empty if the input is invalid.</returns>
        public static string ToCidr(string address, int prefixLength)
        {
            if (!IPAddress.TryParse(address, out IPAddress? ip)) return string.Empty;

            byte[] bytes = ip.GetAddressBytes();
            int bits = bytes.Length * 8;

            if (prefixLength < 0 || prefixLength > bits) return string.Empty;

            // Clear everything after the prefix: what remains is the network address.
            for (int i = 0; i < bytes.Length; i++)
            {
                int keep = prefixLength - (i * 8);

                if (keep >= 8) continue;
                if (keep <= 0) { bytes[i] = 0; continue; }

                bytes[i] &= (byte)(0xFF << (8 - keep));
            }

            return $"{new IPAddress(bytes)}/{prefixLength}";
        }
    }
}
