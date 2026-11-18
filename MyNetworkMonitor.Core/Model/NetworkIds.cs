// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net;
using System.Net.Sockets;

namespace MyNetworkMonitor.Core.Model
{
    /// <summary>
    /// The network an address was seen in, as a stable text key.
    /// <para>
    /// A MAC address identifies a device only within its own network: ARP and the IPv6 neighbor table
    /// see the segment they are asked in, and the same MAC in two networks is a router with one MAC on
    /// several VLANs, a device that moved, or a fault such as a cloned virtual machine. Telling these
    /// apart needs to know which network an address belongs to; the free-text range name cannot do it,
    /// several ranges may carry the same name.
    /// </para>
    /// <para>
    /// The key is the identifier of the configured range (<see cref="ScanScope.Id"/>). For the range of
    /// the own network interface it also carries the subnet actually found at scan time, for example
    /// <c>…@192.0.2.0/24</c>: the same "Local network" range on a notebook covers the home network one day
    /// and the company network the next. A target list has no key - it may mix addresses of several
    /// networks.
    /// </para>
    /// </summary>
    public static class NetworkIds
    {
        /// <summary>The key of a configured range, without subnet.</summary>
        /// <param name="scope">The range.</param>
        /// <returns>The key.</returns>
        public static string ForScope(ScanScope scope)
        {
            ArgumentNullException.ThrowIfNull(scope);
            return scope.Id.ToString("N");
        }

        /// <summary>
        /// The key of an address scanned through a range.
        /// </summary>
        /// <param name="scope">The range the address was scanned through.</param>
        /// <param name="address">The address; for the own network interface it selects the subnet.</param>
        /// <param name="interfaceAddresses">IPv4 addresses and masks of the network interface of the range; only used for <see cref="ScanScopeKind.NetworkInterface"/>.</param>
        /// <returns>The key, or null for a target list.</returns>
        public static string? For(ScanScope scope, IPAddress? address,
                                  IEnumerable<(IPAddress Address, IPAddress Mask)>? interfaceAddresses)
        {
            ArgumentNullException.ThrowIfNull(scope);

            switch (scope.Kind)
            {
                case ScanScopeKind.TargetList:
                    return null;

                case ScanScopeKind.NetworkInterface:
                    string? subnet = SubnetOf(address, interfaceAddresses ?? []);
                    return subnet is null ? ForScope(scope) : $"{ForScope(scope)}@{subnet}";

                default:
                    return ForScope(scope);
            }
        }

        /// <summary>
        /// The IPv4 subnet in CIDR notation among the interface addresses: the one containing
        /// <paramref name="address"/>, or the first one if the address is not IPv4 (an IPv6 address on
        /// the same interface shares its segment).
        /// </summary>
        /// <param name="address">The address to place; null or IPv6 selects the first subnet.</param>
        /// <param name="interfaceAddresses">IPv4 addresses with their masks.</param>
        /// <returns>For example <c>192.0.2.0/24</c>; null if there is no usable IPv4 address.</returns>
        public static string? SubnetOf(IPAddress? address, IEnumerable<(IPAddress Address, IPAddress Mask)> interfaceAddresses)
        {
            ArgumentNullException.ThrowIfNull(interfaceAddresses);

            uint? value = address is { AddressFamily: AddressFamily.InterNetwork } ? ToUInt(address) : null;
            string? first = null;

            foreach ((IPAddress own, IPAddress mask) in interfaceAddresses)
            {
                if (own.AddressFamily != AddressFamily.InterNetwork || mask.AddressFamily != AddressFamily.InterNetwork) continue;

                uint m = ToUInt(mask);
                if (m == 0) continue;

                uint network = ToUInt(own) & m;
                int prefix = System.Numerics.BitOperations.PopCount(m);
                string cidr = $"{FromUInt(network)}/{prefix}";

                if (value is null) return cidr;
                if ((value.Value & m) == network) return cidr;

                first ??= cidr;
            }

            return value is null ? first : null;
        }

        /// <summary>
        /// Gives addresses without a key the key of the configured range that contains them - for
        /// inventories saved before addresses carried their network, and for the first start after an
        /// update. Only IPv4 ranges (from-to) are used; the range of the own network interface depends
        /// on the subnet at scan time and is filled by the next scan. An IPv6 address takes the key of
        /// the device's IPv4 addresses if they all lie in one network.
        /// </summary>
        /// <param name="devices">The devices to complete.</param>
        /// <param name="scopes">The configured ranges.</param>
        /// <returns>The number of addresses given a key.</returns>
        public static int FillMissing(IEnumerable<Device> devices, IEnumerable<ScanScope> scopes)
        {
            ArgumentNullException.ThrowIfNull(devices);
            ArgumentNullException.ThrowIfNull(scopes);

            List<(uint First, uint Last, string Key)> ranges = [];
            foreach (ScanScope scope in scopes)
            {
                if (scope.Kind != ScanScopeKind.IPv4Range) continue;
                if (!TryParseV4(scope.FirstIP, out uint first) || !TryParseV4(scope.LastIP, out uint last) || first > last) continue;
                ranges.Add((first, last, ForScope(scope)));
            }

            int filled = 0;

            foreach (Device device in devices)
            {
                foreach (DeviceAddress address in device.Ipv4Addresses)
                {
                    if (address.NetworkId is not null) continue;

                    uint value = ToUInt(address.Info.Address);
                    foreach ((uint first, uint last, string key) in ranges)
                    {
                        if (value < first || value > last) continue;
                        address.NetworkId = key;
                        filled++;
                        break;
                    }
                }

                List<string> networks = [.. device.Ipv4Addresses.Select(a => a.NetworkId).OfType<string>().Distinct()];
                if (networks.Count != 1) continue;

                foreach (DeviceAddress address in device.Ipv6Addresses.Where(a => a.NetworkId is null))
                {
                    address.NetworkId = networks[0];
                    filled++;
                }
            }

            return filled;
        }

        /// <summary>
        /// Places the devices of a satellite result in the networks of this main scanner.
        /// <para>
        /// The satellite reports addresses with the keys of its own job - ranges this main scanner
        /// does not know. Taken over unchanged, a device seen here and by the satellite would end up
        /// twice, because the same MAC would seem to come from two networks. Every IPv4 address
        /// therefore takes the key of the configured range containing it, and the device the name of
        /// that range: the job carries only the name of its first range. An address outside every
        /// range stays apart under a key of the satellite; an IPv6 address follows the IPv4 addresses
        /// of its device if they lie in one network.
        /// </para>
        /// </summary>
        /// <param name="devices">The devices of the satellite result.</param>
        /// <param name="scopes">The configured ranges; those assigned to the satellite should come first.</param>
        /// <param name="satelliteKey">A stable key of the satellite, for addresses outside every range.</param>
        public static void AdoptSatelliteResult(IEnumerable<Device> devices, IEnumerable<ScanScope> scopes, string satelliteKey)
        {
            ArgumentNullException.ThrowIfNull(devices);
            ArgumentNullException.ThrowIfNull(scopes);

            List<(uint First, uint Last, ScanScope Scope)> ranges = [];
            foreach (ScanScope scope in scopes)
            {
                if (scope.Kind != ScanScopeKind.IPv4Range) continue;
                if (!TryParseV4(scope.FirstIP, out uint first) || !TryParseV4(scope.LastIP, out uint last) || first > last) continue;
                ranges.Add((first, last, scope));
            }

            string Outside(DeviceAddress address) => $"{satelliteKey}:{address.NetworkId ?? "unknown"}";

            foreach (Device device in devices)
            {
                ScanScope? groupOf = null;

                foreach (DeviceAddress address in device.Ipv4Addresses)
                {
                    uint value = ToUInt(address.Info.Address);
                    ScanScope? range = ranges.FirstOrDefault(r => value >= r.First && value <= r.Last).Scope;

                    address.NetworkId = range is null ? Outside(address) : ForScope(range);
                    groupOf ??= range;
                }

                if (groupOf is not null) device.GroupDescription = groupOf.GroupDescription;

                List<string> networks = [.. device.Ipv4Addresses.Select(a => a.NetworkId).OfType<string>().Distinct()];
                foreach (DeviceAddress address in device.Ipv6Addresses)
                {
                    address.NetworkId = networks.Count == 1 ? networks[0] : Outside(address);
                }
            }
        }

        private static bool TryParseV4(string? text, out uint value)
        {
            value = 0;
            if (!IPAddress.TryParse(text?.Trim(), out IPAddress? address) || address.AddressFamily != AddressFamily.InterNetwork)
                return false;

            value = ToUInt(address);
            return true;
        }

        private static uint ToUInt(IPAddress address)
        {
            byte[] b = address.GetAddressBytes();
            return (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
        }

        private static string FromUInt(uint value) =>
            $"{value >> 24}.{(value >> 16) & 0xFF}.{(value >> 8) & 0xFF}.{value & 0xFF}";
    }
}
