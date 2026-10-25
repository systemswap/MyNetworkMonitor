// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// An IPv6 prefix with its length, onto which addresses can be placed.
    /// </summary>
    public sealed class Ipv6Prefix
    {
        /// <summary>The network address of the prefix.</summary>
        public required IPAddress Network { get; init; }
        /// <summary>The prefix length in bits.</summary>
        public required int Length { get; init; }

        /// <summary>Where the prefix comes from - displayed with the finding.</summary>
        public required string Origin { get; init; }

        /// <summary>
        /// Adapter zone. Indispensable for link-local, otherwise 0.
        /// </summary>
        public long ScopeId { get; init; }

        /// <summary>
        /// Places an interface identifier onto the prefix. Expects the lower
        /// 8 bytes; shorter values are inserted right-aligned.
        /// </summary>
        /// <param name="interfaceId">The interface identifier bytes.</param>
        /// <returns>The combined address, with the zone set if the prefix has one.</returns>
        public IPAddress Combine(ReadOnlySpan<byte> interfaceId)
        {
            byte[] bytes = Network.GetAddressBytes();

            // Everything from the prefix length on is overwritten - the rest of
            // the prefix remains untouched.
            int firstHostByte = Length / 8;

            for (int i = firstHostByte; i < 16; i++) bytes[i] = 0;

            int offset = 16 - interfaceId.Length;
            for (int i = 0; i < interfaceId.Length; i++)
            {
                int target = offset + i;
                if (target >= firstHostByte) bytes[target] = interfaceId[i];
            }

            return ScopeId != 0 ? new IPAddress(bytes, ScopeId) : new IPAddress(bytes);
        }

        public override string ToString() => $"{Network}/{Length} ({Origin})";
    }

    /// <summary>
    /// Collects the prefixes on which addresses can be guessed.
    /// <para>
    /// Two of the six discovery methods - the sweep of the low bytes and the
    /// derivation from known MAC addresses - cannot work blindly: they need a
    /// prefix onto which they place their interface identifier. Where it comes
    /// from is the same question for both, so it is answered here.
    /// </para>
    /// <para>
    /// <b>Link-local is included, and first.</b> <c>fe80::/64</c> exists on
    /// every segment, even where no router announces a prefix - according to
    /// <see cref="Ipv6Availability.LinkLocalOnly"/> the most common case in
    /// corporate networks. A method that only knows global prefixes would run
    /// there without a single target.
    /// </para>
    /// </summary>
    public static class Ipv6Prefixes
    {
        /// <summary>fe80::/64 - present on every segment.</summary>
        /// <param name="interfaceIndex">The adapter index used as zone.</param>
        public static Ipv6Prefix LinkLocal(int interfaceIndex) => new()
        {
            Network = IPAddress.Parse("fe80::"),
            Length = 64,
            Origin = "link-local",
            ScopeId = interfaceIndex
        };

        /// <summary>
        /// The prefixes of an adapter: always link-local, plus every global and
        /// unique local prefix on which the adapter itself has an address.
        /// <para>
        /// Only /64 and shorter are taken. An address with prefix length 128 is
        /// not a network but a single entry - there is nothing to search there.
        /// </para>
        /// </summary>
        /// <param name="nic">The adapter.</param>
        /// <param name="interfaceIndex">The adapter index used as zone for link-local.</param>
        /// <returns>The prefixes, link-local first.</returns>
        public static List<Ipv6Prefix> ForInterface(NetworkInterface nic, int interfaceIndex)
        {
            ArgumentNullException.ThrowIfNull(nic);

            List<Ipv6Prefix> prefixes = [LinkLocal(interfaceIndex)];
            HashSet<string> seen = [];

            try
            {
                foreach (UnicastIPAddressInformation unicast in nic.GetIPProperties().UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily != AddressFamily.InterNetworkV6) continue;
                    if (unicast.Address.IsIPv6LinkLocal) continue;

                    int length = unicast.PrefixLength;
                    if (length is <= 0 or > 64) continue;

                    IpAddressInfo info = IpAddressAnalyzer.Analyze(unicast.Address);
                    if (info.Scope is not (IpAddressScope.Global or IpAddressScope.UniqueLocal)) continue;

                    IPAddress network = Mask(unicast.Address, length);
                    if (!seen.Add($"{network}/{length}")) continue;

                    prefixes.Add(new Ipv6Prefix
                    {
                        Network = network,
                        Length = length,
                        Origin = info.Scope == IpAddressScope.Global ? "global prefix" : "unique local prefix"
                    });
                }
            }
            catch (NetworkInformationException) { /* adapter disappeared - link-local only */ }
            catch (PlatformNotSupportedException) { /* likewise */ }

            return prefixes;
        }

        /// <summary>Sets all bits after the prefix length to zero.</summary>
        /// <param name="address">The address.</param>
        /// <param name="prefixLength">The prefix length in bits.</param>
        /// <returns>The network address.</returns>
        public static IPAddress Mask(IPAddress address, int prefixLength)
        {
            ArgumentNullException.ThrowIfNull(address);

            byte[] bytes = address.GetAddressBytes();

            for (int bit = prefixLength; bit < 128; bit++)
            {
                bytes[bit / 8] &= (byte)~(1 << (7 - (bit % 8)));
            }

            return new IPAddress(bytes);
        }

        /// <summary>
        /// Forms the modified EUI-64 interface identifier from a MAC address
        /// (RFC 4291, appendix A): ff:fe in the middle, u/l bit flipped. The
        /// inverse of the recovery in <c>IpAddressAnalyzer</c>.
        /// </summary>
        /// <param name="mac">The MAC address.</param>
        /// <returns>The 8-byte identifier, or null for missing, all-zero or broadcast MAC addresses.</returns>
        public static byte[]? Eui64FromMac(PhysicalAddress? mac)
        {
            byte[]? bytes = mac?.GetAddressBytes();
            if (bytes is null || bytes.Length != 6) return null;

            // An all-zero MAC stands for "not resolved", a broadcast MAC for
            // "to everyone". Neither yields a device address.
            if (bytes.All(b => b == 0x00) || bytes.All(b => b == 0xFF)) return null;

            return
            [
                (byte)(bytes[0] ^ 0x02),
                bytes[1],
                bytes[2],
                0xFF,
                0xFE,
                bytes[3],
                bytes[4],
                bytes[5]
            ];
        }
    }
}
