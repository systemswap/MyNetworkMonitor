using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// Evaluates an IP address based on its bits alone. No network access, no
    /// side effects - therefore usable anywhere, including during a scan.
    /// <para>
    /// The analyzer deliberately states only what follows from the address.
    /// Whether a random-looking address is a privacy extension (RFC 8981, which
    /// obsoletes RFC 4941) or a stable opaque identifier (RFC 7217) cannot be
    /// decided this way - both yield <see cref="InterfaceIdKind.Random"/>. Only
    /// observation over time or information from the operating system can make
    /// that distinction.
    /// </para>
    /// </summary>
    public static class IpAddressAnalyzer
    {
        /// <summary>
        /// Splits an address into its components. Does not throw - an address
        /// that cannot be interpreted yields a record with <see cref="IpAddressScope.Unknown"/>.
        /// </summary>
        /// <param name="address">The address to analyze.</param>
        /// <returns>The analysis result.</returns>
        public static IpAddressInfo Analyze(IPAddress address)
        {
            ArgumentNullException.ThrowIfNull(address);

            return address.AddressFamily == AddressFamily.InterNetworkV6
                ? AnalyzeV6(address)
                : AnalyzeV4(address);
        }

        /// <summary>
        /// Like <see cref="Analyze(IPAddress)"/>, but takes text - including a
        /// zone ("fe80::1%12"). Returns <c>false</c> if the text cannot be read
        /// as an address.
        /// </summary>
        /// <param name="text">The address as text.</param>
        /// <param name="info">The analysis result, or null if the text is not an address.</param>
        /// <returns><c>true</c> if the text is a valid address.</returns>
        public static bool TryAnalyze(string? text, out IpAddressInfo? info)
        {
            info = null;
            if (string.IsNullOrWhiteSpace(text)) return false;
            if (!IPAddress.TryParse(text.Trim(), out IPAddress? parsed)) return false;

            info = Analyze(parsed);
            return true;
        }

        // ---------------------------------------------------------------- IPv4

        private static IpAddressInfo AnalyzeV4(IPAddress address)
        {
            byte[] b = address.GetAddressBytes();

            IpAddressScope scope =
                b[0] == 127 ? IpAddressScope.Loopback :
                b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 ? IpAddressScope.Unspecified :
                b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255 ? IpAddressScope.Broadcast :
                b[0] == 169 && b[1] == 254 ? IpAddressScope.LinkLocal :
                b[0] >= 224 && b[0] <= 239 ? IpAddressScope.Multicast :
                IsPrivateV4(b) ? IpAddressScope.UniqueLocal :
                IpAddressScope.Global;

            return new IpAddressInfo
            {
                Address = address,
                Family = IpFamily.IPv4,
                Scope = scope,
                InterfaceIdKind = InterfaceIdKind.NotApplicable,
                Canonical = address.ToString(),
                SortKey = BuildV4SortKey(b)
            };
        }

        /// <summary>RFC 1918 and the carrier-grade NAT range from RFC 6598.</summary>
        private static bool IsPrivateV4(byte[] b) =>
            b[0] == 10 ||
            (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
            (b[0] == 192 && b[1] == 168) ||
            (b[0] == 100 && b[1] >= 64 && b[1] <= 127);

        /// <summary>
        /// IPv4 is sorted as IPv4-mapped (::ffff:a.b.c.d) so that a mixed list
        /// sorts sensibly in one column.
        /// </summary>
        private static byte[] BuildV4SortKey(byte[] v4)
        {
            byte[] key = new byte[16];
            key[10] = 0xFF;
            key[11] = 0xFF;
            Array.Copy(v4, 0, key, 12, 4);
            return key;
        }

        // ---------------------------------------------------------------- IPv6

        private static IpAddressInfo AnalyzeV6(IPAddress address)
        {
            byte[] b = address.GetAddressBytes();

            IpAddressSpecial special = DetectSpecial(address, b);
            IpAddressScope scope = DetectV6Scope(address, b, special);
            IPAddress? embedded = ExtractEmbeddedV4(b, special);

            InterfaceIdKind iidKind = scope == IpAddressScope.Multicast
                ? InterfaceIdKind.NotApplicable
                : DetectInterfaceIdKind(b, special);

            PhysicalAddress? mac = iidKind == InterfaceIdKind.Eui64 ? ExtractMac(b) : null;

            long? zone = address.ScopeId != 0 ? address.ScopeId : null;

            return new IpAddressInfo
            {
                Address = address,
                Family = IpFamily.IPv6,
                Scope = scope,
                Special = special,
                InterfaceIdKind = iidKind,
                ZoneId = zone,
                DerivedMac = mac,
                EmbeddedIPv4 = embedded,
                // .NET already produces the short form per RFC 5952 for IPv6
                // (lower case, longest run of zeros compressed to ::) and
                // appends an existing zone with %.
                Canonical = address.ToString(),
                SortKey = b
            };
        }

        private static IpAddressScope DetectV6Scope(IPAddress address, byte[] b, IpAddressSpecial special)
        {
            if (IPAddress.IPv6Loopback.Equals(address)) return IpAddressScope.Loopback;
            if (IPAddress.IPv6Any.Equals(address)) return IpAddressScope.Unspecified;

            if (b[0] == 0xFF) return IpAddressScope.Multicast;

            // fe80::/10 (RFC 4291, section 2.5.6)
            if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return IpAddressScope.LinkLocal;

            // fc00::/7 - unique local (RFC 4193)
            if ((b[0] & 0xFE) == 0xFC) return IpAddressScope.UniqueLocal;

            // Documentation and benchmarking ranges are formally global but
            // not routed. Reporting them as global would be misleading.
            if (special is IpAddressSpecial.Documentation or IpAddressSpecial.Benchmarking)
                return IpAddressScope.Unknown;

            // 2000::/3 - the only global unicast range allocated by IANA
            if ((b[0] & 0xE0) == 0x20) return IpAddressScope.Global;

            return IpAddressScope.Unknown;
        }

        private static IpAddressSpecial DetectSpecial(IPAddress address, byte[] b)
        {
            if (address.IsIPv4MappedToIPv6) return IpAddressSpecial.IPv4Mapped;

            // ff02::1:ffXX:XXXX - solicited-node multicast (RFC 4291, section 2.7.1)
            if (b[0] == 0xFF && b[1] == 0x02 &&
                b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 &&
                b[8] == 0 && b[9] == 0 && b[10] == 0 && b[11] == 0x01 && b[12] == 0xFF)
            {
                return IpAddressSpecial.SolicitedNodeMulticast;
            }

            // 64:ff9b::/96 - NAT64 well-known prefix (RFC 6052)
            if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B &&
                b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 &&
                b[8] == 0 && b[9] == 0 && b[10] == 0 && b[11] == 0)
            {
                return IpAddressSpecial.Nat64WellKnown;
            }

            if (b[0] == 0x20 && b[1] == 0x01)
            {
                // 2001:0000::/32 - Teredo (RFC 4380)
                if (b[2] == 0x00 && b[3] == 0x00) return IpAddressSpecial.Teredo;

                // 2001:db8::/32 - documentation (RFC 3849)
                if (b[2] == 0x0D && b[3] == 0xB8) return IpAddressSpecial.Documentation;

                // 2001:2::/48 - benchmarking (RFC 5180)
                if (b[2] == 0x00 && b[3] == 0x02 && b[4] == 0x00 && b[5] == 0x00)
                    return IpAddressSpecial.Benchmarking;
            }

            // 2002::/16 - 6to4 (RFC 3056)
            if (b[0] == 0x20 && b[1] == 0x02) return IpAddressSpecial.SixToFour;

            // fc00::/8 - intended for central assignment, never allocated (RFC 4193)
            if (b[0] == 0xFC) return IpAddressSpecial.UnassignedUniqueLocal;

            // Interface identifier 0000:5efe or 0200:5efe - ISATAP (RFC 5214)
            if ((b[8] == 0x00 || b[8] == 0x02) && b[9] == 0x00 && b[10] == 0x5E && b[11] == 0xFE)
                return IpAddressSpecial.Isatap;

            // ::a.b.c.d - IPv4-compatible, deprecated (RFC 4291, section 2.5.5.1).
            // The unspecified address and loopback must not fall into this.
            bool upperAllZero = true;
            for (int i = 0; i < 12; i++)
            {
                if (b[i] != 0) { upperAllZero = false; break; }
            }
            if (upperAllZero && !(b[12] == 0 && b[13] == 0 && b[14] == 0 && (b[15] == 0 || b[15] == 1)))
                return IpAddressSpecial.IPv4Compatible;

            return IpAddressSpecial.None;
        }

        private static IPAddress? ExtractEmbeddedV4(byte[] b, IpAddressSpecial special)
        {
            switch (special)
            {
                case IpAddressSpecial.IPv4Mapped:
                case IpAddressSpecial.IPv4Compatible:
                case IpAddressSpecial.Nat64WellKnown:
                    return new IPAddress(b[12..16]);

                case IpAddressSpecial.SixToFour:
                    // 2002:AABB:CCDD::/48 - the IPv4 address follows the prefix directly.
                    return new IPAddress(b[2..6]);

                case IpAddressSpecial.Isatap:
                    return new IPAddress(b[12..16]);

                case IpAddressSpecial.Teredo:
                    // The client address is stored bitwise inverted (RFC 4380, section 4).
                    byte[] client = new byte[4];
                    for (int i = 0; i < 4; i++) client[i] = (byte)(b[12 + i] ^ 0xFF);
                    return new IPAddress(client);

                default:
                    return null;
            }
        }

        private static InterfaceIdKind DetectInterfaceIdKind(byte[] b, IpAddressSpecial special)
        {
            if (special is IpAddressSpecial.Isatap
                        or IpAddressSpecial.Teredo
                        or IpAddressSpecial.SixToFour
                        or IpAddressSpecial.IPv4Mapped
                        or IpAddressSpecial.IPv4Compatible
                        or IpAddressSpecial.Nat64WellKnown)
            {
                return InterfaceIdKind.Embedded;
            }

            // EUI-64: ff:fe in the middle of the interface identifier (RFC 4291, appendix A)
            if (b[11] == 0xFF && b[12] == 0xFE) return InterfaceIdKind.Eui64;

            // The upper 6 bytes of the identifier are zero, so at most
            // ::ffff remains.
            bool iidNearlyZero = true;
            for (int i = 8; i < 14; i++)
            {
                if (b[i] != 0) { iidNearlyZero = false; break; }
            }

            if (iidNearlyZero)
            {
                // Entirely zero: that is the subnet-router anycast address
                // (RFC 4291, section 2.6.1) or a bare prefix, not a device.
                if (b[14] == 0 && b[15] == 0) return InterfaceIdKind.Unknown;

                // Very small value such as ::1 or ::20. Such addresses are
                // assigned manually - typical for servers and infrastructure.
                return InterfaceIdKind.LowByte;
            }

            // Everything else looks random. Whether privacy extension or
            // stable opaque identifier cannot be decided here.
            return InterfaceIdKind.Random;
        }

        /// <summary>
        /// Converts an EUI-64 interface identifier back to the MAC address: the
        /// inserted bytes ff:fe are dropped and the u/l bit is flipped back.
        /// </summary>
        private static PhysicalAddress ExtractMac(byte[] b)
        {
            byte[] mac =
            [
                (byte)(b[8] ^ 0x02),
                b[9],
                b[10],
                b[13],
                b[14],
                b[15]
            ];
            return new PhysicalAddress(mac);
        }
    }
}
