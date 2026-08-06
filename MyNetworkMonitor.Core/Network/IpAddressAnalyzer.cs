using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// Wertet eine IP-Adresse allein anhand ihrer Bits aus. Kein Netzwerkzugriff,
    /// keine Nebenwirkungen - damit ueberall einsetzbar, auch waehrend eines Scans.
    /// <para>
    /// Der Analysator sagt bewusst nur das, was aus der Adresse folgt. Ob eine
    /// zufaellig aussehende Adresse eine Privacy Extension (RFC 4941) oder ein
    /// stabiler opaker Identifier (RFC 7217) ist, laesst sich so nicht
    /// entscheiden - beides ergibt <see cref="InterfaceIdKind.Random"/>. Diese
    /// Unterscheidung kann nur die Beobachtung ueber die Zeit oder die Angabe
    /// des Betriebssystems liefern.
    /// </para>
    /// </summary>
    public static class IpAddressAnalyzer
    {
        /// <summary>
        /// Zerlegt eine Adresse in ihre Bestandteile. Wirft nicht - eine nicht
        /// deutbare Adresse ergibt einen Datensatz mit <see cref="IpAddressScope.Unknown"/>.
        /// </summary>
        public static IpAddressInfo Analyze(IPAddress address)
        {
            ArgumentNullException.ThrowIfNull(address);

            return address.AddressFamily == AddressFamily.InterNetworkV6
                ? AnalyzeV6(address)
                : AnalyzeV4(address);
        }

        /// <summary>
        /// Wie <see cref="Analyze(IPAddress)"/>, nimmt aber Text entgegen -
        /// einschliesslich Zone ("fe80::1%12"). Liefert <c>false</c>, wenn sich
        /// der Text nicht als Adresse lesen laesst.
        /// </summary>
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

        /// <summary>RFC 1918 sowie der Carrier-Grade-NAT-Bereich aus RFC 6598.</summary>
        private static bool IsPrivateV4(byte[] b) =>
            b[0] == 10 ||
            (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
            (b[0] == 192 && b[1] == 168) ||
            (b[0] == 100 && b[1] >= 64 && b[1] <= 127);

        /// <summary>
        /// IPv4 wird als IPv4-mapped (::ffff:a.b.c.d) einsortiert, damit eine
        /// gemischte Liste in einer Spalte sinnvoll sortiert.
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
                // .NET erzeugt fuer IPv6 bereits die Kurzform nach RFC 5952
                // (klein, laengste Nullfolge zu :: zusammengefasst) und haengt
                // eine vorhandene Zone mit % an.
                Canonical = address.ToString(),
                SortKey = b
            };
        }

        private static IpAddressScope DetectV6Scope(IPAddress address, byte[] b, IpAddressSpecial special)
        {
            if (IPAddress.IPv6Loopback.Equals(address)) return IpAddressScope.Loopback;
            if (IPAddress.IPv6Any.Equals(address)) return IpAddressScope.Unspecified;

            if (b[0] == 0xFF) return IpAddressScope.Multicast;

            // fe80::/10
            if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return IpAddressScope.LinkLocal;

            // fc00::/7 - Unique Local
            if ((b[0] & 0xFE) == 0xFC) return IpAddressScope.UniqueLocal;

            // Dokumentations- und Messbereiche sind zwar formal global, aber
            // nicht geroutet. Sie als global auszuweisen waere irrefuehrend.
            if (special is IpAddressSpecial.Documentation or IpAddressSpecial.Benchmarking)
                return IpAddressScope.Unknown;

            // 2000::/3 - der einzige bisher zugeteilte globale Unicast-Bereich
            if ((b[0] & 0xE0) == 0x20) return IpAddressScope.Global;

            return IpAddressScope.Unknown;
        }

        private static IpAddressSpecial DetectSpecial(IPAddress address, byte[] b)
        {
            if (address.IsIPv4MappedToIPv6) return IpAddressSpecial.IPv4Mapped;

            // ff02::1:ffXX:XXXX - Solicited-Node-Multicast
            if (b[0] == 0xFF && b[1] == 0x02 &&
                b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 &&
                b[8] == 0 && b[9] == 0 && b[10] == 0 && b[11] == 0x01 && b[12] == 0xFF)
            {
                return IpAddressSpecial.SolicitedNodeMulticast;
            }

            // 64:ff9b::/96
            if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B &&
                b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 &&
                b[8] == 0 && b[9] == 0 && b[10] == 0 && b[11] == 0)
            {
                return IpAddressSpecial.Nat64WellKnown;
            }

            if (b[0] == 0x20 && b[1] == 0x01)
            {
                // 2001:0000::/32 - Teredo
                if (b[2] == 0x00 && b[3] == 0x00) return IpAddressSpecial.Teredo;

                // 2001:db8::/32 - Dokumentation
                if (b[2] == 0x0D && b[3] == 0xB8) return IpAddressSpecial.Documentation;

                // 2001:2::/48 - Benchmarking
                if (b[2] == 0x00 && b[3] == 0x02 && b[4] == 0x00 && b[5] == 0x00)
                    return IpAddressSpecial.Benchmarking;
            }

            // 2002::/16 - 6to4
            if (b[0] == 0x20 && b[1] == 0x02) return IpAddressSpecial.SixToFour;

            // fc00::/8 - zentral zu vergeben, bislang nie zugeteilt
            if (b[0] == 0xFC) return IpAddressSpecial.UnassignedUniqueLocal;

            // Interface-Identifier 0000:5efe oder 0200:5efe - ISATAP
            if ((b[8] == 0x00 || b[8] == 0x02) && b[9] == 0x00 && b[10] == 0x5E && b[11] == 0xFE)
                return IpAddressSpecial.Isatap;

            // ::a.b.c.d - IPv4-kompatibel, abgekuendigt. Die Nulladresse und
            // Loopback duerfen nicht hineinfallen.
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
                    // 2002:AABB:CCDD::/48 - die IPv4 steht direkt hinter dem Praefix
                    return new IPAddress(b[2..6]);

                case IpAddressSpecial.Isatap:
                    return new IPAddress(b[12..16]);

                case IpAddressSpecial.Teredo:
                    // Die Client-Adresse ist bitweise invertiert abgelegt.
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

            // EUI-64: ff:fe in der Mitte des Interface-Identifiers
            if (b[11] == 0xFF && b[12] == 0xFE) return InterfaceIdKind.Eui64;

            // Die oberen 6 Byte des Identifiers sind null, es bleibt also
            // hoechstens ::ffff.
            bool iidNearlyZero = true;
            for (int i = 8; i < 14; i++)
            {
                if (b[i] != 0) { iidNearlyZero = false; break; }
            }

            if (iidNearlyZero)
            {
                // Vollstaendig null: das ist die Subnetz-Router-Anycast-Adresse
                // bzw. ein blosses Praefix, kein Geraet.
                if (b[14] == 0 && b[15] == 0) return InterfaceIdKind.Unknown;

                // Sehr kleiner Wert wie ::1 oder ::20. Solche Adressen werden
                // von Hand vergeben - typisch fuer Server und Infrastruktur.
                return InterfaceIdKind.LowByte;
            }

            // Alles Uebrige sieht zufaellig aus. Ob Privacy Extension oder
            // stabiler opaker Identifier, ist hier nicht entscheidbar.
            return InterfaceIdKind.Random;
        }

        /// <summary>
        /// Rechnet einen EUI-64-Interface-Identifier auf die MAC zurueck:
        /// die eingeschobenen Bytes ff:fe entfallen, das u/l-Bit wird
        /// zurueckgekippt.
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
