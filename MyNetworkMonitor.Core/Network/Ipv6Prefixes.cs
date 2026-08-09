using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// Ein IPv6-Praefix samt der Laenge, auf das Adressen gesetzt werden
    /// koennen.
    /// </summary>
    public sealed class Ipv6Prefix
    {
        public required IPAddress Network { get; init; }
        public required int Length { get; init; }

        /// <summary>Woher das Praefix stammt - fuer die Anzeige am Fund.</summary>
        public required string Origin { get; init; }

        /// <summary>
        /// Adapterzone. Bei Link-Local unverzichtbar, sonst 0.
        /// </summary>
        public long ScopeId { get; init; }

        /// <summary>
        /// Setzt einen Interface-Identifier auf das Praefix. Erwartet die
        /// unteren 8 Byte; kuerzere Werte werden rechtsbuendig eingesetzt.
        /// </summary>
        public IPAddress Combine(ReadOnlySpan<byte> interfaceId)
        {
            byte[] bytes = Network.GetAddressBytes();

            // Alles ab der Praefixlaenge wird ueberschrieben - der Rest des
            // Praefixes bleibt unangetastet.
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
    /// Sammelt die Praefixe, auf denen sich Adressen erraten lassen.
    /// <para>
    /// Zwei der sechs Suchverfahren - der Durchlauf der niedrigen Bytes und die
    /// Ableitung aus bekannten MAC-Adressen - koennen nicht ins Blaue hinein
    /// arbeiten: sie brauchen ein Praefix, auf das sie ihren Interface-
    /// Identifier setzen. Woher das kommt, ist fuer beide dieselbe Frage,
    /// darum steht sie hier.
    /// </para>
    /// <para>
    /// <b>Link-Local gehoert dazu, und zwar zuerst.</b> <c>fe80::/64</c> gibt
    /// es in jedem Segment, auch dort, wo kein Router ein Praefix ankuendigt -
    /// das ist laut <see cref="Ipv6Availability.LinkLocalOnly"/> der haeufigste
    /// Fall in Firmennetzen. Ein Verfahren, das nur globale Praefixe kennt,
    /// liefe dort ohne ein einziges Ziel.
    /// </para>
    /// </summary>
    public static class Ipv6Prefixes
    {
        /// <summary>fe80::/64 - in jedem Segment vorhanden.</summary>
        public static Ipv6Prefix LinkLocal(int interfaceIndex) => new()
        {
            Network = IPAddress.Parse("fe80::"),
            Length = 64,
            Origin = "link-local",
            ScopeId = interfaceIndex
        };

        /// <summary>
        /// Die Praefixe eines Adapters: link-local immer, dazu jedes globale
        /// und lokal eindeutige Praefix, auf dem der Adapter selbst eine
        /// Adresse hat.
        /// <para>
        /// Nur /64 und kuerzer werden uebernommen. Eine Adresse mit
        /// Praefixlaenge 128 ist kein Netz, sondern ein Einzeleintrag - dort
        /// gibt es nichts zu durchsuchen.
        /// </para>
        /// </summary>
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
            catch (NetworkInformationException) { /* Adapter verschwunden - dann eben nur link-local */ }
            catch (PlatformNotSupportedException) { /* dito */ }

            return prefixes;
        }

        /// <summary>Setzt alle Bits hinter der Praefixlaenge auf null.</summary>
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
        /// Bildet den EUI-64-Interface-Identifier aus einer MAC-Adresse:
        /// ff:fe in die Mitte, das u/l-Bit umkippen. Die Umkehrung von
        /// <c>IpAddressAnalyzer</c>s Rueckrechnung.
        /// </summary>
        public static byte[]? Eui64FromMac(PhysicalAddress? mac)
        {
            byte[]? bytes = mac?.GetAddressBytes();
            if (bytes is null || bytes.Length != 6) return null;

            // Eine MAC aus lauter Nullen steht fuer "nicht aufgeloest", eine
            // Broadcast-MAC fuer "an alle". Beide ergeben keine Geraeteadresse.
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
