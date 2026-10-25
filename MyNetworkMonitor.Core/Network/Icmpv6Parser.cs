// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;

namespace MyNetworkMonitor.Core.Network
{
    /// <summary>A prefix as a router announces it in its advertisement (RFC 4861, section 4.6.2).</summary>
    public sealed class AdvertisedPrefix
    {
        /// <summary>The prefix address.</summary>
        public required IPAddress Prefix { get; init; }
        /// <summary>The prefix length in bits.</summary>
        public required int Length { get; init; }

        /// <summary>Devices may form an address of their own here (A flag).</summary>
        public bool Autonomous { get; init; }

        /// <summary>The prefix applies to this segment (L flag).</summary>
        public bool OnLink { get; init; }

        /// <summary>How long the prefix remains valid, in seconds.</summary>
        public uint ValidLifetimeSeconds { get; init; }

        public override string ToString() => $"{Prefix}/{Length}";
    }

    /// <summary>
    /// A parsed router advertisement (RFC 4861, section 4.2).
    /// <para>
    /// It is the most revealing message on the IPv6 segment: it names the
    /// router, the valid prefixes, the name servers and - via two flags -
    /// whether a DHCPv6 server also operates on the network. All of that
    /// without having asked.
    /// </para>
    /// </summary>
    public sealed class RouterAdvertisement
    {
        /// <summary>The sender address of the advertisement.</summary>
        public required IPAddress Router { get; init; }

        /// <summary>MAC address of the router, if it sends it (option 1).</summary>
        public PhysicalAddress? RouterMac { get; init; }

        /// <summary>
        /// How long this router counts as default gateway. 0 means it is none -
        /// it only announces prefixes.
        /// </summary>
        public int RouterLifetimeSeconds { get; init; }

        /// <summary>M flag: addresses come from a DHCPv6 server.</summary>
        public bool ManagedAddressConfiguration { get; init; }

        /// <summary>O flag: further information (such as DNS) comes from DHCPv6.</summary>
        public bool OtherConfiguration { get; init; }

        /// <summary>The link MTU from the MTU option, if present.</summary>
        public int? Mtu { get; init; }

        /// <summary>The advertised prefixes.</summary>
        public List<AdvertisedPrefix> Prefixes { get; } = [];

        /// <summary>Name servers from the RDNSS option (RFC 8106, section 5.1).</summary>
        public List<IPAddress> DnsServers { get; } = [];

        /// <summary>Search domains from the DNSSL option (RFC 8106, section 5.2).</summary>
        public List<string> SearchDomains { get; } = [];
    }

    /// <summary>
    /// A report on the multicast groups a device has joined.
    /// </summary>
    public sealed class MulticastListenerReport
    {
        /// <summary>The sender address of the report.</summary>
        public required IPAddress Listener { get; init; }

        /// <summary>The groups the device listens to.</summary>
        public List<IPAddress> Groups { get; } = [];
    }

    /// <summary>
    /// Parses the ICMPv6 messages that can be overheard.
    /// <para>
    /// Separate from the scan methods because evaluating bytes is a different
    /// matter from running a scan - and because it can be tested this way
    /// without a network. All methods are lenient: a truncated or nonsensical
    /// packet yields <c>null</c> or an empty list, never an exception. Anything
    /// can appear on the wire.
    /// </para>
    /// </summary>
    public static class Icmpv6Parser
    {
        // --- Option types from RFC 4861 and RFC 8106 -------------------------
        private const byte OptionSourceLinkLayerAddress = 1;
        private const byte OptionPrefixInformation = 3;
        private const byte OptionMtu = 5;
        private const byte OptionRecursiveDnsServer = 25;
        private const byte OptionDnsSearchList = 31;

        /// <summary>
        /// Parses a router advertisement. <paramref name="source"/> is the
        /// sender address from the receive call - it is not part of the ICMPv6
        /// body, and under IPv6 the packet header is not delivered.
        /// </summary>
        /// <param name="packet">The ICMPv6 message, starting with the type byte.</param>
        /// <param name="source">The sender address.</param>
        /// <returns>The advertisement, or <c>null</c> if the packet is not a valid router advertisement.</returns>
        public static RouterAdvertisement? ParseRouterAdvertisement(ReadOnlyMemory<byte> packet, IPAddress source)
        {
            ArgumentNullException.ThrowIfNull(source);

            ReadOnlySpan<byte> message = packet.Span;

            // 16-byte fixed part: type, code, checksum, hop limit, flags,
            // router lifetime, reachable time, retrans timer.
            if (message.Length < 16) return null;
            if (message[0] != Icmpv6Channel.RouterAdvertisement) return null;

            byte flags = message[5];

            RouterAdvertisement advertisement = new()
            {
                Router = source,
                RouterLifetimeSeconds = BinaryPrimitives.ReadUInt16BigEndian(message[6..]),
                ManagedAddressConfiguration = (flags & 0x80) != 0,
                OtherConfiguration = (flags & 0x40) != 0
            };

            PhysicalAddress? mac = null;
            int? mtu = null;

            foreach ((byte type, byte[] bodyArray) in Options(packet[16..]))
            {
                ReadOnlySpan<byte> body = bodyArray;

                switch (type)
                {
                    case OptionSourceLinkLayerAddress when body.Length >= 6:
                        mac = new PhysicalAddress(body[..6].ToArray());
                        break;

                    case OptionPrefixInformation when body.Length >= 30:
                        // Layout: prefix length(1) flags(1) valid lifetime(4)
                        // preferred lifetime(4) reserved(4) prefix(16)
                        advertisement.Prefixes.Add(new AdvertisedPrefix
                        {
                            Length = body[0],
                            OnLink = (body[1] & 0x80) != 0,
                            Autonomous = (body[1] & 0x40) != 0,
                            ValidLifetimeSeconds = BinaryPrimitives.ReadUInt32BigEndian(body[2..]),
                            Prefix = new IPAddress(body[14..30].ToArray())
                        });
                        break;

                    case OptionMtu when body.Length >= 6:
                        mtu = (int)BinaryPrimitives.ReadUInt32BigEndian(body[2..]);
                        break;

                    case OptionRecursiveDnsServer when body.Length >= 6:
                        // Reserved(2) lifetime(4), then one address per 16 bytes.
                        for (int offset = 6; offset + 16 <= body.Length; offset += 16)
                        {
                            advertisement.DnsServers.Add(new IPAddress(body.Slice(offset, 16).ToArray()));
                        }
                        break;

                    case OptionDnsSearchList when body.Length > 6:
                        advertisement.SearchDomains.AddRange(ReadDomainNames(body[6..]));
                        break;
                }
            }

            return new RouterAdvertisementBuilder(advertisement, mac, mtu).Build();
        }

        /// <summary>
        /// Parses an MLD report - version 1 (type 131, RFC 2710) as well as
        /// version 2 (type 143, RFC 9777, formerly RFC 3810). Both say the same in different form:
        /// version 1 names one group per message, version 2 any number.
        /// </summary>
        /// <param name="message">The ICMPv6 message, starting with the type byte.</param>
        /// <param name="source">The sender address.</param>
        /// <returns>The report, or <c>null</c> if the message is not a valid MLD report.</returns>
        public static MulticastListenerReport? ParseMulticastListenerReport(ReadOnlySpan<byte> message, IPAddress source)
        {
            ArgumentNullException.ThrowIfNull(source);

            if (message.Length < 4) return null;

            MulticastListenerReport report = new() { Listener = source };

            switch (message[0])
            {
                case Icmpv6Channel.MulticastListenerReportV1:
                    // Type(1) code(1) checksum(2) maximum response delay(2)
                    // reserved(2) multicast address(16)
                    if (message.Length < 24) return null;
                    report.Groups.Add(new IPAddress(message.Slice(8, 16).ToArray()));
                    return report;

                case Icmpv6Channel.MulticastListenerReportV2:
                    // Type(1) reserved(1) checksum(2) reserved(2) record count(2)
                    if (message.Length < 8) return null;

                    int records = BinaryPrimitives.ReadUInt16BigEndian(message[6..]);
                    int position = 8;

                    for (int i = 0; i < records && position + 20 <= message.Length; i++)
                    {
                        // Record: type(1) aux data length(1) source count(2)
                        // multicast address(16) sources(16 each) aux data(4-byte words)
                        int auxWords = message[position + 1];
                        int sources = BinaryPrimitives.ReadUInt16BigEndian(message[(position + 2)..]);

                        report.Groups.Add(new IPAddress(message.Slice(position + 4, 16).ToArray()));

                        position += 20 + (sources * 16) + (auxWords * 4);
                    }

                    return report;

                default:
                    return null;
            }
        }

        /// <summary>
        /// Walks the options of a neighbor discovery message. The length is given
        /// in units of 8 bytes and includes type and length themselves; a length
        /// of 0 is invalid per RFC 4861, section 4.6, and ends the walk -
        /// otherwise the loop would never terminate.
        /// </summary>
        private static IEnumerable<(byte Type, byte[] Body)> Options(ReadOnlyMemory<byte> options)
        {
            int position = 0;

            while (position + 2 <= options.Length)
            {
                byte type = options.Span[position];
                int length = options.Span[position + 1] * 8;

                if (length == 0 || position + length > options.Length) yield break;

                yield return (type, options.Slice(position + 2, length - 2).ToArray());

                position += length;
            }
        }

        /// <summary>
        /// Reads domain names in DNS wire format: one length byte per label, a
        /// zero ends the name. Padding bytes at the end are zeros and yield empty
        /// names, which are discarded.
        /// </summary>
        private static List<string> ReadDomainNames(ReadOnlySpan<byte> data)
        {
            List<string> names = [];
            List<string> labels = [];
            int position = 0;

            while (position < data.Length)
            {
                int length = data[position++];

                if (length == 0)
                {
                    if (labels.Count > 0) names.Add(string.Join('.', labels));
                    labels.Clear();
                    continue;
                }

                if (position + length > data.Length) break;

                labels.Add(System.Text.Encoding.ASCII.GetString(data.Slice(position, length)));
                position += length;
            }

            return names;
        }

        /// <summary>
        /// Fills in the two values that only become known while walking the
        /// options. <see cref="RouterAdvertisement"/> uses init-only properties
        /// so that a half-filled result cannot arise in the first place.
        /// </summary>
        private readonly struct RouterAdvertisementBuilder(RouterAdvertisement source, PhysicalAddress? mac, int? mtu)
        {
            public RouterAdvertisement Build()
            {
                RouterAdvertisement result = new()
                {
                    Router = source.Router,
                    RouterMac = mac,
                    RouterLifetimeSeconds = source.RouterLifetimeSeconds,
                    ManagedAddressConfiguration = source.ManagedAddressConfiguration,
                    OtherConfiguration = source.OtherConfiguration,
                    Mtu = mtu
                };

                result.Prefixes.AddRange(source.Prefixes);
                result.DnsServers.AddRange(source.DnsServers);
                result.SearchDomains.AddRange(source.SearchDomains);

                return result;
            }
        }
    }
}
