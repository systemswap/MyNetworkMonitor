using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;

namespace MyNetworkMonitor.Core.Network
{
    /// <summary>Ein Praefix, wie es ein Router in seiner Ankuendigung nennt.</summary>
    public sealed class AdvertisedPrefix
    {
        public required IPAddress Prefix { get; init; }
        public required int Length { get; init; }

        /// <summary>Geraete duerfen sich hier selbst eine Adresse bilden (A-Bit).</summary>
        public bool Autonomous { get; init; }

        /// <summary>Das Praefix gilt fuer dieses Segment (L-Bit).</summary>
        public bool OnLink { get; init; }

        public uint ValidLifetimeSeconds { get; init; }

        public override string ToString() => $"{Prefix}/{Length}";
    }

    /// <summary>
    /// Eine ausgewertete Router-Ankuendigung.
    /// <para>
    /// Sie ist die aufschlussreichste Nachricht im IPv6-Segment: sie nennt den
    /// Router, die gueltigen Praefixe, die Namensserver und - ueber zwei Bits -
    /// ob im Netz zusaetzlich ein DHCPv6-Server arbeitet. Das alles, ohne
    /// gefragt zu haben.
    /// </para>
    /// </summary>
    public sealed class RouterAdvertisement
    {
        public required IPAddress Router { get; init; }

        /// <summary>MAC des Routers, sofern er sie mitschickt (Option 1).</summary>
        public PhysicalAddress? RouterMac { get; init; }

        /// <summary>
        /// Wie lange dieser Router als Standardgateway gilt. 0 heisst: er ist
        /// keines - dann kuendigt er nur Praefixe an.
        /// </summary>
        public int RouterLifetimeSeconds { get; init; }

        /// <summary>M-Bit: Adressen kommen von einem DHCPv6-Server.</summary>
        public bool ManagedAddressConfiguration { get; init; }

        /// <summary>O-Bit: weitere Angaben (etwa DNS) kommen von DHCPv6.</summary>
        public bool OtherConfiguration { get; init; }

        public int? Mtu { get; init; }

        public List<AdvertisedPrefix> Prefixes { get; } = [];

        /// <summary>Namensserver aus der RDNSS-Option (RFC 8106).</summary>
        public List<IPAddress> DnsServers { get; } = [];

        /// <summary>Suchdomaenen aus der DNSSL-Option.</summary>
        public List<string> SearchDomains { get; } = [];
    }

    /// <summary>
    /// Ein Bericht ueber Multicast-Gruppen, denen ein Geraet beigetreten ist.
    /// </summary>
    public sealed class MulticastListenerReport
    {
        public required IPAddress Listener { get; init; }

        /// <summary>Die Gruppen, in denen das Geraet zuhoert.</summary>
        public List<IPAddress> Groups { get; } = [];
    }

    /// <summary>
    /// Zerlegt die ICMPv6-Nachrichten, die sich mithoeren lassen.
    /// <para>
    /// Getrennt von den Verfahren, weil das Auswerten von Bytes eine andere
    /// Sache ist als das Fuehren eines Scans - und weil es sich so ohne Netz
    /// pruefen laesst. Alle Methoden sind gutmuetig: ein abgeschnittenes oder
    /// unsinniges Paket ergibt <c>null</c> beziehungsweise eine leere Liste,
    /// nie eine Ausnahme. Auf dem Netz liegt alles Moegliche.
    /// </para>
    /// </summary>
    public static class Icmpv6Parser
    {
        // --- Optionstypen aus RFC 4861 und RFC 8106 -------------------------
        private const byte OptionSourceLinkLayerAddress = 1;
        private const byte OptionPrefixInformation = 3;
        private const byte OptionMtu = 5;
        private const byte OptionRecursiveDnsServer = 25;
        private const byte OptionDnsSearchList = 31;

        /// <summary>
        /// Wertet eine Router-Ankuendigung aus. <paramref name="source"/> ist
        /// die Absenderadresse aus dem Empfang - im ICMPv6-Rumpf steht sie
        /// nicht, unter IPv6 wird der Paketkopf nicht mitgeliefert.
        /// </summary>
        public static RouterAdvertisement? ParseRouterAdvertisement(ReadOnlyMemory<byte> packet, IPAddress source)
        {
            ArgumentNullException.ThrowIfNull(source);

            ReadOnlySpan<byte> message = packet.Span;

            // 16 Byte fester Teil: Typ, Code, Pruefsumme, Hop Limit, Flags,
            // Router-Lebensdauer, Reachable Time, Retrans Timer.
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
                        // Aufbau: Praefixlaenge(1) Flags(1) Gueltigkeit(4)
                        // Bevorzugt(4) Reserviert(4) Praefix(16)
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
                        // Reserviert(2) Lebensdauer(4), dann je 16 Byte eine Adresse.
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
        /// Wertet einen MLD-Bericht aus - Version 1 (Typ 131) wie Version 2
        /// (Typ 143). Beide sagen dasselbe, nur in anderer Form: Version 1
        /// nennt eine Gruppe je Nachricht, Version 2 beliebig viele.
        /// </summary>
        public static MulticastListenerReport? ParseMulticastListenerReport(ReadOnlySpan<byte> message, IPAddress source)
        {
            ArgumentNullException.ThrowIfNull(source);

            if (message.Length < 4) return null;

            MulticastListenerReport report = new() { Listener = source };

            switch (message[0])
            {
                case Icmpv6Channel.MulticastListenerReportV1:
                    // Typ(1) Code(1) Pruefsumme(2) Antwortzeit(2)
                    // Reserviert(2) Gruppenadresse(16)
                    if (message.Length < 24) return null;
                    report.Groups.Add(new IPAddress(message.Slice(8, 16).ToArray()));
                    return report;

                case Icmpv6Channel.MulticastListenerReportV2:
                    // Typ(1) Code(1) Pruefsumme(2) Reserviert(2) Anzahl(2)
                    if (message.Length < 8) return null;

                    int records = BinaryPrimitives.ReadUInt16BigEndian(message[6..]);
                    int position = 8;

                    for (int i = 0; i < records && position + 20 <= message.Length; i++)
                    {
                        // Datensatz: Typ(1) AuxLaenge(1) Quellenzahl(2)
                        // Gruppenadresse(16) Quellen(je 16) Zusatz(je 4 Byte)
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
        /// Laeuft die Optionen einer Nachbarschaftsnachricht ab. Die Laenge
        /// steht in Einheiten von 8 Byte und schliesst Typ und Laenge selbst
        /// ein; eine Laenge von 0 ist laut RFC 4861 ungueltig und beendet den
        /// Durchlauf - sonst liefe die Schleife ewig.
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
        /// Liest Domaennamen im DNS-Format: je Bestandteil ein Laengenbyte,
        /// eine Null beendet den Namen. Auffuellbytes am Ende sind Nullen und
        /// ergeben leere Namen, die verworfen werden.
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
        /// Setzt die beiden Angaben nach, die erst beim Durchlaufen der
        /// Optionen bekannt werden. <see cref="RouterAdvertisement"/> ist
        /// unveraenderlich angelegt, damit ein halb gefuelltes Ergebnis gar
        /// nicht erst entstehen kann.
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
