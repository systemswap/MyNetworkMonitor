using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// Wie ein ICMPv6-Kanal zustande gekommen ist. Bestimmt, was mit ihm geht -
    /// und was der Nutzer als Grund zu sehen bekommt, wenn wenig dabei
    /// herauskommt.
    /// </summary>
    public enum Icmpv6Access
    {
        /// <summary>Nicht verfuegbar - fehlende Rechte oder kein IPv6.</summary>
        None,

        /// <summary>
        /// Datagramm-Socket (<c>SOCK_DGRAM</c> auf <c>IPPROTO_ICMPV6</c>).
        /// Linux erlaubt das ohne Sonderrechte, sofern die Gruppe des Nutzers in
        /// <c>net.ipv4.ping_group_range</c> liegt - auf den gaengigen
        /// Distributionen ist das der Fall. Reicht fuer Echo und Echo-Antwort,
        /// nicht fuer Router Advertisements. Unter Windows gibt es das nicht.
        /// </summary>
        Datagram,

        /// <summary>
        /// Rohsocket. Sieht jedes ICMPv6-Paket, also auch Router
        /// Advertisements und MLD. Braucht Administratorrechte bzw.
        /// <c>CAP_NET_RAW</c>.
        /// </summary>
        Raw
    }

    /// <summary>
    /// Ein ICMPv6-Socket samt der Frage, wie weit er reicht.
    /// <para>
    /// Der Kern der Rechtefrage steckt hier und nicht in den Verfahren: ein
    /// Rohsocket ist der beste Fall, ein Datagramm-Socket der zweitbeste, und
    /// wenn beides ausfaellt, muss das Verfahren einen anderen Weg gehen statt
    /// eine Ausnahme nach oben zu reichen. Alle drei Faelle an einer Stelle
    /// entschieden zu haben, haelt das aus den Verfahren heraus.
    /// </para>
    /// <para>
    /// <b>Zwei Fallen, beide am 2026-08-09 nachgemessen</b> - sie kosten sonst
    /// jeweils einen stillen Fehlschlag:
    /// </para>
    /// <list type="number">
    /// <item>
    /// <b>Windows laesst einen Rohsocket ohne Administratorrechte anlegen</b>,
    /// und erst danach kommt nie ein Paket an. Kein Fehler, keine Ausnahme -
    /// nur Stille. Ein Verfahren, das sich auf das gelungene
    /// <c>new Socket(...)</c> verlaesst, meldet dann "nichts gefunden", wo in
    /// Wahrheit die Rechte fehlen. Darum wird unter Windows <b>vorher</b> auf
    /// erhoehte Rechte geprueft.
    /// </item>
    /// <item>
    /// <b>Die Pruefsumme rechnet unter Windows niemand.</b> RFC 3542 sieht vor,
    /// dass der Kernel sie bei <c>IPPROTO_ICMPV6</c> selbst eintraegt - Linux
    /// tut das, Windows nicht. Ein Paket mit Pruefsumme 0 verwirft jeder
    /// Empfaenger stillschweigend. Sie wird darum hier gerechnet; wo der Kernel
    /// sie ohnehin ueberschreibt, schadet das nicht.
    /// </item>
    /// </list>
    /// </summary>
    public sealed class Icmpv6Channel : IDisposable
    {
        /// <summary>Alle Knoten im Segment (RFC 4291).</summary>
        public static readonly IPAddress AllNodes = IPAddress.Parse("ff02::1");

        /// <summary>Alle Router im Segment.</summary>
        public static readonly IPAddress AllRouters = IPAddress.Parse("ff02::2");

        public const int EchoRequest = 128;
        public const int EchoReply = 129;
        public const int RouterSolicitation = 133;
        public const int RouterAdvertisement = 134;
        public const int NeighborSolicitation = 135;
        public const int NeighborAdvertisement = 136;

        /// <summary>MLDv1: Abfrage und Bericht.</summary>
        public const int MulticastListenerQuery = 130;
        public const int MulticastListenerReportV1 = 131;

        /// <summary>MLDv2-Bericht - die Antwort auf eine Multicast-Listener-Abfrage.</summary>
        public const int MulticastListenerReportV2 = 143;

        /// <summary>Kennzahl von ICMPv6 im Pseudokopf der Pruefsumme.</summary>
        private const byte NextHeaderIcmpv6 = 58;

        private readonly Socket _socket;

        private Icmpv6Channel(Socket socket, Icmpv6Access access, IPAddress localAddress, int interfaceIndex)
        {
            _socket = socket;
            Access = access;
            LocalAddress = localAddress;
            InterfaceIndex = interfaceIndex;
        }

        public Icmpv6Access Access { get; }

        /// <summary>Die Link-Local-Adresse, an die gebunden wurde - die Quelle der Pakete.</summary>
        public IPAddress LocalAddress { get; }

        public int InterfaceIndex { get; }

        public Socket Socket => _socket;

        // ------------------------------------------------------------- Oeffnen

        /// <summary>
        /// Oeffnet den bestmoeglichen Kanal auf einem Adapter. Liefert
        /// <c>null</c>, wenn weder Roh- noch Datagramm-Socket moeglich sind -
        /// der Aufrufer entscheidet dann, ob er einen Ersatzweg geht oder das
        /// Verfahren als blockiert meldet.
        /// </summary>
        /// <param name="nic">
        /// Der Adapter. Aus ihm kommt die Link-Local-Adresse, die als Quelle
        /// gebunden wird - ohne sie laesst sich die Pruefsumme nicht rechnen.
        /// </param>
        /// <param name="interfaceIndex">Adapterindex fuer den Multicast-Versand.</param>
        /// <param name="wantRaw">
        /// Rohsocket verlangt. Verfahren, die mithoeren statt zu fragen - RA
        /// und MLD -, kommen mit einem Datagramm-Socket nicht aus: der liefert
        /// nur Echo-Antworten.
        /// </param>
        public static Icmpv6Channel? TryOpen(NetworkInterface nic, int interfaceIndex, bool wantRaw = false)
        {
            ArgumentNullException.ThrowIfNull(nic);

            if (!Socket.OSSupportsIPv6) return null;

            IPAddress? local = LinkLocalAddressOf(nic, interfaceIndex);
            if (local is null) return null;

            // Wer mithoeren will, bekommt dort keinen Kanal, wo der Empfang
            // nicht funktioniert - lieber gar keinen als einen stummen.
            if (wantRaw && !RawReceiveSupported) return null;

            if (RawSocketsUsable)
            {
                Icmpv6Channel? raw = TryOpen(SocketType.Raw, Icmpv6Access.Raw, local, interfaceIndex);
                if (raw is not null) return raw;
            }

            return wantRaw ? null : TryOpen(SocketType.Dgram, Icmpv6Access.Datagram, local, interfaceIndex);
        }

        /// <summary>
        /// Laesst sich auf einem Rohsocket ueberhaupt <b>empfangen</b>?
        /// <para>
        /// Unter Windows nein - und zwar unabhaengig von den Rechten. Am
        /// 2026-08-09 nachgemessen, mit Administratorrechten und in vier
        /// Varianten: gebunden an die Link-Local-Adresse und an <c>::</c>,
        /// jeweils mit und ohne Beitritt zu <c>ff02::1</c>, <c>ff02::2</c>,
        /// <c>ff02::16</c> und <c>ff02::1:2</c>. In allen vier Faellen kamen
        /// <b>null</b> Pakete an, obwohl im Segment zwoelf aktive IPv6-Geraete
        /// standen. Der Windows-Netzwerkstapel verbraucht ICMPv6 selbst; es
        /// mitzulesen setzt einen Mitschnitttreiber wie Npcap voraus, und der
        /// soll ausdruecklich nicht noetig sein.
        /// </para>
        /// <para>
        /// Senden geht unter Windows weiterhin - der Rueckgabewert betrifft
        /// nur das Zuhoeren. Verfahren, die mithoeren, muessen unter Windows
        /// einen anderen Weg gehen (siehe <see cref="Ipv6StackInfo"/>) oder
        /// sich als dort nicht verfuegbar melden.
        /// </para>
        /// </summary>
        public static bool RawReceiveSupported => !OperatingSystem.IsWindows();

        /// <summary>
        /// Hat das <b>Anlegen</b> eines Rohsockets hier Aussicht auf Erfolg?
        /// <para>
        /// Unter Windows nur mit erhoehten Rechten - und das muss vorher
        /// feststehen, weil das Anlegen sonst gelingt und der Socket
        /// anschliessend stumm bleibt (siehe Klassenkommentar). Unter Linux
        /// scheitert das Anlegen ohne <c>CAP_NET_RAW</c> ehrlich mit
        /// <c>EPERM</c>, dort genuegt der Versuch.
        /// </para>
        /// </summary>
        public static bool RawSocketsUsable
        {
            get
            {
                if (!OperatingSystem.IsWindows()) return true;

                try
                {
                    using System.Security.Principal.WindowsIdentity identity =
                        System.Security.Principal.WindowsIdentity.GetCurrent();

                    return new System.Security.Principal.WindowsPrincipal(identity)
                        .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
                }
                catch (Exception)
                {
                    // Laesst sich das nicht feststellen, lieber den Ersatzweg
                    // gehen als auf einen stummen Socket zu setzen.
                    return false;
                }
            }
        }

        private static Icmpv6Channel? TryOpen(SocketType type, Icmpv6Access access, IPAddress local, int interfaceIndex)
        {
            Socket? socket = null;

            try
            {
                socket = new Socket(AddressFamily.InterNetworkV6, type, ProtocolType.IcmpV6);

                // Ohne diese Bindung sucht der Kernel den Adapter selbst aus.
                // Bei Link-Local-Multicast ist das regelmaessig der falsche -
                // auf einem Arbeitsplatz stehen VPN- und Hypervisor-Adapter
                // davor.
                socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastInterface, interfaceIndex);

                // Hoehere Sprungzahl waere falsch: ff02:: ist link-lokal und
                // darf das Segment nicht verlassen.
                socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastTimeToLive, 1);
                socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastLoopback, false);

                // Empfangen geht nur ueber einen gebundenen Socket, und die
                // gebundene Adresse ist zugleich die Quelle im Pseudokopf der
                // Pruefsumme.
                socket.Bind(new IPEndPoint(local, 0));

                return new Icmpv6Channel(socket, access, local, interfaceIndex);
            }
            catch (SocketException)
            {
                // AccessDenied ohne Rechte, ProtocolNotSupported fuer
                // SOCK_DGRAM unter Windows. Beides ist eine Antwort, kein
                // Fehler.
                socket?.Dispose();
                return null;
            }
            catch (PlatformNotSupportedException)
            {
                socket?.Dispose();
                return null;
            }
        }

        /// <summary>
        /// Die Link-Local-Adresse des Adapters, mit gesetzter Zone. Ohne sie
        /// ist im Segment nichts zu machen - fe80::1 gibt es an jedem Adapter
        /// einmal, erst die Zone macht daraus ein Ziel.
        /// </summary>
        public static IPAddress? LinkLocalAddressOf(NetworkInterface nic, int interfaceIndex)
        {
            try
            {
                foreach (UnicastIPAddressInformation unicast in nic.GetIPProperties().UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily != AddressFamily.InterNetworkV6) continue;
                    if (!unicast.Address.IsIPv6LinkLocal) continue;

                    return unicast.Address.ScopeId != 0 || interfaceIndex <= 0
                        ? unicast.Address
                        : new IPAddress(unicast.Address.GetAddressBytes(), interfaceIndex);
                }
            }
            catch (NetworkInformationException) { /* Adapter verschwunden */ }
            catch (PlatformNotSupportedException) { /* keine IPv6-Angaben */ }

            return null;
        }

        /// <summary>Eine Multicast-Adresse mit der Zone dieses Kanals.</summary>
        public IPAddress Scoped(IPAddress multicast) =>
            new(multicast.GetAddressBytes(), InterfaceIndex);

        // ------------------------------------------------------------- Senden

        /// <summary>
        /// Sendet eine Echo-Anforderung an ein Ziel und traegt dabei die
        /// Pruefsumme ein.
        /// </summary>
        public async Task SendEchoAsync(
            IPAddress destination,
            ushort identifier,
            ushort sequence,
            CancellationToken cancellationToken)
        {
            byte[] packet = BuildEchoRequest(identifier, sequence);
            WriteChecksum(packet, LocalAddress, destination);

            await _socket.SendToAsync(packet, SocketFlags.None, new IPEndPoint(destination, 0), cancellationToken);
        }

        /// <summary>
        /// Baut eine Echo-Anforderung. Die Pruefsumme bleibt zunaechst null und
        /// wird von <see cref="WriteChecksum"/> nachgetragen, sobald das Ziel
        /// feststeht - sie haengt an Quelle und Ziel.
        /// </summary>
        public static byte[] BuildEchoRequest(ushort identifier, ushort sequence, int payloadBytes = 32)
        {
            byte[] packet = new byte[8 + payloadBytes];

            packet[0] = EchoRequest;
            packet[1] = 0;                  // Code
            packet[2] = 0;                  // Pruefsumme
            packet[3] = 0;

            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), identifier);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(6), sequence);

            // Erkennbarer Inhalt: wer mitschneidet, sieht sofort, woher das
            // Paket kommt. Dasselbe macht ping seit jeher mit dem Alphabet.
            for (int i = 0; i < payloadBytes; i++)
            {
                packet[8 + i] = (byte)('a' + (i % 26));
            }

            return packet;
        }

        /// <summary>
        /// Traegt die ICMPv6-Pruefsumme in Byte 2 und 3 ein. Sie laeuft ueber
        /// einen Pseudokopf aus Quelle, Ziel, Laenge und Protokollkennzahl -
        /// deshalb muss die Quelladresse feststehen, und deshalb bindet der
        /// Kanal sich an eine feste Adresse, statt sie den Kernel waehlen zu
        /// lassen.
        /// </summary>
        public static void WriteChecksum(byte[] message, IPAddress source, IPAddress destination)
        {
            ArgumentNullException.ThrowIfNull(message);

            message[2] = 0;
            message[3] = 0;

            byte[] pseudo = new byte[40 + message.Length];
            source.GetAddressBytes().CopyTo(pseudo, 0);
            destination.GetAddressBytes().CopyTo(pseudo, 16);
            BinaryPrimitives.WriteUInt32BigEndian(pseudo.AsSpan(32), (uint)message.Length);
            pseudo[39] = NextHeaderIcmpv6;
            message.CopyTo(pseudo, 40);

            uint sum = 0;
            int i = 0;
            for (; i + 1 < pseudo.Length; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(pseudo.AsSpan(i));
            if (i < pseudo.Length) sum += (uint)(pseudo[i] << 8);

            while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16);

            BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2), (ushort)~sum);
        }

        /// <summary>
        /// Der ICMPv6-Typ eines empfangenen Pakets. Bei einem Rohsocket steht
        /// der ICMPv6-Kopf am Anfang der Nutzlast - der IPv6-Kopf wird unter
        /// IPv6 nicht mitgeliefert, anders als bei IPv4.
        /// </summary>
        public static int TypeOf(byte[] buffer, int length) => length < 1 ? -1 : buffer[0];

        public void Dispose() => _socket.Dispose();
    }
}
