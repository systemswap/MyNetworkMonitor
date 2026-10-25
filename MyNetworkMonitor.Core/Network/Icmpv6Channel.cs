using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// How an ICMPv6 channel was established. Determines what it can do - and
    /// which reason is displayed when little comes of it.
    /// </summary>
    public enum Icmpv6Access
    {
        /// <summary>Not available - missing privileges or no IPv6.</summary>
        None,

        /// <summary>
        /// Datagram socket (<c>SOCK_DGRAM</c> on <c>IPPROTO_ICMPV6</c>).
        /// Linux allows this without special privileges as long as the user's
        /// group lies within <c>net.ipv4.ping_group_range</c> - the case on common
        /// distributions. Sufficient for echo and echo reply, not for router
        /// advertisements. Not available on Windows.
        /// </summary>
        Datagram,

        /// <summary>
        /// Raw socket. Sees every ICMPv6 packet, including router advertisements
        /// and MLD. Requires administrator rights or <c>CAP_NET_RAW</c>.
        /// </summary>
        Raw
    }

    /// <summary>
    /// An ICMPv6 socket together with the answer to how far it reaches.
    /// <para>
    /// The privilege question is settled here and not in the scan methods: a raw
    /// socket is the best case, a datagram socket the second best, and if both
    /// fail, the method must take another path instead of passing an exception
    /// up. Deciding all three cases in one place keeps this out of the methods.
    /// </para>
    /// <para>
    /// <b>Two pitfalls, both verified by measurement</b> - each would otherwise
    /// cause a silent failure:
    /// </para>
    /// <list type="number">
    /// <item>
    /// <b>Windows allows creating a raw socket without administrator rights</b>,
    /// but then no packet ever arrives. No error, no exception - only silence.
    /// A method relying on the successful <c>new Socket(...)</c> would then
    /// report "nothing found" when in fact privileges are missing. Therefore
    /// elevated rights are checked <b>beforehand</b> on Windows.
    /// </item>
    /// <item>
    /// <b>Windows does not compute the checksum.</b> RFC 3542, section 3.1,
    /// specifies that the kernel fills it in for <c>IPPROTO_ICMPV6</c> sockets -
    /// Linux does, Windows does not. Every receiver silently discards a packet
    /// with checksum 0. It is therefore computed here; where the kernel
    /// overwrites it anyway, this does no harm.
    /// </item>
    /// </list>
    /// </summary>
    public sealed class Icmpv6Channel : IDisposable
    {
        /// <summary>All nodes on the segment (RFC 4291, section 2.7.1).</summary>
        public static readonly IPAddress AllNodes = IPAddress.Parse("ff02::1");

        /// <summary>All routers on the segment (RFC 4291, section 2.7.1).</summary>
        public static readonly IPAddress AllRouters = IPAddress.Parse("ff02::2");

        /// <summary>ICMPv6 type Echo Request (RFC 4443, section 4.1).</summary>
        public const int EchoRequest = 128;
        /// <summary>ICMPv6 type Echo Reply (RFC 4443, section 4.2).</summary>
        public const int EchoReply = 129;
        /// <summary>ICMPv6 type Router Solicitation (RFC 4861, section 4.1).</summary>
        public const int RouterSolicitation = 133;
        /// <summary>ICMPv6 type Router Advertisement (RFC 4861, section 4.2).</summary>
        public const int RouterAdvertisement = 134;
        /// <summary>ICMPv6 type Neighbor Solicitation (RFC 4861, section 4.3).</summary>
        public const int NeighborSolicitation = 135;
        /// <summary>ICMPv6 type Neighbor Advertisement (RFC 4861, section 4.4).</summary>
        public const int NeighborAdvertisement = 136;

        /// <summary>MLDv1 query (RFC 2710, section 3); also used by MLDv2 (RFC 3810, section 5.1).</summary>
        public const int MulticastListenerQuery = 130;
        /// <summary>MLDv1 report (RFC 2710, section 3).</summary>
        public const int MulticastListenerReportV1 = 131;

        /// <summary>MLDv2 report - the answer to a multicast listener query (RFC 3810, section 5.2).</summary>
        public const int MulticastListenerReportV2 = 143;

        /// <summary>Next-header value of ICMPv6 in the checksum pseudo-header.</summary>
        private const byte NextHeaderIcmpv6 = 58;

        private readonly Socket _socket;

        private Icmpv6Channel(Socket socket, Icmpv6Access access, IPAddress localAddress, int interfaceIndex)
        {
            _socket = socket;
            Access = access;
            LocalAddress = localAddress;
            InterfaceIndex = interfaceIndex;
        }

        /// <summary>How the channel was established.</summary>
        public Icmpv6Access Access { get; }

        /// <summary>The link-local address the socket is bound to - the source of the packets.</summary>
        public IPAddress LocalAddress { get; }

        /// <summary>Index of the adapter the channel sends on.</summary>
        public int InterfaceIndex { get; }

        /// <summary>The underlying socket, for receiving.</summary>
        public Socket Socket => _socket;

        // ------------------------------------------------------------- Opening

        /// <summary>
        /// Opens the best possible channel on an adapter. Returns <c>null</c> if
        /// neither a raw nor a datagram socket is possible - the caller then
        /// decides whether to take a fallback path or report the method as
        /// blocked.
        /// </summary>
        /// <param name="nic">
        /// The adapter. It provides the link-local address that is bound as the
        /// source - without it the checksum cannot be computed.
        /// </param>
        /// <param name="interfaceIndex">Adapter index for multicast sending.</param>
        /// <param name="wantRaw">
        /// Raw socket required. Methods that listen instead of asking - RA and
        /// MLD - cannot work with a datagram socket: it only delivers echo
        /// replies.
        /// </param>
        /// <returns>The channel, or <c>null</c> if none can be opened.</returns>
        public static Icmpv6Channel? TryOpen(NetworkInterface nic, int interfaceIndex, bool wantRaw = false)
        {
            ArgumentNullException.ThrowIfNull(nic);

            if (!Socket.OSSupportsIPv6) return null;

            IPAddress? local = LinkLocalAddressOf(nic, interfaceIndex);
            if (local is null) return null;

            // A listener gets no channel where receiving does not work -
            // better none than a silent one.
            if (wantRaw && !RawReceiveSupported) return null;

            if (RawSocketsUsable)
            {
                Icmpv6Channel? raw = TryOpen(SocketType.Raw, Icmpv6Access.Raw, local, interfaceIndex);
                if (raw is not null) return raw;
            }

            return wantRaw ? null : TryOpen(SocketType.Dgram, Icmpv6Access.Datagram, local, interfaceIndex);
        }

        /// <summary>
        /// Can a raw socket <b>receive</b> at all?
        /// <para>
        /// Not on Windows - regardless of privileges. Measured with administrator
        /// rights in four variants: bound to the link-local address and to
        /// <c>::</c>, each with and without joining <c>ff02::1</c>, <c>ff02::2</c>,
        /// <c>ff02::16</c> and <c>ff02::1:2</c>. In all four cases <b>zero</b>
        /// packets arrived, although twelve active IPv6 devices were on the
        /// segment. The Windows network stack consumes ICMPv6 itself; reading
        /// along requires a capture driver such as Npcap, which is deliberately
        /// not a requirement.
        /// </para>
        /// <para>
        /// Sending still works on Windows - the return value only concerns
        /// listening. Methods that listen must take another path on Windows
        /// (see <see cref="Ipv6StackInfo"/>) or report themselves as unavailable
        /// there.
        /// </para>
        /// </summary>
        public static bool RawReceiveSupported => !OperatingSystem.IsWindows();

        /// <summary>
        /// Does <b>creating</b> a raw socket have a chance of success here?
        /// <para>
        /// On Windows only with elevated rights - and that must be known
        /// beforehand, because otherwise creation succeeds and the socket then
        /// stays silent (see class remarks). On Linux, creation without
        /// <c>CAP_NET_RAW</c> fails honestly with <c>EPERM</c>, so the attempt
        /// suffices there.
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
                    // If this cannot be determined, take the fallback path rather
                    // than rely on a silent socket.
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

                // Without this binding the kernel picks the adapter itself.
                // For link-local multicast that is regularly the wrong one -
                // on a workstation, VPN and hypervisor adapters come first.
                socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastInterface, interfaceIndex);

                // A higher hop limit would be wrong: ff02:: is link-local and
                // must not leave the segment.
                socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastTimeToLive, 1);
                socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastLoopback, false);

                // Receiving only works on a bound socket, and the bound
                // address is also the source in the checksum pseudo-header.
                socket.Bind(new IPEndPoint(local, 0));

                return new Icmpv6Channel(socket, access, local, interfaceIndex);
            }
            catch (SocketException)
            {
                // AccessDenied without privileges, ProtocolNotSupported for
                // SOCK_DGRAM on Windows. Both are an answer, not an error.
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
        /// The link-local address of the adapter, with the zone set. Nothing can
        /// be done on the segment without it - fe80::1 exists once on every
        /// adapter; only the zone turns it into a destination.
        /// </summary>
        /// <param name="nic">The adapter.</param>
        /// <param name="interfaceIndex">The zone to set if the address carries none.</param>
        /// <returns>The scoped link-local address, or <c>null</c> if the adapter has none.</returns>
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
            catch (NetworkInformationException) { /* adapter disappeared */ }
            catch (PlatformNotSupportedException) { /* no IPv6 information */ }

            return null;
        }

        /// <summary>A multicast address with the zone of this channel.</summary>
        public IPAddress Scoped(IPAddress multicast) =>
            new(multicast.GetAddressBytes(), InterfaceIndex);

        // ------------------------------------------------------------- Sending

        /// <summary>
        /// Sends an echo request to a destination and fills in the checksum.
        /// </summary>
        /// <param name="destination">The destination address, scoped for link-local destinations.</param>
        /// <param name="identifier">Echo identifier for matching replies.</param>
        /// <param name="sequence">Echo sequence number.</param>
        /// <param name="cancellationToken">Cancels the send.</param>
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
        /// Builds an echo request. The checksum stays zero for now and is filled
        /// in by <see cref="WriteChecksum"/> once the destination is known - it
        /// depends on source and destination.
        /// </summary>
        /// <param name="identifier">Echo identifier.</param>
        /// <param name="sequence">Echo sequence number.</param>
        /// <param name="payloadBytes">Length of the payload.</param>
        /// <returns>The ICMPv6 message without IPv6 header.</returns>
        public static byte[] BuildEchoRequest(ushort identifier, ushort sequence, int payloadBytes = 32)
        {
            byte[] packet = new byte[8 + payloadBytes];

            packet[0] = EchoRequest;
            packet[1] = 0;                  // Code
            packet[2] = 0;                  // Checksum
            packet[3] = 0;

            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), identifier);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(6), sequence);

            // Recognizable content: a packet capture immediately shows where the
            // packet comes from. ping does the same with the alphabet.
            for (int i = 0; i < payloadBytes; i++)
            {
                packet[8 + i] = (byte)('a' + (i % 26));
            }

            return packet;
        }

        /// <summary>
        /// Writes the ICMPv6 checksum into bytes 2 and 3 (RFC 4443, section 2.3).
        /// It covers a pseudo-header of source, destination, length and next
        /// header (RFC 8200, section 8.1) - therefore the source address must be
        /// known, and therefore the channel binds to a fixed address instead of
        /// letting the kernel choose it.
        /// </summary>
        /// <param name="message">The ICMPv6 message; bytes 2 and 3 are overwritten.</param>
        /// <param name="source">The source address.</param>
        /// <param name="destination">The destination address.</param>
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
        /// The ICMPv6 type of a received packet. On a raw socket the ICMPv6 header
        /// is at the start of the payload - under IPv6 the IPv6 header is not
        /// delivered, unlike IPv4.
        /// </summary>
        /// <returns>The type, or -1 if the buffer is empty.</returns>
        public static int TypeOf(byte[] buffer, int length) => length < 1 ? -1 : buffer[0];

        /// <summary>Closes the socket.</summary>
        public void Dispose() => _socket.Dispose();
    }
}
