// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// An echo request to <c>ff02::1</c> ("all nodes on this segment"). One
    /// packet out, many answers back.
    /// <para>
    /// This is the IPv6 counterpart of the ping sweep over an IPv4 network,
    /// and it is superior to it: 254 requests and timeouts become a single
    /// question that every device on the segment answers. That is exactly why
    /// it does not matter under IPv6 that a /64 cannot be enumerated.
    /// </para>
    /// <para>
    /// <b>Two ways, depending on privileges</b>, so that the method runs in
    /// both cases instead of failing without administrator rights:
    /// </para>
    /// <list type="number">
    /// <item>
    /// With an ICMPv6 socket (on Linux usually without special privileges, on
    /// Windows with administrator rights): the request is sent and
    /// <em>every</em> answer is collected. The complete result.
    /// </item>
    /// <item>
    /// Without a socket: the request is sent through <see cref="Ping"/>,
    /// which accepts only the first answer, but the operating system enters
    /// <em>all</em> responders into its neighbor table, which is read
    /// afterwards. The detour costs nothing and in practice finds almost the
    /// same.
    /// </item>
    /// </list>
    /// </summary>
    public sealed class Ipv6MulticastPingScanMethod : Ipv6MethodBase
    {
        public override string Id => "ipv6.multicastping";
        public override string DisplayName => "IPv6 multicast ping";

        public override string Explanation =>
            "Asks the whole network segment at once: \"who is there?\" Under IPv6 there is " +
            "an address that means every device on the local cable, and practically all of " +
            "them answer - phones, printers, servers, switches. One question replaces the " +
            "hundreds of single pings an IPv4 scan needs, and it finds devices whose " +
            "address you could never have guessed. It only reaches your own segment: " +
            "anything behind a router stays out of earshot. Works without administrator " +
            "rights, and with them it sees more of the answers.";

        protected override Ipv6Discovery Discovery => Ipv6Discovery.MulticastPing;

        /// <summary>
        /// Not required: without elevated privileges the method takes the
        /// detour through the neighbor table. A checkbox greyed out although
        /// the method runs would be misleading.
        /// </summary>
        public override bool RequiresElevation => false;

        /// <summary>
        /// How long to wait for answers. Devices answer a multicast request with
        /// a deliberate random delay (RFC 4443) so that they do not all send at
        /// once; stopping to listen too early loses exactly the slow devices.
        /// </summary>
        private static readonly TimeSpan ListenWindow = TimeSpan.FromSeconds(3);

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(context);

            List<Ipv6Segment> segments = Segments(context);
            if (segments.Count == 0) return;

            int done = 0;
            int found = 0;

            foreach (Ipv6Segment segment in segments)
            {
                cancellationToken.ThrowIfCancellationRequested();

                found += await ProbeAsync(context, segment, cancellationToken);

                done++;
                context.ReportProgress(done, found, segments.Count);
            }
        }

        /// <summary>
        /// Queries one segment: the direct way first, otherwise the detour.
        /// Returns the number of devices reported.
        /// </summary>
        private async Task<int> ProbeAsync(ScanContext context, Ipv6Segment segment, CancellationToken cancellationToken)
        {
            using Icmpv6Channel? channel = Icmpv6Channel.TryOpen(segment.Interface, segment.InterfaceIndex);

            return channel is not null
                ? await ListenForRepliesAsync(context, segment, channel, cancellationToken)
                : await ViaNeighborTableAsync(context, segment, cancellationToken);
        }

        // ------------------------------------------------- Way 1: own socket

        /// <summary>
        /// Sends the request and collects everything that comes back.
        /// </summary>
        private async Task<int> ListenForRepliesAsync(
            ScanContext context,
            Ipv6Segment segment,
            Icmpv6Channel channel,
            CancellationToken cancellationToken)
        {
            // The identifier separates replies to this request from other
            // ICMPv6 traffic. A raw socket sees all traffic, including that of
            // other programs.
            ushort identifier = (ushort)Random.Shared.Next(1, ushort.MaxValue);

            try
            {
                await channel.SendEchoAsync(
                    channel.Scoped(Icmpv6Channel.AllNodes), identifier, sequence: 1, cancellationToken);
            }
            catch (SocketException)
            {
                // Sending is not possible although the socket was opened; the
                // detour through the table remains.
                return await ViaNeighborTableAsync(context, segment, cancellationToken);
            }

            HashSet<string> seen = [];
            byte[] buffer = new byte[1500];

            using CancellationTokenSource window = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            window.CancelAfter(ListenWindow);

            while (!window.IsCancellationRequested)
            {
                SocketReceiveFromResult result;

                try
                {
                    result = await channel.Socket.ReceiveFromAsync(
                        buffer, SocketFlags.None, new IPEndPoint(IPAddress.IPv6Any, 0), window.Token);
                }
                catch (OperationCanceledException)
                {
                    // The time window has expired. Cancellation through the
                    // token is distinguished below.
                    break;
                }
                catch (SocketException)
                {
                    break;
                }

                if (Icmpv6Channel.TypeOf(buffer, result.ReceivedBytes) != Icmpv6Channel.EchoReply) continue;
                if (result.RemoteEndPoint is not IPEndPoint sender) continue;

                if (!seen.Add(sender.Address.ToString())) continue;

                ReportAddress(context, segment, sender.Address, details: new Dictionary<string, string>
                {
                    ["Answered"] = "Multicast echo to ff02::1"
                });
            }

            cancellationToken.ThrowIfCancellationRequested();

            // The local machine does not answer its own request (multicast
            // loopback is off), and it is not a target anyway. What the
            // replies do not provide, the MAC, comes from the neighbor table,
            // which the operating system has just filled through the same
            // exchange.
            int viaTable = await ViaNeighborTableAsync(context, segment, cancellationToken);

            return Math.Max(seen.Count, viaTable);
        }

        // ------------------------------------------- Way 2: neighbor table

        /// <summary>
        /// Stirs up the segment with an echo request through
        /// <see cref="Ping"/> and then reads who has ended up in the neighbor
        /// table as a result.
        /// <para>
        /// The ping itself returns only a single answer; that is a limitation
        /// of the class and cannot be worked around. What matters, however, is
        /// not what <see cref="Ping"/> returns but what the operating system
        /// learns along the way: it enters every responder into its table,
        /// which is fully readable.
        /// </para>
        /// </summary>
        private async Task<int> ViaNeighborTableAsync(
            ScanContext context,
            Ipv6Segment segment,
            CancellationToken cancellationToken)
        {
            INeighborProvider? provider = PlatformServices.NeighborsOrNull;
            if (provider is null) return 0;

            IPAddress allNodes = new(Icmpv6Channel.AllNodes.GetAddressBytes(), segment.InterfaceIndex);

            try
            {
                using Ping ping = new();
                await ping.SendPingAsync(allNodes, ListenWindow);
            }
            catch (PingException) { /* The answer is irrelevant; only the side effect matters. */ }
            catch (PlatformNotSupportedException) { /* as above */ }
            catch (SocketException) { /* as above */ }

            cancellationToken.ThrowIfCancellationRequested();

            IReadOnlyList<NeighborEntry> entries = await provider.GetNeighborsAsync(cancellationToken);

            return Ipv6NeighborCacheScanMethod.Report(context, [segment], entries, DisplayName);
        }
    }
}
