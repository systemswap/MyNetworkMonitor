using System.Net;
using System.Net.Sockets;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// Listens for router advertisements, and asks once instead of waiting.
    /// <para>
    /// A router advertisement is the most informative message on an IPv6
    /// segment. In one packet it states who routes, which prefixes are valid,
    /// which name servers are responsible, how large packets may be, and,
    /// through two flags, whether a DHCPv6 server is in use as well. Under
    /// IPv4 this would take DHCP capture, SNMP and a route query combined.
    /// </para>
    /// <para>
    /// <b>Why this method sends although it is a listening method:</b>
    /// routers advertise unsolicited only every few minutes, longer than a
    /// scan may take. A router solicitation is therefore sent to
    /// <c>ff02::2</c> first, and every router answers within seconds. Every
    /// device does exactly this when it starts up; it is the intended
    /// mechanism and stands out to nobody.
    /// </para>
    /// <para>
    /// The prefixes found are also the basis of the two guessing methods:
    /// only once the /64 of the segment is known can they build addresses in
    /// it.
    /// </para>
    /// <para>
    /// <b>Two ways, depending on the platform</b>, so that the method runs on
    /// both instead of failing on Windows:
    /// </para>
    /// <list type="number">
    /// <item>
    /// <b>Listening</b> (Linux, with <c>CAP_NET_RAW</c>): the advertisement
    /// itself is read. Complete, including MTU, lifetimes and which router
    /// announces what.
    /// </item>
    /// <item>
    /// <b>Querying the stack</b> (Windows): Windows does not deliver ICMPv6 to
    /// raw sockets (verified by measurement, see
    /// <see cref="Icmpv6Channel.RawReceiveSupported"/>). It <em>has</em>
    /// received and processed the advertisements, though, or the machine
    /// would have no IPv6 address. So the result is read instead of the
    /// packet: routers, prefixes, name servers and the origin of each address
    /// are available through regular APIs. This gives a snapshot rather than
    /// the live message, with the same content, and needs <b>no</b>
    /// administrator rights there.
    /// </item>
    /// </list>
    /// </summary>
    public sealed class Ipv6RouterAdvertisementScanMethod : Ipv6MethodBase
    {
        public override string Id => "ipv6.routeradvertisement";
        public override string DisplayName => "IPv6 router advertisements";

        public override string Explanation =>
            "Listens for what the routers announce about themselves, after asking them " +
            "once so you do not have to wait for the next announcement. In a single reply " +
            "you learn which device routes this network, which address ranges are valid " +
            "here, which name servers it hands out and whether a DHCPv6 server is running " +
            "as well. It also exposes a router nobody knew about - a second one announcing " +
            "itself is either a misconfiguration or something worse. On Linux it reads the " +
            "announcements themselves and needs the right to do so; on Windows it reads " +
            "what the system already made of them, and needs nothing.";

        protected override Ipv6Discovery Discovery => Ipv6Discovery.ListenRouterAdvertisements;

        public override bool IsPassive => true;

        /// <summary>
        /// Not required: where no raw socket is available, the network stack
        /// is read instead. A greyed-out checkbox would be misleading, because
        /// the method still delivers results there.
        /// </summary>
        public override bool RequiresElevation => false;

        /// <summary>
        /// How long to wait for advertisements. Routers answer a solicitation
        /// after a random delay of up to half a second (MAX_RA_DELAY_TIME,
        /// RFC 4861, sections 6.2.6 and 10); four seconds leave time for a slow
        /// device and may also catch a periodic advertisement.
        /// </summary>
        private static readonly TimeSpan ListenWindow = TimeSpan.FromSeconds(4);

        /// <summary>
        /// Always available once IPv6 is usable on the segment, if necessary
        /// through the stack. Missing privileges are no obstacle here, only the
        /// difference between "message read directly" and "result read from
        /// the stack".
        /// </summary>
        public override ScanMethodAvailability CheckAvailability(ScanContext context) =>
            base.CheckAvailability(context);

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(context);

            List<Ipv6Segment> segments = Segments(context);
            if (segments.Count == 0) return;

            int done = 0;
            int routers = 0;

            foreach (Ipv6Segment segment in segments)
            {
                cancellationToken.ThrowIfCancellationRequested();

                routers += await AskAndListenAsync(context, segment, cancellationToken);

                done++;
                context.ReportProgress(done, routers, segments.Count);
            }
        }

        private async Task<int> AskAndListenAsync(
            ScanContext context,
            Ipv6Segment segment,
            CancellationToken cancellationToken)
        {
            using Icmpv6Channel? channel = Icmpv6Channel.TryOpen(segment.Interface, segment.InterfaceIndex, wantRaw: true);

            // No channel to listen on: use what the stack has derived from the
            // advertisements.
            if (channel is null) return FromStack(context, segment);

            await SolicitAsync(channel, cancellationToken);

            HashSet<string> seen = [];

            await ListenAsync(channel, ListenWindow, (buffer, length, sender) =>
            {
                if (Icmpv6Channel.TypeOf(buffer, length) != Icmpv6Channel.RouterAdvertisement) return;

                // A router often advertises several times within the window.
                if (!seen.Add(sender.ToString())) return;

                RouterAdvertisement? advertisement =
                    Icmpv6Parser.ParseRouterAdvertisement(buffer.AsMemory(0, length), sender);

                if (advertisement is not null) ReportRouter(context, segment, advertisement);
            }, cancellationToken);

            // Even with a raw socket the window may stay empty; the same
            // fallback then applies, instead of reporting "nothing found"
            // although the machine demonstrably knows a router.
            return seen.Count > 0 ? seen.Count : FromStack(context, segment);
        }

        // ------------------------------------------------- Way 2: the stack

        /// <summary>
        /// Reports what the operating system has derived from the
        /// advertisements.
        /// <para>
        /// The information is deliberately marked as such: it comes from the
        /// network stack, not from a packet just received. A reader of the
        /// entry must be able to tell the difference; it does not state when a
        /// router said this, only that it did.
        /// </para>
        /// </summary>
        private int FromStack(ScanContext context, Ipv6Segment segment)
        {
            Ipv6StackInfo info = Ipv6StackInfo.ForInterface(segment.Interface, segment.InterfaceIndex);
            if (!info.HasAnything) return 0;

            Dictionary<string, string> shared = new()
            {
                ["Source"] = "Read from this computer's IPv6 settings, not captured live"
            };

            if (info.Prefixes.Count > 0)
            {
                shared["Announced prefixes"] = string.Join(", ", info.Prefixes);
            }

            if (info.DnsServers.Count > 0)
            {
                shared["Name servers"] = string.Join(", ", info.DnsServers);
            }

            if (info.SearchDomain is not null) shared["Search domain"] = info.SearchDomain;

            shared["Address configuration"] = info.UsesDhcpv6
                ? info.UsesSlaac
                    ? "Both: self-assigned from a router prefix and DHCPv6"
                    : "DHCPv6 (managed)"
                : info.UsesSlaac
                    ? "Self-assigned from a router prefix (SLAAC)"
                    : "No address from a router on this adapter";

            // Without a known gateway there is no device to attach the
            // information to. Reporting it for a made-up address would be
            // worse than omitting it.
            if (info.Routers.Count == 0) return 0;

            foreach (IPAddress router in info.Routers)
            {
                Dictionary<string, string> details = new(shared)
                {
                    ["Role"] = "Router (default gateway for this segment)"
                };

                ReportAddress(context, segment, router, details: details);
            }

            return info.Routers.Count;
        }

        /// <summary>
        /// Sends a router solicitation to <c>ff02::2</c> ("all routers").
        /// Layout per RFC 4861, section 4.1: type, code, checksum, four
        /// reserved bytes. The source link-layer address option is permitted
        /// but optional; it is omitted so that the solicitation reveals as
        /// little as possible about the sender.
        /// </summary>
        private static async Task SolicitAsync(Icmpv6Channel channel, CancellationToken cancellationToken)
        {
            byte[] solicitation = new byte[8];
            solicitation[0] = Icmpv6Channel.RouterSolicitation;

            IPAddress destination = channel.Scoped(Icmpv6Channel.AllRouters);
            Icmpv6Channel.WriteChecksum(solicitation, channel.LocalAddress, destination);

            try
            {
                await channel.Socket.SendToAsync(
                    solicitation, SocketFlags.None, new IPEndPoint(destination, 0), cancellationToken);
            }
            catch (SocketException)
            {
                // If the solicitation cannot be sent, listening continues; a
                // periodic advertisement arrives eventually anyway.
            }
        }

        /// <summary>
        /// Turns an advertisement into an observation. The router is the
        /// device; everything else (prefixes, name servers, DHCPv6 hint) is
        /// attached as details, because this router announces it.
        /// </summary>
        private void ReportRouter(ScanContext context, Ipv6Segment segment, RouterAdvertisement advertisement)
        {
            Dictionary<string, string> details = new()
            {
                ["Role"] = advertisement.RouterLifetimeSeconds > 0
                    ? "Router (default gateway for this segment)"
                    : "Router (announces prefixes, but is not a default gateway)"
            };

            if (advertisement.Prefixes.Count > 0)
            {
                details["Announced prefixes"] = string.Join(", ", advertisement.Prefixes);
            }

            if (advertisement.DnsServers.Count > 0)
            {
                details["Name servers"] = string.Join(", ", advertisement.DnsServers);
            }

            if (advertisement.SearchDomains.Count > 0)
            {
                details["Search domains"] = string.Join(", ", advertisement.SearchDomains);
            }

            if (advertisement.Mtu is int mtu) details["MTU"] = mtu.ToString();

            // The M and O flags (RFC 4861, section 4.2) tell where devices on
            // the segment get their configuration. That answers why a device
            // has an address matching no announced prefix.
            details["Address configuration"] = advertisement.ManagedAddressConfiguration
                ? "DHCPv6 (managed)"
                : advertisement.OtherConfiguration
                    ? "Self-assigned, other settings from DHCPv6"
                    : "Self-assigned (SLAAC only)";

            ReportAddress(context, segment, advertisement.Router, advertisement.RouterMac, details: details);
        }
    }
}
