using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// Listens for MLD reports, the messages with which devices tell the
    /// network which multicast groups they have joined.
    /// <para>
    /// This is the most unusual of the six methods and the one with the
    /// highest yield per packet: a group membership <b>is</b> service
    /// information. A device listening on <c>ff02::fb</c> speaks mDNS, so it
    /// is an Apple device, a printer or a TV. One listening on <c>ff02::c</c>
    /// speaks UPnP. One listening on <c>ff02::1:2</c> is looking for a DHCPv6
    /// server. This reveals which services a device runs without touching a
    /// single port, and without anything appearing in the device's log.
    /// </para>
    /// <para>
    /// <b>Listening rather than asking, and why.</b> A general MLD query,
    /// which all devices would have to answer, could be sent. It requires the
    /// Router Alert option in the IPv6 header, however, which cannot be set
    /// with the sockets .NET provides, and receivers discard a query without
    /// it (RFC 3810, section 6.2). Sending a packet that half the devices are
    /// known to drop would only be noise. Instead the method listens: devices
    /// report on their own when they join a group, and they answer the
    /// router's periodic query. That is why the time window here is
    /// considerably longer than for the other methods.
    /// </para>
    /// </summary>
    public sealed class Ipv6MulticastGroupScanMethod : Ipv6MethodBase
    {
        public override string Id => "ipv6.multicastgroups";
        public override string DisplayName => "IPv6 multicast groups (MLD)";

        public override string Explanation =>
            "Listens in on which multicast groups the devices around you have joined - " +
            "and a group is a service in disguise: a device listening on the mDNS group " +
            "is an Apple device, a printer or a TV; one listening on the UPnP group " +
            "offers media or port forwarding; one listening on the DHCPv6 group is " +
            "looking for a server. So you learn what a device runs without touching a " +
            "single port and without leaving a trace in its log. Purely passive, which " +
            "is also the catch: it only finds devices that happen to announce themselves " +
            "while it listens. Linux only, and there it needs the right to read raw " +
            "packets - Windows never hands these reports to a program at all.";

        protected override Ipv6Discovery Discovery => Ipv6Discovery.ListenMulticastGroups;

        public override bool IsPassive => true;
        public override bool RequiresElevation => true;

        /// <summary>
        /// Considerably longer than for the other methods, because nothing is
        /// triggered here: only what arrives unsolicited is seen. Fifteen
        /// seconds catch the joins on a busy segment but stay short enough
        /// that a scan does not stall on it.
        /// </summary>
        private static readonly TimeSpan ListenWindow = TimeSpan.FromSeconds(15);

        public override ScanMethodAvailability CheckAvailability(ScanContext context)
        {
            ScanMethodAvailability basic = base.CheckAvailability(context);
            if (!basic.CanRun) return basic;

            // Unlike router advertisements, there is no fallback here: the
            // local network stack does not know which groups *another* device
            // has joined. This information exists only in the packets.
            if (!Icmpv6Channel.RawReceiveSupported)
            {
                return ScanMethodAvailability.Blocked(
                    "Not available on Windows: it hands ICMPv6 to its own network stack and " +
                    "never to a program, no matter the rights - measured, not assumed. " +
                    "Reading these reports would need a capture driver such as Npcap, and " +
                    "this program deliberately installs nothing. Works on Linux.");
            }

            return Icmpv6Channel.RawSocketsUsable
                ? ScanMethodAvailability.Available
                : ScanMethodAvailability.Blocked(NoRawSocketReason("multicast group reports"));
        }

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(context);

            List<Ipv6Segment> segments = Segments(context);
            if (segments.Count == 0) return;

            int done = 0;
            int listeners = 0;

            foreach (Ipv6Segment segment in segments)
            {
                cancellationToken.ThrowIfCancellationRequested();

                listeners += await ListenOnAsync(context, segment, cancellationToken);

                done++;
                context.ReportProgress(done, listeners, segments.Count);
            }
        }

        private async Task<int> ListenOnAsync(
            ScanContext context,
            Ipv6Segment segment,
            CancellationToken cancellationToken)
        {
            using Icmpv6Channel? channel = Icmpv6Channel.TryOpen(segment.Interface, segment.InterfaceIndex, wantRaw: true);
            if (channel is null) return 0;

            // Groups are collected per device rather than reported at once: a
            // device spreads its groups over several messages, and only the
            // complete set yields the service list.
            Dictionary<string, GroupSighting> byDevice = [];

            await ListenAsync(channel, ListenWindow, (buffer, length, sender) =>
            {
                int type = Icmpv6Channel.TypeOf(buffer, length);

                if (type is not (Icmpv6Channel.MulticastListenerReportV1
                              or Icmpv6Channel.MulticastListenerReportV2)) return;

                MulticastListenerReport? report =
                    Icmpv6Parser.ParseMulticastListenerReport(buffer.AsSpan(0, length), sender);

                if (report is null) return;

                // The unspecified address appears in reports sent during
                // address configuration. It belongs to no particular device.
                if (IPAddress.IPv6Any.Equals(sender)) return;

                string key = sender.ToString();
                if (!byDevice.TryGetValue(key, out GroupSighting? sighting))
                {
                    sighting = new GroupSighting(sender);
                    byDevice[key] = sighting;
                }

                foreach (IPAddress group in report.Groups) sighting.Groups.Add(group.ToString());
            }, cancellationToken);

            foreach (GroupSighting sighting in byDevice.Values) ReportListener(context, segment, sighting);

            return byDevice.Count;
        }

        private sealed class GroupSighting(IPAddress address)
        {
            public IPAddress Address { get; } = address;
            public SortedSet<string> Groups { get; } = new(StringComparer.OrdinalIgnoreCase);
        }

        private void ReportListener(ScanContext context, Ipv6Segment segment, GroupSighting sighting)
        {
            Dictionary<string, string> details = new()
            {
                ["Multicast groups"] = string.Join(", ", sighting.Groups)
            };

            List<string> services = [.. sighting.Groups.Select(ServiceBehind).Where(s => s is not null).Distinct()!];
            if (services.Count > 0) details["Implied services"] = string.Join(", ", services);

            ReportAddress(context, segment, sighting.Address, details: details);
        }

        /// <summary>
        /// The service behind a known group address. The mapping follows the
        /// IANA registry of IPv6 multicast addresses; unknown groups stay
        /// uninterpreted rather than being guessed.
        /// </summary>
        private static string? ServiceBehind(string group) => group.ToLowerInvariant() switch
        {
            "ff02::fb" or "ff05::fb" => "mDNS (Bonjour/Avahi - Apple devices, printers, TVs)",
            "ff02::c" or "ff05::c" => "SSDP/UPnP (media servers, routers, smart home)",
            "ff02::1:2" or "ff05::1:2" => "DHCPv6 client (looking for a server)",
            "ff02::1:3" or "ff05::1:3" => "LLMNR (Windows name resolution)",
            "ff02::2" => "Router",
            "ff02::16" => "MLDv2 capable",
            "ff02::6a" => "All snoopers",
            "ff02::101" or "ff05::101" => "NTP (time service)",
            "ff02::9" => "RIPng (routing protocol)",
            "ff02::a" => "EIGRP (Cisco routing protocol)",
            "ff02::5" or "ff02::6" => "OSPFv3 (routing protocol)",
            "ff02::d" => "PIM (multicast routing)",
            "ff02::12" => "VRRP (redundant gateway)",
            "ff02::1:ff00:0" => null,   // Solicited-node: every device has one, says nothing
            _ => null
        };
    }
}
