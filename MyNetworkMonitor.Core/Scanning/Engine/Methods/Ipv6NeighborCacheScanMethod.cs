using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// Reads the operating system's neighbor table, the IPv6 counterpart of
    /// the ARP table.
    /// <para>
    /// Deliberately the first of the six methods: it sends not a single
    /// packet, needs no privileges and returns immediately. Everything the
    /// local machine has recently exchanged data with is already listed.
    /// </para>
    /// <para>
    /// Under IPv6 the table carries two pieces of information that do not
    /// exist under IPv4 and are evaluated here: the entry state and the
    /// router flag. The state separates real neighbors from mere resolution
    /// attempts; an entry in state <c>INCOMPLETE</c> only shows that the
    /// local machine has asked, not that anyone is there. Reporting it as a
    /// found device would be a fabrication.
    /// </para>
    /// </summary>
    public sealed class Ipv6NeighborCacheScanMethod : Ipv6MethodBase
    {
        public override string Id => "ipv6.neighborcache";
        public override string DisplayName => "IPv6 neighbour table";

        public override string Explanation =>
            "Looks into a list your own computer already keeps: every IPv6 device it has " +
            "recently exchanged data with, with hardware address (MAC) and whether that " +
            "device is a router. Costs nothing and disturbs nobody - not a single packet " +
            "leaves the machine, so nothing shows up in any log. The catch is the same as " +
            "with the ARP table: it only knows devices your computer has actually talked " +
            "to. Best used together with the multicast ping, which makes the others talk " +
            "first.";

        protected override Ipv6Discovery Discovery => Ipv6Discovery.NeighborCache;

        /// <summary>Listening rather than asking; no packet is sent.</summary>
        public override bool IsPassive => true;

        public override ScanMethodAvailability CheckAvailability(ScanContext context)
        {
            if (PlatformServices.NeighborsOrNull is null)
            {
                return ScanMethodAvailability.Blocked(
                    "No neighbour table provider registered. This platform is not supported yet.");
            }

            return base.CheckAvailability(context);
        }

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(context);

            List<Ipv6Segment> segments = Segments(context);
            if (segments.Count == 0) return;

            INeighborProvider? provider = PlatformServices.NeighborsOrNull;
            if (provider is null) return;

            IReadOnlyList<NeighborEntry> entries = await provider.GetNeighborsAsync(cancellationToken);

            cancellationToken.ThrowIfCancellationRequested();

            int reported = Report(context, segments, entries);

            // The table is a snapshot: once read, there is no progress to
            // show. The final count is still reported, so that it is visible
            // that the method ran; a method without numbers looks like one
            // that was skipped.
            context.ReportProgress(entries.Count, reported, entries.Count);
        }

        /// <summary>
        /// Reports all usable IPv6 entries and returns their number. A separate
        /// method because the multicast ping needs the same evaluation: without
        /// a raw socket, it also collects its answers from this table.
        /// </summary>
        internal static int Report(
            ScanContext context,
            IReadOnlyList<Ipv6Segment> segments,
            IReadOnlyList<NeighborEntry> entries,
            string? sourceOverride = null)
        {
            Dictionary<int, Ipv6Segment> byIndex = [];
            foreach (Ipv6Segment segment in segments) byIndex[segment.InterfaceIndex] = segment;

            int reported = 0;

            foreach (NeighborEntry entry in entries)
            {
                if (entry.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6) continue;

                // Only entries that actually stand for a device.
                if (!entry.IsUsable) continue;

                // Multicast addresses appear in the table but are not devices:
                // ff02::1 addresses everyone, not one.
                IpAddressInfo info = IpAddressAnalyzer.Analyze(entry.Address);
                if (info.Scope is IpAddressScope.Multicast
                                or IpAddressScope.Loopback
                                or IpAddressScope.Unspecified) continue;

                // An entry without a matching interface belongs to a segment
                // that is not to be scanned.
                if (!byIndex.TryGetValue(entry.InterfaceIndex, out Ipv6Segment? segment))
                {
                    continue;
                }

                Dictionary<string, string> details = new()
                {
                    ["Neighbour state"] = entry.State.ToString()
                };

                // Who routes on the segment is the first question of any IPv6
                // investigation, and the table answers it for free.
                if (entry.IsRouter) details["Role"] = "Router (announces itself on this segment)";

                context.Report(new DeviceObservation
                {
                    Source = sourceOverride ?? "IPv6 neighbour table",
                    Address = info,
                    Mac = entry.Mac ?? info.DerivedMac,

                    // The entry shows that the device answered at some point,
                    // not that it answers now. Only a recently confirmed entry
                    // counts as reachable.
                    IsResponding = entry.State is NeighborState.Reachable,

                    GroupDescription = segment.Scope.Scope.GroupDescription,
                    Domain = string.IsNullOrWhiteSpace(segment.Scope.Scope.Domain)
                        ? null
                        : segment.Scope.Scope.Domain,
                    Details = details
                });

                reported++;
            }

            return reported;
        }
    }
}
