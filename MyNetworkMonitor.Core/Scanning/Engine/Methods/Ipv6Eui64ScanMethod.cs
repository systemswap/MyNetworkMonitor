// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net;
using System.Net.NetworkInformation;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// Builds the corresponding EUI-64 address from every MAC address already
    /// known and probes it.
    /// <para>
    /// The technique: a MAC address converts unambiguously into a 64-bit
    /// interface identifier (modified EUI-64, RFC 4291, appendix A): insert
    /// <c>ff:fe</c> in the middle and flip one bit. A device that forms its
    /// IPv6 address in this classic way therefore has a <b>predictable</b>
    /// address. 254 IPv4 findings of the ping pass thus become 254 targeted
    /// IPv6 probes instead of 18 quintillion possibilities.
    /// </para>
    /// <para>
    /// <b>Runs at the end of the discovery phase, which is not a matter of
    /// taste.</b> The method depends on what ARP, ping and the neighbor cache
    /// have collected; run first, it knows no MAC and finds nothing. The
    /// engine runs the methods of a phase in registration order, so this
    /// method is registered last.
    /// </para>
    /// <para>
    /// Not preselected: it only finds devices that still derive their address
    /// from the MAC. Windows and the mobile operating systems use random
    /// interface identifiers (privacy extensions) instead. Printers, cameras,
    /// controllers and older embedded devices still use EUI-64, and they are
    /// often exactly the devices being looked for.
    /// </para>
    /// </summary>
    public sealed class Ipv6Eui64ScanMethod : Ipv6MethodBase
    {
        public override string Id => "ipv6.eui64";
        public override string DisplayName => "IPv6 from known MACs";

        public override string Explanation =>
            "Takes the hardware addresses (MACs) already found in this scan and works out " +
            "what IPv6 address each device would have if it built one the classic way - " +
            "the rule for that is fixed, so the address can be calculated rather than " +
            "guessed. That turns an unsearchable IPv6 network into a short, targeted " +
            "list. Printers, cameras, controllers and older embedded devices still do it " +
            "this way; Windows, phones and Macs pick a random address instead and will " +
            "not be found here. Run it after Ping or ARP, otherwise it has no MACs to " +
            "work from.";

        protected override Ipv6Discovery Discovery => Ipv6Discovery.Eui64FromKnownMacs;

        public override ScanMethodAvailability CheckAvailability(ScanContext context)
        {
            ScanMethodAvailability basic = base.CheckAvailability(context);
            if (!basic.CanRun) return basic;

            // Without known MAC addresses there is nothing to calculate. Not an
            // error; it means the discovery methods have to run first.
            if (KnownMacs(context).Count == 0)
            {
                return ScanMethodAvailability.NotApplicable(
                    "No hardware addresses known yet. Run Ping, ARP or the neighbour table first - " +
                    "this method builds on what they find.");
            }

            return ScanMethodAvailability.Available;
        }

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(context);

            List<Ipv6Segment> segments = Segments(context);
            if (segments.Count == 0) return;

            List<PhysicalAddress> macs = KnownMacs(context);
            if (macs.Count == 0) return;

            List<Ipv6Candidate> candidates = [];
            HashSet<string> seen = [];

            foreach (Ipv6Segment segment in segments)
            {
                List<Ipv6Prefix> prefixes = Ipv6Prefixes.ForInterface(segment.Interface, segment.InterfaceIndex);

                foreach (PhysicalAddress mac in macs)
                {
                    byte[]? interfaceId = Ipv6Prefixes.Eui64FromMac(mac);
                    if (interfaceId is null) continue;

                    foreach (Ipv6Prefix prefix in prefixes)
                    {
                        IPAddress address = prefix.Combine(interfaceId);
                        if (!seen.Add(address.ToString())) continue;

                        candidates.Add(new Ipv6Candidate
                        {
                            Segment = segment,
                            Address = address,
                            Origin = $"Derived from MAC {Format(mac)}"
                        });
                    }
                }
            }

            await ProbeCandidatesAsync(context, candidates, cancellationToken);
        }

        /// <summary>
        /// All MAC addresses in the store so far.
        /// <para>
        /// Addresses already present as EUI-64 are not skipped: that a device
        /// is addressed this way under <em>one</em> prefix does not mean it is
        /// absent under the others. Duplicate targets are filtered by the set
        /// in <see cref="ExecuteAsync"/>.
        /// </para>
        /// </summary>
        private static List<PhysicalAddress> KnownMacs(ScanContext context)
        {
            List<PhysicalAddress> macs = [];
            HashSet<string> seen = [];

            lock (context.Store.SyncRoot)
            {
                foreach (Device device in context.Store.Devices)
                {
                    if (device.Mac is null) continue;
                    if (!seen.Add(device.Mac.ToString())) continue;

                    macs.Add(device.Mac);
                }
            }

            return macs;
        }

        private static string Format(PhysicalAddress mac) =>
            string.Join('-', mac.GetAddressBytes().Select(b => b.ToString("x2")));
    }
}
