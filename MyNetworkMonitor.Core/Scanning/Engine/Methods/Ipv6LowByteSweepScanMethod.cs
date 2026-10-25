// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// Tries the low addresses of a prefix, <c>::1</c> through <c>::ff</c>.
    /// <para>
    /// Why this works despite 18 quintillion possible addresses per /64:
    /// <b>manually assigned addresses are small</b>. A statically addressed
    /// server, switch or printer gets <c>::1</c>, <c>::10</c> or <c>::100</c>;
    /// nobody types in a random 64-bit number. These devices are also the
    /// interesting ones, and exactly those the other methods find poorly: they
    /// are often on a different segment and answer neither multicast nor
    /// neighbor discovery there.
    /// </para>
    /// <para>
    /// Not preselected for that reason (it is not part of
    /// <see cref="Ipv6Discovery.Default"/>): it is the only one of the six
    /// that sends a significant number of packets to addresses where mostly
    /// nobody is.
    /// </para>
    /// </summary>
    public sealed class Ipv6LowByteSweepScanMethod : Ipv6MethodBase
    {
        public override string Id => "ipv6.lowbytesweep";
        public override string DisplayName => "IPv6 low address sweep";

        public override string Explanation =>
            "Tries the low addresses of your IPv6 network, ::1 through ::ff. It sounds " +
            "hopeless - an IPv6 network holds more addresses than could ever be tried - " +
            "but addresses handed out by a person are always small ones: servers, " +
            "switches, printers and firewalls get ::1 or ::10, never a random number. " +
            "Those are usually the devices you care about, and the other methods miss " +
            "them when they sit in a different part of the network. Costs a few hundred " +
            "packets, so it is off unless you switch it on.";

        protected override Ipv6Discovery Discovery => Ipv6Discovery.LowByteSweep;

        /// <summary>
        /// There is a target list, and unlike for the other five it can be
        /// counted. A "known devices only" checkbox would still be pointless
        /// here: the list consists precisely of addresses nobody knows yet.
        /// </summary>
        public override bool EnumeratesTargets => false;

        /// <summary>
        /// Upper end of the sweep. 0xff covers what people assign manually;
        /// beyond that the effort grows linearly but the yield does not.
        /// </summary>
        private const int HighestLowByte = 0xFF;

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(context);

            List<Ipv6Segment> segments = Segments(context);
            if (segments.Count == 0) return;

            List<Ipv6Candidate> candidates = [];
            HashSet<string> seen = [];

            foreach (Ipv6Segment segment in segments)
            {
                foreach (Ipv6Prefix prefix in PrefixesFor(segment))
                {
                    for (int low = 1; low <= HighestLowByte; low++)
                    {
                        IPAddress address = prefix.Combine([(byte)(low >> 8), (byte)low]);

                        // The same address can result from two prefixes when
                        // scopes overlap.
                        if (!seen.Add(address.ToString())) continue;

                        candidates.Add(new Ipv6Candidate
                        {
                            Segment = segment,
                            Address = address,
                            Origin = $"Low address sweep on {prefix.Network}/{prefix.Length}"
                        });
                    }
                }
            }

            await ProbeCandidatesAsync(context, candidates, cancellationToken);
        }

        /// <summary>
        /// The prefixes to sweep. A scope of kind
        /// <see cref="ScanScopeKind.IPv6Prefix"/> specifies its prefix
        /// explicitly; then only that prefix applies, since that is what it
        /// was configured for. Otherwise the prefixes come from the interface.
        /// </summary>
        private static List<Ipv6Prefix> PrefixesFor(Ipv6Segment segment)
        {
            if (segment.Scope.Scope.Kind == ScanScopeKind.IPv6Prefix &&
                IPAddress.TryParse(segment.Scope.Scope.Prefix, out IPAddress? declared) &&
                declared.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                int length = segment.Scope.Scope.PrefixLength;

                return
                [
                    new Ipv6Prefix
                    {
                        Network = Ipv6Prefixes.Mask(declared, length),
                        Length = length,
                        Origin = "range setting",
                        ScopeId = declared.IsIPv6LinkLocal ? segment.InterfaceIndex : 0
                    }
                ];
            }

            return Ipv6Prefixes.ForInterface(segment.Interface, segment.InterfaceIndex);
        }
    }
}
