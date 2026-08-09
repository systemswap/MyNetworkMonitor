using System.Net;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// Probiert die niedrigen Adressen eines Praefixes durch - <c>::1</c> bis
    /// <c>::ff</c>.
    /// <para>
    /// Der Grund, warum das trotz 18 Trillionen moeglicher Adressen je /64
    /// funktioniert: <b>von Hand vergebene Adressen sind klein</b>. Wer einen
    /// Server, einen Switch oder einen Drucker fest adressiert, nimmt <c>::1</c>,
    /// <c>::10</c>, <c>::100</c> - niemand tippt eine zufaellige 64-Bit-Zahl ab.
    /// Genau diese Geraete sind zugleich die interessanten, und genau sie
    /// finden die uebrigen Verfahren schlecht: sie stehen oft in einem anderen
    /// Segment und antworten dort weder auf Multicast noch auf Neighbor
    /// Discovery.
    /// </para>
    /// <para>
    /// Deshalb ist dieses Verfahren nicht voreingestellt (es steht nicht in
    /// <see cref="Ipv6Discovery.Default"/>): es sendet als einziges der sechs
    /// nennenswert viele Pakete an Adressen, an denen ueberwiegend niemand ist.
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
        /// Es gibt eine Zielliste - und anders als bei den uebrigen fuenf
        /// laesst sie sich auch beziffern. Ein Kaestchen "nur bekannte Geraete"
        /// waere hier trotzdem sinnlos: die Liste besteht gerade aus Adressen,
        /// die noch niemand kennt.
        /// </summary>
        public override bool EnumeratesTargets => false;

        /// <summary>
        /// Wie weit hochgezaehlt wird. 0xff deckt ab, was Menschen vergeben;
        /// darueber hinaus stiege der Aufwand linear, der Ertrag aber nicht.
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

                        // Dieselbe Adresse kann aus zwei Praefixen entstehen,
                        // wenn sich Bereiche ueberschneiden.
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
        /// Die Praefixe, die durchprobiert werden. Ein Bereich vom Typ
        /// <see cref="ScanScopeKind.IPv6Prefix"/> gibt seines ausdruecklich vor
        /// - dann gilt nur dieses, denn genau dafuer hat der Nutzer es
        /// eingetragen. Sonst kommen sie vom Adapter.
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
