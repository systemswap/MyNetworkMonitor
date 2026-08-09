using System.Net;
using System.Net.NetworkInformation;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// Bildet aus jeder bereits bekannten MAC-Adresse die zugehoerige
    /// EUI-64-Adresse und prueft sie.
    /// <para>
    /// Der Kunstgriff: eine MAC-Adresse laesst sich nach RFC 4291 eindeutig in
    /// einen 64 Bit langen Interface-Identifier umrechnen - <c>ff:fe</c> in die
    /// Mitte, ein Bit umkippen. Ein Geraet, das seine IPv6-Adresse auf diese
    /// klassische Weise bildet, hat damit eine <b>vorhersagbare</b> Adresse.
    /// Aus 254 IPv4-Funden des Ping-Durchlaufs werden so 254 gezielte
    /// IPv6-Proben statt 18 Trillionen Moeglichkeiten.
    /// </para>
    /// <para>
    /// <b>Steht am Ende der Suchstufe, und das ist keine Geschmacksfrage.</b>
    /// Das Verfahren lebt von dem, was ARP, Ping und der Neighbor Cache vorher
    /// eingesammelt haben - laeuft es zuerst, kennt es keine einzige MAC und
    /// findet nichts. Die Engine fuehrt die Verfahren einer Stufe in der
    /// Reihenfolge ihrer Registrierung aus; deshalb wird es dort als letztes
    /// eingetragen.
    /// </para>
    /// <para>
    /// Nicht voreingestellt: es findet nur Geraete, die ihre Adresse noch aus
    /// der MAC bilden. Windows und die Mobilbetriebssysteme tun das seit Jahren
    /// nicht mehr, sie wuerfeln (Privacy Extensions). Drucker, Kameras,
    /// Steuerungen und aeltere eingebettete Geraete dagegen schon - und die
    /// sind haeufig genau die, die man sucht.
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

            // Ohne bekannte MAC-Adressen gibt es nichts zu rechnen. Das ist
            // kein Fehler, sondern heisst: erst suchen lassen, dann hierher.
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
        /// Alle MAC-Adressen aus dem bisherigen Bestand.
        /// <para>
        /// Adressen, die bereits als EUI-64 vorliegen, werden dabei nicht
        /// ausgelassen: dass ein Geraet unter <em>einem</em> Praefix so
        /// adressiert ist, heisst nicht, dass es unter den uebrigen fehlt.
        /// Doppelte Ziele faengt die Menge in
        /// <see cref="ExecuteAsync"/> ab.
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
