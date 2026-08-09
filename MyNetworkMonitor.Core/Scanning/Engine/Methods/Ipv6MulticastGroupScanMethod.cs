using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// Hoert die MLD-Berichte mit - die Meldungen, mit denen Geraete dem Netz
    /// mitteilen, welchen Multicast-Gruppen sie beigetreten sind.
    /// <para>
    /// Das ist das eigentuemlichste der sechs Verfahren und das mit dem
    /// hoechsten Ertrag je Paket: eine Gruppenmitgliedschaft <b>ist</b> eine
    /// Dienstauskunft. Wer in <c>ff02::fb</c> zuhoert, spricht mDNS - also ein
    /// Apple-Geraet, ein Drucker oder ein Fernseher. Wer in <c>ff02::c</c>
    /// zuhoert, spricht UPnP. Wer in <c>ff02::1:2</c> zuhoert, sucht einen
    /// DHCPv6-Server. Man erfaehrt also, welche Dienste ein Geraet betreibt,
    /// ohne einen einzigen Port angefasst zu haben - und ohne dass im Protokoll
    /// des Geraets etwas auftaucht.
    /// </para>
    /// <para>
    /// <b>Zuhoeren, nicht fragen - und warum.</b> Es gaebe die Moeglichkeit,
    /// eine allgemeine MLD-Abfrage zu senden, auf die alle Geraete antworten
    /// muessten. Sie braucht aber die Router-Alert-Option im IPv6-Kopf, und
    /// die laesst sich mit den Sockets, die .NET anbietet, nicht setzen -
    /// Empfaenger nach RFC 3810 verwerfen eine Abfrage ohne sie. Ein Paket zu
    /// senden, von dem feststeht, dass die Haelfte der Geraete es wegwirft,
    /// waere nur Laerm. Stattdessen wird zugehoert: Geraete melden sich von
    /// selbst, wenn sie einer Gruppe beitreten, und beantworten die regelmaessige
    /// Abfrage des Routers. Deshalb ist das Zeitfenster hier deutlich groesser
    /// als bei den uebrigen Verfahren.
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
        /// Deutlich laenger als bei den uebrigen Verfahren, weil hier nichts
        /// angestossen wird: es kommt, was von selbst kommt. Fuenfzehn Sekunden
        /// fangen in einem belebten Segment die Beitritte mit, bleiben aber
        /// kurz genug, dass ein Scan nicht daran haengt.
        /// </summary>
        private static readonly TimeSpan ListenWindow = TimeSpan.FromSeconds(15);

        public override ScanMethodAvailability CheckAvailability(ScanContext context)
        {
            ScanMethodAvailability basic = base.CheckAvailability(context);
            if (!basic.CanRun) return basic;

            // Anders als bei der Router-Ankuendigung gibt es hier keinen
            // Ersatzweg: welchen Gruppen ein *fremdes* Geraet beigetreten ist,
            // weiss der eigene Netzwerkstapel nicht. Diese Auskunft steht
            // ausschliesslich in den Paketen.
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

            // Je Geraet die Gruppen sammeln statt sofort melden: ein Geraet
            // schickt seine Gruppen ueber mehrere Nachrichten verteilt, und
            // erst die vollstaendige Menge ergibt die Dienstliste.
            Dictionary<string, GroupSighting> byDevice = [];

            await ListenAsync(channel, ListenWindow, (buffer, length, sender) =>
            {
                int type = Icmpv6Channel.TypeOf(buffer, length);

                if (type is not (Icmpv6Channel.MulticastListenerReportV1
                              or Icmpv6Channel.MulticastListenerReportV2)) return;

                MulticastListenerReport? report =
                    Icmpv6Parser.ParseMulticastListenerReport(buffer.AsSpan(0, length), sender);

                if (report is null) return;

                // Die unbestimmte Adresse steht in Berichten waehrend der
                // Adressbildung. Sie gehoert zu keinem bestimmten Geraet.
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
        /// Welcher Dienst hinter einer bekannten Gruppenadresse steht. Die
        /// Zuordnung stammt aus der IANA-Liste der IPv6-Multicast-Adressen;
        /// unbekannte Gruppen bleiben ohne Deutung, statt geraten zu werden.
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
            "ff02::1:ff00:0" => null,   // Solicited-Node - hat jedes Geraet, sagt nichts
            _ => null
        };
    }
}
