using System.Net;
using System.Net.Sockets;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// Hoert die Ankuendigungen der Router mit - und fragt einmal nach, statt
    /// zu warten.
    /// <para>
    /// Eine Router-Ankuendigung ist die aufschlussreichste Nachricht im
    /// IPv6-Segment. Sie nennt in einem Paket: wer routet, welche Praefixe
    /// gelten, welche Namensserver zustaendig sind, wie gross die Pakete sein
    /// duerfen - und ueber zwei Bits, ob zusaetzlich ein DHCPv6-Server
    /// arbeitet. Unter IPv4 braeuchte man dafuer DHCP-Mitschnitt, SNMP und
    /// Routenabfrage nebeneinander.
    /// </para>
    /// <para>
    /// <b>Warum hier gesendet wird, obwohl das Verfahren "mithoeren" heisst:</b>
    /// Router kuendigen von sich aus nur alle paar Minuten an - laenger, als
    /// ein Scan dauern darf. Deshalb geht zuerst eine Router-Anfrage
    /// (<c>Router Solicitation</c>) an <c>ff02::2</c> hinaus. Darauf antwortet
    /// jeder Router binnen Sekunden. Genau das tut jedes Geraet beim
    /// Einschalten; es ist der vorgesehene Weg und faellt niemandem auf.
    /// </para>
    /// <para>
    /// Die gefundenen Praefixe sind zugleich die Grundlage der beiden
    /// Rateverfahren: erst wenn bekannt ist, welches /64 im Segment gilt,
    /// koennen sie darauf Adressen bilden.
    /// </para>
    /// <para>
    /// <b>Zwei Wege, je nach Plattform</b> - und das Verfahren laeuft auf
    /// beiden, statt unter Windows auszufallen:
    /// </para>
    /// <list type="number">
    /// <item>
    /// <b>Mithoeren</b> (Linux, mit <c>CAP_NET_RAW</c>): die Ankuendigung wird
    /// im Original gelesen. Vollstaendig, einschliesslich MTU, Lebensdauern
    /// und der Frage, welcher Router was sagt.
    /// </item>
    /// <item>
    /// <b>Den Stapel fragen</b> (Windows): Windows liefert ICMPv6 nicht an
    /// Rohsockets aus - nachgemessen, siehe
    /// <see cref="Icmpv6Channel.RawReceiveSupported"/>. Es <em>hat</em> die
    /// Ankuendigungen aber empfangen und ausgewertet, sonst haette der Rechner
    /// keine IPv6-Adresse. Also wird das Ergebnis ausgelesen statt das Paket:
    /// Router, Praefixe, Namensserver und die Herkunft jeder Adresse stehen in
    /// gewoehnlichen APIs. Das kostet die Momentaufnahme, nicht den Inhalt -
    /// und braucht dort <b>keine</b> Administratorrechte.
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
        /// Nicht zwingend: wo kein Rohsocket zu haben ist, wird der
        /// Netzwerkstapel ausgelesen. Ein ausgegrautes Kaestchen waere die
        /// falsche Auskunft, weil das Verfahren dort trotzdem etwas liefert.
        /// </summary>
        public override bool RequiresElevation => false;

        /// <summary>
        /// Wie lange auf Ankuendigungen gewartet wird. Router antworten auf
        /// eine Anfrage nach einer zufaelligen Verzoegerung von bis zu einer
        /// halben Sekunde (RFC 4861); vier Sekunden lassen auch einem
        /// langsamen Geraet Zeit und fangen nebenbei eine turnusmaessige
        /// Ankuendigung mit.
        /// </summary>
        private static readonly TimeSpan ListenWindow = TimeSpan.FromSeconds(4);

        /// <summary>
        /// Immer verfuegbar, sobald IPv6 im Segment nutzbar ist - notfalls
        /// ueber den Stapel. Fehlende Rechte sind hier kein Hindernis, sondern
        /// nur der Unterschied zwischen "im Original gelesen" und "das
        /// Ergebnis ausgelesen".
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

            // Kein Kanal zum Mithoeren: dann das nehmen, was der Stapel aus
            // den Ankuendigungen gemacht hat.
            if (channel is null) return FromStack(context, segment);

            await SolicitAsync(channel, cancellationToken);

            HashSet<string> seen = [];

            await ListenAsync(channel, ListenWindow, (buffer, length, sender) =>
            {
                if (Icmpv6Channel.TypeOf(buffer, length) != Icmpv6Channel.RouterAdvertisement) return;

                // Ein Router kuendigt im Zeitfenster oft mehrfach an.
                if (!seen.Add(sender.ToString())) return;

                RouterAdvertisement? advertisement =
                    Icmpv6Parser.ParseRouterAdvertisement(buffer.AsMemory(0, length), sender);

                if (advertisement is not null) ReportRouter(context, segment, advertisement);
            }, cancellationToken);

            // Auch mit Rohsocket kann das Fenster leer bleiben - dann greift
            // derselbe Ausweg, statt "nichts gefunden" zu melden, obwohl der
            // Rechner nachweislich einen Router kennt.
            return seen.Count > 0 ? seen.Count : FromStack(context, segment);
        }

        // ------------------------------------------------- Weg 2: der Stapel

        /// <summary>
        /// Meldet, was das Betriebssystem aus den Ankuendigungen gemacht hat.
        /// <para>
        /// Die Angaben werden bewusst als solche gekennzeichnet: sie stammen
        /// aus dem Netzwerkstapel und nicht aus einem gerade empfangenen
        /// Paket. Wer die Zeile spaeter liest, muss den Unterschied erkennen
        /// koennen - hier steht nicht, wann ein Router das gesagt hat, nur
        /// dass er es gesagt hat.
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

            // Ohne bekanntes Gateway gibt es kein Geraet, an das sich die
            // Angaben haengen liessen. Sie dann an eine erfundene Adresse zu
            // melden waere schlimmer als sie wegzulassen.
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
        /// Sendet eine Router-Anfrage an <c>ff02::2</c> - "alle Router".
        /// Aufbau nach RFC 4861: Typ, Code, Pruefsumme, vier reservierte Byte.
        /// Die Angabe der eigenen MAC ist zulaessig, aber freiwillig; sie
        /// bleibt weg, damit die Anfrage so wenig wie moeglich ueber uns
        /// verraet.
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
                // Geht die Anfrage nicht hinaus, bleibt das Zuhoeren - eine
                // turnusmaessige Ankuendigung kommt ohnehin irgendwann.
            }
        }

        /// <summary>
        /// Macht aus einer Ankuendigung eine Sichtung. Der Router ist das
        /// Geraet; alles Uebrige - Praefixe, Namensserver, DHCPv6-Hinweis -
        /// haengt als Angabe daran, weil es dieser Router bekanntgibt.
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

            // Die beiden Bits sagen, woher die Geraete im Segment ihre
            // Angaben bekommen. Das beantwortet die Frage, warum ein Geraet
            // eine Adresse hat, die zu keinem angekuendigten Praefix passt.
            details["Address configuration"] = advertisement.ManagedAddressConfiguration
                ? "DHCPv6 (managed)"
                : advertisement.OtherConfiguration
                    ? "Self-assigned, other settings from DHCPv6"
                    : "Self-assigned (SLAAC only)";

            ReportAddress(context, segment, advertisement.Router, advertisement.RouterMac, details: details);
        }
    }
}
