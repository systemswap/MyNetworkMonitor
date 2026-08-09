using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// Liest die Nachbarschaftstabelle des Betriebssystems aus - das
    /// IPv6-Gegenstueck zur ARP-Tabelle.
    /// <para>
    /// Steht bewusst als erstes der sechs Verfahren: es sendet kein einziges
    /// Paket, braucht keine Rechte und liefert sofort. Alles, womit der eigene
    /// Rechner in letzter Zeit gesprochen hat, steht schon da.
    /// </para>
    /// <para>
    /// Die Tabelle traegt unter IPv6 zwei Angaben, die es unter IPv4 nicht
    /// gibt und die hier ausgewertet werden: den Zustand des Eintrags und das
    /// Router-Merkmal. Der Zustand trennt echte Nachbarn von blossen
    /// Anfrageversuchen - ein Eintrag im Zustand <c>INCOMPLETE</c> bezeugt nur,
    /// dass <em>wir</em> gefragt haben, nicht dass jemand da ist. Ihn als
    /// gefundenes Geraet zu melden waere eine Erfindung.
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

        /// <summary>Zuhoeren statt fragen - es geht kein Paket hinaus.</summary>
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

            // Die Tabelle ist eine Momentaufnahme: gelesen ist gelesen, es gibt
            // keinen Fortschritt zu zeigen. Der Endstand steht trotzdem in der
            // Anzeige, damit man sieht, dass das Verfahren gelaufen ist - ein
            // Verfahren ohne Zahlen sieht aus wie eines, das uebersprungen wurde.
            context.ReportProgress(entries.Count, reported, entries.Count);
        }

        /// <summary>
        /// Meldet alle brauchbaren IPv6-Eintraege und liefert deren Anzahl.
        /// Ausgelagert, weil der Multicast-Ping dieselbe Auswertung braucht:
        /// ohne Rohsocket sammelt er seine Antworten ebenfalls aus dieser
        /// Tabelle ein.
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

                // Nur Eintraege, hinter denen tatsaechlich ein Geraet steht.
                if (!entry.IsUsable) continue;

                // Multicast-Adressen stehen in der Tabelle, sind aber kein
                // Geraet: ff02::1 ist die Ansprache aller, nicht eines.
                IpAddressInfo info = IpAddressAnalyzer.Analyze(entry.Address);
                if (info.Scope is IpAddressScope.Multicast
                                or IpAddressScope.Loopback
                                or IpAddressScope.Unspecified) continue;

                // Ein Eintrag ohne zugeordneten Adapter gehoert zu einem
                // Segment, das gar nicht gescannt werden sollte.
                if (!byIndex.TryGetValue(entry.InterfaceIndex, out Ipv6Segment? segment))
                {
                    continue;
                }

                Dictionary<string, string> details = new()
                {
                    ["Neighbour state"] = entry.State.ToString()
                };

                // Wer im Segment routet, ist die erste Frage bei jeder
                // IPv6-Untersuchung - und die Tabelle beantwortet sie umsonst.
                if (entry.IsRouter) details["Role"] = "Router (announces itself on this segment)";

                context.Report(new DeviceObservation
                {
                    Source = sourceOverride ?? "IPv6 neighbour table",
                    Address = info,
                    Mac = entry.Mac ?? info.DerivedMac,

                    // Der Eintrag bezeugt, dass das Geraet einmal geantwortet
                    // hat - nicht, dass es jetzt antwortet. Nur ein frisch
                    // bestaetigter Eintrag gilt als erreichbar.
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
