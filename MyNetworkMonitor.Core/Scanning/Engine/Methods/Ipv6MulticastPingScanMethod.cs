using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// Eine Echo-Anforderung an <c>ff02::1</c> - "alle Knoten in diesem
    /// Segment". Ein Paket hinaus, viele Antworten zurueck.
    /// <para>
    /// Das ist der eigentliche Ersatz fuer den Ping-Durchlauf ueber ein
    /// IPv4-Netz, und er ist dem Original ueberlegen: 254 Anfragen und
    /// Wartezeiten werden zu einer einzigen Frage, die jedes Geraet im Segment
    /// von sich aus beantwortet. Genau deshalb faellt der Unterschied unter
    /// IPv6 nicht ins Gewicht, dass ein /64 nicht durchlaufbar ist.
    /// </para>
    /// <para>
    /// <b>Zwei Wege, je nach Rechten</b> - und das Verfahren laeuft in beiden
    /// Faellen, statt ohne Administratorrechte auszufallen:
    /// </para>
    /// <list type="number">
    /// <item>
    /// Mit ICMPv6-Socket (unter Linux meist auch ohne Sonderrechte, unter
    /// Windows mit Administratorrechten): die Anforderung geht hinaus und
    /// <em>jede</em> Antwort wird eingesammelt. Das vollstaendige Ergebnis.
    /// </item>
    /// <item>
    /// Ohne Socket: die Anforderung geht ueber
    /// <see cref="Ping"/> hinaus - der nimmt zwar nur die erste Antwort
    /// entgegen, aber das Betriebssystem traegt <em>alle</em> Antwortenden in
    /// seine Nachbarschaftstabelle ein. Die wird danach ausgelesen. Der Umweg
    /// kostet nichts und findet in der Praxis fast dasselbe.
    /// </item>
    /// </list>
    /// </summary>
    public sealed class Ipv6MulticastPingScanMethod : Ipv6MethodBase
    {
        public override string Id => "ipv6.multicastping";
        public override string DisplayName => "IPv6 multicast ping";

        public override string Explanation =>
            "Asks the whole network segment at once: \"who is there?\" Under IPv6 there is " +
            "an address that means every device on the local cable, and practically all of " +
            "them answer - phones, printers, servers, switches. One question replaces the " +
            "hundreds of single pings an IPv4 scan needs, and it finds devices whose " +
            "address you could never have guessed. It only reaches your own segment: " +
            "anything behind a router stays out of earshot. Works without administrator " +
            "rights, and with them it sees more of the answers.";

        protected override Ipv6Discovery Discovery => Ipv6Discovery.MulticastPing;

        /// <summary>
        /// Nicht zwingend: ohne erhoehte Rechte geht der Umweg ueber die
        /// Nachbarschaftstabelle. Ein Kaestchen, das ausgegraut waere, obwohl
        /// das Verfahren laeuft, waere die falsche Auskunft.
        /// </summary>
        public override bool RequiresElevation => false;

        /// <summary>
        /// Wie lange auf Antworten gewartet wird. Geraete antworten auf eine
        /// Multicast-Anfrage bewusst verzoegert und zufaellig verteilt (RFC
        /// 4443), damit nicht alle gleichzeitig senden - wer zu frueh aufhoert
        /// zuzuhoeren, verliert genau die langsamen Geraete.
        /// </summary>
        private static readonly TimeSpan ListenWindow = TimeSpan.FromSeconds(3);

        public override async Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(context);

            List<Ipv6Segment> segments = Segments(context);
            if (segments.Count == 0) return;

            int done = 0;
            int found = 0;

            foreach (Ipv6Segment segment in segments)
            {
                cancellationToken.ThrowIfCancellationRequested();

                found += await ProbeAsync(context, segment, cancellationToken);

                done++;
                context.ReportProgress(done, found, segments.Count);
            }
        }

        /// <summary>
        /// Fragt ein Segment ab. Erst der direkte Weg, sonst der Umweg - der
        /// Rueckgabewert ist die Zahl der gemeldeten Geraete.
        /// </summary>
        private async Task<int> ProbeAsync(ScanContext context, Ipv6Segment segment, CancellationToken cancellationToken)
        {
            using Icmpv6Channel? channel = Icmpv6Channel.TryOpen(segment.Interface, segment.InterfaceIndex);

            return channel is not null
                ? await ListenForRepliesAsync(context, segment, channel, cancellationToken)
                : await ViaNeighborTableAsync(context, segment, cancellationToken);
        }

        // ------------------------------------------------- Weg 1: eigener Socket

        /// <summary>
        /// Sendet die Anforderung und sammelt alles ein, was zurueckkommt.
        /// </summary>
        private async Task<int> ListenForRepliesAsync(
            ScanContext context,
            Ipv6Segment segment,
            Icmpv6Channel channel,
            CancellationToken cancellationToken)
        {
            // Die Kennung erlaubt, die eigenen Antworten von fremdem
            // ICMPv6-Verkehr zu trennen. Ein Rohsocket sieht allen Verkehr,
            // auch den anderer Programme.
            ushort identifier = (ushort)Random.Shared.Next(1, ushort.MaxValue);

            try
            {
                await channel.SendEchoAsync(
                    channel.Scoped(Icmpv6Channel.AllNodes), identifier, sequence: 1, cancellationToken);
            }
            catch (SocketException)
            {
                // Senden nicht moeglich, obwohl der Socket zustande kam - dann
                // bleibt der Umweg ueber die Tabelle.
                return await ViaNeighborTableAsync(context, segment, cancellationToken);
            }

            HashSet<string> seen = [];
            byte[] buffer = new byte[1500];

            using CancellationTokenSource window = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            window.CancelAfter(ListenWindow);

            while (!window.IsCancellationRequested)
            {
                SocketReceiveFromResult result;

                try
                {
                    result = await channel.Socket.ReceiveFromAsync(
                        buffer, SocketFlags.None, new IPEndPoint(IPAddress.IPv6Any, 0), window.Token);
                }
                catch (OperationCanceledException)
                {
                    // Das Zeitfenster ist abgelaufen. Ein Abbruch durch den
                    // Nutzer wird unten unterschieden.
                    break;
                }
                catch (SocketException)
                {
                    break;
                }

                if (Icmpv6Channel.TypeOf(buffer, result.ReceivedBytes) != Icmpv6Channel.EchoReply) continue;
                if (result.RemoteEndPoint is not IPEndPoint sender) continue;

                if (!seen.Add(sender.Address.ToString())) continue;

                ReportAddress(context, segment, sender.Address, details: new Dictionary<string, string>
                {
                    ["Answered"] = "Multicast echo to ff02::1"
                });
            }

            cancellationToken.ThrowIfCancellationRequested();

            // Der eigene Rechner antwortet auf die eigene Anfrage nicht (die
            // Rueckschleife ist abgeschaltet), steht aber ohnehin nicht zur
            // Debatte. Was die Antworten nicht hergeben - die MAC - traegt der
            // Blick in die Nachbarschaftstabelle nach, die das Betriebssystem
            // durch denselben Austausch gerade gefuellt hat.
            int viaTable = await ViaNeighborTableAsync(context, segment, cancellationToken);

            return Math.Max(seen.Count, viaTable);
        }

        // ------------------------------------------- Weg 2: Nachbarschaftstabelle

        /// <summary>
        /// Stoert das Segment mit einer Echo-Anforderung ueber
        /// <see cref="Ping"/> auf und liest anschliessend aus, wer daraufhin in
        /// der Nachbarschaftstabelle gelandet ist.
        /// <para>
        /// Der Ping selbst liefert nur eine einzige Antwort - das ist die
        /// Grenze der Klasse und laesst sich nicht umgehen. Entscheidend ist
        /// aber nicht, was <see cref="Ping"/> zurueckgibt, sondern was das
        /// Betriebssystem nebenbei lernt: es traegt jeden Antwortenden in seine
        /// Tabelle ein, und die steht uns vollstaendig offen.
        /// </para>
        /// </summary>
        private async Task<int> ViaNeighborTableAsync(
            ScanContext context,
            Ipv6Segment segment,
            CancellationToken cancellationToken)
        {
            INeighborProvider? provider = PlatformServices.NeighborsOrNull;
            if (provider is null) return 0;

            IPAddress allNodes = new(Icmpv6Channel.AllNodes.GetAddressBytes(), segment.InterfaceIndex);

            try
            {
                using Ping ping = new();
                await ping.SendPingAsync(allNodes, ListenWindow);
            }
            catch (PingException) { /* Die Antwort interessiert nicht - nur die Wirkung. */ }
            catch (PlatformNotSupportedException) { /* dito */ }
            catch (SocketException) { /* dito */ }

            cancellationToken.ThrowIfCancellationRequested();

            IReadOnlyList<NeighborEntry> entries = await provider.GetNeighborsAsync(cancellationToken);

            return Ipv6NeighborCacheScanMethod.Report(context, [segment], entries, DisplayName);
        }
    }
}
