using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// Ein Adapter, ueber den ein IPv6-Verfahren arbeiten kann, samt der
    /// Bereiche, die ihn benutzen.
    /// <para>
    /// Die Bereiche werden mitgefuehrt, weil ein Fund einem Bereich
    /// zugeschlagen werden muss - Gruppenbezeichnung und Domain haengen daran.
    /// Zeigen mehrere Bereiche auf denselben Adapter, gewinnt der erste; das
    /// Segment ist dasselbe, und ein Geraet zweimal zu melden brachte nichts.
    /// </para>
    /// </summary>
    internal sealed class Ipv6Segment
    {
        public required NetworkInterface Interface { get; init; }
        public required int InterfaceIndex { get; init; }
        public required ScopeRuntime Scope { get; init; }

        public override string ToString() => $"{Interface.Name} [{InterfaceIndex}]";
    }

    /// <summary>
    /// Gemeinsamer Unterbau der sechs IPv6-Suchverfahren.
    /// <para>
    /// Sie teilen mehr, als sie unterscheidet: alle arbeiten am Adapter statt
    /// an einer Zielliste, alle sind auf ein Segment mit nutzbarem IPv6
    /// angewiesen, und alle werden je Bereich ueber ein Flag in
    /// <see cref="Ipv6Discovery"/> zu- oder abgewaehlt. Diese drei Pruefungen
    /// stehen darum einmal hier statt sechsmal.
    /// </para>
    /// <para>
    /// Warum ueberhaupt eigene Verfahren und keine Erweiterung der bestehenden:
    /// ein /64 umfasst 18 Trillionen Adressen. Eine Zielliste, wie sie Ping und
    /// Portscan durchgehen, gibt es unter IPv6 nicht - es bleibt nur, einmal in
    /// die Runde zu fragen oder zuzuhoeren. Das ist eine andere Bauform, keine
    /// zweite Adressfamilie am selben Verfahren.
    /// </para>
    /// </summary>
    /// <summary>
    /// Eine erratene Adresse, die noch zu pruefen ist - samt der Begruendung,
    /// warum sie geraten wurde. Die Begruendung landet am Fund: "aus der MAC
    /// abgeleitet" ist eine andere Auskunft als "durchprobiert".
    /// </summary>
    internal sealed class Ipv6Candidate
    {
        public required Ipv6Segment Segment { get; init; }
        public required System.Net.IPAddress Address { get; init; }
        public required string Origin { get; init; }
    }

    public abstract class Ipv6MethodBase : IScanMethod
    {
        public abstract string Id { get; }
        public abstract string DisplayName { get; }
        public abstract string Explanation { get; }

        /// <summary>Welches Flag am Bereich dieses Verfahren zulaesst.</summary>
        protected abstract Ipv6Discovery Discovery { get; }

        public virtual ScanPhase Phase => ScanPhase.Discovery;

        /// <summary>Ausnahmslos IPv6 - dafuer gibt es die Verfahren.</summary>
        public FamilySupport Families => FamilySupport.IPv6;

        public virtual bool IsPassive => false;
        public virtual bool RequiresElevation => false;

        /// <summary>
        /// Keines der sechs geht eine Zielliste durch - sie fragen ins Segment
        /// oder hoeren zu. Damit gibt es auch nichts, das sich auf die bereits
        /// gefundenen Geraete kuerzen liesse.
        /// </summary>
        public virtual bool EnumeratesTargets => false;

        public virtual ScanMethodAvailability CheckAvailability(ScanContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            if (!Ipv6Readiness.OperatingSystemSupportsIpv6)
            {
                return ScanMethodAvailability.Blocked("This operating system does not support IPv6.");
            }

            if (!context.AnyScopeAllowsLocalIpv6)
            {
                return ScanMethodAvailability.Blocked(context.Ipv6BlockReason);
            }

            if (Segments(context).Count == 0)
            {
                return ScanMethodAvailability.NotApplicable(
                    $"No selected range uses this method. Switch it on in the range settings " +
                    $"(\"{Discovery}\") to use it.");
            }

            return ScanMethodAvailability.Available;
        }

        public abstract Task ExecuteAsync(ScanContext context, CancellationToken cancellationToken);

        // ------------------------------------------------------------ Segmente

        /// <summary>
        /// Die Adapter, ueber die dieses Verfahren laufen soll: aus jedem
        /// gewaehlten Bereich, der IPv6 im Segment kann und dieses Verfahren
        /// zugelassen hat - jeder Adapter nur einmal.
        /// </summary>
        internal List<Ipv6Segment> Segments(ScanContext context)
        {
            List<Ipv6Segment> segments = [];
            HashSet<int> seen = [];

            foreach (ScopeRuntime runtime in context.Scopes)
            {
                if (!runtime.Ipv6.CanScanLocalSegment) continue;
                if (!runtime.Scope.Ipv6Discovery.HasFlag(Discovery)) continue;
                if (runtime.Interface is null) continue;

                // Ein getrennter Adapter behaelt seine Link-Local-Adresse und
                // seine Eintraege in der Nachbarschaftstabelle - er sieht in
                // jeder Pruefung nutzbar aus. Am 2026-08-09 aufgefallen: ein
                // Lauf ging ueber sieben Segmente, davon zwei mit
                // abgezogenem Kabel bzw. abgeschaltetem Bluetooth. Die
                // lieferten nichts als Karteileichen aus einem Netz, in dem
                // der Rechner laengst nicht mehr steckt.
                if (runtime.Interface.OperationalStatus != OperationalStatus.Up) continue;

                int index = IndexOf(runtime.Interface);
                if (index <= 0 || !seen.Add(index)) continue;

                segments.Add(new Ipv6Segment
                {
                    Interface = runtime.Interface,
                    InterfaceIndex = index,
                    Scope = runtime
                });
            }

            return segments;
        }

        /// <summary>
        /// Der IPv6-Adapterindex. 0 heisst "nicht ermittelbar" - dann ist der
        /// Adapter fuer IPv6 ohnehin nicht zu gebrauchen.
        /// </summary>
        internal static int IndexOf(NetworkInterface nic)
        {
            try { return nic.GetIPProperties().GetIPv6Properties().Index; }
            catch (NetworkInformationException) { return 0; }
            catch (PlatformNotSupportedException) { return 0; }
        }

        // ------------------------------------------------------------ Pruefen

        /// <summary>
        /// Wie viele Proben gleichzeitig laufen. Ein Multicast-Verfahren
        /// braucht das nicht - diese beiden schon: sie gehen eine geratene
        /// Liste durch, und die besteht ueberwiegend aus Adressen, an denen
        /// niemand ist. Nacheinander waeren 255 Zeitlimits nacheinander.
        /// </summary>
        private const int ParallelProbes = 32;

        /// <summary>
        /// Prueft geratene Adressen einzeln per Echo und meldet, wer antwortet.
        /// <para>
        /// Bewusst ueber <see cref="Ping"/> und nicht ueber einen eigenen
        /// ICMPv6-Socket: eine Echo-Anforderung an eine <em>einzelne</em>
        /// Adresse kann <see cref="Ping"/> vollstaendig, auf beiden Plattformen
        /// und ohne Sonderrechte. Der eigene Socket ist nur dort noetig, wo
        /// viele Antworten auf ein Paket kommen - beim Multicast - oder wo
        /// mitgehoert wird.
        /// </para>
        /// </summary>
        private protected async Task<int> ProbeCandidatesAsync(
            ScanContext context,
            IReadOnlyList<Ipv6Candidate> candidates,
            CancellationToken cancellationToken)
        {
            if (candidates.Count == 0) return 0;

            using SemaphoreSlim gate = new(ParallelProbes);

            int sent = 0;
            int responded = 0;
            int generalFailures = 0;

            IEnumerable<Task> probes = candidates.Select(async candidate =>
            {
                await gate.WaitAsync(cancellationToken);

                try
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    using Ping ping = new();
                    PingReply reply = await ping.SendPingAsync(
                        candidate.Address, TimeSpan.FromMilliseconds(context.Settings.PortTimeoutMs));

                    // Die gesendeten Proben werden gezaehlt, sobald die Probe
                    // fertig ist - nicht beim Absenden. Sonst stuende die
                    // Anzeige sofort auf 255/255, waehrend noch gewartet wird.
                    Interlocked.Increment(ref sent);

                    if (IsGeneralFailure(reply.Status)) Interlocked.Increment(ref generalFailures);

                    if (reply.Status == IPStatus.Success)
                    {
                        Interlocked.Increment(ref responded);

                        ReportAddress(context, candidate.Segment, candidate.Address, details: new Dictionary<string, string>
                        {
                            ["Found by"] = candidate.Origin,
                            ["Response time"] = $"{reply.RoundtripTime} ms"
                        });
                    }
                }
                catch (PingException) { Interlocked.Increment(ref sent); }
                catch (SocketException) { Interlocked.Increment(ref sent); }
                catch (OperationCanceledException) { /* Abbruch - nicht mitzaehlen */ }
                finally
                {
                    gate.Release();
                    context.ReportProgress(Volatile.Read(ref sent), Volatile.Read(ref responded), candidates.Count);
                }
            });

            await Task.WhenAll(probes);

            cancellationToken.ThrowIfCancellationRequested();

            // Kein einziger Erfolg, und jede Probe scheiterte am
            // Betriebssystem statt an einer ausbleibenden Antwort: dann war
            // hier gar kein Versuch moeglich. Das ist etwas anderes als "es
            // hat niemand geantwortet" und muss auch anders dastehen - sonst
            // sucht der Nutzer den Fehler bei den Geraeten.
            if (responded == 0 && generalFailures == sent && sent > 0)
            {
                throw new InvalidOperationException(
                    "IPv6 could not be used on this adapter: the operating system rejected every " +
                    "probe outright instead of timing out. The usual cause is a VPN client that " +
                    "switches IPv6 off on the underlying adapter, or a missing on-link route for " +
                    "fe80::/64. Nothing was found because nothing could be asked.");
            }

            return responded;
        }

        /// <summary>
        /// Die Probe ist nicht unbeantwortet geblieben, sondern gar nicht erst
        /// hinausgegangen.
        /// <para>
        /// <c>IP_GENERAL_FAILURE</c> (11050) fehlt in <see cref="IPStatus"/> -
        /// .NET reicht die Zahl unuebersetzt durch. Sie steht unter anderem
        /// dafuer, dass dem Adapter die On-Link-Route fuer <c>fe80::/64</c>
        /// fehlt; am 2026-08-09 an einem Rechner mit aktivem VPN gesehen, wo
        /// selbst <c>ping -6</c> nur "Allgemeiner Fehler" meldete.
        /// </para>
        /// </summary>
        private static bool IsGeneralFailure(IPStatus status) =>
            (int)status == 11050 || status == IPStatus.Unknown;

        // ------------------------------------------------------------ Mithoeren

        /// <summary>
        /// Hoert einen Kanal fuer die Dauer eines Zeitfensters ab und reicht
        /// jedes Paket weiter.
        /// <para>
        /// Das Zeitfenster ist der ganze Unterschied zwischen "hat nichts
        /// gefunden" und "war zu kurz da": mitgehoerte Nachrichten kommen,
        /// wann der Absender will, nicht wann wir fragen. Der Aufrufer legt
        /// die Dauer darum selbst fest.
        /// </para>
        /// <para>
        /// Ein Abbruch durch den Nutzer wird vom Ablaufen des Fensters
        /// unterschieden - Ersteres wirft, Letzteres kehrt zurueck.
        /// </para>
        /// </summary>
        private protected static async Task ListenAsync(
            Icmpv6Channel channel,
            TimeSpan window,
            Action<byte[], int, IPAddress> onPacket,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(channel);
            ArgumentNullException.ThrowIfNull(onPacket);

            byte[] buffer = new byte[2048];

            using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            limit.CancelAfter(window);

            while (!limit.IsCancellationRequested)
            {
                SocketReceiveFromResult received;

                try
                {
                    received = await channel.Socket.ReceiveFromAsync(
                        buffer, SocketFlags.None, new System.Net.IPEndPoint(System.Net.IPAddress.IPv6Any, 0), limit.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (SocketException)
                {
                    // Ein einzelnes verworfenes Paket beendet das Zuhoeren
                    // nicht - etwa ein zu grosses, das nicht in den Puffer
                    // passte.
                    continue;
                }

                if (received.RemoteEndPoint is System.Net.IPEndPoint sender)
                {
                    onPacket(buffer, received.ReceivedBytes, sender.Address);
                }
            }

            cancellationToken.ThrowIfCancellationRequested();
        }

        /// <summary>
        /// Der Grund, den ein Mithoer-Verfahren meldet, wenn kein Rohsocket zu
        /// bekommen ist. Steht hier, weil beide betroffenen Verfahren
        /// denselben Satz brauchen und er die eigentliche Frage beantworten
        /// muss: was der Nutzer dagegen tun kann.
        /// </summary>
        private protected static string NoRawSocketReason(string what) =>
            OperatingSystem.IsWindows()
                ? $"Listening for {what} needs administrator rights - Windows hands out no " +
                  "raw sockets without them. Start the program as administrator to use this method."
                : $"Listening for {what} needs the CAP_NET_RAW capability. Either start the " +
                  "program with sudo, or grant it once with: " +
                  "sudo setcap cap_net_raw+ep $(which MyNetworkMonitor.Avalonia)";

        // ------------------------------------------------------------ Meldung

        /// <summary>
        /// Meldet eine gefundene IPv6-Adresse. Nimmt dem einzelnen Verfahren
        /// das Zusammenbauen der Sichtung ab - Bereichsangaben und die Analyse
        /// der Adresse sind ueberall dieselben.
        /// </summary>
        private protected void ReportAddress(
            ScanContext context,
            Ipv6Segment segment,
            System.Net.IPAddress address,
            PhysicalAddress? mac = null,
            bool isResponding = true,
            Dictionary<string, string>? details = null)
        {
            IpAddressInfo info = IpAddressAnalyzer.Analyze(address);

            context.Report(new DeviceObservation
            {
                Source = DisplayName,
                Address = info,

                // Steht keine MAC zur Verfuegung, kann sie in der Adresse
                // stecken: eine EUI-64-Adresse traegt sie im hinteren Teil.
                Mac = mac ?? info.DerivedMac,

                IsResponding = isResponding,
                GroupDescription = segment.Scope.Scope.GroupDescription,
                Domain = string.IsNullOrWhiteSpace(segment.Scope.Scope.Domain)
                    ? null
                    : segment.Scope.Scope.Domain,
                Details = details
            });
        }
    }
}
