// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Core.Scanning.Engine.Methods
{
    /// <summary>
    /// A network interface an IPv6 method can work over, together with the
    /// scope that uses it.
    /// <para>
    /// The scope is carried along because a finding has to be assigned to a
    /// scope; group description and domain depend on it. If several scopes
    /// point to the same interface, the first one wins; the segment is the
    /// same, and reporting a device twice gains nothing.
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
    /// A guessed address still to be checked, together with the reason it was
    /// guessed. The reason ends up on the finding: "derived from the MAC" is
    /// different information from "tried in a sweep".
    /// </summary>
    internal sealed class Ipv6Candidate
    {
        public required Ipv6Segment Segment { get; init; }
        public required System.Net.IPAddress Address { get; init; }
        public required string Origin { get; init; }
    }

    /// <summary>
    /// Common base of the six IPv6 discovery methods.
    /// <para>
    /// They share more than separates them: all work on an interface rather
    /// than a target list, all depend on a segment with usable IPv6, and all
    /// are enabled or disabled per scope through a flag in
    /// <see cref="Ipv6Discovery"/>. These three checks therefore live here
    /// once instead of six times.
    /// </para>
    /// <para>
    /// Why separate methods rather than extending the IPv4 ones: a /64
    /// contains 18 quintillion addresses. A target list as walked by ping and
    /// the port scan does not exist under IPv6; what remains is asking
    /// everyone at once or listening. That is a different design, not a
    /// second address family on the same method.
    /// </para>
    /// </summary>
    public abstract class Ipv6MethodBase : IScanMethod
    {
        public abstract string Id { get; }
        public abstract string DisplayName { get; }
        public abstract string Explanation { get; }

        /// <summary>The scope flag that enables this method.</summary>
        protected abstract Ipv6Discovery Discovery { get; }

        public virtual ScanPhase Phase => ScanPhase.Discovery;

        /// <summary>Always IPv6; that is what these methods exist for.</summary>
        public FamilySupport Families => FamilySupport.IPv6;

        public virtual bool IsPassive => false;
        public virtual bool RequiresElevation => false;

        /// <summary>
        /// None of the six walks through a target list; they query the segment
        /// or listen. So there is nothing that could be restricted to devices
        /// already found.
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

        // ------------------------------------------------------------ Segments

        /// <summary>
        /// The interfaces this method runs over: from every selected scope that
        /// supports IPv6 on its segment and has this method enabled, each
        /// interface only once.
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

                // A disconnected interface keeps its link-local address and
                // its neighbor table entries, so it looks usable in every
                // other check. A run over seven segments, two of them with an
                // unplugged cable or Bluetooth switched off, would deliver
                // nothing but stale entries from a network the machine is no
                // longer connected to.
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
        /// The IPv6 interface index. 0 means "cannot be determined"; the
        /// interface is then unusable for IPv6 anyway.
        /// </summary>
        internal static int IndexOf(NetworkInterface nic)
        {
            try { return nic.GetIPProperties().GetIPv6Properties().Index; }
            catch (NetworkInformationException) { return 0; }
            catch (PlatformNotSupportedException) { return 0; }
        }

        // ------------------------------------------------------------ Probing

        /// <summary>
        /// Number of probes running concurrently. A multicast method does not
        /// need this, but the two guessing methods do: they walk through a
        /// guessed list consisting mostly of addresses where nobody is.
        /// Sequentially, that would be 255 timeouts in a row.
        /// </summary>
        private const int ParallelProbes = 32;

        /// <summary>
        /// Checks guessed addresses individually by echo request and reports
        /// who answers.
        /// <para>
        /// Deliberately uses <see cref="Ping"/> rather than a dedicated ICMPv6
        /// socket: <see cref="Ping"/> fully handles an echo request to a
        /// <em>single</em> address, on both platforms and without special
        /// privileges. A dedicated socket is only needed where many answers
        /// arrive for one packet (multicast) or where traffic is captured.
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

                    // Sent probes are counted when the probe has finished, not
                    // when it is sent. Otherwise the display would show
                    // 255/255 immediately while still waiting.
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
                catch (OperationCanceledException) { /* cancelled - not counted */ }
                finally
                {
                    gate.Release();
                    context.ReportProgress(Volatile.Read(ref sent), Volatile.Read(ref responded), candidates.Count);
                }
            });

            await Task.WhenAll(probes);

            cancellationToken.ThrowIfCancellationRequested();

            // Not a single success, and every probe failed in the operating
            // system rather than for lack of an answer: no attempt was
            // possible here at all. That differs from "nobody answered" and
            // must be reported differently; otherwise the cause would be
            // sought in the devices.
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
        /// The probe did not go unanswered; it never left the machine.
        /// <para>
        /// <c>IP_GENERAL_FAILURE</c> (11050) is missing from
        /// <see cref="IPStatus"/>; .NET passes the number through untranslated.
        /// Among other things it indicates that the interface lacks the on-link
        /// route for <c>fe80::/64</c>, as happens on a machine with an active
        /// VPN, where even <c>ping -6</c> reports only "General failure".
        /// </para>
        /// </summary>
        private static bool IsGeneralFailure(IPStatus status) =>
            (int)status == 11050 || status == IPStatus.Unknown;

        // ------------------------------------------------------------ Listening

        /// <summary>
        /// Listens on a channel for the duration of a time window and passes
        /// on every packet.
        /// <para>
        /// The window makes all the difference between "found nothing" and
        /// "did not listen long enough": captured messages arrive when the
        /// sender chooses, not when asked. The caller therefore sets the
        /// duration.
        /// </para>
        /// <para>
        /// Cancellation through the token is distinguished from the window
        /// expiring: the former throws, the latter returns.
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
                    // A single dropped packet does not end listening, for
                    // example one too large for the buffer.
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
        /// The reason a listening method reports when no raw socket can be
        /// obtained. Lives here because both affected methods need the same
        /// text, and it has to answer the actual question: what can be done
        /// about it.
        /// </summary>
        private protected static string NoRawSocketReason(string what) =>
            OperatingSystem.IsWindows()
                ? $"Listening for {what} needs administrator rights - Windows hands out no " +
                  "raw sockets without them. Start the program as administrator to use this method."
                : $"Listening for {what} needs the CAP_NET_RAW capability. " +
                  RawSocketRights.GrantHint(RawSocketRights.AppImagePath) +
                  (RawSocketRights.GrantCommand(Environment.ProcessPath ?? "MyNetworkMonitor.Avalonia", RawSocketRights.AppImagePath) is { } command
                      ? " " + command
                      : string.Empty);

        // ------------------------------------------------------------ Reporting

        /// <summary>
        /// Reports a found IPv6 address. Builds the observation for the
        /// individual method; scope information and address analysis are the
        /// same everywhere.
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

                // Without a known MAC, it may be contained in the address: an
                // EUI-64 address carries it in its interface identifier.
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
