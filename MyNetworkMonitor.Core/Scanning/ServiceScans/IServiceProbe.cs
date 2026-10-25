using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// The conditions a probe works under during a run.
    /// <para>
    /// The timeout and retry defaults are deliberately <b>not</b> taken from
    /// <c>ScanSettings.PortTimeoutMs</c>: service detection does not use the
    /// port-timeout slider, and coupling it to the slider would change the
    /// duration of every service scan.
    /// </para>
    /// </summary>
    public sealed class ProbeContext
    {
        /// <summary>Timeout for connecting and for the answer, in milliseconds.</summary>
        public int TimeoutMs { get; init; } = 2000;

        /// <summary>Attempts per port before the port counts as "no response".</summary>
        public int RetryCount { get; init; } = 3;

        /// <summary>
        /// Whether a probe may send a request that changes the state of the
        /// remote side.
        /// <para>
        /// Defaults to <c>false</c> for a concrete reason. In SECS/GEM there is
        /// exactly one message an equipment in the "not communicating" state
        /// must answer: S1F13, Establish Communications Request (SEMI E5). The
        /// equipment answers with model and software revision, but enters the
        /// communicating state and treats the sender as its host: in a
        /// measurement, an alarm
        /// report and a continuous stream of events with real production data
        /// arrived within half a second. Where spooling is configured, these
        /// messages can be missing at the real host.
        /// </para>
        /// <para>
        /// The decision therefore lies not with the probe but with whoever
        /// knows the equipment in the network: per service, in the service
        /// manager.
        /// </para>
        /// </summary>
        public bool ActiveInquiry { get; init; }
    }

    /// <summary>
    /// A service that can be searched for, with everything that defines it in
    /// one place: its ports, its hello packet, its answer check and, where
    /// needed, its own procedure. Adding a service means adding one file.
    /// <para>
    /// The detection packets are determined experimentally and are not
    /// "tidied up"; they change only for a protocol reason. Every probe
    /// checks the answer against its protocol and sends real application
    /// data; see docs/FEHLERGEDAECHTNIS.md, No. 2 and No. 14.
    /// </para>
    /// </summary>
    public interface IServiceProbe
    {
        /// <summary>The service this probe detects.</summary>
        ServiceType Service { get; }

        /// <summary>Group in the service manager, one of <see cref="ServiceGroups"/>.</summary>
        string Group { get; }

        /// <summary>
        /// The ports this service usually listens on. These are defaults:
        /// <c>services.xml</c> can override them, which is their purpose.
        /// </summary>
        IReadOnlyList<int> DefaultPorts { get; }

        /// <summary>
        /// What is sent to get an answer. Empty for services that send a
        /// greeting on their own: FTP, MySQL, MariaDB.
        /// </summary>
        byte[] Hello { get; }

        /// <summary>Checks whether an answer matches the protocol of this service.</summary>
        /// <param name="response">The bytes received after sending <see cref="Hello"/>.</param>
        /// <returns><c>true</c> if the answer comes from this service.</returns>
        bool Identify(byte[] response);

        /// <summary>
        /// Called once per run, before the first target is touched. For services
        /// that do not work target by target: DHCP asks once by broadcast and
        /// afterwards only compares who answered.
        /// </summary>
        /// <param name="context">The conditions of the run.</param>
        /// <param name="targets">All addresses of the run.</param>
        /// <param name="token">Cancels the run.</param>
        Task PrepareAsync(ProbeContext context, IReadOnlyList<string> targets, CancellationToken token);

        /// <summary>Probes one port on one target.</summary>
        /// <param name="context">The conditions of the run.</param>
        /// <param name="address">The target address.</param>
        /// <param name="port">The port to probe.</param>
        /// <param name="token">Cancels the run.</param>
        /// <returns>The status of the port and a log text for the details view.</returns>
        Task<PortResult> ProbeAsync(ProbeContext context, string address, int port, CancellationToken token);
    }
}
