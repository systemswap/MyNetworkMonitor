using System.Text.Json.Serialization;

// The namespace is called SatelliteLink and not Satellite: the type
// Models.Satellite has that name, and a namespace of the same name would
// hide it everywhere in Core.
namespace MyNetworkMonitor.Core.SatelliteLink
{
    /// <summary>The message types of the satellite protocol. See SATELLIT.md, section 6.</summary>
    public static class MessageType
    {
        // Satellite -> main scanner

        /// <summary>First message of a connection: name, version, operating system, site.</summary>
        public const string Hello = "hello";

        /// <summary>Progress of the running job.</summary>
        public const string Progress = "progress";

        /// <summary>The job has been accepted and started.</summary>
        public const string Accepted = "accepted";

        /// <summary>The job was refused because another job is running.</summary>
        public const string Busy = "busy";

        /// <summary>The devices found by a job.</summary>
        public const string Result = "result";

        /// <summary>The job was cancelled.</summary>
        public const string Cancelled = "cancelled";

        /// <summary>An error with a plain-text message.</summary>
        public const string Error = "error";

        /// <summary>Answer to <see cref="Ping"/>.</summary>
        public const string Pong = "pong";

        // Main scanner -> satellite

        /// <summary>The satellite is approved; jobs may follow.</summary>
        public const string Welcome = "welcome";

        /// <summary>The satellite is connected but waits for approval.</summary>
        public const string Pending = "pending";

        /// <summary>A scan job; the job text is in <see cref="SatelliteMessage.Text"/>.</summary>
        public const string Job = "job";

        /// <summary>Cancels a job.</summary>
        public const string Cancel = "cancel";

        /// <summary>Acknowledges receipt of a <see cref="Result"/>.</summary>
        public const string ResultAck = "resultAck";

        /// <summary>The main scanner listens on a new port from now on.</summary>
        public const string ListenPortChanged = "listenPortChanged";

        /// <summary>Keep-alive check; both sides answer with <see cref="Pong"/>.</summary>
        public const string Ping = "ping";
    }

    /// <summary>
    /// A message of the satellite protocol.
    /// <para>
    /// Deliberately <em>one</em> envelope with optional fields instead of one
    /// class per type: this avoids polymorphism when reading and keeps a
    /// capture readable. Which type uses a field is noted at the field.
    /// </para>
    /// </summary>
    public sealed class SatelliteMessage
    {
        /// <summary>One of the constants of <see cref="MessageType"/>.</summary>
        public string Type { get; set; } = string.Empty;

        /// <summary>
        /// Protocol version. Strict: a mismatch is rejected, because half
        /// understood jobs are worse than a clear message.
        /// </summary>
        public int ProtocolVersion { get; set; }

        // --- Greeting --------------------------------------------------------

        /// <summary>The name the satellite gives itself.</summary>
        public string? Name { get; set; }

        /// <summary>Application version of the peer.</summary>
        public string? AppVersion { get; set; }

        /// <summary>Operating system of the peer.</summary>
        public string? Os { get; set; }

        /// <summary>
        /// Where the satellite is located: host name, domain, addresses and
        /// networks.
        /// <para>
        /// Collected and sent anew with <em>every</em> login, not only the first
        /// time. After a restart, an adapter change or a new DHCP lease, the
        /// main scanner would otherwise keep the old addresses, and the
        /// selection would show a range that no longer exists.
        /// </para>
        /// <para>
        /// Without this information, the main scanner shows only a name, and
        /// whether this satellite is the right one for a range would be guesswork.
        /// </para>
        /// </summary>
        public SitePayload? Site { get; set; }

        // --- Job and run -----------------------------------------------------

        /// <summary>Identifier of the job the message refers to.</summary>
        public string? JobId { get; set; }

        /// <summary>Who cancelled, so that a job never disappears unexplained.</summary>
        public string? CancelledBy { get; set; }

        /// <summary>Progress: method, sent, answered, total.</summary>
        public ProgressPayload? Progress { get; set; }

        // --- Other -----------------------------------------------------------

        /// <summary>
        /// For <see cref="MessageType.Job"/> the job text, for
        /// <see cref="MessageType.Error"/> the message to display.
        /// </summary>
        public string? Text { get; set; }

        /// <summary>
        /// For <see cref="MessageType.Result"/> the devices found, in the same
        /// format as <c>lastScanResult.json</c>.
        /// </summary>
        public string? Devices { get; set; }

        /// <summary>
        /// For <see cref="MessageType.Result"/>: the job was cancelled, and the
        /// devices are those found up to that point.
        /// <para>
        /// A cancelled run has not seen everything. Without this flag its result
        /// could not be told apart from a complete one, and "only these devices
        /// are here" would become a conclusion the data does not support.
        /// Satellites that do not know the field leave it <c>false</c>, which is
        /// correct: they send nothing at all when cancelled.
        /// </para>
        /// </summary>
        public bool Partial { get; set; }

        /// <summary>New port of the main scanner, for the next connection attempt.</summary>
        public int? ListenPort { get; set; }

        /// <summary>True if this is a <see cref="MessageType.Hello"/>.</summary>
        [JsonIgnore]
        public bool IsHello => Type == MessageType.Hello;
    }

    /// <summary>
    /// Progress of a running job.
    /// <para>
    /// Carries the same information as the local display: which method is
    /// running, how far the job is, what is done and what is pending, plus the
    /// three counters of the running method. Without them, a remote view shows
    /// only <em>that</em> the satellite works; whether a method still yields
    /// results or only runs into timeouts is exactly what these counters show.
    /// </para>
    /// </summary>
    public sealed class ProgressPayload
    {
        /// <summary>
        /// 0 to 100: the progress of the <em>running method</em>, not of the
        /// whole job.
        /// <para>
        /// Not the share of completed methods: with three methods, that number
        /// jumps from 0 to 33 to 67 to 100 and stands still for minutes in
        /// between, so during long methods the satellite looks hung. What
        /// matters is how far the running method is: "Ping 40 %".
        /// </para>
        /// </summary>
        public int Percent { get; set; }

        /// <summary>The method that is running.</summary>
        public string Current { get; set; } = string.Empty;

        /// <summary>The position of the running method within the job.</summary>
        public int Step { get; set; }

        /// <summary>How many methods the job comprises.</summary>
        public int Steps { get; set; }

        /// <summary>What is already done, like <c>CompletedScansText</c> locally.</summary>
        public string Done { get; set; } = string.Empty;

        /// <summary>What is still pending, like <c>PendingScansText</c> locally.</summary>
        public string Pending { get; set; } = string.Empty;

        // --- The three counters of the running method ------------------------
        //
        // Same meaning as in the local command bar: sent, answered, total.
        // Satellites that do not know the fields leave them at 0; the display
        // then hides them instead of showing three zeros.

        /// <summary>Requests sent by the running method.</summary>
        public int Sent { get; set; }

        /// <summary>Targets that answered.</summary>
        public int Answered { get; set; }

        /// <summary>Total targets of the running method.</summary>
        public int Total { get; set; }
    }

    /// <summary>
    /// The location of a satellite, as it reports itself.
    /// <para>
    /// Deliberately plain strings and no address objects: the main scanner
    /// only displays and compares the values, never computes with them. What
    /// the satellite reports is information, not a guarantee: the main scanner
    /// keeps scanning the ranges <em>it</em> assigned, not those the satellite
    /// names.
    /// </para>
    /// </summary>
    public sealed class SitePayload
    {
        /// <summary>Host name of the satellite.</summary>
        public string HostName { get; set; } = string.Empty;

        /// <summary>DNS domain of the satellite, if any.</summary>
        public string Domain { get; set; } = string.Empty;

        /// <summary>All usable IPv4 addresses, comma-separated.</summary>
        public string Ipv4 { get; set; } = string.Empty;

        /// <summary>All usable IPv6 addresses, comma-separated.</summary>
        public string Ipv6 { get; set; } = string.Empty;

        /// <summary>
        /// The network that best describes the satellite, for example
        /// <c>192.0.2.0/24</c>: that of the adapter with the default gateway.
        /// The main scanner shows exactly this one after the name in its
        /// selection.
        /// </summary>
        public string PrimaryNetwork { get; set; } = string.Empty;

        /// <summary>All networks, comma-separated.</summary>
        public string Networks { get; set; } = string.Empty;
    }
}
