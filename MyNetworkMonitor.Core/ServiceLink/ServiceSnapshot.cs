// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.ServiceLink
{
    /// <summary>
    /// The message types between user interface and service.
    /// <para>
    /// Deliberately the same envelope as the satellite protocol
    /// (<c>SatelliteMessage</c>) and the same framing: a local connection
    /// needs no second protocol, and its traffic can be read with the same
    /// tools.
    /// </para>
    /// </summary>
    public static class ServiceMessageType
    {
        /// <summary>User interface asks for the current state.</summary>
        public const string Status = "svc.status";

        /// <summary>Service answers with a <see cref="ServiceSnapshot"/> as JSON.</summary>
        public const string StatusReply = "svc.status.reply";

        /// <summary>User interface requests to stop the running job.</summary>
        public const string StopJob = "svc.stopJob";

        /// <summary>User interface requests to reload the host list and reconnect.</summary>
        public const string Reconnect = "svc.reconnect";

        /// <summary>Service reports a command as executed, with a plain-text result.</summary>
        public const string Done = "svc.done";
    }

    /// <summary>The state of a single receiver, as seen by the service.</summary>
    public sealed class ServiceHostState
    {
        /// <summary>How the receiver is shown in the list.</summary>
        public string Display { get; set; } = string.Empty;
        /// <summary>Whether the connection is established.</summary>
        public bool IsConnected { get; set; }
        /// <summary>Whether the receiver has approved this installation.</summary>
        public bool IsApproved { get; set; }
        /// <summary>The last status message of the connection.</summary>
        public string Status { get; set; } = string.Empty;
    }

    /// <summary>
    /// What the service is currently doing - a snapshot as shown by the user
    /// interface.
    /// <para>
    /// A snapshot on request rather than a stream of events: the user
    /// interface polls every second. This needs no state on either side,
    /// survives every closing and reopening of the window and cannot get out
    /// of sync.
    /// </para>
    /// </summary>
    public sealed class ServiceSnapshot
    {
        /// <summary>The name the service announces itself with.</summary>
        public string OwnName { get; set; } = string.Empty;

        /// <summary>The application version of the service.</summary>
        public string Version { get; set; } = string.Empty;

        /// <summary>The main scanner the current scan runs for; empty if none.</summary>
        public string JobHost { get; set; } = string.Empty;

        /// <summary>Identifier of the running job.</summary>
        public string JobId { get; set; } = string.Empty;

        /// <summary>Job progress from 0 to 100.</summary>
        public int JobPercent { get; set; }

        /// <summary>The scan method currently running.</summary>
        public string JobCurrent { get; set; } = string.Empty;

        /// <summary>The steps already completed.</summary>
        public string JobDone { get; set; } = string.Empty;

        /// <summary>The steps still pending.</summary>
        public string JobPending { get; set; } = string.Empty;

        /// <summary>The state per receiver.</summary>
        public List<ServiceHostState> Hosts { get; set; } = [];

        /// <summary>A job is currently running.</summary>
        public bool IsBusy => !string.IsNullOrEmpty(JobId);
    }

    /// <summary>The pipe name - the same constant on both sides.</summary>
    public static class ServicePipe
    {
        /// <summary>
        /// The name of the pipe.
        /// <para>
        /// On Windows this becomes <c>\\.\pipe\MyNetworkMonitorSatellite</c>, on
        /// Linux a file in the temporary directory - .NET maps named pipes to
        /// Unix domain sockets there. The same code serves both platforms; only
        /// access permissions are handled differently, see the pipe factory in
        /// PlatformServices.
        /// </para>
        /// </summary>
        public const string Name = "MyNetworkMonitorSatellite";
    }
}
