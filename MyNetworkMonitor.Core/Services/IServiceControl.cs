// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.Services
{
    /// <summary>The state of the satellite service.</summary>
    public enum ServiceState
    {
        /// <summary>Not installed.</summary>
        NotInstalled,

        /// <summary>Installed, but not running.</summary>
        Stopped,

        /// <summary>Installed and running.</summary>
        Running,

        /// <summary>Cannot be determined - for example because the platform does not support it.</summary>
        Unknown
    }

    /// <summary>What is known about the service.</summary>
    /// <param name="State">The state.</param>
    /// <param name="Message">Plain-language message for display.</param>
    /// <param name="StartsWithSystem">The service starts automatically at boot.</param>
    public readonly record struct ServiceStatus(ServiceState State, string Message, bool StartsWithSystem)
    {
        /// <summary>The service is installed, running or not.</summary>
        public bool IsInstalled => State is ServiceState.Stopped or ServiceState.Running;
        /// <summary>The service is running.</summary>
        public bool IsRunning => State == ServiceState.Running;
    }

    /// <summary>Result of an operation on the service.</summary>
    /// <param name="Success">The operation succeeded.</param>
    /// <param name="Message">Plain-language message for display - also on success.</param>
    public readonly record struct ServiceChangeResult(bool Success, string Message);

    /// <summary>
    /// Installs and controls the satellite service.
    /// <para>
    /// The satellite runs permanently and comes back by itself after a reboot -
    /// a started user interface is not sufficient for that. The service starts
    /// the same application with <c>--satellite</c>: without a window, logging
    /// to a file (SATELLIT.md, section 9).
    /// </para>
    /// <para>
    /// Installing and removing require elevated privileges. The implementation
    /// may restart itself elevated for this - the only visible effect is a
    /// confirmation prompt of the operating system.
    /// </para>
    /// </summary>
    public interface IServiceControl
    {
        /// <summary>Whether a service can be installed on this platform at all.</summary>
        bool IsSupported { get; }

        /// <summary>Whether the application currently runs elevated.</summary>
        bool IsElevated { get; }

        /// <summary>Queries the state.</summary>
        /// <returns>The current state with a message for display.</returns>
        ServiceStatus Read();

        /// <summary>
        /// Installs the service with automatic start and restart after a crash,
        /// and starts it right away.
        /// </summary>
        /// <param name="executablePath">The application to run as a service.</param>
        /// <returns>Whether the operation succeeded, with a message for display.</returns>
        ServiceChangeResult Install(string executablePath);

        /// <summary>Stops the service and removes it.</summary>
        ServiceChangeResult Uninstall();

        /// <summary>Starts the installed service.</summary>
        ServiceChangeResult Start();

        /// <summary>Stops the running service without removing it.</summary>
        ServiceChangeResult Stop();
    }

    /// <summary>Used when no implementation is available - reports that the operation is not supported.</summary>
    public sealed class NullServiceControl : IServiceControl
    {
        private const string NotHere = "Setting up a service is not supported on this platform yet.";

        public bool IsSupported => false;
        public bool IsElevated => false;

        public ServiceStatus Read() => new(ServiceState.Unknown, NotHere, false);

        public ServiceChangeResult Install(string executablePath) => new(false, NotHere);
        public ServiceChangeResult Uninstall() => new(false, NotHere);
        public ServiceChangeResult Start() => new(false, NotHere);
        public ServiceChangeResult Stop() => new(false, NotHere);
    }
}
