using System;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Central registry of the platform-specific providers. The scan engine in
    /// Core knows only the interfaces; the startup project (Avalonia, with the
    /// Windows or Linux implementations) registers its implementations here at
    /// startup.
    /// </summary>
    public static class PlatformServices
    {
        private static IArpProvider? _arp;
        private static IRoutingProvider? _routing;
        private static IRegistryReader? _registry;
        private static IWifiProvider? _wifi;
        private static IEnterpriseEnvironment? _enterprise;
        private static INeighborProvider? _neighbors;
        private static IFirewallInspector? _firewall;
        private static IServiceControl? _serviceControl;

        /// <summary>Registers the ARP provider.</summary>
        public static void RegisterArp(IArpProvider provider) => _arp = provider;
        /// <summary>Registers the neighbor table provider.</summary>
        public static void RegisterNeighbors(INeighborProvider provider) => _neighbors = provider;
        /// <summary>Registers the routing table provider.</summary>
        public static void RegisterRouting(IRoutingProvider provider) => _routing = provider;
        /// <summary>Registers the registry reader.</summary>
        public static void RegisterRegistry(IRegistryReader provider) => _registry = provider;
        /// <summary>Registers the Wi-Fi provider.</summary>
        public static void RegisterWifi(IWifiProvider provider) => _wifi = provider;
        /// <summary>Registers the corporate network detection.</summary>
        public static void RegisterEnterprise(IEnterpriseEnvironment provider) => _enterprise = provider;
        /// <summary>Registers the firewall inspector.</summary>
        public static void RegisterFirewall(IFirewallInspector provider) => _firewall = provider;
        /// <summary>Registers the satellite service control.</summary>
        public static void RegisterServiceControl(IServiceControl provider) => _serviceControl = provider;

        /// <summary>The registered ARP provider.</summary>
        /// <exception cref="InvalidOperationException">No provider is registered.</exception>
        public static IArpProvider Arp => Require(_arp, nameof(IArpProvider));
        /// <summary>The registered neighbor table provider.</summary>
        /// <exception cref="InvalidOperationException">No provider is registered.</exception>
        public static INeighborProvider Neighbors => Require(_neighbors, nameof(INeighborProvider));
        /// <summary>The registered routing table provider.</summary>
        /// <exception cref="InvalidOperationException">No provider is registered.</exception>
        public static IRoutingProvider Routing => Require(_routing, nameof(IRoutingProvider));
        /// <summary>The registered registry reader.</summary>
        /// <exception cref="InvalidOperationException">No provider is registered.</exception>
        public static IRegistryReader Registry => Require(_registry, nameof(IRegistryReader));
        /// <summary>The registered Wi-Fi provider.</summary>
        /// <exception cref="InvalidOperationException">No provider is registered.</exception>
        public static IWifiProvider Wifi => Require(_wifi, nameof(IWifiProvider));
        /// <summary>The registered corporate network detection.</summary>
        /// <exception cref="InvalidOperationException">No provider is registered.</exception>
        public static IEnterpriseEnvironment Enterprise => Require(_enterprise, nameof(IEnterpriseEnvironment));

        /// <summary>
        /// Reads the firewall rules. Without registration, an implementation that
        /// reports nothing - the firewall display is an aid, not a core feature,
        /// and must not hold anything up.
        /// </summary>
        public static IFirewallInspector Firewall => _firewall ??= new NullFirewallInspector();

        /// <summary>
        /// Installs the satellite service. Without registration, an implementation
        /// that reports that this platform does not support it - the management
        /// view can display that instead of failing.
        /// </summary>
        public static IServiceControl ServiceControl => _serviceControl ??= new NullServiceControl();

        // --------------------------------------------------- Control pipe

        private static Func<string, System.IO.Pipes.NamedPipeServerStream>? _pipeServerFactory;

        /// <summary>
        /// How the service opens its control pipe.
        /// <para>
        /// Platform-specific because the permissions are: on Windows the service
        /// runs as LocalSystem and the user interface as the signed-in user.
        /// Without an explicit access control list, the user interface cannot
        /// open the pipe, and the window permanently shows "service does not
        /// respond". The required API exists only on Windows, so the Windows
        /// project registers it. On Linux the permissions of the socket file
        /// control access, and the default below is sufficient.
        /// </para>
        /// </summary>
        /// <param name="factory">Creates the pipe server for a given pipe name.</param>
        public static void RegisterPipeServerFactory(Func<string, System.IO.Pipes.NamedPipeServerStream> factory) =>
            _pipeServerFactory = factory;

        /// <summary>Creates the control pipe of the service.</summary>
        /// <param name="name">The pipe name.</param>
        /// <returns>The registered factory's pipe, or an asynchronous byte-mode pipe with default permissions.</returns>
        public static System.IO.Pipes.NamedPipeServerStream CreatePipeServer(string name)
        {
            if (_pipeServerFactory is not null) return _pipeServerFactory(name);

            return new System.IO.Pipes.NamedPipeServerStream(
                name,
                System.IO.Pipes.PipeDirection.InOut,
                maxNumberOfServerInstances: 1,
                System.IO.Pipes.PipeTransmissionMode.Byte,
                System.IO.Pipes.PipeOptions.Asynchronous);
        }

        // For callers that handle a missing registration themselves instead of
        // getting an exception - for example the scan methods, which turn it
        // into a message for display.
        public static IArpProvider? ArpOrNull => _arp;
        public static INeighborProvider? NeighborsOrNull => _neighbors;
        public static IRoutingProvider? RoutingOrNull => _routing;
        public static IRegistryReader? RegistryOrNull => _registry;
        public static IWifiProvider? WifiOrNull => _wifi;
        public static IEnterpriseEnvironment? EnterpriseOrNull => _enterprise;

        private static T Require<T>(T? instance, string name) where T : class
            => instance ?? throw new InvalidOperationException(
                $"Kein {name} registriert. Das Startprojekt muss PlatformServices.Register... beim Start aufrufen.");
    }
}
