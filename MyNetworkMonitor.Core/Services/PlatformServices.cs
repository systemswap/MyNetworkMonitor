using System;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Zentrale Registrierung der plattformabhaengigen Provider. Die Scan-Engine in
    /// Core kennt nur die Interfaces; das jeweilige Startprojekt (WPF/Windows bzw.
    /// Avalonia/Linux) traegt beim Start seine Implementierungen hier ein.
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

        public static void RegisterArp(IArpProvider provider) => _arp = provider;
        public static void RegisterNeighbors(INeighborProvider provider) => _neighbors = provider;
        public static void RegisterRouting(IRoutingProvider provider) => _routing = provider;
        public static void RegisterRegistry(IRegistryReader provider) => _registry = provider;
        public static void RegisterWifi(IWifiProvider provider) => _wifi = provider;
        public static void RegisterEnterprise(IEnterpriseEnvironment provider) => _enterprise = provider;
        public static void RegisterFirewall(IFirewallInspector provider) => _firewall = provider;
        public static void RegisterServiceControl(IServiceControl provider) => _serviceControl = provider;

        public static IArpProvider Arp => Require(_arp, nameof(IArpProvider));
        public static INeighborProvider Neighbors => Require(_neighbors, nameof(INeighborProvider));
        public static IRoutingProvider Routing => Require(_routing, nameof(IRoutingProvider));
        public static IRegistryReader Registry => Require(_registry, nameof(IRegistryReader));
        public static IWifiProvider Wifi => Require(_wifi, nameof(IWifiProvider));
        public static IEnterpriseEnvironment Enterprise => Require(_enterprise, nameof(IEnterpriseEnvironment));

        /// <summary>
        /// Liest die Firewall-Regeln. Ohne Registrierung eine Umsetzung, die
        /// schlicht nichts meldet - die Firewall-Anzeige ist eine Hilfe, kein
        /// Kernbestandteil, und darf nirgends etwas aufhalten.
        /// </summary>
        public static IFirewallInspector Firewall => _firewall ??= new NullFirewallInspector();

        /// <summary>
        /// Richtet den Satellitendienst ein. Ohne Registrierung eine Umsetzung,
        /// die schlicht meldet, dass es auf dieser Plattform nicht geht - die
        /// Verwaltung soll das anzeigen koennen, statt daran zu scheitern.
        /// </summary>
        public static IServiceControl ServiceControl => _serviceControl ??= new NullServiceControl();

        // --------------------------------------------------- Steuerpipe

        private static Func<string, System.IO.Pipes.NamedPipeServerStream>? _pipeServerFactory;

        /// <summary>
        /// Wie der Dienst seine Steuerpipe aufmacht.
        /// <para>
        /// Plattformabhaengig, weil die Rechte es sind: der Dienst laeuft unter
        /// Windows als LocalSystem, die Oberflaeche als angemeldeter Nutzer.
        /// Ohne ausdrueckliche Zugriffsliste darf dieser die Pipe nicht
        /// oeffnen, und das Fenster zeigte dauerhaft "Dienst antwortet nicht".
        /// Die dafuer noetige API gibt es nur unter Windows - darum wird sie
        /// von dort eingetragen. Unter Linux regeln die Rechte der Socketdatei
        /// den Zugriff, und die Vorgabe unten genuegt.
        /// </para>
        /// </summary>
        public static void RegisterPipeServerFactory(Func<string, System.IO.Pipes.NamedPipeServerStream> factory) =>
            _pipeServerFactory = factory;

        /// <summary>Legt die Steuerpipe des Dienstes an.</summary>
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

        // Fuer Aufrufer, die eine fehlende Registrierung selbst behandeln
        // wollen, statt eine Ausnahme zu bekommen - etwa die Scan-Verfahren,
        // die daraus eine Meldung an den Nutzer machen.
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
