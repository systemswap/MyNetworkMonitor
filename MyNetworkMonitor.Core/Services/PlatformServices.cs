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

        public static void RegisterArp(IArpProvider provider) => _arp = provider;
        public static void RegisterNeighbors(INeighborProvider provider) => _neighbors = provider;
        public static void RegisterRouting(IRoutingProvider provider) => _routing = provider;
        public static void RegisterRegistry(IRegistryReader provider) => _registry = provider;
        public static void RegisterWifi(IWifiProvider provider) => _wifi = provider;
        public static void RegisterEnterprise(IEnterpriseEnvironment provider) => _enterprise = provider;

        public static IArpProvider Arp => Require(_arp, nameof(IArpProvider));
        public static INeighborProvider Neighbors => Require(_neighbors, nameof(INeighborProvider));
        public static IRoutingProvider Routing => Require(_routing, nameof(IRoutingProvider));
        public static IRegistryReader Registry => Require(_registry, nameof(IRegistryReader));
        public static IWifiProvider Wifi => Require(_wifi, nameof(IWifiProvider));
        public static IEnterpriseEnvironment Enterprise => Require(_enterprise, nameof(IEnterpriseEnvironment));

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
