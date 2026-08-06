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

        public static void RegisterArp(IArpProvider provider) => _arp = provider;
        public static void RegisterRouting(IRoutingProvider provider) => _routing = provider;
        public static void RegisterRegistry(IRegistryReader provider) => _registry = provider;
        public static void RegisterWifi(IWifiProvider provider) => _wifi = provider;
        public static void RegisterEnterprise(IEnterpriseEnvironment provider) => _enterprise = provider;

        public static IArpProvider Arp => Require(_arp, nameof(IArpProvider));
        public static IRoutingProvider Routing => Require(_routing, nameof(IRoutingProvider));
        public static IRegistryReader Registry => Require(_registry, nameof(IRegistryReader));
        public static IWifiProvider Wifi => Require(_wifi, nameof(IWifiProvider));
        public static IEnterpriseEnvironment Enterprise => Require(_enterprise, nameof(IEnterpriseEnvironment));

        public static IRegistryReader? RegistryOrNull => _registry;
        public static IWifiProvider? WifiOrNull => _wifi;
        public static IEnterpriseEnvironment? EnterpriseOrNull => _enterprise;

        private static T Require<T>(T? instance, string name) where T : class
            => instance ?? throw new InvalidOperationException(
                $"Kein {name} registriert. Das Startprojekt muss PlatformServices.Register... beim Start aufrufen.");
    }
}
