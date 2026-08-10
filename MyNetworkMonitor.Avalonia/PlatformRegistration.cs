using MyNetworkMonitor.Avalonia.Platform.Linux;
#if WINDOWS
using MyNetworkMonitor.Platform.Windows;
#endif
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Avalonia;

/// <summary>
/// Traegt die plattformabhaengigen Umsetzungen in
/// <see cref="PlatformServices"/> ein.
/// <para>
/// Steht seit dem Satellitendienst hier und nicht mehr in
/// <c>App.OnFrameworkInitializationCompleted</c>: der Dienst laeuft ohne
/// Avalonia, und ohne diese Registrierung schlagen bei ihm ARP-Anfrage und
/// Routing fehl - also genau die Verfahren, wegen derer es den Satelliten
/// ueberhaupt gibt.
/// </para>
/// </summary>
public static class PlatformRegistration
{
    public static void RegisterAll()
    {
        // Wichtig: unter Windows muessen die Windows-Provider registriert
        // werden - mit den Linux-Providern schlagen ARP-Request und Routing
        // dort fehl.
#if WINDOWS
        PlatformServices.RegisterArp(new WindowsArpProvider());
        PlatformServices.RegisterRouting(new WindowsRoutingProvider());
        PlatformServices.RegisterRegistry(new WindowsRegistryReader());
        PlatformServices.RegisterEnterprise(new WindowsEnterpriseEnvironment());
        PlatformServices.RegisterWifi(new ScanningMethod_WiFi());
        PlatformServices.RegisterNeighbors(new WindowsNeighborProvider());
        PlatformServices.RegisterFirewall(new WindowsFirewallInspector());
        PlatformServices.RegisterServiceControl(new WindowsServiceControl());
        PlatformServices.RegisterPipeServerFactory(WindowsPipeServerFactory.Create);
#else
        PlatformServices.RegisterArp(new LinuxArpProvider());
        PlatformServices.RegisterRouting(new LinuxRoutingProvider());
        PlatformServices.RegisterRegistry(new LinuxRegistryReader());
        PlatformServices.RegisterEnterprise(new LinuxEnterpriseEnvironment());
        PlatformServices.RegisterWifi(new LinuxWifiProvider());
        PlatformServices.RegisterNeighbors(new LinuxNeighborProvider());
#endif
    }
}
