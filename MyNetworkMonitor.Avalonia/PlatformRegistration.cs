// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using MyNetworkMonitor.Avalonia.Platform.Linux;
#if WINDOWS
using MyNetworkMonitor.Platform.Windows;
#endif
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Avalonia;

/// <summary>
/// Registers the platform-specific implementations in
/// <see cref="PlatformServices"/>.
/// <para>
/// Lives outside <c>App.OnFrameworkInitializationCompleted</c> because the
/// satellite service runs without Avalonia; without this registration, ARP
/// requests and routing fail there, which are exactly the methods the
/// satellite exists for.
/// </para>
/// </summary>
public static class PlatformRegistration
{
    /// <summary>Registers the providers for the platform this build targets.</summary>
    public static void RegisterAll()
    {
        // Windows builds must register the Windows providers: with the Linux
        // providers, ARP requests and routing fail there.
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
