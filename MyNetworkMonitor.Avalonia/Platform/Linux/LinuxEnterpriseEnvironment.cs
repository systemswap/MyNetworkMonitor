using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Avalonia.Platform.Linux
{
    /// <summary>
    /// Linux-Implementierung von <see cref="IEnterpriseEnvironment"/>. Nutzt
    /// denselben plattformneutralen Test wie Windows - siehe
    /// <see cref="ActiveDirectoryDetector"/>. Die frühere IP-Bereichs-Heuristik
    /// ("10.", "172.") ist entfallen: sie feuerte auf jedem Heimrechner mit
    /// Docker, libvirt oder VPN, weil deren virtuelle Adapter genau diese
    /// Bereiche belegen, ohne dass ein Firmennetz beteiligt ist.
    /// </summary>
    public sealed class LinuxEnterpriseEnvironment : IEnterpriseEnvironment
    {
        public bool IsCompanyNetwork() => ActiveDirectoryDetector.DomainControllerReachable();
    }
}
