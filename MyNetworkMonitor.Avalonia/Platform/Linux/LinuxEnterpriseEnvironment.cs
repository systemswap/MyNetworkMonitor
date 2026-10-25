using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Avalonia.Platform.Linux
{
    /// <summary>
    /// Linux implementation of <see cref="IEnterpriseEnvironment"/>. Uses the
    /// same platform-neutral test as Windows, see
    /// <see cref="ActiveDirectoryDetector"/>. Private address ranges ("10.",
    /// "172.") are no indicator: Docker, libvirt and VPN adapters on any home
    /// machine use exactly these ranges without a company network being
    /// involved. See docs/FEHLERGEDAECHTNIS.md, No. 1.
    /// </summary>
    public sealed class LinuxEnterpriseEnvironment : IEnterpriseEnvironment
    {
        public bool IsCompanyNetwork() => ActiveDirectoryDetector.DomainControllerReachable();
    }
}
