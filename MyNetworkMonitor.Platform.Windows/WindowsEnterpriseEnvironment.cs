using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Platform.Windows
{
    /// <summary>
    /// Windows implementation of <see cref="IEnterpriseEnvironment"/>. Uses the
    /// same platform-neutral test as Linux, see
    /// <see cref="ActiveDirectoryDetector"/>.
    /// <para>
    /// Criteria such as <c>Domain.GetComputerDomain()</c>, the Azure AD SID or
    /// the Azure AD registration key are not used: they only answer "has this
    /// device ever joined a domain", not "is this device in that network right
    /// now". A domain-joined laptop on a home network would be reported as being
    /// in a company network, just like with address-range heuristics. The DNS SRV
    /// query needs a peer that is reachable right now and therefore answers the
    /// right question. See docs/FEHLERGEDAECHTNIS.md, No. 1.
    /// </para>
    /// </summary>
    public sealed class WindowsEnterpriseEnvironment : IEnterpriseEnvironment
    {
        public bool IsCompanyNetwork() => ActiveDirectoryDetector.DomainControllerReachable();
    }
}
