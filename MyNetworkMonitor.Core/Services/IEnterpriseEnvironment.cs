namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Detects whether the application runs on a corporate network.
    /// Both platform implementations (Windows, Linux) rely on
    /// <see cref="ActiveDirectoryDetector"/> - the same platform-neutral DNS check
    /// instead of a separate heuristic per operating system.
    /// See docs/FEHLERGEDAECHTNIS.md, No. 1.
    /// </summary>
    public interface IEnterpriseEnvironment
    {
        /// <summary>Whether an Active Directory domain controller is reachable on the current network.</summary>
        bool IsCompanyNetwork();
    }
}
