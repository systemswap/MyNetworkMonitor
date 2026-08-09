namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Erkennung, ob die Anwendung in einem Unternehmensnetzwerk läuft.
    /// Beide Plattform-Implementierungen (Windows, Linux) stützen sich auf
    /// <see cref="ActiveDirectoryDetector"/> - denselben, plattformneutralen
    /// DNS-Test statt einer je Betriebssystem eigenen Heuristik.
    /// </summary>
    public interface IEnterpriseEnvironment
    {
        bool IsCompanyNetwork();
    }
}
