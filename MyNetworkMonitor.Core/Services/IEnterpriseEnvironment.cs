namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Erkennung, ob die Anwendung in einem Unternehmensnetzwerk läuft.
    /// Die Windows-Implementierung wertet Domänen-/Azure-AD-Zugehörigkeit
    /// (ActiveDirectory, WindowsIdentity, Registry) sowie bekannte IP-Bereiche aus;
    /// eine spätere Linux-Implementierung kann eine eigene Heuristik liefern.
    /// </summary>
    public interface IEnterpriseEnvironment
    {
        bool IsCompanyNetwork();
    }
}
