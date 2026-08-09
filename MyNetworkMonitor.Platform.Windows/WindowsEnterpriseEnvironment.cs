using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Platform.Windows
{
    /// <summary>
    /// Windows-Implementierung von <see cref="IEnterpriseEnvironment"/>. Nutzt
    /// denselben plattformneutralen Test wie Linux - siehe
    /// <see cref="ActiveDirectoryDetector"/>.
    /// <para>
    /// Frühere Kriterien wie <c>Domain.GetComputerDomain()</c>, die Azure-AD-SID
    /// und der Azure-AD-Registrierungsschlüssel sind entfallen: sie beantworten
    /// nur "ist dieses Gerät jemals einer Domäne beigetreten", nicht "bin ich
    /// gerade in diesem Netz" - ein domänengebundener Laptop im Homeoffice löste
    /// damit dieselbe Fehlmeldung aus wie die alte IP-Bereichs-Heuristik, nur aus
    /// einem anderen Grund. Die DNS-SRV-Abfrage braucht dagegen eine aktuell
    /// erreichbare Gegenstelle und beantwortet damit die richtige Frage.
    /// </para>
    /// </summary>
    public sealed class WindowsEnterpriseEnvironment : IEnterpriseEnvironment
    {
        public bool IsCompanyNetwork() => ActiveDirectoryDetector.DomainControllerReachable();
    }
}
