using System.Net.NetworkInformation;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Avalonia.Platform.Linux
{
    /// <summary>
    /// Linux-Implementierung von <see cref="IEnterpriseEnvironment"/>. Die
    /// Windows-spezifischen Kriterien (AD-Domäne, Azure-AD-SID, Registry) entfallen;
    /// als Heuristik bleibt die Prüfung bekannter Unternehmens-IP-Bereiche.
    /// </summary>
    public sealed class LinuxEnterpriseEnvironment : IEnterpriseEnvironment
    {
        public bool IsCompanyNetwork() => IsCompanyIP();

        private static bool IsCompanyIP()
        {
            string[] knownCompanyNetworks = { "10.", "172." };

            foreach (var netInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (var unicast in netInterface.GetIPProperties().UnicastAddresses)
                {
                    string ip = unicast.Address.ToString();
                    foreach (var companyNetwork in knownCompanyNetworks)
                    {
                        if (ip.StartsWith(companyNetwork))
                            return true;
                    }
                }
            }
            return false;
        }
    }
}
