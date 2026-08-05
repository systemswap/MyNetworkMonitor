using System;
using System.DirectoryServices.ActiveDirectory;
using System.Net.NetworkInformation;
using System.Security.Principal;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Platform.Windows
{
    /// <summary>
    /// Windows-Implementierung von <see cref="IEnterpriseEnvironment"/>.
    /// Kapselt die Windows-spezifische Unternehmens-Erkennung (ActiveDirectory,
    /// WindowsIdentity, Registry via <see cref="IRegistryReader"/>).
    /// </summary>
    public sealed class WindowsEnterpriseEnvironment : IEnterpriseEnvironment
    {
        private readonly IRegistryReader _registry;

        public WindowsEnterpriseEnvironment(IRegistryReader? registryReader = null)
        {
            _registry = registryReader ?? new WindowsRegistryReader();
        }

        public bool IsCompanyNetwork()
        {
            return IsDomainJoined() || IsAzureADUser() || IsAzureADJoined() || IsDomainUser() || IsCompanyIP();
        }

        private static bool IsDomainJoined()
        {
            try
            {
                Domain domain = Domain.GetComputerDomain();
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool IsDomainUser()
        {
            string userDomain = Environment.UserDomainName;
            string computerName = Environment.MachineName;
            return !string.IsNullOrEmpty(userDomain) && userDomain != computerName;
        }

        private static bool IsAzureADUser()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            return identity.User.Value.StartsWith("S-1-12-1-"); // Azure AD SID beginnt mit S-1-12-1
        }

        private bool IsAzureADJoined()
        {
            try
            {
                return _registry.KeyExists(RegistryHiveKind.LocalMachine,
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD");
            }
            catch
            {
                return false;
            }
        }

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
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }
    }
}
