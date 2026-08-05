using Microsoft.Win32;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Platform
{
    /// <summary>Windows-Implementierung von <see cref="IRegistryReader"/> (Microsoft.Win32.Registry).</summary>
    public sealed class WindowsRegistryReader : IRegistryReader
    {
        public bool KeyExists(RegistryHiveKind hive, string subKeyPath)
        {
            using var key = BaseKey(hive).OpenSubKey(subKeyPath);
            return key != null;
        }

        public string? GetString(RegistryHiveKind hive, string subKeyPath, string valueName)
        {
            using var key = BaseKey(hive).OpenSubKey(subKeyPath);
            return key?.GetValue(valueName) as string;
        }

        private static RegistryKey BaseKey(RegistryHiveKind hive) => hive switch
        {
            RegistryHiveKind.ClassesRoot => Registry.ClassesRoot,
            RegistryHiveKind.CurrentUser => Registry.CurrentUser,
            RegistryHiveKind.LocalMachine => Registry.LocalMachine,
            RegistryHiveKind.Users => Registry.Users,
            RegistryHiveKind.CurrentConfig => Registry.CurrentConfig,
            _ => Registry.LocalMachine
        };
    }
}
