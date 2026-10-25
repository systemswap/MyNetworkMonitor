using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Avalonia.Platform.Linux
{
    /// <summary>
    /// Linux implementation of <see cref="IRegistryReader"/>. Linux has no Windows
    /// registry, so no key or value ever exists.
    /// </summary>
    public sealed class LinuxRegistryReader : IRegistryReader
    {
        public bool KeyExists(RegistryHiveKind hive, string subKeyPath) => false;

        public string? GetString(RegistryHiveKind hive, string subKeyPath, string valueName) => null;
    }
}
