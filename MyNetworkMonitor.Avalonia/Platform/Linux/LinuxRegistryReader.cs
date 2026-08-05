using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Avalonia.Platform.Linux
{
    /// <summary>
    /// Linux-Implementierung von <see cref="IRegistryReader"/>. Unter Linux gibt es
    /// keine Windows-Registry – daher existiert kein Schlüssel/Wert.
    /// </summary>
    public sealed class LinuxRegistryReader : IRegistryReader
    {
        public bool KeyExists(RegistryHiveKind hive, string subKeyPath) => false;

        public string? GetString(RegistryHiveKind hive, string subKeyPath, string valueName) => null;
    }
}
