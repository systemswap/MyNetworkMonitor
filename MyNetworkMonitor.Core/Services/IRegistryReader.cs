namespace MyNetworkMonitor.Core.Services
{
    /// <summary>Registry root key (platform-neutral equivalent of Microsoft.Win32.RegistryHive).</summary>
    public enum RegistryHiveKind
    {
        ClassesRoot,
        CurrentUser,
        LocalMachine,
        Users,
        CurrentConfig
    }

    /// <summary>
    /// Encapsulates read access to the Windows registry behind a neutral
    /// interface. The Windows implementation uses Microsoft.Win32.Registry;
    /// on Linux, which has no registry, the implementation reports every key
    /// and value as missing.
    /// </summary>
    public interface IRegistryReader
    {
        /// <summary>Whether the subkey exists.</summary>
        /// <param name="hive">The root key.</param>
        /// <param name="subKeyPath">The path of the subkey below the root key.</param>
        /// <returns><c>true</c> if the subkey exists.</returns>
        bool KeyExists(RegistryHiveKind hive, string subKeyPath);

        /// <summary>Reads a string value.</summary>
        /// <param name="hive">The root key.</param>
        /// <param name="subKeyPath">The path of the subkey below the root key.</param>
        /// <param name="valueName">The name of the value.</param>
        /// <returns>The value, or null if the key or value is missing.</returns>
        string? GetString(RegistryHiveKind hive, string subKeyPath, string valueName);
    }
}
