namespace MyNetworkMonitor.Core.Services
{
    /// <summary>Registry-Wurzelschlüssel (plattformneutrale Entsprechung von Microsoft.Win32.RegistryHive).</summary>
    public enum RegistryHiveKind
    {
        ClassesRoot,
        CurrentUser,
        LocalMachine,
        Users,
        CurrentConfig
    }

    /// <summary>
    /// Kapselt lesenden Zugriff auf die Windows-Registry hinter einer neutralen
    /// Schnittstelle. Die Windows-Implementierung nutzt Microsoft.Win32.Registry;
    /// unter Linux (wo es keine Registry gibt) kann eine Implementierung injiziert
    /// werden, die schlicht "nicht vorhanden" liefert.
    /// </summary>
    public interface IRegistryReader
    {
        /// <summary>true, wenn der Unterschlüssel existiert.</summary>
        bool KeyExists(RegistryHiveKind hive, string subKeyPath);

        /// <summary>Liest einen String-Wert oder null, wenn Schlüssel/Wert fehlt.</summary>
        string? GetString(RegistryHiveKind hive, string subKeyPath, string valueName);
    }
}
