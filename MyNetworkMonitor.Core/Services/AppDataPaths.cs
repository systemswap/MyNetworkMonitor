namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Wohin die Anwendung Daten schreibt, die sie waehrend des Betriebs
    /// erneuert.
    /// <para>
    /// Nicht neben das Programm: unter Linux liegt eine installierte Anwendung
    /// in einem Verzeichnis, das dem Systemverwalter gehoert. Ein Schreibversuch
    /// dorthin endet mit "Permission denied" - genau daran ist das Erneuern der
    /// MAC-Herstellerliste gescheitert. Unter Windows fiel es nicht auf, weil
    /// das Programm dort ueblicherweise aus einem eigenen Ordner laeuft.
    /// </para>
    /// <para>
    /// Der Ort ist der, den das Betriebssystem dafuer vorsieht: unter Windows
    /// <c>%AppData%</c>, unter Linux <c>~/.config</c> (bzw. was
    /// <c>XDG_CONFIG_HOME</c> sagt). Beides gehoert dem angemeldeten Benutzer,
    /// beides braucht keine erhoehten Rechte.
    /// </para>
    /// </summary>
    public static class AppDataPaths
    {
        /// <summary>Der eigene Ordner unterhalb des Benutzerverzeichnisses.</summary>
        public static string Root => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "MyNetworkMonitor");

        /// <summary>
        /// Die erneuerte MAC-Herstellerliste. Die mitgelieferte bleibt neben dem
        /// Programm liegen und dient als Rueckfall - siehe
        /// <see cref="MacVendorCsvCandidates"/>.
        /// </summary>
        public static string MacVendorCsv => Path.Combine(Root, "MacVendors", "mac_vendors.csv");

        /// <summary>
        /// Wo nach der Herstellerliste gesucht wird, in dieser Reihenfolge:
        /// erst die selbst erneuerte im Benutzerverzeichnis, dann die
        /// mitgelieferte neben dem Programm, zuletzt das Arbeitsverzeichnis.
        /// </summary>
        public static IEnumerable<string> MacVendorCsvCandidates
        {
            get
            {
                yield return MacVendorCsv;
                yield return Path.Combine(AppContext.BaseDirectory, "MacVendors", "mac_vendors.csv");
                yield return Path.Combine(Directory.GetCurrentDirectory(), "MacVendors", "mac_vendors.csv");
            }
        }
    }
}
