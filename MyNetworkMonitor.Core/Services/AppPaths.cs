namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Wo die Anwendung ihre Dateien ablegt.
    /// <para>
    /// Der Satellitenbetrieb braucht einen zweiten Ort neben den
    /// Einstellungen des angemeldeten Nutzers: der Dienst laeuft als
    /// LocalSystem und hat kein Dokumente-Verzeichnis. Alles, was Dienst
    /// <em>und</em> Oberflaeche gemeinsam brauchen - der eigene Schluessel, die
    /// Hostliste, die Satellitenliste - liegt darum maschinenweit. Sonst
    /// haetten beide verschiedene Schluessel und damit verschiedene
    /// Kennungen, und eine Freigabe am Hauptscanner gaelte nur fuer eine von
    /// beiden.
    /// </para>
    /// </summary>
    public static class AppPaths
    {
        private const string FolderName = "MyNetworkMonitor";

        /// <summary>
        /// Ein eigener Ablageort statt der ueblichen - gesetzt ueber
        /// <c>--state</c> auf der Befehlszeile.
        /// <para>
        /// Damit laesst sich eine zweite Instanz auf demselben Rechner
        /// betreiben, ohne der ersten in die Dateien zu schreiben. Gebraucht
        /// wird das beim Ausprobieren: Hauptscanner und Satellit auf einer
        /// Maschine, jeder mit <b>eigenem Schluessel</b> - und damit einem
        /// eigenen Fingerabdruck, sonst waere die Freigabe eine Freigabe fuer
        /// sich selbst und pruefte nichts.
        /// </para>
        /// </summary>
        private static string? _stateRoot;

        /// <summary>
        /// Legt Ablageort und Einstellungen dieser Instanz auf einen eigenen
        /// Ordner. Vor dem ersten Zugriff aufzurufen, also beim Start.
        /// </summary>
        public static void UseOwnState(string root)
        {
            _stateRoot = string.IsNullOrWhiteSpace(root) ? null : Path.GetFullPath(root);
        }

        /// <summary>Ob diese Instanz einen eigenen Ablageort benutzt.</summary>
        public static bool HasOwnState => _stateRoot is not null;

        /// <summary>
        /// Der Einstellungsordner, wenn ein eigener Ablageort gilt - sonst
        /// <c>null</c>, dann bleibt es beim Ordner unter Dokumente.
        /// </summary>
        public static string? OwnSettingsFolder =>
            _stateRoot is null ? null : Path.Combine(_stateRoot, "Settings");

        /// <summary>
        /// Der maschinenweite Ordner: unter Windows <c>%ProgramData%</c>,
        /// sonst <c>/var/lib</c>.
        /// <para>
        /// Nicht <see cref="Environment.SpecialFolder.CommonApplicationData"/>
        /// unter Linux: das ist dort <c>/usr/share</c> und gehoert der
        /// Paketverwaltung, nicht den Daten eines Dienstes.
        /// </para>
        /// </summary>
        public static string MachineFolder
        {
            get
            {
                if (_stateRoot is not null) return Path.Combine(_stateRoot, "Machine");

                string root = OperatingSystem.IsWindows()
                    ? Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
                    : "/var/lib";

                return Path.Combine(root, FolderName);
            }
        }

        /// <summary>
        /// Legt den maschinenweiten Ordner an, falls er fehlt, und gibt ihn
        /// zurueck.
        /// </summary>
        public static string EnsureMachineFolder()
        {
            string folder = MachineFolder;
            if (!Directory.Exists(folder)) Directory.CreateDirectory(folder);
            return folder;
        }

        /// <summary>
        /// Die Dateien des Satellitenbetriebs, die vom nutzereigenen Ordner in
        /// den maschinenweiten wandern.
        /// </summary>
        private static readonly string[] SharedFiles =
            ["identity.pfx", "satellites.json", "mainScanners.json"];

        /// <summary>
        /// Holt den vorhandenen Bestand aus den Einstellungen des Nutzers
        /// nach, falls maschinenweit noch nichts liegt.
        /// <para>
        /// Ohne das bekaeme jede bestehende Installation beim ersten Start
        /// nach dem Umbau einen <em>neuen</em> Schluessel: die Gegenstellen
        /// saehen einen fremden Fingerabdruck, und jede Freigabe muesste von
        /// Hand erneuert werden. Es wird kopiert und nicht verschoben - geht
        /// etwas schief, ist der alte Stand noch da.
        /// </para>
        /// </summary>
        /// <param name="userSettingsFolder">Der bisherige Ort, etwa Dokumente\MyNetworkMonitor\Settings.</param>
        public static void MigrateSatelliteState(string userSettingsFolder)
        {
            if (string.IsNullOrWhiteSpace(userSettingsFolder)) return;

            try
            {
                string machine = EnsureMachineFolder();

                foreach (string name in SharedFiles)
                {
                    string source = Path.Combine(userSettingsFolder, name);
                    string target = Path.Combine(machine, name);

                    if (File.Exists(source) && !File.Exists(target)) File.Copy(source, target);
                }
            }
            catch (Exception)
            {
                // Ein misslungener Umzug darf den Start nicht aufhalten. Die
                // Folge ist ein neuer Schluessel und damit eine neue Freigabe -
                // aergerlich, aber nicht schlimm.
            }
        }
    }
}
