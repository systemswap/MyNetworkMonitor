// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Where the application stores its files.
    /// <para>
    /// Satellite mode needs a second location besides the signed-in user's
    /// settings: the service runs as LocalSystem and has no Documents folder.
    /// Everything the service <em>and</em> the user interface both need - the own
    /// key, the host list, the satellite list - is therefore stored machine-wide.
    /// Otherwise both would have different keys and thus different identities,
    /// and an approval on the main scanner would apply to only one of them.
    /// </para>
    /// </summary>
    public static class AppPaths
    {
        private const string FolderName = "MyNetworkMonitor";

        /// <summary>
        /// A custom storage location instead of the default one - set via
        /// <c>--state</c> on the command line.
        /// <para>
        /// Allows running a second instance on the same machine without writing
        /// into the files of the first. Used for testing: main scanner and
        /// satellite on one machine, each with its <b>own key</b> - and thus its
        /// own fingerprint; otherwise the approval would be an approval of itself
        /// and verify nothing.
        /// </para>
        /// </summary>
        private static string? _stateRoot;

        /// <summary>
        /// Moves the storage location and settings of this instance to a dedicated
        /// folder. Must be called before the first access, i.e. at startup.
        /// </summary>
        /// <param name="root">The folder to use; empty or whitespace keeps the default location.</param>
        public static void UseOwnState(string root)
        {
            _stateRoot = string.IsNullOrWhiteSpace(root) ? null : Path.GetFullPath(root);
        }

        /// <summary>
        /// The log for crashes and for the elevated setup run of the Windows
        /// service, in the temporary folder of the account that runs the
        /// program. Defined here because the user interface writes it and the
        /// service control refers to it in its messages.
        /// </summary>
        public static string CrashLog { get; } = Path.Combine(Path.GetTempPath(), "MyNetworkMonitor_crash.log");

        /// <summary>Whether this instance uses a custom storage location.</summary>
        public static bool HasOwnState => _stateRoot is not null;

        /// <summary>
        /// The settings folder when a custom storage location applies - otherwise
        /// <c>null</c>, in which case the folder under Documents is used.
        /// </summary>
        public static string? OwnSettingsFolder =>
            _stateRoot is null ? null : Path.Combine(_stateRoot, "Settings");

        /// <summary>
        /// The machine-wide folder: <c>%ProgramData%</c> on Windows,
        /// <c>/var/lib</c> elsewhere.
        /// <para>
        /// Not <see cref="Environment.SpecialFolder.CommonApplicationData"/>
        /// on Linux: there it maps to <c>/usr/share</c>, which belongs to the
        /// package manager, not to the data of a service.
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
        /// Creates the machine-wide folder if it is missing and returns it.
        /// </summary>
        /// <returns>The full path of the machine-wide folder.</returns>
        public static string EnsureMachineFolder()
        {
            string folder = MachineFolder;
            if (!Directory.Exists(folder)) Directory.CreateDirectory(folder);
            return folder;
        }

        /// <summary>
        /// The satellite-mode files that move from the per-user folder to the
        /// machine-wide folder.
        /// </summary>
        private static readonly string[] SharedFiles =
            ["identity.pfx", "satellites.json", "mainScanners.json"];

        /// <summary>
        /// Copies the existing state from the user's settings if nothing is
        /// stored machine-wide yet.
        /// <para>
        /// Without this, an installation that keeps these files in the per-user
        /// settings would get a <em>new</em> key on its first start with the
        /// machine-wide folder: peers would see an unknown fingerprint and every
        /// approval would have to be renewed by hand. Files are copied rather than
        /// moved - if something goes wrong, the previous state is still there.
        /// </para>
        /// </summary>
        /// <param name="userSettingsFolder">The per-user settings folder, for example Documents\MyNetworkMonitor\Settings.</param>
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
                // A failed migration must not block startup. The consequence is
                // a new key and thus a new approval - inconvenient, but not
                // critical.
            }
        }
    }
}
