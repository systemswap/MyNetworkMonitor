// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Where the application writes data that it refreshes during operation.
    /// <para>
    /// Not next to the executable: on Linux an installed application resides in a
    /// directory owned by the administrator, and a write attempt there fails with
    /// "Permission denied" - which makes refreshing the MAC vendor list fail. On
    /// Windows this does not surface because the program usually runs from its own
    /// folder.
    /// </para>
    /// <para>
    /// The location is the one the operating system provides for this purpose:
    /// <c>%AppData%</c> on Windows, <c>~/.config</c> on Linux (or whatever
    /// <c>XDG_CONFIG_HOME</c> specifies). Both belong to the signed-in user and
    /// neither requires elevated privileges.
    /// </para>
    /// </summary>
    public static class AppDataPaths
    {
        /// <summary>The application's own folder below the user profile.</summary>
        public static string Root => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "MyNetworkMonitor");

        /// <summary>
        /// The refreshed MAC vendor list. The bundled list stays next to the
        /// program and serves as fallback - see
        /// <see cref="MacVendorCsvCandidates"/>.
        /// </summary>
        public static string MacVendorCsv => Path.Combine(Root, "MacVendors", "mac_vendors.csv");

        /// <summary>
        /// Where the vendor list is looked up, in this order: first the refreshed
        /// copy in the user profile, then the bundled copy next to the program,
        /// finally the working directory.
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
