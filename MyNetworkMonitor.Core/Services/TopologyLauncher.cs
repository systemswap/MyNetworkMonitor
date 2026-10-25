// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Data;
using System.Runtime.InteropServices;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Combines the steps that make the 3D topology visible: provide the library,
    /// generate the page, start the local server and open the page in the
    /// configured <see cref="IWebViewHost"/>.
    ///
    /// Where the page appears is decided solely by the registered
    /// IWebViewHost implementation - embedded or in the system browser.
    /// </summary>
    public static class TopologyLauncher
    {
        /// <summary>
        /// Storage location of the generated pages, below Documents in the
        /// user profile.
        /// </summary>
        public static string DefaultGraphFolder { get; } = Path.Combine(
            Path.Combine(
                RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                    ? Environment.ExpandEnvironmentVariables("%userprofile%")
                    : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Documents"),
            "MyNetworkMonitor", "3dFoceGraph");

        /// <summary>
        /// Shows the network topology built from the result table.
        /// </summary>
        /// <param name="webViewHost">Where the page is displayed.</param>
        /// <param name="resultTable">The scan result table.</param>
        /// <param name="useOnlineVersion">Load 3d-force-graph from the CDN instead of the bundled copy.</param>
        /// <param name="graphFolder">Where the page is written; <see cref="DefaultGraphFolder"/> if null.</param>
        public static Task ShowAsync(IWebViewHost webViewHost, DataTable resultTable,
                                     bool useOnlineVersion, string? graphFolder = null) =>
            ShowAsync(webViewHost, useOnlineVersion, graphFolder,
                      folder => TopologyGraph.WriteHtmlFile(folder, resultTable, useOnlineVersion));

        /// <summary>
        /// The same display, built from the device model. Only the source of
        /// the page differs - library, server and navigation are the same.
        /// </summary>
        /// <param name="webViewHost">Where the page is displayed.</param>
        /// <param name="devices">The scanned devices.</param>
        /// <param name="useOnlineVersion">Load 3d-force-graph from the CDN instead of the bundled copy.</param>
        /// <param name="graphFolder">Where the page is written; <see cref="DefaultGraphFolder"/> if null.</param>
        public static Task ShowAsync(IWebViewHost webViewHost, IReadOnlyList<Model.Device> devices,
                                     bool useOnlineVersion, string? graphFolder = null) =>
            ShowAsync(webViewHost, useOnlineVersion, graphFolder,
                      folder => TopologyGraph.WriteHtmlFile(folder, devices, useOnlineVersion));

        /// <summary>
        /// The service view. A separate path down to the generated file - only
        /// library, server and navigation are shared, exactly the parts that have
        /// nothing to do with the rendering.
        /// </summary>
        /// <param name="webViewHost">Where the page is displayed.</param>
        /// <param name="devices">The scanned devices.</param>
        /// <param name="useOnlineVersion">Load 3d-force-graph from the CDN instead of the bundled copy.</param>
        /// <param name="graphFolder">Where the page is written; <see cref="DefaultGraphFolder"/> if null.</param>
        public static Task ShowServicesAsync(IWebViewHost webViewHost, IReadOnlyList<Model.Device> devices,
                                             bool useOnlineVersion, string? graphFolder = null) =>
            ShowAsync(webViewHost, useOnlineVersion, graphFolder,
                      folder => ServiceTopologyGraph.WriteHtmlFile(folder, devices, useOnlineVersion));

        private static async Task ShowAsync(IWebViewHost webViewHost, bool useOnlineVersion,
                                            string? graphFolder, Func<string, string> writePage)
        {
            string folder = graphFolder ?? DefaultGraphFolder;

            TopologyGraph.EnsureLocalLibrary(folder);
            string htmlFilePath = writePage(folder);

            // The page must be loaded via http - via file:// Chromium-based
            // engines refuse to load the library.
            string baseUrl = TopologyWebServer.EnsureStarted(folder);

            await webViewHost.EnsureInitializedAsync();
            webViewHost.Navigate(baseUrl + Path.GetFileName(htmlFilePath));
        }
    }
}
