using System.Data;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Fasst die Schritte zusammen, mit denen die 3D-Topologie sichtbar wird:
    /// Bibliothek bereitstellen, Seite erzeugen, lokalen Server starten und die
    /// Seite im konfigurierten <see cref="IWebViewHost"/> oeffnen.
    ///
    /// Wo die Seite landet, entscheidet allein die registrierte
    /// IWebViewHost-Implementierung - eingebettet (WPF: WebView2) oder extern.
    /// </summary>
    public static class TopologyLauncher
    {
        /// <summary>
        /// Ablageort der erzeugten Seiten. Gleicher Pfad wie im WPF-Original,
        /// damit beide Versionen dieselben Dateien schreiben.
        /// </summary>
        public static string DefaultGraphFolder { get; } = Path.Combine(
            Path.Combine(Environment.ExpandEnvironmentVariables("%userprofile%"), "Documents"),
            "MyNetworkMonitor", "3dFoceGraph");

        public static Task ShowAsync(IWebViewHost webViewHost, DataTable resultTable,
                                     bool useOnlineVersion, string? graphFolder = null) =>
            ShowAsync(webViewHost, useOnlineVersion, graphFolder,
                      folder => TopologyGraph.WriteHtmlFile(folder, resultTable, useOnlineVersion));

        /// <summary>
        /// Dieselbe Anzeige aus dem neuen Geraetemodell. Nur die Quelle der
        /// Seite unterscheidet sich - Bibliothek, Server und Navigation sind
        /// dieselben.
        /// </summary>
        public static Task ShowAsync(IWebViewHost webViewHost, IReadOnlyList<Model.Device> devices,
                                     bool useOnlineVersion, string? graphFolder = null) =>
            ShowAsync(webViewHost, useOnlineVersion, graphFolder,
                      folder => TopologyGraph.WriteHtmlFile(folder, devices, useOnlineVersion));

        private static async Task ShowAsync(IWebViewHost webViewHost, bool useOnlineVersion,
                                            string? graphFolder, Func<string, string> writePage)
        {
            string folder = graphFolder ?? DefaultGraphFolder;

            TopologyGraph.EnsureLocalLibrary(folder);
            string htmlFilePath = writePage(folder);

            // Die Seite muss ueber http geladen werden - ueber file:// verweigern
            // Chromium-basierte Engines das Nachladen der Bibliothek.
            string baseUrl = TopologyWebServer.EnsureStarted(folder);

            await webViewHost.EnsureInitializedAsync();
            webViewHost.Navigate(baseUrl + Path.GetFileName(htmlFilePath));
        }
    }
}
