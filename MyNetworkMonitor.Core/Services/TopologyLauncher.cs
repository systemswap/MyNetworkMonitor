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

        public static async Task ShowAsync(IWebViewHost webViewHost, DataTable resultTable,
                                           bool useOnlineVersion, string? graphFolder = null)
        {
            string folder = graphFolder ?? DefaultGraphFolder;

            TopologyGraph.EnsureLocalLibrary(folder);
            string htmlFilePath = TopologyGraph.WriteHtmlFile(folder, resultTable, useOnlineVersion);

            // Die Seite muss ueber http geladen werden - ueber file:// verweigern
            // Chromium-basierte Engines das Nachladen der Bibliothek.
            string baseUrl = TopologyWebServer.EnsureStarted(folder);

            await webViewHost.EnsureInitializedAsync();
            webViewHost.Navigate(baseUrl + Path.GetFileName(htmlFilePath));
        }
    }
}
