namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Kapselt das Hosting einer eingebetteten Webansicht hinter einer neutralen
    /// Schnittstelle. Die WPF-Implementierung nutzt WebView2; die spätere
    /// Avalonia-Implementierung nutzt WebViewControl-Avalonia (CEF/Chromium).
    /// Die Fensterlogik (HTML-Erzeugung, lokaler Server, Navigation) haengt nur
    /// noch von diesem Interface ab.
    /// </summary>
    public interface IWebViewHost
    {
        /// <summary>Initialisiert die zugrunde liegende Webansicht (einmalig).</summary>
        Task EnsureInitializedAsync();

        /// <summary>Navigiert die Webansicht zur angegebenen URL.</summary>
        void Navigate(string url);
    }
}
