using System;
using System.Threading.Tasks;
using Avalonia.Controls;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Avalonia.Platform
{
    /// <summary>
    /// Avalonia-Implementierung von <see cref="IWebViewHost"/> auf Basis von
    /// Avalonias eigenem <see cref="NativeWebView"/> (Paket
    /// Avalonia.Controls.WebView) - das Gegenstueck zur WebView2-Variante des
    /// WPF-Projekts.
    ///
    /// Urspruenglich war CEF ueber WebViewControl-Avalonia vorgesehen; dessen
    /// aktuelle Fassung ist gegen Avalonia 11 gebaut und stuerzt unter
    /// Avalonia 12 beim Erzeugen des Controls ab. NativeWebView nutzt stattdessen
    /// die Engine des Systems (Windows: WebView2, Linux: WebKitGTK) und spart die
    /// grosse Chromium-Laufzeit.
    ///
    /// Achtung fuer den Linux-Lauf: laut Avalonia ist das *eingebettete* Control
    /// dort nicht auf jedem System verfuegbar. Faellt es aus, ist
    /// <c>NativeWebDialog</c> (eigenes Fenster, gleiches Paket) der vorgesehene
    /// Ersatz - dann genuegt eine zweite Implementierung dieses Interfaces.
    /// </summary>
    public sealed class NativeWebViewHost : IWebViewHost
    {
        private readonly NativeWebView _webView;

        public NativeWebViewHost(NativeWebView webView) => _webView = webView;

        /// <summary>
        /// Das Control initialisiert sich selbst, sobald es im visuellen Baum
        /// haengt. Die Methode existiert nur, weil WebView2 sie braucht.
        /// </summary>
        public Task EnsureInitializedAsync() => Task.CompletedTask;

        public void Navigate(string url) => _webView.Source = new Uri(url);
    }
}
