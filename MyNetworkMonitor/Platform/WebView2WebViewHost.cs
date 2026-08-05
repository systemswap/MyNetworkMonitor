using System.Threading.Tasks;
using Microsoft.Web.WebView2.Wpf;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Platform
{
    /// <summary>
    /// WPF-Implementierung von <see cref="IWebViewHost"/>. Umschliesst das in der
    /// View eingebettete WebView2-Control. Die Avalonia-Variante wird analog ein
    /// CEF-basiertes Control umschliessen (WebViewControl-Avalonia).
    /// </summary>
    public sealed class WebView2WebViewHost : IWebViewHost
    {
        private readonly WebView2 _webView;

        public WebView2WebViewHost(WebView2 webView) => _webView = webView;

        public Task EnsureInitializedAsync() => _webView.EnsureCoreWebView2Async(null);

        public void Navigate(string url) => _webView.CoreWebView2.Navigate(url);
    }
}
