// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Encapsulates hosting of an embedded web view behind a neutral interface.
    /// The implementations use the system web engine (WebView2 on Windows,
    /// WebKitGTK on Linux) or hand the page over to the system browser.
    /// The window logic (HTML generation, local server, navigation) depends
    /// only on this interface.
    /// </summary>
    public interface IWebViewHost
    {
        /// <summary>Initializes the underlying web view (once).</summary>
        Task EnsureInitializedAsync();

        /// <summary>Navigates the web view to the given URL.</summary>
        void Navigate(string url);
    }
}
