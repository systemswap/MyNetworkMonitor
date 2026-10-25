// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System;
using System.Threading.Tasks;
using Avalonia.Controls;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Avalonia.Platform
{
    /// <summary>
    /// Avalonia implementation of <see cref="IWebViewHost"/> based on Avalonia's
    /// own <see cref="NativeWebView"/> (package Avalonia.Controls.WebView).
    ///
    /// NativeWebView uses the engine of the system (Windows: WebView2, Linux:
    /// WPE WebKit, or WebKitGTK as a fallback) and avoids shipping a large
    /// Chromium runtime. CEF through WebViewControl-Avalonia is not an option:
    /// its current release is built against Avalonia 11 and crashes on
    /// Avalonia 12 when the control is created.
    ///
    /// On Linux, according to Avalonia, the *embedded* control is not available
    /// on every system, and it is currently disabled there (see
    /// <c>ShellView.EmbeddedWebViewEnabledOnLinux</c>). Where it is not used,
    /// <see cref="SystemBrowserWebViewHost"/> takes its place.
    /// </summary>
    public sealed class NativeWebViewHost : IWebViewHost
    {
        private readonly NativeWebView _webView;

        /// <summary>Creates the host for an embedded web view.</summary>
        /// <param name="webView">The control that displays the pages.</param>
        public NativeWebViewHost(NativeWebView webView) => _webView = webView;

        /// <summary>
        /// The control initializes itself once it is attached to the visual tree.
        /// The method exists only because hosts based on WebView2 need it.
        /// </summary>
        public Task EnsureInitializedAsync() => Task.CompletedTask;

        public void Navigate(string url) => _webView.Source = new Uri(url);
    }
}
