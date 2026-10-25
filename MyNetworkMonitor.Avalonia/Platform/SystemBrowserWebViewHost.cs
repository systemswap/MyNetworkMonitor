using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Avalonia.Platform
{
    /// <summary>
    /// Shows the topology in the default browser of the system instead of an
    /// embedded control.
    /// <para>
    /// <b>Why it exists:</b> <see cref="NativeWebViewHost"/> uses the web
    /// engine of the system: WebView2 on Windows, WPE WebKit on Linux. Without
    /// it, the topology view would stay empty, which looks like an application
    /// error and gives no hint what to do. The page is written to a file and
    /// served by a local web server anyway, so opening it in the browser is not
    /// a workaround but the same content in a different window.
    /// </para>
    /// <para>
    /// The browser is also the only way that works everywhere without
    /// installing anything first, which matters most on Linux.
    /// </para>
    /// </summary>
    public sealed class SystemBrowserWebViewHost : IWebViewHost
    {
        /// <summary>Nothing to prepare: the browser is started on demand.</summary>
        public Task EnsureInitializedAsync() => Task.CompletedTask;

        /// <summary>Opens <paramref name="url"/> in the default browser.</summary>
        /// <param name="url">Address of the page to show.</param>
        /// <exception cref="ArgumentException"><paramref name="url"/> is null, empty or white space.</exception>
        public void Navigate(string url)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(url);

            // UseShellExecute lets the system decide which browser is
            // responsible. On Linux, xdg-open does that; .NET maps the same
            // switch to it, but not reliably on every desktop, hence the
            // explicit call there.
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                Process.Start(new ProcessStartInfo("xdg-open", url) { UseShellExecute = false });
                return;
            }

            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
    }
}
