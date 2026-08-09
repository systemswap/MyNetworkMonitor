using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Avalonia.Platform
{
    /// <summary>
    /// Zeigt die Topologie im Standardbrowser des Systems statt in einem
    /// eingebetteten Control.
    /// <para>
    /// <b>Warum es das gibt:</b> <see cref="NativeWebViewHost"/> benutzt die
    /// Webengine des Systems - unter Windows WebView2, unter Linux WebKitGTK.
    /// Fehlt sie, blieb die Topologieansicht bisher einfach leer, was wie ein
    /// Fehler der Anwendung aussieht und keinen Hinweis gibt, was zu tun waere.
    /// Die Seite selbst wird ohnehin als Datei geschrieben und ueber einen
    /// lokalen Webserver ausgeliefert; sie im Browser zu oeffnen ist darum kein
    /// Notbehelf, sondern derselbe Inhalt in einem anderen Fenster.
    /// </para>
    /// <para>
    /// Der Weg ueber den Browser ist zudem der einzige, der ueberall
    /// funktioniert, ohne dass vorher etwas installiert werden muss - genau die
    /// Eigenschaft, um die es beim Linux-Lauf geht.
    /// </para>
    /// </summary>
    public sealed class SystemBrowserWebViewHost : IWebViewHost
    {
        /// <summary>Nichts vorzubereiten - der Browser laeuft schon.</summary>
        public Task EnsureInitializedAsync() => Task.CompletedTask;

        public void Navigate(string url)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(url);

            // UseShellExecute laesst das System entscheiden, welcher Browser
            // zustaendig ist. Unter Linux tut das xdg-open; .NET bildet das auf
            // demselben Schalter ab, aber nicht auf jeder Oberflaeche
            // zuverlaessig - darum dort der ausdrueckliche Aufruf.
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                Process.Start(new ProcessStartInfo("xdg-open", url) { UseShellExecute = false });
                return;
            }

            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
    }
}
