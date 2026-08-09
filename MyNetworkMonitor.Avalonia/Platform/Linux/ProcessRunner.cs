using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace MyNetworkMonitor.Avalonia.Platform.Linux
{
    /// <summary>Kleiner Helfer, der ein Kommandozeilenwerkzeug ausführt und stdout liefert.</summary>
    internal static class ProcessRunner
    {
        public static async Task<string> RunAsync(string fileName, string arguments, CancellationToken cancellationToken = default)
        {
            var psi = new ProcessStartInfo(fileName, arguments)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) return string.Empty;

            try
            {
                string output = await process.StandardOutput.ReadToEndAsync().WaitAsync(cancellationToken).ConfigureAwait(false);
                await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                return output;
            }
            catch (OperationCanceledException)
            {
                // Ohne das hier liefe der Prozess (ping, ip neigh, ...) im
                // Hintergrund weiter, bis er von selbst endet - bei einem
                // abgebrochenen Scan ueber viele Ziele blieben so Dutzende
                // verwaiste Prozesse zurueck, statt dass "Stop" wirklich stoppt.
                try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { /* bereits beendet */ }
                throw;
            }
        }
    }
}
