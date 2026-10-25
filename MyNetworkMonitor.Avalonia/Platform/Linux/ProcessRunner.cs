using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace MyNetworkMonitor.Avalonia.Platform.Linux
{
    /// <summary>Runs a command-line tool and returns its standard output.</summary>
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
                // Reads stderr at the same time: it is redirected, and a full pipe buffer would block the tool forever.
                // See docs/FEHLERGEDAECHTNIS.md, No. 17.
                Task<string> errors = process.StandardError.ReadToEndAsync(cancellationToken);
                string output = await process.StandardOutput.ReadToEndAsync().WaitAsync(cancellationToken).ConfigureAwait(false);
                await errors.ConfigureAwait(false);
                await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                return output;
            }
            catch (OperationCanceledException)
            {
                // Without this, the process (ping, ip neigh, ...) keeps running in
                // the background until it ends on its own; a cancelled scan over
                // many targets would leave dozens of orphaned processes behind
                // instead of "Stop" actually stopping.
                try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { /* already exited */ }
                throw;
            }
        }
    }
}
