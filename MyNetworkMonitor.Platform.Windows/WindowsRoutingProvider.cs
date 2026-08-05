using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Platform.Windows
{
    /// <summary>
    /// Windows-Implementierung von <see cref="IRoutingProvider"/>.
    /// Kapselt den plattformspezifischen Aufruf von "route print".
    /// </summary>
    public sealed class WindowsRoutingProvider : IRoutingProvider
    {
        public async Task<IReadOnlyList<string>> GetRouteNetworkIpsAsync(CancellationToken cancellationToken = default)
        {
            Process? process = null;
            try
            {
                process = Process.Start(new ProcessStartInfo("route", "print")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                });

                if (process == null) return Array.Empty<string>();

                string output = await process.StandardOutput.ReadToEndAsync()
                    .WaitAsync(cancellationToken).ConfigureAwait(false);
                await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

                var matches = Regex.Matches(output, @"(\d+\.\d+\.\d+\.\d+)\s+255");
                return matches.Cast<Match>().Select(m => m.Groups[1].Value).ToList();
            }
            catch
            {
                return Array.Empty<string>();
            }
            finally
            {
                process?.Close();
            }
        }
    }
}
