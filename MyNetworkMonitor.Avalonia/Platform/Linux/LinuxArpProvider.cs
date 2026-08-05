using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using MyNetworkMonitor.Core.Models;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Avalonia.Platform.Linux
{
    /// <summary>
    /// Linux-Implementierung von <see cref="IArpProvider"/> über "ip neigh"
    /// (Nachbartabelle). MAC-Adressen werden ins gleiche Format wie unter Windows
    /// gebracht (Kleinbuchstaben, "-"-getrennt), damit die Vendor-Zuordnung passt.
    /// </summary>
    public sealed class LinuxArpProvider : IArpProvider
    {
        public async Task<string?> ResolveMacAsync(IPAddress ip, CancellationToken cancellationToken = default)
        {
            // Unter Linux gibt es kein direktes SendARP: erst einen Ping absetzen,
            // damit die Nachbartabelle gefüllt wird, dann per "ip neigh" auslesen.
            try { await ProcessRunner.RunAsync("ping", $"-c 1 -W 1 {ip}", cancellationToken).ConfigureAwait(false); }
            catch { /* ignorieren */ }

            var table = await GetArpTableAsync(cancellationToken).ConfigureAwait(false);
            return table.FirstOrDefault(e => e.IpAddress == ip.ToString())?.MacAddress;
        }

        public async Task<IReadOnlyList<ArpEntry>> GetArpTableAsync(CancellationToken cancellationToken = default)
        {
            string output = await ProcessRunner.RunAsync("ip", "neigh", cancellationToken).ConfigureAwait(false);

            var entries = new List<ArpEntry>();
            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                // Beispiel: "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                int idx = Array.IndexOf(parts, "lladdr");
                if (parts.Length < 2 || idx < 0 || idx + 1 >= parts.Length) continue;

                string ip = parts[0];
                string mac = parts[idx + 1].Replace(':', '-').ToLowerInvariant();
                entries.Add(new ArpEntry { IpAddress = ip, MacAddress = mac });
            }
            return entries;
        }

        public bool FlushArpCache()
        {
            try
            {
                var p = Process.Start(new ProcessStartInfo("ip", "neigh flush all")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true
                });
                p?.WaitForExit();
                p?.Close();
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
