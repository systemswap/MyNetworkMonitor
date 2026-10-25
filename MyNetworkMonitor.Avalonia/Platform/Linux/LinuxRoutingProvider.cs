using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Avalonia.Platform.Linux
{
    /// <summary>Linux implementation of <see cref="IRoutingProvider"/> based on "ip route".</summary>
    public sealed class LinuxRoutingProvider : IRoutingProvider
    {
        public async Task<IReadOnlyList<string>> GetRouteNetworkIpsAsync(CancellationToken cancellationToken = default)
        {
            string output = await ProcessRunner.RunAsync("ip", "route", cancellationToken).ConfigureAwait(false);

            var networks = new List<string>();
            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                // e.g. "192.0.2.0/24 dev eth0 proto kernel scope link src 192.0.2.5"
                // or "default via 192.0.2.1 dev eth0" -> "default" is not an IP address and is skipped.
                string first = line.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? string.Empty;
                int slash = first.IndexOf('/');
                string ip = slash > 0 ? first.Substring(0, slash) : first;
                if (IPAddress.TryParse(ip, out _))
                    networks.Add(ip);
            }
            return networks;
        }
    }
}
