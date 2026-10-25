// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net;
using MyNetworkMonitor.Core.Models;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Platform-specific ARP primitives behind a neutral interface.
    /// The Windows implementation uses the Win32 API (SendARP) and the arp
    /// command-line tool; the Linux implementation uses "ip neigh". The scan
    /// logic depends only on this interface.
    /// </summary>
    public interface IArpProvider
    {
        /// <summary>
        /// Resolves the MAC address of an IP address via ARP.
        /// </summary>
        /// <param name="ip">The IPv4 address to resolve.</param>
        /// <param name="cancellationToken">Cancels the resolution.</param>
        /// <returns>The formatted MAC address (e.g. "aa-bb-cc-dd-ee-ff"), or null if there was no answer or no resolution was possible.</returns>
        Task<string?> ResolveMacAsync(IPAddress ip, CancellationToken cancellationToken = default);

        /// <summary>Reads the system ARP table (IP to MAC).</summary>
        Task<IReadOnlyList<ArpEntry>> GetArpTableAsync(CancellationToken cancellationToken = default);

        /// <summary>Flushes the system ARP cache.</summary>
        /// <returns><c>true</c> on success.</returns>
        bool FlushArpCache();
    }
}
