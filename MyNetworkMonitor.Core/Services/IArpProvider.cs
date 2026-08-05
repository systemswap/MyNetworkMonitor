using System.Net;
using MyNetworkMonitor.Core.Models;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Plattformabhängige ARP-Primitiven hinter einer neutralen Schnittstelle.
    /// Die Windows-Implementierung nutzt die Win32-API (SendARP) bzw. das
    /// arp-Kommandozeilenwerkzeug; eine spätere Linux-Implementierung kann z.B.
    /// "ip neigh" verwenden. Die Scan-Logik hängt nur noch von diesem Interface ab.
    /// </summary>
    public interface IArpProvider
    {
        /// <summary>
        /// Löst die MAC-Adresse einer IP per ARP auf.
        /// Liefert die formatierte MAC (z.B. "aa-bb-cc-dd-ee-ff") oder null,
        /// wenn keine Antwort/Auflösung möglich war.
        /// </summary>
        Task<string?> ResolveMacAsync(IPAddress ip, CancellationToken cancellationToken = default);

        /// <summary>Liest die ARP-Tabelle des Systems (IP ↔ MAC).</summary>
        Task<IReadOnlyList<ArpEntry>> GetArpTableAsync(CancellationToken cancellationToken = default);

        /// <summary>Leert den ARP-Cache des Systems. true bei Erfolg.</summary>
        bool FlushArpCache();
    }
}
