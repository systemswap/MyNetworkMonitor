namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Plattformabhängiger Zugriff auf die Routing-Tabelle hinter einer neutralen
    /// Schnittstelle. Die Windows-Implementierung nutzt "route print"; eine spätere
    /// Linux-Implementierung kann z.B. "ip route" verwenden.
    /// </summary>
    public interface IRoutingProvider
    {
        /// <summary>
        /// Liefert die Netzwerk-/Ziel-IPv4-Adressen aus der Routing-Tabelle
        /// (Einträge mit einer 255er-Netzmaske).
        /// </summary>
        Task<IReadOnlyList<string>> GetRouteNetworkIpsAsync(CancellationToken cancellationToken = default);
    }
}
