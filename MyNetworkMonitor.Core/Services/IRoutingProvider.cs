namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Platform-specific access to the routing table behind a neutral
    /// interface. The Windows implementation uses "route print"; the Linux
    /// implementation uses "ip route".
    /// </summary>
    public interface IRoutingProvider
    {
        /// <summary>
        /// Returns the network/destination IPv4 addresses from the routing table
        /// (entries whose netmask starts with 255).
        /// </summary>
        Task<IReadOnlyList<string>> GetRouteNetworkIpsAsync(CancellationToken cancellationToken = default);
    }
}
