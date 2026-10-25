// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.Models
{
    /// <summary>An entry of the ARP table (IP address to MAC address).</summary>
    public sealed class ArpEntry
    {
        /// <summary>The IP address of the entry.</summary>
        public string IpAddress { get; init; } = string.Empty;
        /// <summary>The MAC address resolved for <see cref="IpAddress"/>.</summary>
        public string MacAddress { get; init; } = string.Empty;
    }
}
