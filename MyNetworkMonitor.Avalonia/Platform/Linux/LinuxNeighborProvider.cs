// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Avalonia.Platform.Linux
{
    /// <summary>
    /// Reads the neighbor table with <c>ip neigh</c>. The tool belongs to
    /// <c>iproute2</c>, which practically every Linux installation includes;
    /// the startup check (<see cref="SystemRequirements"/>) reports it if it is
    /// missing.
    /// <para>
    /// The output is not localized: <c>ip</c> prints the state names
    /// (<c>REACHABLE</c>, <c>STALE</c> …) in upper case regardless of the
    /// language setting. Unlike <c>netsh</c> on Windows, parsing the text is
    /// therefore safe here.
    /// </para>
    /// </summary>
    public sealed class LinuxNeighborProvider : INeighborProvider
    {
        public async Task<IReadOnlyList<NeighborEntry>> GetNeighborsAsync(CancellationToken cancellationToken = default)
        {
            string output;
            try
            {
                // Without -6/-4, both address families arrive in one pass.
                output = await ProcessRunner.RunAsync("ip", "neigh show", cancellationToken).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // iproute2 missing or the call fails: an empty table instead of
                // an exception; the scan method then reports by itself that it
                // found nothing.
                return [];
            }

            // Adapter name -> index. Built once instead of searched per line.
            Dictionary<string, int> indexByName = BuildInterfaceIndex();

            var entries = new List<NeighborEntry>();

            foreach (string line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                NeighborEntry? entry = ParseLine(line, indexByName);
                if (entry is not null) entries.Add(entry);
            }

            return entries;
        }

        /// <summary>
        /// Parses one line of <c>ip neigh</c>. Examples:
        /// <code>
        /// fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff router REACHABLE
        /// 192.0.2.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE
        /// fe80::99 dev eth0  FAILED
        /// </code>
        /// The state is always last; the other fields precede it as key-value
        /// pairs, so values are looked up by keyword rather than by position.
        /// </summary>
        private static NeighborEntry? ParseLine(string line, IReadOnlyDictionary<string, int> indexByName)
        {
            string[] parts = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) return null;

            if (!IPAddress.TryParse(parts[0], out IPAddress? address)) return null;

            string? deviceName = ValueAfter(parts, "dev");
            string? macText = ValueAfter(parts, "lladdr");

            PhysicalAddress? mac = null;
            if (macText is not null)
            {
                // PhysicalAddress.Parse rejects colons but accepts hyphens.
                // It also requires upper case.
                if (PhysicalAddress.TryParse(macText.Replace(':', '-').ToUpperInvariant(), out PhysicalAddress? parsed))
                {
                    mac = parsed;
                }
            }

            // A link-local address without a zone cannot be reached; the adapter
            // is on the same line, so the zone is attached right away.
            int interfaceIndex = 0;
            if (deviceName is not null && indexByName.TryGetValue(deviceName, out int found))
            {
                interfaceIndex = found;

                if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
                    address.IsIPv6LinkLocal && address.ScopeId == 0)
                {
                    address = new IPAddress(address.GetAddressBytes(), found);
                }
            }

            return new NeighborEntry
            {
                Address = address,
                Mac = mac,
                InterfaceIndex = interfaceIndex,
                InterfaceName = deviceName,
                State = ToState(parts[^1]),
                IsRouter = parts.Contains("router")
            };
        }

        /// <summary>The value following a keyword, if present.</summary>
        private static string? ValueAfter(string[] parts, string keyword)
        {
            int index = Array.IndexOf(parts, keyword);
            return index >= 0 && index + 1 < parts.Length ? parts[index + 1] : null;
        }

        private static NeighborState ToState(string text) => text.ToUpperInvariant() switch
        {
            "REACHABLE" => NeighborState.Reachable,
            "STALE" => NeighborState.Stale,
            "DELAY" => NeighborState.Delay,
            "PROBE" => NeighborState.Probe,
            "PERMANENT" => NeighborState.Permanent,

            // NOARP appears on interfaces without address resolution, such as
            // point-to-point links. The entry is valid but never re-verified,
            // which is treated the same as PERMANENT.
            "NOARP" => NeighborState.Permanent,

            "INCOMPLETE" => NeighborState.Incomplete,
            "FAILED" => NeighborState.Failed,
            _ => NeighborState.Unknown
        };

        private static Dictionary<string, int> BuildInterfaceIndex()
        {
            Dictionary<string, int> map = new(StringComparer.Ordinal);

            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    try
                    {
                        IPInterfaceProperties properties = nic.GetIPProperties();
                        int index = nic.Supports(NetworkInterfaceComponent.IPv6)
                            ? properties.GetIPv6Properties().Index
                            : properties.GetIPv4Properties().Index;

                        map[nic.Name] = index;
                    }
                    catch (NetworkInformationException) { /* adapter without that address family */ }
                    catch (PlatformNotSupportedException) { /* same */ }
                }
            }
            catch (NetworkInformationException) { /* no adapter list: continue without indexes */ }

            return map;
        }
    }
}
