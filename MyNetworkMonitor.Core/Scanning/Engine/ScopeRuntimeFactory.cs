// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine
{
    /// <summary>
    /// Resolves scopes into runtime information and targets.
    /// <para>
    /// Lives outside <see cref="ScanEngine"/> because the UI needs the same
    /// information: to show which methods are available, it has to know the
    /// IPv6 state of each scope, without starting a scan or enumerating 254
    /// addresses.
    /// </para>
    /// </summary>
    public static class ScopeRuntimeFactory
    {
        /// <summary>
        /// Assigns each scope its network interface and that interface's IPv6 state.
        /// </summary>
        /// <param name="scopes">The scopes to resolve.</param>
        /// <returns>One runtime entry per scope, ordered by <see cref="ScanScope.Index"/>.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="scopes"/> is null.</exception>
        public static List<ScopeRuntime> Build(IEnumerable<ScanScope> scopes)
        {
            ArgumentNullException.ThrowIfNull(scopes);

            NetworkInterface[] all = SafeGetInterfaces();
            List<ScopeRuntime> result = [];

            foreach (ScanScope scope in scopes.OrderBy(s => s.Index))
            {
                NetworkInterface? nic = null;

                if (!string.IsNullOrWhiteSpace(scope.InterfaceId))
                {
                    nic = all.FirstOrDefault(n => n.Id == scope.InterfaceId);
                }

                // Scopes without a fixed interface use the interface the
                // operating system would route them through anyway.
                nic ??= PickDefaultInterface(all);

                result.Add(new ScopeRuntime
                {
                    Scope = scope,
                    Interface = nic,
                    Ipv6 = Ipv6Readiness.ForInterface(nic)
                });
            }

            return result;
        }

        /// <summary>
        /// Enumerates all targets of the scopes. An IPv6 prefix deliberately
        /// yields none; it is not iterated but examined by the IPv6 methods
        /// themselves.
        /// </summary>
        /// <param name="runtimes">Resolved scopes from <see cref="Build"/>.</param>
        /// <returns>All targets; host names that resolve also carry their address.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="runtimes"/> is null.</exception>
        public static List<ScanTargetEntry> BuildTargets(IEnumerable<ScopeRuntime> runtimes)
        {
            ArgumentNullException.ThrowIfNull(runtimes);

            List<ScanTargetEntry> targets = [];

            foreach (ScopeRuntime runtime in runtimes)
            {
                switch (runtime.Scope.Kind)
                {
                    case ScanScopeKind.IPv4Range:
                        foreach (IPAddress address in runtime.Scope.EnumerateIPv4Range())
                        {
                            targets.Add(new ScanTargetEntry
                            {
                                Address = IpAddressAnalyzer.Analyze(address),
                                Scope = runtime
                            });
                        }
                        break;

                    case ScanScopeKind.TargetList:
                        (List<IpAddressInfo> addresses, List<string> hostnames) = runtime.Scope.SplitTargetList();

                        foreach (IpAddressInfo info in addresses)
                        {
                            targets.Add(new ScanTargetEntry { Address = info, Scope = runtime });
                        }
                        foreach (string host in hostnames)
                        {
                            // Resolved first, then added as an address target.
                            //
                            // Without resolution the name is scanned but its
                            // result is discarded: the evaluation requires a
                            // target that parses as an IP address, and a name
                            // does not. A host name entered in the target list
                            // would never show a result, even when the device
                            // answers.
                            //
                            // The name stays on the target so that it appears
                            // in the table and does not have to be recovered
                            // by reverse resolution.
                            IpAddressInfo? resolved = ResolveHost(host);

                            targets.Add(resolved is null
                                ? new ScanTargetEntry { HostName = host, Scope = runtime }
                                : new ScanTargetEntry { Address = resolved, HostName = host, Scope = runtime });
                        }
                        break;

                    case ScanScopeKind.NetworkInterface:
                        targets.AddRange(EnumerateInterfaceSubnet(runtime));
                        break;

                    case ScanScopeKind.IPv6Prefix:
                        break;
                }
            }

            return targets;
        }

        /// <summary>
        /// Number of targets in a scope, without enumerating them.
        /// <para>
        /// An interface scope only knows its size at runtime, from address and
        /// mask. The size is calculated rather than enumerated because the UI
        /// needs this number again on every checkbox change, and a /16 would
        /// otherwise create 65,000 objects per click.
        /// </para>
        /// </summary>
        /// <param name="runtime">The resolved scope.</param>
        /// <param name="isEstimate">Set to true if the number is only an estimate.</param>
        /// <returns>The number of targets.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="runtime"/> is null.</exception>
        public static long CountTargets(ScopeRuntime runtime, out bool isEstimate)
        {
            ArgumentNullException.ThrowIfNull(runtime);

            if (runtime.Scope.Kind != ScanScopeKind.NetworkInterface)
            {
                return runtime.Scope.CountTargets(out isEstimate);
            }

            isEstimate = false;

            if (runtime.Interface is null) return 0;

            long total = 0;

            try
            {
                foreach (UnicastIPAddressInformation unicast in runtime.Interface.GetIPProperties().UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    if (unicast.IPv4Mask is null) continue;

                    uint mask = ToUInt32(unicast.IPv4Mask);
                    if (mask == 0) continue;

                    // Host addresses, minus network and broadcast address
                    long hosts = (long)(~mask) - 1;
                    if (hosts > 0) total += hosts;
                }
            }
            catch (NetworkInformationException)
            {
                isEstimate = true;
                return 0;
            }

            return total;
        }

        /// <summary>
        /// One or two sample targets per scope, enough for a method to see which
        /// address families occur. Used by the availability display of the UI,
        /// which runs again on every checkbox change and therefore must not
        /// create 254 addresses.
        /// </summary>
        /// <param name="runtime">The resolved scope.</param>
        /// <returns>A few representative targets.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="runtime"/> is null.</exception>
        public static IEnumerable<ScanTargetEntry> SampleTargets(ScopeRuntime runtime)
        {
            ArgumentNullException.ThrowIfNull(runtime);

            switch (runtime.Scope.Kind)
            {
                case ScanScopeKind.IPv4Range:
                    IPAddress? first = runtime.Scope.EnumerateIPv4Range().FirstOrDefault();
                    if (first is not null)
                    {
                        yield return new ScanTargetEntry
                        {
                            Address = IpAddressAnalyzer.Analyze(first),
                            Scope = runtime
                        };
                    }
                    break;

                case ScanScopeKind.TargetList:
                    (List<IpAddressInfo> addresses, List<string> hostnames) = runtime.Scope.SplitTargetList();

                    // One sample per family, so that a mixed list shows
                    // both.
                    foreach (IpFamily family in (IpFamily[])[IpFamily.IPv4, IpFamily.IPv6])
                    {
                        IpAddressInfo? sample = addresses.FirstOrDefault(a => a.Family == family);
                        if (sample is not null)
                        {
                            yield return new ScanTargetEntry { Address = sample, Scope = runtime };
                        }
                    }

                    if (hostnames.Count > 0)
                    {
                        yield return new ScanTargetEntry { HostName = hostnames[0], Scope = runtime };
                    }
                    break;

                case ScanScopeKind.NetworkInterface:
                    ScanTargetEntry? entry = EnumerateInterfaceSubnet(runtime).FirstOrDefault();
                    if (entry is not null) yield return entry;
                    break;

                case ScanScopeKind.IPv6Prefix:
                    if (IPAddress.TryParse(runtime.Scope.Prefix, out IPAddress? prefix))
                    {
                        yield return new ScanTargetEntry
                        {
                            Address = IpAddressAnalyzer.Analyze(prefix),
                            Scope = runtime
                        };
                    }
                    break;
            }
        }

        /// <summary>
        /// Derives the IPv4 subnet from an interface and enumerates it. IPv6 is
        /// covered by the IPv6 methods themselves; a /64 cannot be enumerated.
        /// </summary>
        private static IEnumerable<ScanTargetEntry> EnumerateInterfaceSubnet(ScopeRuntime runtime)
        {
            if (runtime.Interface is null) yield break;

            UnicastIPAddressInformationCollection unicasts;
            try
            {
                unicasts = runtime.Interface.GetIPProperties().UnicastAddresses;
            }
            catch (NetworkInformationException)
            {
                yield break;
            }

            foreach (UnicastIPAddressInformation unicast in unicasts)
            {
                if (unicast.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                if (unicast.IPv4Mask is null) continue;

                uint address = ToUInt32(unicast.Address);
                uint mask = ToUInt32(unicast.IPv4Mask);
                if (mask == 0) continue;

                uint network = address & mask;
                uint broadcast = network | ~mask;

                // Network and broadcast addresses are not targets. A /31 or
                // /32 leaves nothing.
                if (broadcast <= network + 1) continue;

                for (uint value = network + 1; value < broadcast; value++)
                {
                    yield return new ScanTargetEntry
                    {
                        Address = IpAddressAnalyzer.Analyze(FromUInt32(value)),
                        Scope = runtime
                    };
                }
            }
        }

        /// <summary>
        /// Finds the interface through which the machine is actually connected.
        /// <para>
        /// "The first operational one" is not sufficient: workstations commonly
        /// list Hyper-V, VMware, VPN and Bluetooth adapters first, all reporting
        /// "Up". After switching networks (from cable to Wi-Fi) the scan would
        /// then cover the network of a virtual bridge instead of the real one.
        /// </para>
        /// <para>
        /// The default gateway is decisive: only an interface that has one
        /// leads anywhere. If several qualify, a physical one (Ethernet or
        /// Wi-Fi) wins over all others. The route metric would be the more
        /// precise criterion, but .NET does not expose it in a
        /// platform-neutral way.
        /// </para>
        /// </summary>
        private static NetworkInterface? PickDefaultInterface(NetworkInterface[] all)
        {
            List<NetworkInterface> usable =
            [
                .. all.Where(n =>
                    n.OperationalStatus == OperationalStatus.Up &&
                    n.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                    n.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
            ];

            return usable
                .Where(HasGateway)
                .OrderBy(Rank)
                .FirstOrDefault()
                // No interface with a gateway: fall back to the first usable
                // one, so that a lab segment without a router still gets a scope.
                ?? usable.OrderBy(Rank).FirstOrDefault();

            static bool HasGateway(NetworkInterface nic)
            {
                try
                {
                    return nic.GetIPProperties().GatewayAddresses
                        .Any(g => g.Address is not null && !IPAddress.Any.Equals(g.Address));
                }
                catch (NetworkInformationException) { return false; }
            }

            // Workstations commonly carry Hyper-V, VMware, VPN and Bluetooth
            // adapters, all reporting "Up". They must not rank ahead of the
            // interface connected to the network cable or Wi-Fi.
            static int Rank(NetworkInterface nic) => nic.NetworkInterfaceType switch
            {
                NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet => 0,
                NetworkInterfaceType.Wireless80211 => 1,
                _ => 2
            };
        }

        /// <summary>
        /// Resolves a host name to an address. IPv4 is preferred over IPv6
        /// because the remaining methods depend on it. If resolution fails, the
        /// result is <c>null</c>; the name then stays as a target and the run
        /// reports it as unreachable instead of silently skipping it.
        /// </summary>
        private static IpAddressInfo? ResolveHost(string host)
        {
            try
            {
                IPAddress[] found = Dns.GetHostAddresses(host);

                IPAddress? best =
                    found.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                    ?? found.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetworkV6);

                return best is null ? null : IpAddressAnalyzer.Analyze(best);
            }
            catch (Exception)
            {
                // Unknown name, no reachable name server, timeout: all mean
                // the same thing, there is no address.
                return null;
            }
        }

        private static NetworkInterface[] SafeGetInterfaces()
        {
            try { return NetworkInterface.GetAllNetworkInterfaces(); }
            catch (NetworkInformationException) { return []; }
        }

        private static uint ToUInt32(IPAddress address)
        {
            byte[] b = address.GetAddressBytes();
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }

        private static IPAddress FromUInt32(uint value) => new(new[]
        {
            (byte)(value >> 24),
            (byte)(value >> 16),
            (byte)(value >> 8),
            (byte)value
        });
    }
}
