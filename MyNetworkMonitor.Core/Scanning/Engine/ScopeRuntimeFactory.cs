using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Scanning.Engine
{
    /// <summary>
    /// Loest Bereiche in Laufzeitangaben und Ziele auf.
    /// <para>
    /// Sitzt ausserhalb der <see cref="ScanEngine"/>, weil die Oberflaeche
    /// dasselbe braucht: um zu zeigen, welche Verfahren verfuegbar sind, muss
    /// sie die IPv6-Lage je Bereich kennen - ohne deshalb einen Scan zu starten
    /// oder 254 Adressen aufzuzaehlen.
    /// </para>
    /// </summary>
    public static class ScopeRuntimeFactory
    {
        /// <summary>
        /// Ordnet jedem Bereich seinen Adapter und dessen IPv6-Zustand zu.
        /// </summary>
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

                // Bereiche ohne festen Adapter laufen ueber den Adapter, ueber
                // den das Betriebssystem sie ohnehin routen wuerde. Bis die
                // Routenwahl steht, dient der erste betriebsbereite Adapter
                // als Naeherung.
                nic ??= all.FirstOrDefault(n =>
                    n.OperationalStatus == OperationalStatus.Up &&
                    n.NetworkInterfaceType != NetworkInterfaceType.Loopback);

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
        /// Zaehlt alle Ziele der Bereiche auf. Ein IPv6-Praefix liefert
        /// bewusst keine - es wird nicht durchlaufen, sondern von den
        /// IPv6-Verfahren selbst untersucht.
        /// </summary>
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
                            targets.Add(new ScanTargetEntry { HostName = host, Scope = runtime });
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
        /// Wie viele Ziele ein Bereich umfasst - ohne sie aufzuzaehlen.
        /// <para>
        /// Der Adapter-Bereich kennt seine Groesse erst zur Laufzeit, aus
        /// Adresse und Maske. Sie wird gerechnet und nicht durchlaufen, weil
        /// die Oberflaeche diese Zahl bei jedem Haken neu braucht und ein /16
        /// sonst 65.000 Objekte je Klick erzeugen wuerde.
        /// </para>
        /// </summary>
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

                    // Anzahl der Hostbits, abzueglich Netz- und Broadcastadresse
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
        /// Ein bis zwei Beispielziele je Bereich - genug, damit ein Verfahren
        /// erkennt, welche Adressfamilien vorkommen. Fuer die
        /// Verfuegbarkeitsanzeige der Oberflaeche, die bei jedem Haken neu
        /// laeuft und darum nicht 254 Adressen erzeugen darf.
        /// </summary>
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

                    // Je Familie ein Beispiel, damit eine gemischte Liste
                    // beide Seiten zeigt.
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
        /// Leitet aus einem Adapter das IPv4-Subnetz ab und zaehlt es auf. Die
        /// IPv6-Seite steuern die IPv6-Verfahren selbst bei - ein /64 laesst
        /// sich nicht aufzaehlen.
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

                // Netz- und Broadcast-Adresse sind keine Ziele. Bei /31 oder
                // /32 bleibt nichts uebrig.
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
