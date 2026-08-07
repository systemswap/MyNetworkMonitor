using System.Net;
using System.Net.NetworkInformation;

namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// Ein Netzwerkadapter dieses Rechners, so wie er in der Netzansicht steht.
    /// </summary>
    public sealed class AdapterInfo
    {
        public required string Name { get; init; }
        public required string Description { get; init; }
        public required NetworkInterfaceType Type { get; init; }
        public required bool IsUp { get; init; }

        public string MacText { get; init; } = string.Empty;

        public IReadOnlyList<string> Ipv4Addresses { get; init; } = [];
        public IReadOnlyList<string> Ipv6Addresses { get; init; } = [];
        public IReadOnlyList<string> Gateways { get; init; } = [];

        /// <summary>
        /// Die Namensserver dieses Adapters, in der Reihenfolge, in der sie
        /// gefragt werden.
        /// </summary>
        public IReadOnlyList<string> DnsServers { get; init; } = [];

        /// <summary>Die Adresse stammt von einem DHCP-Server, nicht aus der Konfiguration.</summary>
        public bool DhcpEnabled { get; init; }

        public string DnsSuffix { get; init; } = string.Empty;

        /// <summary>
        /// Auffaellig viele Namensserver. Zwei bis drei sind ueblich, vier noch
        /// erklaerbar - was darueber liegt, hat sich der Adapter irgendwo
        /// eingesammelt, meist ueber wiederholte DHCP-Bezuege, und kostet bei
        /// jedem fehlschlagenden Server Wartezeit.
        /// </summary>
        public bool HasTooManyDnsServers => DnsServers.Count > MaxPlausibleDnsServers;

        /// <summary>Ab wann die Zahl der Namensserver als Befund gilt.</summary>
        public const int MaxPlausibleDnsServers = 4;

        public string Ipv4Text => string.Join(", ", Ipv4Addresses);
        public string Ipv6Text => string.Join(", ", Ipv6Addresses);
        public string GatewayText => string.Join(", ", Gateways);
        public string DnsText => string.Join(", ", DnsServers);

        public int DnsServerCount => DnsServers.Count;

        /// <summary>Woher die Konfiguration stammt - fuer die Spalte daneben.</summary>
        public string ConfigurationText => DhcpEnabled ? "DHCP" : "static";

        public override string ToString() => $"{Name} [{DnsServers.Count} DNS]";
    }

    /// <summary>
    /// Liest die Adapter dieses Rechners samt ihrer Namensserver.
    /// <para>
    /// Die Namensserver stehen bewusst je Adapter und nicht als eine Liste:
    /// genau daran war einmal zu sehen, dass sich ein einzelner Adapter ueber
    /// DHCP fuenfundzwanzig Server gezogen hatte. Zusammengefasst waere das
    /// nicht aufgefallen.
    /// </para>
    /// </summary>
    public static class NetworkAdapters
    {
        /// <summary>
        /// Alle Adapter, die eine Adresse tragen. Loopback und Tunnel bleiben
        /// draussen - sie stehen in jeder Aufzaehlung und sagen nichts.
        /// </summary>
        public static List<AdapterInfo> Read(bool includeDown = false)
        {
            List<AdapterInfo> adapters = [];

            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;

                bool isUp = nic.OperationalStatus == OperationalStatus.Up;
                if (!isUp && !includeDown) continue;

                IPInterfaceProperties properties;

                try
                {
                    properties = nic.GetIPProperties();
                }
                catch (NetworkInformationException)
                {
                    // Ein Adapter kann zwischen Aufzaehlung und Abfrage
                    // verschwinden - VPN-Clients tun das staendig.
                    continue;
                }

                // Windows fuehrt jeden gebundenen Filtertreiber als eigenen
                // Adapter - "…-QoS Packet Scheduler-0000" und ein halbes
                // Dutzend mehr je echter Karte. Sie tragen nie eine Adresse,
                // und daran sind sie zu erkennen: ohne Adresse ist ein Adapter
                // fuer diese Ansicht nichts wert.
                List<string> v4 = [.. Unicast(properties, System.Net.Sockets.AddressFamily.InterNetwork)];
                List<string> v6 = [.. Unicast(properties, System.Net.Sockets.AddressFamily.InterNetworkV6)];

                if (v4.Count == 0 && v6.Count == 0) continue;

                adapters.Add(new AdapterInfo
                {
                    Name = nic.Name,
                    Description = nic.Description,
                    Type = nic.NetworkInterfaceType,
                    IsUp = isUp,
                    MacText = FormatMac(nic),
                    Ipv4Addresses = v4,
                    Ipv6Addresses = v6,
                    Gateways = [.. properties.GatewayAddresses
                        .Where(g => g.Address is not null && !IsUnspecified(g.Address))
                        .Select(g => g.Address.ToString())],
                    DnsServers = [.. properties.DnsAddresses.Select(d => d.ToString())],
                    DhcpEnabled = IsDhcp(properties),
                    DnsSuffix = properties.DnsSuffix ?? string.Empty
                });
            }

            return adapters;
        }

        private static IEnumerable<string> Unicast(IPInterfaceProperties properties, System.Net.Sockets.AddressFamily family) =>
            properties.UnicastAddresses
                .Where(u => u.Address.AddressFamily == family)
                .Select(u => u.Address.ToString());

        /// <summary>
        /// Ob der Adapter seine Adresse ueber DHCP bezieht. Unter Linux wirft
        /// die Abfrage, statt eine Antwort zu verweigern - dort laesst sich das
        /// so nicht feststellen.
        /// </summary>
        private static bool IsDhcp(IPInterfaceProperties properties)
        {
            try
            {
                return properties.GetIPv4Properties()?.IsDhcpEnabled ?? false;
            }
            catch (PlatformNotSupportedException)
            {
                return false;
            }
            catch (NetworkInformationException)
            {
                return false;
            }
        }

        private static bool IsUnspecified(IPAddress address) =>
            address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);

        private static string FormatMac(NetworkInterface nic)
        {
            byte[] bytes = nic.GetPhysicalAddress().GetAddressBytes();

            return bytes.Length == 0 ? string.Empty : string.Join(":", bytes.Select(b => b.ToString("x2")));
        }
    }
}
