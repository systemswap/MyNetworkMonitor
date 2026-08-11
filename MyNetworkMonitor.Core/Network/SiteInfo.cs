using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// Eine Adresse dieses Rechners samt dem Netz, in dem sie steht.
    /// </summary>
    public sealed class SiteAddress
    {
        public required string Address { get; init; }

        /// <summary>Praefixlaenge, etwa 24 fuer eine Maske 255.255.255.0.</summary>
        public required int PrefixLength { get; init; }

        /// <summary>
        /// Ob der Adapter dieser Adresse ein Standardgateway hat.
        /// <para>
        /// Das unterscheidet die Karte am echten Netz von den virtuellen
        /// Adaptern, die Hyper-V, WSL, Docker und VPN-Clients anlegen. Die
        /// tragen ebenfalls eine Adresse und stehen ebenfalls auf "up", taugen
        /// als Standortangabe aber nichts.
        /// </para>
        /// </summary>
        public required bool HasGateway { get; init; }

        public required bool IsIpv4 { get; init; }

        /// <summary>Der Adaptername - fuer die Anzeige, wenn mehrere in Frage kommen.</summary>
        public string AdapterName { get; init; } = string.Empty;

        /// <summary>
        /// Das Netz in CIDR-Schreibweise, etwa <c>192.0.2.0/24</c>. Genau das
        /// braucht man drueben, um zu sehen, welcher Satellit fuer einen
        /// Bereich zustaendig ist.
        /// </summary>
        public string Network => SiteInfo.ToCidr(Address, PrefixLength);

        public override string ToString() => $"{Address}/{PrefixLength}";
    }

    /// <summary>
    /// Wer dieser Rechner ist und in welchen Netzen er steht.
    /// <para>
    /// Der Satellit schickt das bei jeder Anmeldung mit. Ohne diese Angaben
    /// weiss am Hauptscanner niemand, in welchem Segment ein Satellit
    /// eigentlich sitzt - man saehe nur einen Namen und muesste raten, ob er
    /// fuer einen Bereich der richtige ist.
    /// </para>
    /// </summary>
    public sealed class SiteInfo
    {
        public string HostName { get; init; } = string.Empty;

        /// <summary>Die Domaene dieses Rechners. Leer, wenn er keiner angehoert.</summary>
        public string Domain { get; init; } = string.Empty;

        public IReadOnlyList<SiteAddress> Addresses { get; init; } = [];

        public IEnumerable<SiteAddress> Ipv4 => Addresses.Where(a => a.IsIpv4);
        public IEnumerable<SiteAddress> Ipv6 => Addresses.Where(a => !a.IsIpv4);

        public string Ipv4Text => Join(Ipv4.Select(a => a.Address));
        public string Ipv6Text => Join(Ipv6.Select(a => a.Address));

        /// <summary>
        /// Das Netz, das diesen Rechner am ehesten beschreibt: das erste
        /// IPv4-Netz eines Adapters mit Gateway. Genau dieses steht in der
        /// Auswahl hinter dem Namen des Satelliten.
        /// </summary>
        public string PrimaryNetwork =>
            Ipv4.FirstOrDefault(a => a.HasGateway)?.Network
            ?? Ipv4.FirstOrDefault()?.Network
            ?? string.Empty;

        /// <summary>Alle Netze, ohne Doppelte - fuer Tooltip und Maske.</summary>
        public IReadOnlyList<string> Networks =>
            [.. Addresses.Select(a => a.Network)
                        .Where(n => n.Length > 0)
                        .Distinct(StringComparer.OrdinalIgnoreCase)];

        public string NetworksText => Join(Networks);

        private static string Join(IEnumerable<string> values)
        {
            string text = string.Join(", ", values);
            return text.Length == 0 ? "-" : text;
        }

        /// <summary>
        /// Liest Name, Domaene und Adressen dieses Rechners.
        /// <para>
        /// Loopback und link-lokale Adressen bleiben draussen: aus einem
        /// anderen Segment sind sie nie erreichbar, und als Standortangabe
        /// waeren sie schlicht falsch.
        /// </para>
        /// </summary>
        public static SiteInfo Read()
        {
            string domain;
            try
            {
                domain = IPGlobalProperties.GetIPGlobalProperties().DomainName ?? string.Empty;
            }
            catch (Exception)
            {
                domain = string.Empty;
            }

            List<SiteAddress> addresses = [];

            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;

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

                    bool hasGateway = properties.GatewayAddresses
                        .Any(g => g.Address is not null && !IsUnspecified(g.Address));

                    foreach (UnicastIPAddressInformation unicast in properties.UnicastAddresses)
                    {
                        IPAddress ip = unicast.Address;
                        if (!IsUsable(ip)) continue;

                        int prefix = PrefixOf(unicast, ip);

                        addresses.Add(new SiteAddress
                        {
                            Address = ip.ToString(),
                            PrefixLength = prefix,
                            HasGateway = hasGateway,
                            IsIpv4 = ip.AddressFamily == AddressFamily.InterNetwork,
                            AdapterName = nic.Name
                        });
                    }
                }
            }
            catch (Exception)
            {
                // Ohne Adapterliste bleibt die Aufstellung leer - das ist eine
                // Auskunft und darf nichts zum Scheitern bringen.
            }

            // Adapter mit Gateway zuerst, IPv4 vor IPv6: was oben steht, ist
            // das, was drueben in der Auswahl landet.
            return new SiteInfo
            {
                HostName = Environment.MachineName,
                Domain = domain,
                Addresses = [.. addresses
                    .OrderByDescending(a => a.HasGateway)
                    .ThenByDescending(a => a.IsIpv4)
                    .ThenBy(a => a.Address, StringComparer.OrdinalIgnoreCase)]
            };
        }

        /// <summary>
        /// Ob eine Adresse als Standortangabe taugt. Loopback und link-lokal
        /// nicht - aus einem anderen Segment kommt dort niemand an.
        /// </summary>
        private static bool IsUsable(IPAddress ip)
        {
            if (IPAddress.IsLoopback(ip)) return false;

            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                return !ip.IsIPv6LinkLocal && !ip.IsIPv6Multicast;
            }

            byte[] b = ip.GetAddressBytes();
            return !(b[0] == 169 && b[1] == 254);
        }

        /// <summary>
        /// Die Praefixlaenge. Unter Linux wirft die Abfrage bei manchen
        /// Adaptern, statt eine Antwort zu verweigern - dann wird auf die
        /// ueblichen Werte zurueckgefallen, damit wenigstens etwas dasteht.
        /// </summary>
        private static int PrefixOf(UnicastIPAddressInformation unicast, IPAddress ip)
        {
            try
            {
                int p = unicast.PrefixLength;
                if (p > 0) return p;
            }
            catch (Exception) { }

            return ip.AddressFamily == AddressFamily.InterNetwork ? 24 : 64;
        }

        private static bool IsUnspecified(IPAddress address) =>
            address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);

        /// <summary>
        /// Rechnet Adresse und Praefixlaenge in die Netzschreibweise um, also
        /// <c>192.0.2.22</c> mit 24 zu <c>192.0.2.0/24</c>.
        /// </summary>
        public static string ToCidr(string address, int prefixLength)
        {
            if (!IPAddress.TryParse(address, out IPAddress? ip)) return string.Empty;

            byte[] bytes = ip.GetAddressBytes();
            int bits = bytes.Length * 8;

            if (prefixLength < 0 || prefixLength > bits) return string.Empty;

            // Alles hinter dem Praefix auf null: uebrig bleibt die Netzadresse.
            for (int i = 0; i < bytes.Length; i++)
            {
                int keep = prefixLength - (i * 8);

                if (keep >= 8) continue;
                if (keep <= 0) { bytes[i] = 0; continue; }

                bytes[i] &= (byte)(0xFF << (8 - keep));
            }

            return $"{new IPAddress(bytes)}/{prefixLength}";
        }
    }
}
