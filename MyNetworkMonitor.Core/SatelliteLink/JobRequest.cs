using System.Globalization;
using System.Net;
using MyNetworkMonitor.Core.Model;

namespace MyNetworkMonitor.Core.SatelliteLink
{
    /// <summary>
    /// Ein Scan-Auftrag als Text.
    /// <para>
    /// Bewusst eine Zeile statt eines serialisierten Einstellungsbaums: so muss
    /// nicht jede Option einzeln uebertragen und ueber Versionen hinweg
    /// gepflegt werden, der Auftrag steht lesbar im Protokoll, und was der
    /// Auftrag nicht nennt, bleibt beim Satelliten auf seiner Vorgabe.
    /// </para>
    /// <para>
    /// Form:
    /// <code>
    /// scan ranges=10.0.0.1-10.0.0.254;192.168.1.0/24 methods=ping,arp
    ///      tcp=22,80,443 udp=161 timeout=2500 dns=10.0.0.1 gateway=10.0.0.1
    ///      group=IDF2
    /// </code>
    /// Pflicht sind nur <c>scan</c> und <c>ranges</c>. Mehrere Bereiche werden
    /// mit Semikolon getrennt, Listen innerhalb eines Feldes mit Komma.
    /// </para>
    /// </summary>
    public sealed class JobRequest
    {
        /// <summary>Die zu scannenden Bereiche.</summary>
        public List<ScanScope> Scopes { get; } = [];

        /// <summary>Kennungen der Verfahren. Leer heisst: die Vorgabe des Satelliten.</summary>
        public List<string> MethodIds { get; } = [];

        /// <summary>
        /// Die Verfahren, die nur abfragen sollen, was schon gefunden wurde.
        /// <para>
        /// Muss mit uebertragen werden, sonst arbeitet der Satellit anders als
        /// derselbe Lauf oertlich: Portscan, Diensterkennung, NetBIOS und SMB
        /// gingen dort ueber <em>alle</em> Adressen des Bereichs statt nur ueber
        /// die gefundenen Geraete. Bei 128 Adressen und 83 Geraeten sind das 45
        /// Ziele, an denen jeder Port ins Zeitlimit laeuft - der teuerste Teil
        /// eines Laufs, fuer nichts.
        /// </para>
        /// </summary>
        public List<string> OnlyKnownFor { get; } = [];

        public List<int> TcpPorts { get; } = [];
        public List<int> UdpPorts { get; } = [];

        /// <summary>Zeitlimit je Port in Millisekunden, wenn genannt.</summary>
        public int? TimeoutMs { get; private set; }

        /// <summary>Wenn der Auftrag nicht gelesen werden konnte - Klartext.</summary>
        public string? Problem { get; private set; }

        public bool IsValid => Problem is null && Scopes.Count > 0;

        /// <summary>
        /// Setzt einen Auftragstext aus Bereichen und Einstellungen zusammen -
        /// die Gegenrichtung zu <see cref="Parse"/>.
        /// </summary>
        public static string Format(
            IEnumerable<ScanScope> scopes,
            IEnumerable<string>? methodIds = null,
            IEnumerable<int>? tcpPorts = null,
            IEnumerable<int>? udpPorts = null,
            int? timeoutMs = null,
            IEnumerable<string>? onlyKnownFor = null)
        {
            ArgumentNullException.ThrowIfNull(scopes);

            List<string> parts = ["scan"];

            List<string> ranges = [];
            string? dns = null;
            string? gateway = null;
            string? group = null;

            foreach (ScanScope scope in scopes)
            {
                switch (scope.Kind)
                {
                    case ScanScopeKind.IPv4Range:
                        ranges.Add($"{scope.FirstIP}-{scope.LastIP}");
                        break;

                    case ScanScopeKind.TargetList:
                        ranges.AddRange(scope.Targets);
                        break;

                    case ScanScopeKind.IPv6Prefix:
                        ranges.Add($"{scope.Prefix}/{scope.PrefixLength}");
                        break;

                    // Der Adapter-Bereich ergibt beim Satelliten keinen Sinn -
                    // er hat seine eigenen Adapter. Uebertragen wird, was sich
                    // als Adressbereich ausdruecken laesst.
                    default:
                        break;
                }

                dns ??= string.IsNullOrWhiteSpace(scope.DnsServers) ? null : scope.DnsServers;
                gateway ??= string.IsNullOrWhiteSpace(scope.GatewayIP) ? null : scope.GatewayIP;
                group ??= string.IsNullOrWhiteSpace(scope.GroupDescription) ? null : scope.GroupDescription;
            }

            if (ranges.Count > 0) parts.Add("ranges=" + string.Join(';', ranges));

            List<string> methods = [.. methodIds ?? []];
            if (methods.Count > 0) parts.Add("methods=" + string.Join(',', methods));

            List<int> tcp = [.. tcpPorts ?? []];
            if (tcp.Count > 0) parts.Add("tcp=" + string.Join(',', tcp));

            List<int> udp = [.. udpPorts ?? []];
            if (udp.Count > 0) parts.Add("udp=" + string.Join(',', udp));

            // Nur die, die in diesem Auftrag ueberhaupt vorkommen - eine Liste
            // von Verfahren, die gar nicht laufen, sagt nichts und macht den
            // Auftragstext im Protokoll nur laenger.
            List<string> known = [.. (onlyKnownFor ?? [])
                .Where(id => methods.Count == 0 || methods.Contains(id, StringComparer.OrdinalIgnoreCase))];

            if (known.Count > 0) parts.Add("known=" + string.Join(',', known));

            if (timeoutMs is > 0) parts.Add("timeout=" + timeoutMs.Value.ToString(CultureInfo.InvariantCulture));
            if (dns is not null) parts.Add("dns=" + dns.Replace(" ", string.Empty));
            if (gateway is not null) parts.Add("gateway=" + gateway);
            if (group is not null) parts.Add("group=" + group.Replace(' ', '_'));

            return string.Join(' ', parts);
        }

        /// <summary>
        /// Liest einen Auftragstext. Ein unverstaendlicher Auftrag ergibt ein
        /// Ergebnis mit <see cref="Problem"/> statt einer Ausnahme: der Satellit
        /// soll den Grund zurueckmelden koennen, nicht abstuerzen.
        /// </summary>
        public static JobRequest Parse(string text)
        {
            JobRequest job = new();

            if (string.IsNullOrWhiteSpace(text))
            {
                job.Problem = "The job is empty.";
                return job;
            }

            string[] tokens = text.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            if (!tokens[0].Equals("scan", StringComparison.OrdinalIgnoreCase))
            {
                job.Problem = $"Unknown job \"{tokens[0]}\" - expected \"scan\".";
                return job;
            }

            string ranges = string.Empty;
            string dns = string.Empty;
            string gateway = string.Empty;
            string group = "Satellite";

            foreach (string token in tokens.Skip(1))
            {
                int split = token.IndexOf('=');
                if (split <= 0)
                {
                    job.Problem = $"\"{token}\" is not a key=value pair.";
                    return job;
                }

                string key = token[..split].ToLowerInvariant();
                string value = token[(split + 1)..];

                switch (key)
                {
                    case "ranges": ranges = value; break;
                    case "methods": job.MethodIds.AddRange(SplitList(value)); break;
                    case "known": job.OnlyKnownFor.AddRange(SplitList(value)); break;
                    case "tcp": job.TcpPorts.AddRange(ParsePorts(value)); break;
                    case "udp": job.UdpPorts.AddRange(ParsePorts(value)); break;
                    case "dns": dns = value; break;
                    case "gateway": gateway = value; break;
                    case "group": group = value.Replace('_', ' '); break;

                    case "timeout":
                        if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int ms) && ms > 0)
                        {
                            job.TimeoutMs = ms;
                        }
                        break;

                    default:
                        // Unbekannte Felder werden uebergangen statt abgelehnt:
                        // ein neuerer Hauptscanner darf mehr schicken, als
                        // dieser Satellit versteht, ohne dass der Auftrag
                        // scheitert.
                        break;
                }
            }

            if (string.IsNullOrWhiteSpace(ranges))
            {
                job.Problem = "The job names no ranges.";
                return job;
            }

            foreach (string part in ranges.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                ScanScope? scope = ParseRange(part, dns, gateway, group);

                if (scope is null)
                {
                    job.Problem = $"\"{part}\" is not a range, a prefix or an address.";
                    return job;
                }

                job.Scopes.Add(scope);
            }

            return job;
        }

        /// <summary>
        /// Ein einzelner Bereich: "a-b" als IPv4-Spanne, "adresse/laenge" als
        /// IPv6-Praefix, alles andere als einzelnes Ziel.
        /// </summary>
        private static ScanScope? ParseRange(string part, string dns, string gateway, string group)
        {
            ScanScope scope = new()
            {
                GroupDescription = group,
                DnsServers = dns,
                GatewayIP = gateway,
                IsSelected = true
            };

            int dash = part.IndexOf('-');
            if (dash > 0)
            {
                string first = part[..dash];
                string last = part[(dash + 1)..];

                if (!IPAddress.TryParse(first, out _) || !IPAddress.TryParse(last, out _)) return null;

                scope.Kind = ScanScopeKind.IPv4Range;
                scope.FirstIP = first;
                scope.LastIP = last;
                return scope;
            }

            int slash = part.IndexOf('/');
            if (slash > 0)
            {
                string prefix = part[..slash];

                if (!IPAddress.TryParse(prefix, out IPAddress? address)) return null;
                if (!int.TryParse(part[(slash + 1)..], out int length)) return null;

                if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    scope.Kind = ScanScopeKind.IPv6Prefix;
                    scope.Prefix = prefix;
                    scope.PrefixLength = length;
                    return scope;
                }

                // IPv4 mit Praefixlaenge: in erste und letzte Adresse umrechnen,
                // weil der Bereichstyp genau so arbeitet.
                if (length is < 0 or > 32) return null;

                byte[] bytes = address.GetAddressBytes();
                uint raw = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
                uint mask = length == 0 ? 0 : uint.MaxValue << (32 - length);

                uint start = raw & mask;
                uint end = start | ~mask;

                // Netz- und Rundrufadresse auslassen, sofern das Netz Platz dafuer hat.
                if (length <= 30) { start++; end--; }

                scope.Kind = ScanScopeKind.IPv4Range;
                scope.FirstIP = ToAddress(start);
                scope.LastIP = ToAddress(end);
                return scope;
            }

            if (!IPAddress.TryParse(part, out _)) return null;

            scope.Kind = ScanScopeKind.TargetList;
            scope.Targets.Add(part);
            return scope;
        }

        private static string ToAddress(uint value) =>
            $"{(value >> 24) & 0xFF}.{(value >> 16) & 0xFF}.{(value >> 8) & 0xFF}.{value & 0xFF}";

        private static IEnumerable<string> SplitList(string value) =>
            value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        private static IEnumerable<int> ParsePorts(string value)
        {
            foreach (string part in SplitList(value))
            {
                if (int.TryParse(part, NumberStyles.Integer, CultureInfo.InvariantCulture, out int port) &&
                    port is > 0 and <= 65535)
                {
                    yield return port;
                }
            }
        }
    }
}
