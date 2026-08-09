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
    /// Liest die Nachbarschaftstabelle ueber <c>ip neigh</c>. Das Werkzeug
    /// gehoert zu <c>iproute2</c> und ist auf jeder Linux-Installation
    /// vorhanden - es muss nichts nachinstalliert werden.
    /// <para>
    /// Die Ausgabe ist nicht uebersetzt: <c>ip</c> gibt die Zustandsnamen
    /// (<c>REACHABLE</c>, <c>STALE</c> …) unabhaengig von der Spracheinstellung
    /// in Grossbuchstaben aus. Anders als bei <c>netsh</c> unter Windows ist
    /// eine Textauswertung hier also unbedenklich.
    /// </para>
    /// </summary>
    public sealed class LinuxNeighborProvider : INeighborProvider
    {
        public async Task<IReadOnlyList<NeighborEntry>> GetNeighborsAsync(CancellationToken cancellationToken = default)
        {
            string output;
            try
            {
                // Ohne -6/-4 kommen beide Familien in einem Durchgang.
                output = await ProcessRunner.RunAsync("ip", "neigh show", cancellationToken).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Kein iproute2 vorhanden oder der Aufruf scheitert: leere
                // Tabelle statt Ausnahme - das Verfahren meldet dann selbst,
                // dass es nichts gefunden hat.
                return [];
            }

            // Adaptername -> Index. Einmal aufgebaut statt je Zeile gesucht.
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
        /// Eine Zeile von <c>ip neigh</c>. Beispiele:
        /// <code>
        /// fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff router REACHABLE
        /// 192.168.1.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE
        /// fe80::99 dev eth0  FAILED
        /// </code>
        /// Der Zustand steht immer am Ende, die uebrigen Angaben stehen als
        /// Schluessel-Wert-Paare davor - darum wird nach Schluesselwort gesucht
        /// und nicht nach Position gezaehlt.
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
                // PhysicalAddress.Parse mag Doppelpunkte nicht, Bindestriche
                // schon. Grossbuchstaben sind dort ebenfalls Pflicht.
                if (PhysicalAddress.TryParse(macText.Replace(':', '-').ToUpperInvariant(), out PhysicalAddress? parsed))
                {
                    mac = parsed;
                }
            }

            // Link-Local ohne Zone ist nicht ansprechbar - der Adapter steht in
            // derselben Zeile, also gleich anhaengen.
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

        /// <summary>Der Wert hinter einem Schluesselwort, sofern vorhanden.</summary>
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

            // NOARP steht an Schnittstellen ohne Adressaufloesung, etwa an
            // Punkt-zu-Punkt-Verbindungen. Der Eintrag gilt, er wird nur nie
            // nachgeprueft - fuer uns dasselbe wie PERMANENT.
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
                    catch (NetworkInformationException) { /* Adapter ohne die jeweilige Familie */ }
                    catch (PlatformNotSupportedException) { /* dito */ }
                }
            }
            catch (NetworkInformationException) { /* keine Adapterliste - dann eben ohne Index */ }

            return map;
        }
    }
}
