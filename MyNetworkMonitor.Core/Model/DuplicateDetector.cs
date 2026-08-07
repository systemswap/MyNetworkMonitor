using System.Text;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Model
{
    /// <summary>
    /// Was an einem Geraet doppelt vergeben ist. Mehrere Befunde koennen
    /// zugleich zutreffen, darum Flags.
    /// </summary>
    [Flags]
    public enum DeviceConflict
    {
        None = 0,

        /// <summary>
        /// Dieselbe IP-Adresse antwortet an mehreren Geraeten. Der schwerste
        /// Befund: einer der beiden verliert Pakete, und welcher, entscheidet
        /// der ARP-Cache des Absenders.
        /// </summary>
        Address = 1,

        /// <summary>
        /// Derselbe Hostname zeigt auf mehrere Geraete. Meist ein Altbestand
        /// im DNS, gelegentlich zwei Rechner mit gleichem Namen.
        /// </summary>
        HostName = 2,

        /// <summary>Derselbe selbst vergebene Name steht an mehreren Geraeten.</summary>
        InternalName = 4,

        /// <summary>
        /// Der Hostname loest im DNS auf mehrere Adressen auf. Der Befund, den
        /// nur der Vorwaertslookup liefert: die beteiligten Geraete antworten
        /// jedes fuer sich unauffaellig, und ohne DNS faellt gar nicht auf,
        /// dass sie sich einen Namen teilen.
        /// </summary>
        DnsMultipleAddresses = 16,

        /// <summary>
        /// Der Name zeigt auf eine Adresse, unter der das Geraet nicht
        /// antwortet - Altbestand im DNS oder ein fremder Namensvetter.
        /// </summary>
        DnsMismatch = 32,

        /// <summary>
        /// Der Rueckwaertslookup liefert zur Adresse mehrere Namen. Umgekehrter
        /// Fall zu <see cref="DnsMultipleAddresses"/>.
        /// </summary>
        DnsMultipleNames = 64,

        /// <summary>
        /// Derselbe Alias steht an mehreren Geraeten. Ein Alias ist genauso
        /// eine Namensvergabe wie der Hostname - und weil er selten
        /// nachgehalten wird, bleibt ein Altbestand dort noch laenger stehen.
        /// </summary>
        DuplicateAlias = 128,

        /// <summary>
        /// Ein Geraet antwortet unter mehreren IPv4-Adressen. Unter IPv6 ist
        /// das der Normalfall und kein Befund, unter IPv4 fast immer ein
        /// zweiter DHCP-Bezug oder eine vergessene feste Adresse.
        /// </summary>
        MultipleIpv4 = 8
    }

    /// <summary>
    /// Findet doppelt vergebene Adressen und Namen im Geraetebestand.
    /// <para>
    /// Das ist der Befund, den kein anderer Scanner liefert, und er entsteht
    /// erst aus der Gesamtschau: einzeln betrachtet sieht jedes der beteiligten
    /// Geraete unauffaellig aus. Darum wird nicht je Zeile geprueft, sondern
    /// einmal ueber den ganzen Bestand gruppiert - die bisherige Anwendung hat
    /// je Zeile ein <c>Select("IP = …")</c> abgesetzt, was quadratisch laeuft
    /// und an einem Apostroph im Namen zerbricht.
    /// </para>
    /// <para>
    /// Voraussetzung ist, dass der <see cref="DeviceStore"/> Geraete mit
    /// widersprechender MAC gar nicht erst zusammenfuehrt - sonst waere die
    /// Doppelbelegung zu einem Eintrag verschmolzen, bevor hier jemand
    /// nachsehen kann.
    /// </para>
    /// </summary>
    public static class DuplicateDetector
    {
        /// <summary>
        /// Prueft den gesamten Bestand und schreibt das Ergebnis an die
        /// Geraete. Aufzurufen, wenn ein Lauf fertig ist - waehrenddessen waere
        /// jeder Befund vorlaeufig, weil das Gegenstueck noch fehlen kann.
        /// </summary>
        /// <returns>Wie viele Geraete einen Befund tragen.</returns>
        public static int Analyze(IReadOnlyList<Device> devices)
        {
            ArgumentNullException.ThrowIfNull(devices);

            // Welche Adresse an welchen Geraeten haengt. Link-Local bleibt
            // aussen vor: fe80::1 darf je Schnittstelle vorkommen, das ist
            // keine Doppelvergabe, sondern die Bauart von IPv6.
            Dictionary<string, List<Device>> byAddress = new(StringComparer.OrdinalIgnoreCase);

            foreach (Device device in devices)
            {
                foreach (DeviceAddress address in device.Addresses)
                {
                    if (address.Info.Scope == IpAddressScope.LinkLocal) continue;

                    if (!byAddress.TryGetValue(address.Info.Canonical, out List<Device>? holders))
                    {
                        holders = [];
                        byAddress[address.Info.Canonical] = holders;
                    }

                    holders.Add(device);
                }
            }

            Dictionary<string, int> hostNameCount = Count(devices, d => d.HostName);
            Dictionary<string, int> internalNameCount = Count(devices, d => d.InternalName);

            // Aliase zaehlen wie Hostnamen: ein Name, der auf zwei Geraete
            // zeigt, ist auch dann doppelt vergeben, wenn er im DNS nur der
            // zweite Eintrag ist. Je Geraet einmal zaehlen - mehrere gleiche
            // Aliase an demselben Geraet sind keine Doppelvergabe.
            Dictionary<string, int> aliasCount = new(StringComparer.OrdinalIgnoreCase);

            foreach (Device device in devices)
            {
                foreach (string alias in device.Aliases.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    if (string.IsNullOrWhiteSpace(alias)) continue;

                    aliasCount[alias] = aliasCount.GetValueOrDefault(alias) + 1;
                }
            }

            int affected = 0;

            foreach (Device device in devices)
            {
                DeviceConflict conflicts = DeviceConflict.None;
                List<string> reasons = [];

                foreach (DeviceAddress address in device.Addresses)
                {
                    if (!byAddress.TryGetValue(address.Info.Canonical, out List<Device>? holders)) continue;
                    if (holders.Count <= 1) continue;

                    conflicts |= DeviceConflict.Address;
                    reasons.Add($"{address.Info.Canonical} is also used by {Others(holders, device)}");
                }

                if (device.Ipv4Addresses.Count() > 1)
                {
                    conflicts |= DeviceConflict.MultipleIpv4;
                    reasons.Add("answers on several IPv4 addresses: " +
                                string.Join(", ", device.Ipv4Addresses.Select(a => a.Info.Canonical)));
                }

                if (!string.IsNullOrWhiteSpace(device.HostName) &&
                    hostNameCount.GetValueOrDefault(device.HostName) > 1)
                {
                    conflicts |= DeviceConflict.HostName;
                    reasons.Add($"host name \"{device.HostName}\" is used by several devices");
                }

                if (!string.IsNullOrWhiteSpace(device.InternalName) &&
                    internalNameCount.GetValueOrDefault(device.InternalName) > 1)
                {
                    conflicts |= DeviceConflict.InternalName;
                    reasons.Add($"name \"{device.InternalName}\" is assigned more than once");
                }

                // Was der Namensdienst weiss und der Scan allein nicht sieht.
                if (device.WasLookedUp && device.LookupAddresses.Count > 1)
                {
                    conflicts |= DeviceConflict.DnsMultipleAddresses;
                    reasons.Add($"DNS resolves \"{device.HostName}\" to several addresses: " +
                                string.Join(", ", device.LookupAddresses));
                }

                if (device.HasLookupMismatch)
                {
                    conflicts |= DeviceConflict.DnsMismatch;
                    reasons.Add($"DNS points \"{device.HostName}\" at {string.Join(", ", device.LookupAddresses)}, " +
                                "but the device does not answer there");
                }

                if (device.Aliases.Count > 1)
                {
                    conflicts |= DeviceConflict.DnsMultipleNames;
                    reasons.Add("reverse lookup returns several names: " + string.Join(", ", device.Aliases));
                }

                List<string> sharedAliases = [.. device.Aliases
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Where(a => !string.IsNullOrWhiteSpace(a) && aliasCount.GetValueOrDefault(a) > 1)];

                if (sharedAliases.Count > 0)
                {
                    conflicts |= DeviceConflict.DuplicateAlias;
                    reasons.Add($"alias {string.Join(", ", sharedAliases.Select(a => $"\"{a}\""))} " +
                                "is also used by another device");
                }

                device.Conflicts = conflicts;
                device.ConflictDetails = Join(reasons);

                if (conflicts != DeviceConflict.None) affected++;
            }

            return affected;
        }

        /// <summary>Setzt alle Befunde zurueck. Vor einem neuen Lauf.</summary>
        public static void Reset(IReadOnlyList<Device> devices)
        {
            foreach (Device device in devices)
            {
                device.Conflicts = DeviceConflict.None;
                device.ConflictDetails = string.Empty;
            }
        }

        private static Dictionary<string, int> Count(IReadOnlyList<Device> devices, Func<Device, string> key)
        {
            Dictionary<string, int> counts = new(StringComparer.OrdinalIgnoreCase);

            foreach (Device device in devices)
            {
                string value = key(device);
                if (string.IsNullOrWhiteSpace(value)) continue;

                counts[value] = counts.GetValueOrDefault(value) + 1;
            }

            return counts;
        }

        /// <summary>
        /// Die anderen Halter einer Adresse, benannt. Wer den Befund sieht,
        /// will als Naechstes wissen, wen er anrufen muss.
        /// </summary>
        private static string Others(List<Device> holders, Device self)
        {
            List<string> names = [.. holders
                .Where(d => !ReferenceEquals(d, self))
                .Select(d => string.IsNullOrWhiteSpace(d.MacText) ? d.DisplayName : $"{d.DisplayName} ({d.MacText})")];

            return names.Count == 0 ? "another device" : string.Join(", ", names);
        }

        private static string Join(List<string> reasons)
        {
            if (reasons.Count == 0) return string.Empty;

            StringBuilder text = new();

            foreach (string reason in reasons)
            {
                if (text.Length > 0) text.Append('\n');
                text.Append(reason);
            }

            return text.ToString();
        }
    }
}
