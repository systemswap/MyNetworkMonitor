// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Text;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Model
{
    /// <summary>
    /// What is assigned more than once on a device. Several findings can apply
    /// at the same time, hence flags.
    /// </summary>
    [Flags]
    public enum DeviceConflict
    {
        /// <summary>No conflict.</summary>
        None = 0,

        /// <summary>
        /// The same IP address answers on several devices. The most serious
        /// finding: one of the two loses packets, and the sender's ARP cache
        /// decides which one.
        /// </summary>
        Address = 1,

        /// <summary>
        /// The same host name points to several devices. Usually a stale DNS
        /// entry, occasionally two computers with the same name.
        /// </summary>
        HostName = 2,

        /// <summary>The same internal name is assigned to several devices.</summary>
        InternalName = 4,

        /// <summary>
        /// The host name resolves to several addresses in DNS. Only the forward
        /// lookup reveals this: the devices involved each respond
        /// inconspicuously, and without DNS it goes unnoticed that they share a
        /// name.
        /// </summary>
        DnsMultipleAddresses = 16,

        /// <summary>
        /// The name points to an address at which the device does not answer -
        /// a stale DNS entry or another device with the same name.
        /// </summary>
        DnsMismatch = 32,

        /// <summary>
        /// The reverse lookup returns several names for the address. The
        /// reverse case of <see cref="DnsMultipleAddresses"/>.
        /// </summary>
        DnsMultipleNames = 64,

        /// <summary>
        /// The same alias appears on several devices. An alias is a name
        /// assignment just like the host name - and because aliases are rarely
        /// maintained, stale entries remain there even longer.
        /// </summary>
        DuplicateAlias = 128,

        /// <summary>
        /// A device answers on several IPv4 addresses. For IPv6 this is normal
        /// and not a finding; for IPv4 it is almost always a second DHCP lease
        /// or a forgotten static address.
        /// </summary>
        MultipleIpv4 = 8,

        /// <summary>
        /// The same MAC answers in another network at the same time. A router with one MAC on several
        /// VLANs, or a fault: a cloned virtual machine, a MAC configured twice.
        /// </summary>
        SameMacInOtherNetwork = 256,

        /// <summary>
        /// The same MAC was seen in another network, but only one of the two answers now - usually a
        /// device that moved, for example from the cable network to Wi-Fi.
        /// </summary>
        MacSeenInOtherNetwork = 512,

        /// <summary>
        /// One MAC answers for several IPv4 addresses, and one of them is held by another device with
        /// its own MAC in the same network: the signature of ARP spoofing.
        /// </summary>
        SuspectedArpSpoofing = 1024
    }

    /// <summary>One finding on a device: what kind it is and the text that explains it.</summary>
    /// <param name="Kind">The single kind of conflict this line is about.</param>
    /// <param name="Text">The explanation, naming the other devices involved.</param>
    public sealed record ConflictReason(DeviceConflict Kind, string Text);

    /// <summary>
    /// Finds addresses and names assigned more than once in the device
    /// inventory.
    /// <para>
    /// The finding emerges only from the overall view: taken individually,
    /// each device involved looks inconspicuous. The check therefore groups
    /// once over the whole inventory instead of querying per row - a per-row
    /// <c>DataTable.Select("IP = …")</c> runs in quadratic time and breaks on an
    /// apostrophe in a name.
    /// </para>
    /// <para>
    /// Requires that the <see cref="DeviceStore"/> never merges devices with
    /// conflicting MAC addresses - otherwise the duplicate assignment would be
    /// merged into one entry before it can be examined here.
    /// </para>
    /// </summary>
    public static class DuplicateDetector
    {
        /// <summary>
        /// Checks the whole inventory and writes the result to the devices.
        /// Call it when a run has finished - during a run every finding would
        /// be provisional, because the counterpart may still be missing.
        /// </summary>
        /// <param name="devices">The complete device inventory.</param>
        /// <returns>The number of devices with a finding.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="devices"/> is <c>null</c>.</exception>
        public static int Analyze(IReadOnlyList<Device> devices) => Analyze(devices, null);

        /// <summary>
        /// Checks the whole inventory and writes the result to the devices.
        /// </summary>
        /// <param name="devices">The devices to check.</param>
        /// <param name="gateways">Gateway addresses of the configured ranges; named in the text when one MAC answers for several addresses including a gateway.</param>
        /// <returns>The number of devices with at least one finding.</returns>
        public static int Analyze(IReadOnlyList<Device> devices, IReadOnlySet<string>? gateways)
        {
            ArgumentNullException.ThrowIfNull(devices);
            gateways ??= new HashSet<string>();

            // Which devices share a MAC. Within one network the inventory keeps them as one device;
            // two devices with the same MAC therefore lie in different networks.
            Dictionary<string, List<Device>> byMac = new(StringComparer.OrdinalIgnoreCase);
            foreach (Device device in devices)
            {
                if (!DeviceStore.IsIdentifying(device.Mac)) continue;

                string key = Convert.ToHexString(device.Mac!.GetAddressBytes());
                if (!byMac.TryGetValue(key, out List<Device>? same)) byMac[key] = same = [];
                same.Add(device);
            }

            // Which address belongs to which devices. Link-local addresses are
            // excluded: fe80::1 may occur once per interface - that is not a
            // duplicate assignment but how IPv6 works (RFC 4291, section 2.5.6).
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

            // Aliases count like host names: a name pointing to two devices is
            // assigned twice even if it is only the second entry in DNS. Each
            // device counts once - identical aliases on the same device are not
            // a duplicate assignment.
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
                List<ConflictReason> reasons = [];

                void Add(DeviceConflict kind, string text)
                {
                    conflicts |= kind;
                    reasons.Add(new ConflictReason(kind, text));
                }

                bool sharedWithOtherMac = false;
                foreach (DeviceAddress address in device.Addresses)
                {
                    if (!byAddress.TryGetValue(address.Info.Canonical, out List<Device>? holders)) continue;
                    if (holders.Count <= 1) continue;

                    Add(DeviceConflict.Address, $"{address.Info.Canonical} is also used by {Others(holders, device)}");

                    if (address.Info.Family == IpFamily.IPv4 && holders.Any(h => !ReferenceEquals(h, device) &&
                            DeviceStore.IsIdentifying(h.Mac) && device.Mac is not null && !h.Mac!.Equals(device.Mac)))
                    {
                        sharedWithOtherMac = true;
                    }
                }

                List<DeviceAddress> ipv4 = [.. device.Ipv4Addresses];
                if (ipv4.Count > 1)
                {
                    string list = string.Join(", ", ipv4.Select(a => a.Info.Canonical));
                    string? gateway = ipv4.Select(a => a.Info.Canonical).FirstOrDefault(gateways.Contains);

                    if (DeviceStore.IsIdentifying(device.Mac) && sharedWithOtherMac)
                    {
                        // ARP spoofing: a foreign MAC answers for an address that has its own device.
                        Add(DeviceConflict.SuspectedArpSpoofing,
                            $"MAC {device.MacText} answers for {list}, and another device with its own MAC holds one of " +
                            "these addresses - suspected ARP spoofing");
                    }
                    else if (DeviceStore.IsIdentifying(device.Mac))
                    {
                        Add(DeviceConflict.MultipleIpv4,
                            $"one MAC answers for several IPv4 addresses: {list}" +
                            (gateway is null ? string.Empty : $", including the gateway {gateway}") +
                            " - a secondary address, an old DHCP lease, a repeater or bridge, or ARP spoofing");
                    }
                    else
                    {
                        Add(DeviceConflict.MultipleIpv4, "answers on several IPv4 addresses: " + list);
                    }
                }

                if (DeviceStore.IsIdentifying(device.Mac) &&
                    byMac.TryGetValue(Convert.ToHexString(device.Mac!.GetAddressBytes()), out List<Device>? sameMac) &&
                    sameMac.Count > 1)
                {
                    foreach (Device other in sameMac.Where(d => !ReferenceEquals(d, device)))
                    {
                        string where = $"{(string.IsNullOrWhiteSpace(other.GroupDescription) ? "another network" : other.GroupDescription)} " +
                                       $"at {other.Ipv4Text} ({other.DisplayName})";

                        if (device.IsOnline && other.IsOnline)
                        {
                            Add(DeviceConflict.SameMacInOtherNetwork,
                                $"MAC {device.MacText} also answers in {where} - a router on several VLANs, or a cloned or " +
                                "duplicated MAC");
                        }
                        else
                        {
                            Add(DeviceConflict.MacSeenInOtherNetwork,
                                $"MAC {device.MacText} was also seen in {where}; only one of them answers now - " +
                                "probably the device moved");
                        }
                    }
                }

                if (!string.IsNullOrWhiteSpace(device.HostName) &&
                    hostNameCount.GetValueOrDefault(device.HostName) > 1)
                {
                    Add(DeviceConflict.HostName, $"host name \"{device.HostName}\" is used by several devices");
                }

                if (!string.IsNullOrWhiteSpace(device.InternalName) &&
                    internalNameCount.GetValueOrDefault(device.InternalName) > 1)
                {
                    Add(DeviceConflict.InternalName, $"name \"{device.InternalName}\" is assigned more than once");
                }

                // What the name service knows and the scan alone cannot see.
                if (device.WasLookedUp && device.LookupAddresses.Count > 1)
                {
                    Add(DeviceConflict.DnsMultipleAddresses, $"DNS resolves \"{device.HostName}\" to several addresses: " +
                                string.Join(", ", device.LookupAddresses));
                }

                if (device.HasLookupMismatch)
                {
                    Add(DeviceConflict.DnsMismatch, $"DNS points \"{device.HostName}\" at {string.Join(", ", device.LookupAddresses)}, " +
                                "but the device does not answer there");
                }

                if (device.Aliases.Count > 1)
                {
                    Add(DeviceConflict.DnsMultipleNames, "reverse lookup returns several names: " + string.Join(", ", device.Aliases));
                }

                List<string> sharedAliases = [.. device.Aliases
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Where(a => !string.IsNullOrWhiteSpace(a) && aliasCount.GetValueOrDefault(a) > 1)];

                if (sharedAliases.Count > 0)
                {
                    Add(DeviceConflict.DuplicateAlias, $"alias {string.Join(", ", sharedAliases.Select(a => $"\"{a}\""))} " +
                                "is also used by another device");
                }

                device.Conflicts = conflicts;
                device.ConflictReasons = reasons;
                device.ConflictDetails = Join([.. reasons.Select(r => r.Text)]);

                if (conflicts != DeviceConflict.None) affected++;
            }

            return affected;
        }

        /// <summary>Clears all findings. Call before a new run.</summary>
        /// <param name="devices">The devices to reset.</param>
        public static void Reset(IReadOnlyList<Device> devices)
        {
            foreach (Device device in devices)
            {
                device.Conflicts = DeviceConflict.None;
                device.ConflictReasons = [];
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
        /// The other holders of an address, by name. The next question after
        /// seeing the finding is which device to look at.
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
