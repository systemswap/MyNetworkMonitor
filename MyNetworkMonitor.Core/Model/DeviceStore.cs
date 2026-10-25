using System.Collections.ObjectModel;
using System.Net.NetworkInformation;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Model
{
    /// <summary>
    /// Holds the device list and assigns incoming observations to the right
    /// device. The core of the device model.
    /// <para>
    /// An address alone is not a sufficient key: under IPv6 a device has
    /// several addresses, some of which change daily. Assignment therefore
    /// follows a cascade - DUID before MAC before address before host name -
    /// and devices are merged afterwards as soon as two entries turn out to
    /// be the same device.
    /// </para>
    /// <para>
    /// <see cref="Observe"/>, <see cref="LoadFrom"/>, <see cref="MergeFrom"/>
    /// and <see cref="Clear"/> take <see cref="SyncRoot"/>; code that reads
    /// the list while a run is in progress must hold it as well.
    /// </para>
    /// </summary>
    public sealed class DeviceStore
    {
        private readonly ObservableCollection<Device> _devices = [];

        private readonly Dictionary<string, Device> _byDuid = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Device> _byMac = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Device> _byHostName = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Address to device - to <em>all</em> devices carrying it. The other
        /// indexes get by with one value, this one does not: a duplicate IP is
        /// the finding that matters here, and a single-valued index would
        /// silently lose the second device during indexing.
        /// </summary>
        private readonly Dictionary<string, List<Device>> _byAddress = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>The devices, read-only.</summary>
        public ReadOnlyObservableCollection<Device> Devices { get; }

        /// <summary>
        /// The lock under which the inventory is changed. Code that reads
        /// during a run - the result table does, so that it fills up
        /// progressively instead of appearing all at once at the end - must
        /// hold it too. Otherwise the user interface reads a list that a scan
        /// thread is modifying.
        /// </summary>
        public Lock SyncRoot { get; } = new();

        /// <summary>
        /// Suppresses the display notifications of the devices.
        /// <para>
        /// During a run the scan modules report from arbitrary tasks. While the
        /// table already shows the affected row, the binding would then run on
        /// a background thread - but the user interface may only be touched
        /// from its own thread. Whoever sets this takes over calling
        /// <see cref="Device.NotifyDisplayChanged"/> later, on the right thread.
        /// </para>
        /// </summary>
        public bool DeferDisplayNotifications { get; set; }

        /// <summary>Creates an empty store.</summary>
        public DeviceStore()
        {
            Devices = new ReadOnlyObservableCollection<Device>(_devices);
        }

        /// <summary>Raised after every assignment - even if information was only added.</summary>
        public event Action<Device>? DeviceChanged;

        /// <summary>Raised when a new device has appeared.</summary>
        public event Action<Device>? DeviceAdded;

        /// <summary>
        /// Raised when two entries have turned out to be the same device. The
        /// second argument is the dissolved entry and is no longer valid
        /// afterwards.
        /// </summary>
        public event Action<Device, Device>? DevicesMerged;

        /// <summary>
        /// Records an observation and returns the device it belongs to. Creates
        /// the device if it is new, and merges existing entries if the
        /// observation connects them.
        /// </summary>
        /// <param name="observation">The observation to record.</param>
        /// <returns>The device the observation was assigned to.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="observation"/> is <c>null</c>.</exception>
        public Device Observe(DeviceObservation observation)
        {
            ArgumentNullException.ThrowIfNull(observation);

            Device device;
            bool isNew = false;

            lock (SyncRoot)
            {
                List<Device> candidates = FindCandidates(observation);

                // Whatever contradicts the observation is not merged but stays
                // a device of its own. Duplicate detection depends on exactly
                // this: two network cards with the same IP are two devices, not
                // one entry with two names.
                if (candidates.Count > 0)
                {
                    candidates = [.. candidates.Where(c => !ContradictsObservation(c, observation))];
                }

                if (candidates.Count == 0)
                {
                    device = new Device
                    {
                        FirstSeen = observation.Timestamp,
                        LastSeen = observation.Timestamp
                    };
                    _devices.Add(device);
                    isNew = true;
                }
                else
                {
                    // The entry with the strongest identity remains; the others
                    // are merged into it.
                    device = candidates.OrderBy(d => (int)d.IdentityKey).First();

                    // The candidates must also be compatible with each other.
                    // If the observation carries only an address, it can match
                    // two devices with different MACs - merging those two would
                    // be exactly the mistake to avoid.
                    foreach (Device other in candidates.Where(c => !ReferenceEquals(c, device)))
                    {
                        if (Contradicts(device, other)) continue;

                        MergeInto(device, other);
                    }
                }

                Apply(device, observation);
                Reindex(device);
            }

            // The display properties are computed and depend on addresses and
            // services - the binding does not notice their changes on its own.
            if (!DeferDisplayNotifications) device.NotifyDisplayChanged();

            if (isNew) DeviceAdded?.Invoke(device);
            DeviceChanged?.Invoke(device);

            return device;
        }

        /// <summary>Clears the list and all indexes.</summary>
        public void Clear()
        {
            lock (SyncRoot)
            {
                _devices.Clear();
                _byDuid.Clear();
                _byMac.Clear();
                _byAddress.Clear();
                _byHostName.Clear();
            }
        }

        /// <summary>
        /// Replaces the inventory with stored devices and rebuilds the indexes.
        /// <para>
        /// Deliberately not through <see cref="Observe"/>: the devices are
        /// already merged. Sending them through the identity cascade again
        /// would merge exactly the duplicate assignments found in the last run.
        /// </para>
        /// </summary>
        /// <param name="devices">The stored devices.</param>
        /// <exception cref="ArgumentNullException"><paramref name="devices"/> is <c>null</c>.</exception>
        public void LoadFrom(IEnumerable<Device> devices)
        {
            ArgumentNullException.ThrowIfNull(devices);

            lock (SyncRoot)
            {
                Clear();

                foreach (Device device in devices)
                {
                    _devices.Add(device);
                    Reindex(device);
                }
            }
        }

        /// <summary>
        /// Merges devices found elsewhere into the inventory - the result of a
        /// satellite.
        /// <para>
        /// Like <see cref="LoadFrom"/>, deliberately <b>not</b> through
        /// <see cref="Observe"/>: the devices are already merged, and the
        /// identity cascade would merge exactly the duplicate assignments the
        /// satellite found.
        /// </para>
        /// <para>
        /// Unlike <see cref="LoadFrom"/>, the existing inventory is not cleared:
        /// the satellite knows only its segment, everything else stays. A known
        /// device is not replaced either but supplemented - a satellite run
        /// only brings back what <em>this</em> job found. A job that only
        /// refreshes names returns a device without services; replacing the
        /// entry with it would discard the service findings of the previous run.
        /// </para>
        /// </summary>
        /// <param name="devices">The devices from the satellite.</param>
        /// <returns>The number of devices taken over.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="devices"/> is <c>null</c>.</exception>
        public int MergeFrom(IEnumerable<Device> devices)
        {
            ArgumentNullException.ThrowIfNull(devices);

            int taken = 0;
            List<Device> touched = [];

            lock (SyncRoot)
            {
                foreach (Device incoming in devices)
                {
                    Device? target = FindExisting(incoming);

                    if (target is null)
                    {
                        _devices.Add(incoming);
                        Reindex(incoming);
                        touched.Add(incoming);
                    }
                    else
                    {
                        Absorb(target, incoming);
                        Reindex(target);
                        touched.Add(target);
                    }

                    taken++;
                }
            }

            // The display properties depend on addresses and services - the
            // binding does not notice their changes on its own. Without this
            // the row would stay unchanged although the satellite has just
            // added something.
            if (!DeferDisplayNotifications)
            {
                foreach (Device device in touched) device.NotifyDisplayChanged();
            }

            return taken;
        }

        /// <summary>
        /// The existing device the report belongs to - or <c>null</c> if it
        /// describes a new device.
        /// <para>
        /// The search uses the same cascade as for an observation: first the
        /// hard identifiers, then the addresses. Whatever contradicts the
        /// report - different MAC, different DUID - is ruled out; a duplicate
        /// address has two devices behind it, and writing into the wrong one
        /// would be worse than creating a third.
        /// </para>
        /// </summary>
        private Device? FindExisting(Device incoming)
        {
            if (incoming.Duid is { Length: > 0 } duid &&
                _byDuid.TryGetValue(duid, out Device? byDuid) && !Contradicts(byDuid, incoming))
            {
                return byDuid;
            }

            if (incoming.Mac is not null &&
                _byMac.TryGetValue(MacKey(incoming.Mac), out Device? byMac) && !Contradicts(byMac, incoming))
            {
                return byMac;
            }

            foreach (DeviceAddress address in incoming.Addresses)
            {
                if (!_byAddress.TryGetValue(address.Info.Canonical, out List<Device>? holders)) continue;

                foreach (Device holder in holders)
                {
                    if (!Contradicts(holder, incoming)) return holder;
                }
            }

            return null;
        }

        /// <summary>
        /// Records what the satellite reported. As with
        /// <see cref="Apply(Device, DeviceObservation)"/>: a value overwrites
        /// the old one, a missing value deletes nothing. The satellite has
        /// checked freshly, but only for what the job asked for.
        /// </summary>
        private static void Absorb(Device target, Device incoming)
        {
            foreach (DeviceAddress address in incoming.Addresses)
            {
                DeviceAddress? mine = target.Addresses.FirstOrDefault(a =>
                    string.Equals(a.Info.Canonical, address.Info.Canonical, StringComparison.OrdinalIgnoreCase));

                if (mine is null)
                {
                    target.Addresses.Add(address);
                    continue;
                }

                if (address.LastSeen > mine.LastSeen) mine.LastSeen = address.LastSeen;
                if (address.FirstSeen != default && (mine.FirstSeen == default || address.FirstSeen < mine.FirstSeen))
                {
                    mine.FirstSeen = address.FirstSeen;
                }

                if (address.Origin != AddressOrigin.Unknown) mine.Origin = address.Origin;
                if (address.State != AddressState.Unknown) mine.State = address.State;
                if (address.ValidUntil is not null) mine.ValidUntil = address.ValidUntil;
                if (address.PreferredUntil is not null) mine.PreferredUntil = address.PreferredUntil;
                if (address.IsResponding) mine.IsResponding = true;
                if (!string.IsNullOrWhiteSpace(address.DiscoveredBy)) mine.DiscoveredBy = address.DiscoveredBy;
            }

            if (incoming.Duid is { Length: > 0 }) target.Duid = incoming.Duid;
            if (incoming.Mac is not null) target.Mac = incoming.Mac;

            if (!string.IsNullOrWhiteSpace(incoming.Vendor)) target.Vendor = incoming.Vendor;
            if (!string.IsNullOrWhiteSpace(incoming.HostName)) target.HostName = incoming.HostName;
            if (!string.IsNullOrWhiteSpace(incoming.Domain)) target.Domain = incoming.Domain;
            if (!string.IsNullOrWhiteSpace(incoming.NetBiosName)) target.NetBiosName = incoming.NetBiosName;
            if (!string.IsNullOrWhiteSpace(incoming.GroupDescription)) target.GroupDescription = incoming.GroupDescription;

            // The internal name belongs to this installation and is not changed
            // by a foreign inventory - it is only filled in where none exists.
            if (string.IsNullOrWhiteSpace(target.InternalName)) target.InternalName = incoming.InternalName;

            // The lookup is taken over as a whole, not supplemented: it
            // describes the DNS state at the time of the query.
            if (incoming.WasLookedUp)
            {
                target.WasLookedUp = true;
                target.LookupAddresses.Clear();
                target.LookupAddresses.AddRange(incoming.LookupAddresses);
            }

            foreach (string alias in incoming.Aliases.Where(a => !target.Aliases.Contains(a, StringComparer.OrdinalIgnoreCase)))
            {
                target.Aliases.Add(alias);
            }

            foreach (string source in incoming.SeenBy) target.SeenBy.Add(source);

            foreach (KeyValuePair<string, string> detail in incoming.Details)
            {
                target.Details[detail.Key] = detail.Value;
            }

            if (incoming.Ttl > 0) target.Ttl = incoming.Ttl;

            if (!string.IsNullOrWhiteSpace(incoming.SwitchName)) target.SwitchName = incoming.SwitchName;
            if (!string.IsNullOrWhiteSpace(incoming.SwitchPort)) target.SwitchPort = incoming.SwitchPort;
            if (!string.IsNullOrWhiteSpace(incoming.Vlan)) target.Vlan = incoming.Vlan;

            if (!string.IsNullOrWhiteSpace(incoming.WebTitle)) target.WebTitle = incoming.WebTitle;
            if (!string.IsNullOrWhiteSpace(incoming.CertificateSubject)) target.CertificateSubject = incoming.CertificateSubject;
            if (!string.IsNullOrWhiteSpace(incoming.CertificateIssuer)) target.CertificateIssuer = incoming.CertificateIssuer;
            if (incoming.CertificateExpires is not null) target.CertificateExpires = incoming.CertificateExpires;
            if (incoming.CertificateIsSelfSigned) target.CertificateIsSelfSigned = true;

            foreach (DeviceServiceResult service in incoming.Services)
            {
                DeviceServiceResult? mine = target.Services.FirstOrDefault(s => IsSameFinding(s, service));

                if (mine is null)
                {
                    target.Services.Add(service);
                    continue;
                }

                if (service.StatusIPv4 is not null) mine.StatusIPv4 = service.StatusIPv4;
                if (service.StatusIPv6 is not null) mine.StatusIPv6 = service.StatusIPv6;
                if (!string.IsNullOrEmpty(service.PortLog)) mine.PortLog = service.PortLog;
            }

            if (incoming.FirstSeen != default && (target.FirstSeen == default || incoming.FirstSeen < target.FirstSeen))
            {
                target.FirstSeen = incoming.FirstSeen;
            }

            if (incoming.LastSeen > target.LastSeen) target.LastSeen = incoming.LastSeen;
        }

        /// <summary>Finds a device by address. For rescans of individual targets.</summary>
        /// <param name="address">The address to look up.</param>
        /// <returns>The first device carrying the address, or <c>null</c>.</returns>
        public Device? FindByAddress(IpAddressInfo address) =>
            _byAddress.GetValueOrDefault(address.Canonical)?.FirstOrDefault();

        /// <summary>
        /// All devices carrying this address. More than one means the address
        /// is assigned twice.
        /// </summary>
        /// <param name="address">The address to look up.</param>
        /// <returns>The devices carrying the address; empty if none.</returns>
        public IReadOnlyList<Device> FindAllByAddress(IpAddressInfo address) =>
            _byAddress.GetValueOrDefault(address.Canonical) ?? (IReadOnlyList<Device>)[];

        // --------------------------------------------------------- Assignment

        /// <summary>
        /// Finds all existing entries the observation matches. More than one
        /// means the observation connects them - they are then merged.
        /// </summary>
        private List<Device> FindCandidates(DeviceObservation o)
        {
            List<Device> found = [];

            void Add(Device? d)
            {
                if (d is not null && !found.Any(x => ReferenceEquals(x, d))) found.Add(d);
            }

            if (!string.IsNullOrWhiteSpace(o.Duid))
                Add(_byDuid.GetValueOrDefault(o.Duid));

            if (o.Mac is not null)
                Add(_byMac.GetValueOrDefault(MacKey(o.Mac)));

            // An EUI-64 address contains the MAC (RFC 4291, appendix A). A
            // device found over IPv6 can thus be assigned to the same entry as
            // the one found over ARP - without both being seen at the same time.
            if (o.Address?.DerivedMac is { } derived)
                Add(_byMac.GetValueOrDefault(MacKey(derived)));

            // The soft MAC may establish a match: if SNMP reports the base MAC
            // of a device already known through another interface, the
            // observation belongs there. It must not prevent anything -
            // ContradictsObservation ensures this by ignoring it.
            if (o.SoftMac is not null)
                Add(_byMac.GetValueOrDefault(MacKey(o.SoftMac)));

            // If the address belongs to more than one device, all of them are
            // candidates - the MAC check decides which one is meant.
            if (o.Address is not null && _byAddress.TryGetValue(o.Address.Canonical, out List<Device>? holders))
            {
                foreach (Device holder in holders) Add(holder);
            }

            // Host names are weak: several devices can report the same name.
            // Used only if nothing else matches.
            if (found.Count == 0 && !string.IsNullOrWhiteSpace(o.HostName))
                Add(_byHostName.GetValueOrDefault(o.HostName));

            return found;
        }

        /// <summary>
        /// The observation cannot belong to this device, because both carry a
        /// hard identifier and these differ.
        /// <para>
        /// Only DUID and MAC count as hard. A different host name means
        /// nothing - devices have several names. A missing value on either side
        /// does not contradict either; it only means nobody checked.
        /// </para>
        /// <para>
        /// <see cref="DeviceObservation.SoftMac"/> is ignored as well. SNMP
        /// reads the MAC of every interface (ifPhysAddress, RFC 2863) - including
        /// interfaces not connected to this network. Used as a hard identifier,
        /// such a MAC would contradict the one seen through ARP, and the same
        /// device would appear twice in the list.
        /// </para>
        /// </summary>
        private static bool ContradictsObservation(Device device, DeviceObservation o)
        {
            if (device.Duid is { Length: > 0 } && o.Duid is { Length: > 0 } &&
                !string.Equals(device.Duid, o.Duid, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            // The MAC derived from EUI-64 is ignored here: it is inferred, and
            // an inferred value must not prevent a match.
            return device.Mac is not null && o.Mac is not null && !device.Mac.Equals(o.Mac);
        }

        /// <summary>
        /// Two entries cannot be the same device. Same rule as in
        /// <see cref="ContradictsObservation"/>.
        /// </summary>
        private static bool Contradicts(Device a, Device b)
        {
            if (a.Duid is { Length: > 0 } && b.Duid is { Length: > 0 } &&
                !string.Equals(a.Duid, b.Duid, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return a.Mac is not null && b.Mac is not null && !a.Mac.Equals(b.Mac);
        }

        /// <summary>Writes the information of the observation to the device.</summary>
        private void Apply(Device device, DeviceObservation o)
        {
            // During a run the observation comes from a scan thread. Each of
            // the following assignments would raise a notification from there,
            // and a bound row would process it on the foreign thread. The list
            // catches up later in NotifyDisplayChanged.
            if (DeferDisplayNotifications) device.IsQuiet = true;

            if (o.Timestamp > device.LastSeen) device.LastSeen = o.Timestamp;
            if (device.FirstSeen == default || o.Timestamp < device.FirstSeen) device.FirstSeen = o.Timestamp;

            device.SeenBy.Add(o.Source);

            if (!string.IsNullOrWhiteSpace(o.Duid)) device.Duid = o.Duid;

            // A directly observed MAC is more reliable than one derived from
            // EUI-64 or reported by SNMP - the latter two therefore only fill
            // in, never overwrite.
            //
            // The soft MAC only fills a gap: a device found solely through SNMP
            // - behind a router, for example, where ARP does not reach - would
            // otherwise have no MAC. If it overwrote the MAC seen through ARP,
            // it would split the device just the same, only the other way round.
            if (o.Mac is not null) device.Mac = o.Mac;
            else if (device.Mac is null && o.Address?.DerivedMac is { } derived) device.Mac = derived;
            else if (device.Mac is null && o.SoftMac is not null) device.Mac = o.SoftMac;

            if (!string.IsNullOrWhiteSpace(o.Vendor)) device.Vendor = o.Vendor;
            if (!string.IsNullOrWhiteSpace(o.HostName)) device.HostName = o.HostName;
            if (!string.IsNullOrWhiteSpace(o.Domain)) device.Domain = o.Domain;
            if (!string.IsNullOrWhiteSpace(o.NetBiosName)) device.NetBiosName = o.NetBiosName;
            if (!string.IsNullOrWhiteSpace(o.GroupDescription)) device.GroupDescription = o.GroupDescription;

            // The lookup is taken over as a whole, not supplemented: it
            // describes the DNS state at the time of the query. Mixing in old
            // addresses would blur exactly the finding that matters.
            if (o.LookupAddresses is not null)
            {
                device.WasLookedUp = true;
                device.LookupAddresses.Clear();
                device.LookupAddresses.AddRange(o.LookupAddresses);
            }

            if (o.Aliases is not null)
            {
                foreach (string alias in o.Aliases.Where(a => !device.Aliases.Contains(a, StringComparer.OrdinalIgnoreCase)))
                {
                    device.Aliases.Add(alias);
                }
            }

            if (o.Details is not null)
            {
                foreach (KeyValuePair<string, string> detail in o.Details)
                {
                    device.Details[detail.Key] = detail.Value;
                }
            }

            // A measured TTL replaces the previous one, a missing one deletes
            // nothing: only the ping fills the field, every other observation
            // carries a 0 there and would otherwise erase the measurement.
            if (o.Ttl > 0) device.Ttl = o.Ttl;

            if (!string.IsNullOrWhiteSpace(o.SwitchName)) device.SwitchName = o.SwitchName;
            if (!string.IsNullOrWhiteSpace(o.SwitchPort)) device.SwitchPort = o.SwitchPort;
            if (!string.IsNullOrWhiteSpace(o.Vlan)) device.Vlan = o.Vlan;

            if (!string.IsNullOrWhiteSpace(o.WebTitle)) device.WebTitle = o.WebTitle;
            if (!string.IsNullOrWhiteSpace(o.CertificateSubject)) device.CertificateSubject = o.CertificateSubject;
            if (!string.IsNullOrWhiteSpace(o.CertificateIssuer)) device.CertificateIssuer = o.CertificateIssuer;
            if (o.CertificateExpires is not null) device.CertificateExpires = o.CertificateExpires;
            if (o.CertificateIsSelfSigned is { } selfSigned) device.CertificateIsSelfSigned = selfSigned;

            if (o.Address is not null) ApplyAddress(device, o);
            if (o.Services is not null) ApplyServices(device, o);
        }

        /// <summary>
        /// Records service findings. A method always checks only one address
        /// family, so each side is set separately and the other left untouched -
        /// otherwise the IPv4 run would delete the IPv6 finding and the
        /// comparison would be lost.
        /// <para>
        /// Findings are combined by service <b>and</b> ports. A service is
        /// checked against several ports - "WebServices", for example, against
        /// 80, 443, 8080 and others - and yields a separate finding per port.
        /// If the name alone decided, all nine findings would end up in one
        /// entry and the last one to arrive would overwrite the rest: a web
        /// page on port 80 would disappear because port 8443 did not answer
        /// afterwards.
        /// </para>
        /// </summary>
        private static void ApplyServices(Device device, DeviceObservation o)
        {
            foreach (DeviceServiceResult incoming in o.Services!)
            {
                // A port identified by name needs no additional "TCP {Port}"
                // row - it is the same port, once with a name. The order in
                // which findings arrive is not fixed, so both directions are
                // handled: the placeholder gives way to the name, and where a
                // name already exists, no placeholder is added.
                if (IsOpenPortPlaceholder(incoming))
                {
                    if (device.Services.Any(s => !IsOpenPortPlaceholder(s) && s.IsRunning && Covers(s, incoming)))
                        continue;
                }
                else if (incoming.IsRunning)
                {
                    device.Services.RemoveAll(s => IsOpenPortPlaceholder(s) && Covers(incoming, s));
                }

                DeviceServiceResult? existing = device.Services.FirstOrDefault(s => IsSameFinding(s, incoming));

                if (existing is null)
                {
                    device.Services.Add(incoming);
                    continue;
                }

                if (incoming.StatusIPv4 is not null) existing.StatusIPv4 = incoming.StatusIPv4;
                if (incoming.StatusIPv6 is not null) existing.StatusIPv6 = incoming.StatusIPv6;
                if (!string.IsNullOrEmpty(incoming.PortLog)) existing.PortLog = incoming.PortLog;
            }
        }

        /// <summary>
        /// An open port without a detected service - "TCP 3306", "UDP 5353".
        /// Created by the methods whose probe got a connection but no matching
        /// answer.
        /// </summary>
        private static bool IsOpenPortPlaceholder(DeviceServiceResult s) =>
            string.Equals(s.Category, "Open ports", StringComparison.OrdinalIgnoreCase);

        /// <summary>The named finding covers the port of the placeholder.</summary>
        private static bool Covers(DeviceServiceResult named, DeviceServiceResult placeholder) =>
            placeholder.Ports.Count == 1 && named.Ports.Contains(placeholder.Ports[0]);

        /// <summary>
        /// The same finding: same service on exactly the same ports. This
        /// combines the IPv4 and IPv6 runs into one row while keeping the
        /// individual ports of the same service separate.
        /// </summary>
        private static bool IsSameFinding(DeviceServiceResult a, DeviceServiceResult b) =>
            string.Equals(a.ServiceName, b.ServiceName, StringComparison.OrdinalIgnoreCase) &&
            a.Ports.Count == b.Ports.Count &&
            !a.Ports.Except(b.Ports).Any();

        private static void ApplyAddress(Device device, DeviceObservation o)
        {
            IpAddressInfo info = o.Address!;

            DeviceAddress? existing = device.Addresses
                .FirstOrDefault(a => string.Equals(a.Info.Canonical, info.Canonical, StringComparison.OrdinalIgnoreCase));

            if (existing is null)
            {
                existing = new DeviceAddress
                {
                    Info = info,
                    FirstSeen = o.Timestamp,
                    LastSeen = o.Timestamp,
                    DiscoveredBy = o.Source
                };
                device.Addresses.Add(existing);
            }
            else if (o.Timestamp > existing.LastSeen)
            {
                existing.LastSeen = o.Timestamp;
            }

            if (o.Origin != AddressOrigin.Unknown) existing.Origin = o.Origin;
            if (o.State != AddressState.Unknown) existing.State = o.State;
            if (o.ValidUntil is not null) existing.ValidUntil = o.ValidUntil;
            if (o.PreferredUntil is not null) existing.PreferredUntil = o.PreferredUntil;
            if (o.IsResponding) existing.IsResponding = true;
        }

        /// <summary>
        /// Merges <paramref name="other"/> into <paramref name="target"/> and
        /// removes it from the list. Existing values of the target remain; the
        /// dissolved entry only fills gaps.
        /// </summary>
        private void MergeInto(Device target, Device other)
        {
            foreach (DeviceAddress address in other.Addresses)
            {
                bool alreadyThere = target.Addresses.Any(a =>
                    string.Equals(a.Info.Canonical, address.Info.Canonical, StringComparison.OrdinalIgnoreCase));

                if (!alreadyThere) target.Addresses.Add(address);
            }

            target.Duid ??= other.Duid;
            target.Mac ??= other.Mac;

            if (string.IsNullOrWhiteSpace(target.Vendor)) target.Vendor = other.Vendor;
            if (string.IsNullOrWhiteSpace(target.HostName)) target.HostName = other.HostName;
            if (string.IsNullOrWhiteSpace(target.Domain)) target.Domain = other.Domain;
            if (string.IsNullOrWhiteSpace(target.NetBiosName)) target.NetBiosName = other.NetBiosName;
            if (string.IsNullOrWhiteSpace(target.InternalName)) target.InternalName = other.InternalName;
            if (string.IsNullOrWhiteSpace(target.GroupDescription)) target.GroupDescription = other.GroupDescription;

            if (!target.WasLookedUp && other.WasLookedUp)
            {
                target.WasLookedUp = true;
                target.LookupAddresses.AddRange(other.LookupAddresses);
            }

            foreach (string alias in other.Aliases.Where(a => !target.Aliases.Contains(a, StringComparer.OrdinalIgnoreCase)))
            {
                target.Aliases.Add(alias);
            }

            foreach (string source in other.SeenBy) target.SeenBy.Add(source);

            foreach (KeyValuePair<string, string> detail in other.Details)
            {
                target.Details.TryAdd(detail.Key, detail.Value);
            }

            foreach (DeviceServiceResult service in other.Services)
            {
                DeviceServiceResult? mine = target.Services
                    .FirstOrDefault(s => IsSameFinding(s, service));

                if (mine is null)
                {
                    target.Services.Add(service);
                }
                else
                {
                    mine.StatusIPv4 ??= service.StatusIPv4;
                    mine.StatusIPv6 ??= service.StatusIPv6;
                    mine.PortLog ??= service.PortLog;
                }
            }

            if (other.FirstSeen != default && other.FirstSeen < target.FirstSeen) target.FirstSeen = other.FirstSeen;
            if (other.LastSeen > target.LastSeen) target.LastSeen = other.LastSeen;

            RepointIndexes(other, target);
            _devices.Remove(other);

            DevicesMerged?.Invoke(target, other);
        }

        // ------------------------------------------------------------ Indexes

        private void Reindex(Device device)
        {
            if (!string.IsNullOrWhiteSpace(device.Duid)) _byDuid[device.Duid] = device;
            if (device.Mac is not null) _byMac[MacKey(device.Mac)] = device;
            if (!string.IsNullOrWhiteSpace(device.HostName)) _byHostName[device.HostName] = device;

            foreach (DeviceAddress address in device.Addresses)
            {
                List<Device> holders = _byAddress.TryGetValue(address.Info.Canonical, out List<Device>? existing)
                    ? existing
                    : _byAddress[address.Info.Canonical] = [];

                if (!holders.Any(d => ReferenceEquals(d, device))) holders.Add(device);
            }
        }

        /// <summary>
        /// Repoints all index entries that point to <paramref name="from"/> to
        /// <paramref name="to"/> - instead of removing them.
        /// <para>
        /// A device can be known under several keys: two MACs for Wi-Fi and
        /// cable, several host names, many addresses. If the keys of the
        /// dissolved entry were deleted, the same observation would later turn
        /// up as a new device again.
        /// </para>
        /// </summary>
        private void RepointIndexes(Device from, Device to)
        {
            Repoint(_byDuid);
            Repoint(_byMac);
            Repoint(_byHostName);

            void Repoint(Dictionary<string, Device> index)
            {
                foreach (string key in index.Where(kv => ReferenceEquals(kv.Value, from))
                                            .Select(kv => kv.Key)
                                            .ToList())
                {
                    index[key] = to;
                }
            }

            // In the address index the dissolved entry may sit next to another
            // holder of the same address - so only that entry is replaced, not
            // the whole list.
            foreach (List<Device> holders in _byAddress.Values)
            {
                for (int i = holders.Count - 1; i >= 0; i--)
                {
                    if (!ReferenceEquals(holders[i], from)) continue;

                    if (holders.Any(d => ReferenceEquals(d, to))) holders.RemoveAt(i);
                    else holders[i] = to;
                }
            }
        }

        /// <summary>
        /// Uniform key for a MAC: the hexadecimal string of its bytes, so that
        /// every index compares MAC addresses the same way.
        /// </summary>
        private static string MacKey(PhysicalAddress mac) =>
            Convert.ToHexString(mac.GetAddressBytes());
    }
}
