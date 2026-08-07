using System.Collections.ObjectModel;
using System.Net.NetworkInformation;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Model
{
    /// <summary>
    /// Haelt die Geraeteliste und ordnet eingehende Sichtungen dem richtigen
    /// Geraet zu. Der Kern des neuen Modells.
    /// <para>
    /// Unter IPv4 genuegte die Adresse als Schluessel. Unter IPv6 nicht mehr:
    /// ein Geraet hat mehrere Adressen, von denen manche taeglich wechseln.
    /// Darum wird ueber eine Kaskade zugeordnet - DUID vor MAC vor Adresse vor
    /// Hostname - und Geraete werden nachtraeglich zusammengefuehrt, sobald
    /// sich herausstellt, dass zwei Eintraege dasselbe Geraet sind.
    /// </para>
    /// <para>
    /// Nicht threadsicher. Aufrufe sind ueber den UI-Dispatcher oder eine
    /// eigene Sperre zu serialisieren - so, wie es die Scan-Module heute schon
    /// mit der Ergebnisliste halten.
    /// </para>
    /// </summary>
    public sealed class DeviceStore
    {
        private readonly ObservableCollection<Device> _devices = [];

        private readonly Dictionary<string, Device> _byDuid = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Device> _byMac = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Device> _byAddress = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Device> _byHostName = new(StringComparer.OrdinalIgnoreCase);

        public ReadOnlyObservableCollection<Device> Devices { get; }

        /// <summary>
        /// Die Sperre, unter der der Bestand veraendert wird. Wer waehrend
        /// eines Laufs liest - die Ergebnistabelle tut das, damit sie sich
        /// fuellt, statt am Ende auf einen Schlag zu erscheinen - muss sie
        /// ebenfalls halten. Sonst liest die Oberflaeche eine Liste, die ein
        /// Scan-Thread gerade veraendert.
        /// </summary>
        public Lock SyncRoot { get; } = new();

        /// <summary>
        /// Die Anzeigemeldungen der Geraete unterdruecken.
        /// <para>
        /// Waehrend eines Laufs melden die Scan-Module aus beliebigen Aufgaben.
        /// Solange die Tabelle die betroffene Zeile bereits zeigt, liefe die
        /// Bindung damit aus einem Hintergrund-Thread - die Oberflaeche darf
        /// aber nur vom eigenen Thread aus angefasst werden. Wer das setzt,
        /// uebernimmt es, <see cref="Device.NotifyDisplayChanged"/> selbst und
        /// am richtigen Ort nachzuholen.
        /// </para>
        /// </summary>
        public bool DeferDisplayNotifications { get; set; }

        public DeviceStore()
        {
            Devices = new ReadOnlyObservableCollection<Device>(_devices);
        }

        /// <summary>Wird nach jeder Zuordnung ausgeloest - auch wenn nur ergaenzt wurde.</summary>
        public event Action<Device>? DeviceChanged;

        /// <summary>Ein neues Geraet ist aufgetaucht.</summary>
        public event Action<Device>? DeviceAdded;

        /// <summary>
        /// Zwei Eintraege haben sich als dasselbe Geraet erwiesen. Das zweite
        /// Argument ist der aufgeloeste Eintrag und ab dann nicht mehr gueltig.
        /// </summary>
        public event Action<Device, Device>? DevicesMerged;

        /// <summary>
        /// Nimmt eine Sichtung auf und liefert das Geraet, zu dem sie gehoert.
        /// Legt es an, wenn es neu ist, und fuehrt bestehende Eintraege
        /// zusammen, wenn die Sichtung sie verbindet.
        /// </summary>
        public Device Observe(DeviceObservation observation)
        {
            ArgumentNullException.ThrowIfNull(observation);

            Device device;
            bool isNew = false;

            lock (SyncRoot)
            {
                List<Device> candidates = FindCandidates(observation);

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
                    // Der Eintrag mit der staerksten Identitaet bleibt bestehen,
                    // die uebrigen gehen in ihm auf.
                    device = candidates.OrderBy(d => (int)d.IdentityKey).First();

                    foreach (Device other in candidates.Where(c => !ReferenceEquals(c, device)))
                    {
                        MergeInto(device, other);
                    }
                }

                Apply(device, observation);
                Reindex(device);
            }

            // Die Anzeigeeigenschaften sind berechnet und haengen an Adressen
            // und Diensten - deren Aenderungen bemerkt die Bindung nicht von
            // allein.
            if (!DeferDisplayNotifications) device.NotifyDisplayChanged();

            if (isNew) DeviceAdded?.Invoke(device);
            DeviceChanged?.Invoke(device);

            return device;
        }

        /// <summary>Leert die Liste samt aller Zuordnungen.</summary>
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

        /// <summary>Sucht ein Geraet zu einer Adresse. Fuer Nachscans einzelner Ziele.</summary>
        public Device? FindByAddress(IpAddressInfo address) =>
            _byAddress.GetValueOrDefault(address.Canonical);

        // ------------------------------------------------------- Zuordnung

        /// <summary>
        /// Sucht alle bestehenden Eintraege, auf die die Sichtung passt.
        /// Mehr als einer bedeutet, dass die Sichtung sie verbindet - dann
        /// werden sie zusammengefuehrt.
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

            // Eine EUI-64-Adresse traegt die MAC in sich. Damit laesst sich ein
            // ueber IPv6 gefundenes Geraet demselben Eintrag zuordnen wie das
            // ueber ARP gefundene - ohne dass jemand beides zugleich gesehen hat.
            if (o.Address?.DerivedMac is { } derived)
                Add(_byMac.GetValueOrDefault(MacKey(derived)));

            if (o.Address is not null)
                Add(_byAddress.GetValueOrDefault(o.Address.Canonical));

            // Hostnamen sind schwach: mehrere Geraete koennen denselben Namen
            // melden. Nur heranziehen, wenn sonst nichts passt.
            if (found.Count == 0 && !string.IsNullOrWhiteSpace(o.HostName))
                Add(_byHostName.GetValueOrDefault(o.HostName));

            return found;
        }

        /// <summary>Traegt die Angaben der Sichtung am Geraet ein.</summary>
        private static void Apply(Device device, DeviceObservation o)
        {
            if (o.Timestamp > device.LastSeen) device.LastSeen = o.Timestamp;
            if (device.FirstSeen == default || o.Timestamp < device.FirstSeen) device.FirstSeen = o.Timestamp;

            device.SeenBy.Add(o.Source);

            if (!string.IsNullOrWhiteSpace(o.Duid)) device.Duid = o.Duid;

            // Eine unmittelbar beobachtete MAC ist verlaesslicher als eine aus
            // EUI-64 zurueckgerechnete - darum nur ergaenzen, nicht ueberschreiben.
            if (o.Mac is not null) device.Mac = o.Mac;
            else if (device.Mac is null && o.Address?.DerivedMac is { } derived) device.Mac = derived;

            if (!string.IsNullOrWhiteSpace(o.Vendor)) device.Vendor = o.Vendor;
            if (!string.IsNullOrWhiteSpace(o.HostName)) device.HostName = o.HostName;
            if (!string.IsNullOrWhiteSpace(o.Domain)) device.Domain = o.Domain;
            if (!string.IsNullOrWhiteSpace(o.NetBiosName)) device.NetBiosName = o.NetBiosName;
            if (!string.IsNullOrWhiteSpace(o.GroupDescription)) device.GroupDescription = o.GroupDescription;

            if (o.Details is not null)
            {
                foreach (KeyValuePair<string, string> detail in o.Details)
                {
                    device.Details[detail.Key] = detail.Value;
                }
            }

            if (o.Address is not null) ApplyAddress(device, o);
            if (o.Services is not null) ApplyServices(device, o);
        }

        /// <summary>
        /// Traegt Dienstbefunde ein. Ein Verfahren prueft immer nur eine
        /// Adressfamilie, darum wird je Seite gesetzt und die andere nicht
        /// angetastet - sonst wuerde der IPv4-Lauf den IPv6-Befund loeschen
        /// und die Gegenueberstellung ginge verloren.
        /// </summary>
        private static void ApplyServices(Device device, DeviceObservation o)
        {
            foreach (DeviceServiceResult incoming in o.Services!)
            {
                DeviceServiceResult? existing = device.Services.FirstOrDefault(s =>
                    string.Equals(s.ServiceName, incoming.ServiceName, StringComparison.OrdinalIgnoreCase));

                if (existing is null)
                {
                    device.Services.Add(incoming);
                    continue;
                }

                if (incoming.StatusIPv4 is not null) existing.StatusIPv4 = incoming.StatusIPv4;
                if (incoming.StatusIPv6 is not null) existing.StatusIPv6 = incoming.StatusIPv6;
                if (!string.IsNullOrEmpty(incoming.PortLog)) existing.PortLog = incoming.PortLog;

                foreach (int port in incoming.Ports.Where(p => !existing.Ports.Contains(p)))
                {
                    existing.Ports.Add(port);
                }
            }
        }

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
        /// Fuehrt <paramref name="other"/> in <paramref name="target"/> zusammen
        /// und entfernt es aus der Liste. Bestehende Angaben am Ziel bleiben
        /// stehen; der aufgeloeste Eintrag fuellt nur Luecken.
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

            foreach (string source in other.SeenBy) target.SeenBy.Add(source);

            foreach (KeyValuePair<string, string> detail in other.Details)
            {
                target.Details.TryAdd(detail.Key, detail.Value);
            }

            foreach (DeviceServiceResult service in other.Services)
            {
                DeviceServiceResult? mine = target.Services
                    .FirstOrDefault(s => string.Equals(s.ServiceName, service.ServiceName, StringComparison.OrdinalIgnoreCase));

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

        // -------------------------------------------------------- Register

        private void Reindex(Device device)
        {
            if (!string.IsNullOrWhiteSpace(device.Duid)) _byDuid[device.Duid] = device;
            if (device.Mac is not null) _byMac[MacKey(device.Mac)] = device;
            if (!string.IsNullOrWhiteSpace(device.HostName)) _byHostName[device.HostName] = device;

            foreach (DeviceAddress address in device.Addresses)
            {
                _byAddress[address.Info.Canonical] = device;
            }
        }

        /// <summary>
        /// Haengt alle Eintraege, die auf <paramref name="from"/> zeigen, auf
        /// <paramref name="to"/> um - statt sie zu entfernen.
        /// <para>
        /// Ein Geraet kann unter mehreren Schluesseln bekannt sein: zwei MACs
        /// bei WLAN und Kabel, mehrere Hostnamen, viele Adressen. Wuerden die
        /// Schluessel des aufgeloesten Eintrags geloescht, laege dieselbe
        /// Sichtung spaeter wieder als neues Geraet vor.
        /// </para>
        /// </summary>
        private void RepointIndexes(Device from, Device to)
        {
            Repoint(_byDuid);
            Repoint(_byMac);
            Repoint(_byAddress);
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
        }

        /// <summary>
        /// Einheitlicher Schluessel fuer eine MAC. <see cref="PhysicalAddress"/>
        /// als Schluessel taugt nicht - es vergleicht nach Referenz.
        /// </summary>
        private static string MacKey(PhysicalAddress mac) =>
            Convert.ToHexString(mac.GetAddressBytes());
    }
}
