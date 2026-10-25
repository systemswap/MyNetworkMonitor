// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text.Json.Serialization;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Persistence
{
    /// <summary>
    /// Persists the device inventory between two program runs.
    /// <para>
    /// The device model is not a table image - a device carries several
    /// addresses, services per address family and an observation history -
    /// hence a dedicated JSON format.
    /// </para>
    /// <para>
    /// Storage goes through lean records rather than the model classes
    /// themselves: those derive from <c>ObservableObject</c> and carry computed
    /// properties that do not belong in a file. This keeps the format readable
    /// even when the model changes.
    /// </para>
    /// </summary>
    public static class DeviceStoreFile
    {
        /// <summary>The default file name.</summary>
        public const string DefaultFileName = "lastScanResult.json";

        private static readonly JsonSerializerOptions Options = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        /// <summary>
        /// Writes the inventory. Errors are swallowed - a failed save must not
        /// block shutdown.
        /// </summary>
        /// <param name="store">The inventory to save.</param>
        /// <param name="filePath">Target file; its directory is created if needed.</param>
        /// <returns><c>true</c> if the file was written.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="store"/> is <c>null</c>.</exception>
        public static bool Save(DeviceStore store, string filePath)
        {
            ArgumentNullException.ThrowIfNull(store);

            try
            {
                List<DeviceRecord> records;

                lock (store.SyncRoot)
                {
                    records = [.. store.Devices.Select(ToRecord)];
                }

                string? folder = Path.GetDirectoryName(filePath);
                if (!string.IsNullOrEmpty(folder)) Directory.CreateDirectory(folder);

                // An existing inventory is never replaced by an empty one
                // without keeping a backup.
                //
                // Clearing the table and then closing is meant to keep the
                // empty table - that is intended. It is still an easy mistake,
                // and the difference between "cleared" and "not read on load"
                // is not visible from outside. A backup costs nothing, and the
                // case has occurred in practice.
                if (records.Count == 0 && File.Exists(filePath) && new FileInfo(filePath).Length > MinimumMeaningfulSize)
                {
                    try
                    {
                        File.Copy(filePath, filePath + ".backup", overwrite: true);
                    }
                    catch (Exception)
                    {
                        // Continue writing without a backup - it is a bonus,
                        // not a precondition.
                    }
                }

                File.WriteAllText(filePath, JsonSerializer.Serialize(records, Options));
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// The size from which a file counts as "contains something". An empty
        /// list is two characters.
        /// </summary>
        private const int MinimumMeaningfulSize = 8;

        /// <summary>
        /// Serializes the inventory to a string instead of a file - for the
        /// result a satellite sends back.
        /// <para>
        /// Deliberately the same mapping as for saving: a second mapping would
        /// have to be updated for every new device property, which is easily
        /// forgotten.
        /// </para>
        /// </summary>
        /// <param name="store">The inventory to serialize.</param>
        /// <returns>The inventory as JSON.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="store"/> is <c>null</c>.</exception>
        public static string ToJson(DeviceStore store)
        {
            ArgumentNullException.ThrowIfNull(store);

            List<DeviceRecord> records;
            lock (store.SyncRoot)
            {
                records = [.. store.Devices.Select(ToRecord)];
            }

            return JsonSerializer.Serialize(records, Options);
        }

        /// <summary>
        /// Reads devices from a string without adding them anywhere. The caller
        /// decides whether to replace or merge them.
        /// </summary>
        /// <param name="json">JSON as produced by <see cref="ToJson"/>.</param>
        /// <returns>The devices; records that cannot be identified are skipped.</returns>
        /// <exception cref="JsonException">The text is not valid JSON in the expected format.</exception>
        public static List<Device> FromJson(string json)
        {
            if (string.IsNullOrWhiteSpace(json)) return [];

            List<DeviceRecord>? records = JsonSerializer.Deserialize<List<DeviceRecord>>(json, Options);
            if (records is null) return [];

            return [.. records.Select(ToDevice).Where(d => d is not null)!];
        }

        /// <summary>
        /// Loads the inventory into an empty store.
        /// </summary>
        /// <param name="store">The store to fill.</param>
        /// <param name="filePath">The file to read.</param>
        /// <returns>The number of devices read.</returns>
        public static int Load(DeviceStore store, string filePath) => Load(store, filePath, out _);

        /// <summary>
        /// Like <see cref="Load(DeviceStore, string)"/>, but reports whether the
        /// file was unreadable.
        /// <para>
        /// The difference matters: a missing file is the first start, an
        /// unreadable one is an error. Treating both the same writes an empty
        /// list on close over data that merely could not be read.
        /// </para>
        /// </summary>
        /// <param name="store">The store to fill.</param>
        /// <param name="filePath">The file to read.</param>
        /// <param name="error">The error message if the file exists but could not be read; otherwise <c>null</c>.</param>
        /// <returns>The number of devices read.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="store"/> is <c>null</c>.</exception>
        public static int Load(DeviceStore store, string filePath, out string? error)
        {
            ArgumentNullException.ThrowIfNull(store);

            error = null;

            if (!File.Exists(filePath)) return 0;

            try
            {
                List<DeviceRecord>? records =
                    JsonSerializer.Deserialize<List<DeviceRecord>>(File.ReadAllText(filePath), Options);

                if (records is null || records.Count == 0) return 0;

                store.LoadFrom(records.Select(ToDevice).Where(d => d is not null)!);
                return store.Devices.Count;
            }
            catch (Exception ex)
            {
                // A damaged file must not prevent the start - at worst the
                // program starts with an empty list.
                error = ex.Message;
                return 0;
            }
        }

        // ------------------------------------------------------- Conversion

        private static DeviceRecord ToRecord(Device device) => new()
        {
            Duid = device.Duid,
            Mac = device.Mac?.ToString(),
            Vendor = Blank(device.Vendor),
            HostName = Blank(device.HostName),
            Domain = Blank(device.Domain),
            NetBiosName = Blank(device.NetBiosName),
            InternalName = Blank(device.InternalName),
            GroupDescription = Blank(device.GroupDescription),
            FirstSeen = device.FirstSeen,
            LastSeen = device.LastSeen,
            SeenBy = [.. device.SeenBy],
            WasLookedUp = device.WasLookedUp,
            LookupAddresses = [.. device.LookupAddresses],
            Aliases = [.. device.Aliases],
            Details = device.Details.Count > 0 ? new Dictionary<string, string>(device.Details) : null,

            // The TTL is stored, the guess derived from it is not: the rule
            // behind the guess can change, the measurement cannot.
            Ttl = device.Ttl,
            SwitchName = Blank(device.SwitchName),
            SwitchPort = Blank(device.SwitchPort),
            Vlan = Blank(device.Vlan),
            WebTitle = Blank(device.WebTitle),
            CertificateSubject = Blank(device.CertificateSubject),
            CertificateIssuer = Blank(device.CertificateIssuer),
            CertificateExpires = device.CertificateExpires,
            CertificateIsSelfSigned = device.CertificateIsSelfSigned,

            Addresses = [.. device.Addresses.Select(a => new AddressRecord
            {
                Address = a.Info.Canonical,
                Origin = a.Origin,
                State = a.State,
                ValidUntil = a.ValidUntil,
                PreferredUntil = a.PreferredUntil,
                FirstSeen = a.FirstSeen,
                LastSeen = a.LastSeen,
                DiscoveredBy = Blank(a.DiscoveredBy)
            })],
            Services = [.. device.Services.Select(s => new ServiceRecord
            {
                ServiceName = s.ServiceName,
                Category = Blank(s.Category),
                Ports = [.. s.Ports],
                StatusIPv4 = s.StatusIPv4,
                StatusIPv6 = s.StatusIPv6,
                PortLog = s.PortLog
            })]
        };

        private static Device? ToDevice(DeviceRecord record)
        {
            Device device = new()
            {
                Duid = record.Duid,
                Mac = ParseMac(record.Mac),
                Vendor = record.Vendor ?? string.Empty,
                HostName = record.HostName ?? string.Empty,
                Domain = record.Domain ?? string.Empty,
                // Inventories saved by older versions can contain the
                // placeholder "UNKNOWN" from a NetBIOS query that found no name.
                // It would otherwise be displayed as the name, so it is dropped
                // on load.
                NetBiosName = IsPlaceholderName(record.NetBiosName) ? string.Empty : record.NetBiosName ?? string.Empty,
                InternalName = record.InternalName ?? string.Empty,
                GroupDescription = record.GroupDescription ?? string.Empty,
                FirstSeen = record.FirstSeen,
                LastSeen = record.LastSeen,
                WasLookedUp = record.WasLookedUp,

                Ttl = record.Ttl,
                SwitchName = record.SwitchName ?? string.Empty,
                SwitchPort = record.SwitchPort ?? string.Empty,
                Vlan = record.Vlan ?? string.Empty,
                WebTitle = record.WebTitle ?? string.Empty,
                CertificateSubject = record.CertificateSubject ?? string.Empty,
                CertificateIssuer = record.CertificateIssuer ?? string.Empty,
                CertificateExpires = record.CertificateExpires,
                CertificateIsSelfSigned = record.CertificateIsSelfSigned
            };

            foreach (string source in record.SeenBy ?? []) device.SeenBy.Add(source);
            foreach (string address in record.LookupAddresses ?? []) device.LookupAddresses.Add(address);
            foreach (string alias in record.Aliases ?? []) device.Aliases.Add(alias);

            foreach (KeyValuePair<string, string> detail in record.Details ?? [])
            {
                device.Details[detail.Key] = detail.Value;
            }

            foreach (AddressRecord address in record.Addresses ?? [])
            {
                // Address properties are recomputed rather than stored - they
                // follow from the address itself, and a stored version would be
                // wrong after a rule change.
                if (!IpAddressAnalyzer.TryAnalyze(address.Address, out IpAddressInfo? info) || info is null) continue;

                device.Addresses.Add(new DeviceAddress
                {
                    Info = info,
                    Origin = address.Origin,
                    State = address.State,
                    ValidUntil = address.ValidUntil,
                    PreferredUntil = address.PreferredUntil,
                    FirstSeen = address.FirstSeen,
                    LastSeen = address.LastSeen,
                    DiscoveredBy = address.DiscoveredBy ?? string.Empty,

                    // Deliberately not restored: that a device responded
                    // yesterday says nothing about whether it is online now, so
                    // loaded addresses start as not responding.
                    IsResponding = false
                });
            }

            foreach (ServiceRecord service in record.Services ?? [])
            {
                device.Services.Add(new DeviceServiceResult
                {
                    ServiceName = service.ServiceName,
                    Category = service.Category ?? string.Empty,
                    Ports = [.. service.Ports ?? []],
                    StatusIPv4 = service.StatusIPv4,
                    StatusIPv6 = service.StatusIPv6,
                    PortLog = service.PortLog
                });
            }

            // A record without any address and without an identifier could
            // never be matched again.
            return device.Addresses.Count == 0 && device.Mac is null && string.IsNullOrEmpty(device.HostName)
                ? null
                : device;
        }

        private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

        /// <summary>Placeholders from older inventories that are not names.</summary>
        private static bool IsPlaceholderName(string? value) =>
            string.Equals(value?.Trim(), "UNKNOWN", StringComparison.OrdinalIgnoreCase);

        private static PhysicalAddress? ParseMac(string? text)
        {
            if (string.IsNullOrWhiteSpace(text)) return null;

            return PhysicalAddress.TryParse(text, out PhysicalAddress? mac) ? mac : null;
        }

        // ---------------------------------------------------------- Records

        private sealed class DeviceRecord
        {
            public string? Duid { get; set; }
            public string? Mac { get; set; }
            public string? Vendor { get; set; }
            public string? HostName { get; set; }
            public string? Domain { get; set; }
            public string? NetBiosName { get; set; }
            public string? InternalName { get; set; }
            public string? GroupDescription { get; set; }
            public DateTimeOffset FirstSeen { get; set; }
            public DateTimeOffset LastSeen { get; set; }
            public List<string>? SeenBy { get; set; }
            public bool WasLookedUp { get; set; }
            public List<string>? LookupAddresses { get; set; }
            public List<string>? Aliases { get; set; }
            public Dictionary<string, string>? Details { get; set; }

            public int Ttl { get; set; }
            public string? SwitchName { get; set; }
            public string? SwitchPort { get; set; }
            public string? Vlan { get; set; }
            public string? WebTitle { get; set; }
            public string? CertificateSubject { get; set; }
            public string? CertificateIssuer { get; set; }
            public DateTimeOffset? CertificateExpires { get; set; }
            public bool CertificateIsSelfSigned { get; set; }

            public List<AddressRecord>? Addresses { get; set; }
            public List<ServiceRecord>? Services { get; set; }
        }

        private sealed class AddressRecord
        {
            public string Address { get; set; } = string.Empty;
            public AddressOrigin Origin { get; set; }
            public AddressState State { get; set; }
            public DateTimeOffset? ValidUntil { get; set; }
            public DateTimeOffset? PreferredUntil { get; set; }
            public DateTimeOffset FirstSeen { get; set; }
            public DateTimeOffset LastSeen { get; set; }
            public string? DiscoveredBy { get; set; }
        }

        private sealed class ServiceRecord
        {
            public string ServiceName { get; set; } = string.Empty;
            public string? Category { get; set; }
            public List<int>? Ports { get; set; }
            public PortStatus? StatusIPv4 { get; set; }
            public PortStatus? StatusIPv6 { get; set; }
            public string? PortLog { get; set; }
        }
    }
}
