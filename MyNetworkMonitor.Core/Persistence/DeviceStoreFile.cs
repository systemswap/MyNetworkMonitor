using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text.Json.Serialization;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Persistence
{
    /// <summary>
    /// Sichert den Geraetebestand zwischen zwei Programmlaeufen.
    /// <para>
    /// Die bisherige Anwendung hat dafuer die Ergebnistabelle als XML
    /// geschrieben. Das neue Modell ist kein Tabellenabbild mehr - ein Geraet
    /// traegt mehrere Adressen, Dienste je Adressfamilie und eine
    /// Beobachtungshistorie -, darum ein eigenes Format.
    /// </para>
    /// <para>
    /// Gespeichert wird ueber schlanke Datensaetze und nicht ueber die
    /// Modellklassen selbst: die haengen an <c>ObservableObject</c> und tragen
    /// berechnete Eigenschaften, die in einer Datei nichts verloren haben. So
    /// bleibt das Format auch dann lesbar, wenn sich am Modell etwas aendert.
    /// </para>
    /// </summary>
    public static class DeviceStoreFile
    {
        public const string DefaultFileName = "lastScanResult.json";

        private static readonly JsonSerializerOptions Options = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        /// <summary>
        /// Schreibt den Bestand. Fehler werden geschluckt - ein misslungenes
        /// Speichern darf das Beenden nicht aufhalten.
        /// </summary>
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

                File.WriteAllText(filePath, JsonSerializer.Serialize(records, Options));
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Laedt den Bestand in einen leeren Store. Gibt zurueck, wie viele
        /// Geraete gelesen wurden.
        /// </summary>
        public static int Load(DeviceStore store, string filePath)
        {
            ArgumentNullException.ThrowIfNull(store);

            if (!File.Exists(filePath)) return 0;

            try
            {
                List<DeviceRecord>? records =
                    JsonSerializer.Deserialize<List<DeviceRecord>>(File.ReadAllText(filePath), Options);

                if (records is null || records.Count == 0) return 0;

                store.LoadFrom(records.Select(ToDevice).Where(d => d is not null)!);
                return store.Devices.Count;
            }
            catch (Exception)
            {
                // Eine beschaedigte Datei darf den Start nicht verhindern -
                // schlimmstenfalls beginnt man mit einer leeren Liste.
                return 0;
            }
        }

        // ------------------------------------------------------- Umwandlung

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
                NetBiosName = record.NetBiosName ?? string.Empty,
                InternalName = record.InternalName ?? string.Empty,
                GroupDescription = record.GroupDescription ?? string.Empty,
                FirstSeen = record.FirstSeen,
                LastSeen = record.LastSeen,
                WasLookedUp = record.WasLookedUp
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
                // Die Adressmerkmale werden neu berechnet statt gespeichert -
                // sie folgen aus der Adresse selbst, und eine gespeicherte
                // Fassung waere nach einer Regelaenderung falsch.
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

                    // Bewusst nicht uebernommen: dass ein Geraet gestern
                    // geantwortet hat, sagt nichts darueber, ob es jetzt online
                    // ist. Die bisherige Anwendung hat die Statuspunkte beim
                    // Speichern aus demselben Grund auf grau gesetzt.
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

            // Ein Datensatz ohne jede Adresse und ohne Kennung liesse sich
            // spaeter nirgends wiedererkennen.
            return device.Addresses.Count == 0 && device.Mac is null && string.IsNullOrEmpty(device.HostName)
                ? null
                : device;
        }

        private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

        private static PhysicalAddress? ParseMac(string? text)
        {
            if (string.IsNullOrWhiteSpace(text)) return null;

            return PhysicalAddress.TryParse(text, out PhysicalAddress? mac) ? mac : null;
        }

        // ----------------------------------------------------- Datensaetze

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
