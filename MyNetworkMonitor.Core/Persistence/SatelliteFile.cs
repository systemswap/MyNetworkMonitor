// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Text.Json;
using System.Text.Json.Serialization;
using MyNetworkMonitor.Core.Models;

namespace MyNetworkMonitor.Core.Persistence
{
    /// <summary>
    /// Stores the satellite list as JSON next to the other settings.
    /// <para>
    /// JSON rather than DataTable XML: this list has no existing files in
    /// another format to stay compatible with - the same approach as
    /// <see cref="DeviceStoreFile"/>.
    /// </para>
    /// </summary>
    public static class SatelliteFile
    {
        /// <summary>The default file name.</summary>
        public const string DefaultFileName = "satellites.json";

        private static readonly JsonSerializerOptions Options = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        /// <summary>A satellite in the file - only the persistent part.</summary>
        private sealed class Record
        {
            /// <summary>
            /// The identifier that IP ranges refer to. If an older file lacks
            /// it, one is assigned on load.
            /// </summary>
            public string Id { get; set; } = string.Empty;

            public string Name { get; set; } = string.Empty;
            public string Note { get; set; } = string.Empty;
            public string Fingerprint { get; set; } = string.Empty;
            public bool Approved { get; set; }
            public DateTimeOffset? LastSeen { get; set; }
            public string Version { get; set; } = string.Empty;
            public string Os { get; set; } = string.Empty;
            public string RemoteAddress { get; set; } = string.Empty;

            // Where the satellite is located. Overwritten on every login but
            // still persisted: otherwise the selection would show nothing
            // while the satellite is offline.
            public string SiteHostName { get; set; } = string.Empty;
            public string SiteDomain { get; set; } = string.Empty;
            public string SiteIpv4 { get; set; } = string.Empty;
            public string SiteIpv6 { get; set; } = string.Empty;
            public string SiteNetwork { get; set; } = string.Empty;
            public string SiteNetworks { get; set; } = string.Empty;

            // What the satellite should scan - per satellite, independent of
            // the main settings.
            public bool OnlyKnownTargets { get; set; }
            public bool CrossCheckOnlyKnownTargets { get; set; } = true;
            public List<string> OnlyKnownTargetsFor { get; set; } = [];
        }

        /// <summary>Saves the list; entries without a name are skipped.</summary>
        /// <param name="satellites">The satellites to save.</param>
        /// <param name="filePath">Target file; its directory is created if needed.</param>
        /// <exception cref="ArgumentNullException"><paramref name="satellites"/> is <c>null</c>.</exception>
        public static void Save(IEnumerable<Satellite> satellites, string filePath)
        {
            ArgumentNullException.ThrowIfNull(satellites);

            string? dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);

            // IsConnected is deliberately not written: after a restart no
            // satellite is connected until it reports again. Persisted, it
            // would be an unverified claim.
            List<Record> records = [.. satellites
                .Where(s => !string.IsNullOrWhiteSpace(s.Name))
                .Select(s => new Record
                {
                    Id = s.Id,
                    Name = s.Name,
                    Note = s.Note,
                    Fingerprint = s.Fingerprint,
                    Approved = s.Approved,
                    LastSeen = s.LastSeen,
                    Version = s.Version,
                    Os = s.Os,
                    RemoteAddress = s.RemoteAddress,
                    SiteHostName = s.SiteHostName,
                    SiteDomain = s.SiteDomain,
                    SiteIpv4 = s.SiteIpv4,
                    SiteIpv6 = s.SiteIpv6,
                    SiteNetwork = s.SiteNetwork,
                    SiteNetworks = s.SiteNetworks,
                    OnlyKnownTargets = s.OnlyKnownTargets,
                    CrossCheckOnlyKnownTargets = s.CrossCheckOnlyKnownTargets,
                    OnlyKnownTargetsFor = [.. s.OnlyKnownTargetsFor.OrderBy(x => x, StringComparer.OrdinalIgnoreCase)]
                })];

            File.WriteAllText(filePath, JsonSerializer.Serialize(records, Options));
        }

        /// <summary>
        /// Reads the list. A missing or damaged file yields an empty list -
        /// without satellites everything continues locally, which is no reason
        /// to fail the start.
        /// </summary>
        /// <param name="filePath">The file to read.</param>
        /// <returns>The satellites; empty if the file is missing or unreadable.</returns>
        public static List<Satellite> Load(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return [];

                List<Record>? records =
                    JsonSerializer.Deserialize<List<Record>>(File.ReadAllText(filePath), Options);

                if (records is null) return [];

                List<Satellite> loaded = [];

                foreach (Record r in records.Where(r => !string.IsNullOrWhiteSpace(r.Name)))
                {
                    Satellite s = new()
                    {
                        // Files from before satellite identifiers were
                        // introduced have no Id. One is assigned here; IP ranges
                        // that still refer to the name are rewritten to it when
                        // the ranges are loaded.
                        Id = string.IsNullOrWhiteSpace(r.Id) ? Guid.NewGuid().ToString("N") : r.Id,
                        Name = r.Name,
                        Note = r.Note ?? string.Empty,
                        Fingerprint = r.Fingerprint ?? string.Empty,
                        Approved = r.Approved,
                        LastSeen = r.LastSeen,
                        Version = r.Version ?? string.Empty,
                        Os = r.Os ?? string.Empty,
                        RemoteAddress = r.RemoteAddress ?? string.Empty,
                        SiteHostName = r.SiteHostName ?? string.Empty,
                        SiteDomain = r.SiteDomain ?? string.Empty,
                        SiteIpv4 = r.SiteIpv4 ?? string.Empty,
                        SiteIpv6 = r.SiteIpv6 ?? string.Empty,
                        SiteNetwork = r.SiteNetwork ?? string.Empty,
                        SiteNetworks = r.SiteNetworks ?? string.Empty,
                        OnlyKnownTargets = r.OnlyKnownTargets,
                        CrossCheckOnlyKnownTargets = r.CrossCheckOnlyKnownTargets
                    };

                    foreach (string id in r.OnlyKnownTargetsFor ?? []) s.OnlyKnownTargetsFor.Add(id);

                    loaded.Add(s);
                }

                return loaded;
            }
            catch (Exception)
            {
                return [];
            }
        }
    }
}
