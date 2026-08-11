using System.Text.Json;
using System.Text.Json.Serialization;
using MyNetworkMonitor.Core.Models;

namespace MyNetworkMonitor.Core.Persistence
{
    /// <summary>
    /// Speichert die Satellitenliste als JSON neben den uebrigen
    /// Einstellungen.
    /// <para>
    /// JSON und nicht das alte DataTable-XML: fuer diese Liste gibt es keinen
    /// Altbestand, auf den Ruecksicht zu nehmen waere - dasselbe Vorgehen wie
    /// bei <see cref="DeviceStoreFile"/>.
    /// </para>
    /// </summary>
    public static class SatelliteFile
    {
        public const string DefaultFileName = "satellites.json";

        private static readonly JsonSerializerOptions Options = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        /// <summary>Ein Satellit in der Datei - nur das, was dauerhaft gilt.</summary>
        private sealed class Record
        {
            /// <summary>
            /// Die Kennung, auf die Bereiche zeigen. Fehlt sie in einer
            /// aelteren Datei, wird beim Laden eine vergeben.
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

            // Wo er steht. Wird bei jeder Anmeldung ueberschrieben, aber
            // trotzdem gespeichert: sonst stuende in der Auswahl nichts,
            // solange er gerade offline ist.
            public string SiteHostName { get; set; } = string.Empty;
            public string SiteDomain { get; set; } = string.Empty;
            public string SiteIpv4 { get; set; } = string.Empty;
            public string SiteIpv6 { get; set; } = string.Empty;
            public string SiteNetwork { get; set; } = string.Empty;
            public string SiteNetworks { get; set; } = string.Empty;

            // Was er scannen soll - je Satellit, unabhaengig von den
            // Haupteinstellungen.
            public bool OnlyKnownTargets { get; set; }
            public bool CrossCheckOnlyKnownTargets { get; set; } = true;
            public List<string> OnlyKnownTargetsFor { get; set; } = [];
        }

        public static void Save(IEnumerable<Satellite> satellites, string filePath)
        {
            ArgumentNullException.ThrowIfNull(satellites);

            string? dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);

            // IsConnected wird bewusst nicht geschrieben: nach einem Neustart
            // ist niemand verbunden, bis er sich wieder meldet. Gespeichert
            // waere es eine Behauptung, die niemand geprueft hat.
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
        /// Liest die Liste. Eine fehlende oder beschaedigte Datei ergibt eine
        /// leere Liste - ohne Satelliten laeuft alles oertlich weiter, das ist
        /// kein Grund, den Start scheitern zu lassen.
        /// </summary>
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
                        // Eine Datei von vor der Umstellung kennt keine Kennung.
                        // Dann wird hier eine vergeben; die Bereiche, die noch
                        // auf den Namen zeigen, werden beim Laden der Bereiche
                        // darauf umgeschrieben.
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
