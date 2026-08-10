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
            public string Name { get; set; } = string.Empty;
            public string Note { get; set; } = string.Empty;
            public string Fingerprint { get; set; } = string.Empty;
            public bool Approved { get; set; }
            public DateTimeOffset? LastSeen { get; set; }
            public string Version { get; set; } = string.Empty;
            public string Os { get; set; } = string.Empty;
            public string RemoteAddress { get; set; } = string.Empty;
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
                    Name = s.Name,
                    Note = s.Note,
                    Fingerprint = s.Fingerprint,
                    Approved = s.Approved,
                    LastSeen = s.LastSeen,
                    Version = s.Version,
                    Os = s.Os,
                    RemoteAddress = s.RemoteAddress
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

                return [.. records
                    .Where(r => !string.IsNullOrWhiteSpace(r.Name))
                    .Select(r => new Satellite
                    {
                        Name = r.Name,
                        Note = r.Note ?? string.Empty,
                        Fingerprint = r.Fingerprint ?? string.Empty,
                        Approved = r.Approved,
                        LastSeen = r.LastSeen,
                        Version = r.Version ?? string.Empty,
                        Os = r.Os ?? string.Empty,
                        RemoteAddress = r.RemoteAddress ?? string.Empty
                    })];
            }
            catch (Exception)
            {
                return [];
            }
        }
    }
}
