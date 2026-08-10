using System.Text.Json;
using System.Text.Json.Serialization;
using MyNetworkMonitor.Core.Models;

namespace MyNetworkMonitor.Core.Persistence
{
    /// <summary>
    /// Speichert die Liste der Hauptscanner, zu denen sich diese Anlage als
    /// Satellit verbindet.
    /// <para>
    /// Liegt maschinenweit (<c>AppPaths.MachineFolder</c>) und nicht bei den
    /// Einstellungen des Nutzers: der Dienst muss dieselbe Liste lesen, und der
    /// hat kein Dokumente-Verzeichnis.
    /// </para>
    /// </summary>
    public static class MainScannerFile
    {
        public const string DefaultFileName = "mainScanners.json";

        private static readonly JsonSerializerOptions Options = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        /// <summary>Ein Empfaenger in der Datei - nur das, was dauerhaft gilt.</summary>
        private sealed class Record
        {
            public string Host { get; set; } = string.Empty;
            public int Port { get; set; } = 27411;
            public string Note { get; set; } = string.Empty;
            public bool Enabled { get; set; } = true;
            public string PinnedFingerprint { get; set; } = string.Empty;
        }

        public static void Save(IEnumerable<MainScanner> hosts, string filePath)
        {
            ArgumentNullException.ThrowIfNull(hosts);

            string? dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);

            List<Record> records = [.. hosts
                .Where(h => !string.IsNullOrWhiteSpace(h.Host))
                .Select(h => new Record
                {
                    Host = h.Host,
                    Port = h.Port,
                    Note = h.Note,
                    Enabled = h.Enabled,
                    PinnedFingerprint = h.PinnedFingerprint
                })];

            File.WriteAllText(filePath, JsonSerializer.Serialize(records, Options));
        }

        /// <summary>
        /// Liest die Liste. Eine fehlende oder beschaedigte Datei ergibt eine
        /// leere Liste - ohne Empfaenger verbindet sich die Anlage eben
        /// nirgendwohin, das ist kein Grund, den Start scheitern zu lassen.
        /// </summary>
        public static List<MainScanner> Load(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return [];

                List<Record>? records =
                    JsonSerializer.Deserialize<List<Record>>(File.ReadAllText(filePath), Options);

                if (records is null) return [];

                return [.. records
                    .Where(r => !string.IsNullOrWhiteSpace(r.Host))
                    .Select(r => new MainScanner
                    {
                        Host = r.Host,
                        Port = r.Port <= 0 ? 27411 : r.Port,
                        Note = r.Note ?? string.Empty,
                        Enabled = r.Enabled,
                        PinnedFingerprint = r.PinnedFingerprint ?? string.Empty
                    })];
            }
            catch (Exception)
            {
                return [];
            }
        }
    }
}
