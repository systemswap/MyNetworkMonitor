// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Text.Json;
using System.Text.Json.Serialization;
using MyNetworkMonitor.Core.Models;

namespace MyNetworkMonitor.Core.Persistence
{
    /// <summary>
    /// Stores the list of main scanners this installation connects to as a
    /// satellite.
    /// <para>
    /// Stored machine-wide (<c>AppPaths.MachineFolder</c>) rather than with the
    /// per-user settings: the service must read the same list and has no
    /// documents folder.
    /// </para>
    /// </summary>
    public static class MainScannerFile
    {
        /// <summary>The default file name.</summary>
        public const string DefaultFileName = "mainScanners.json";

        private static readonly JsonSerializerOptions Options = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        /// <summary>A receiver in the file - only the persistent part.</summary>
        private sealed class Record
        {
            public string Host { get; set; } = string.Empty;

            /// <summary>
            /// Optional. If an older file lacks it, it stays empty and the host
            /// name is used as entered.
            /// </summary>
            public string Domain { get; set; } = string.Empty;

            public int Port { get; set; } = 27411;
            public string Note { get; set; } = string.Empty;
            public bool Enabled { get; set; } = true;
            public string PinnedFingerprint { get; set; } = string.Empty;
        }

        /// <summary>Saves the list; entries without a host are skipped.</summary>
        /// <param name="hosts">The main scanners to save.</param>
        /// <param name="filePath">Target file; its directory is created if needed.</param>
        /// <exception cref="ArgumentNullException"><paramref name="hosts"/> is <c>null</c>.</exception>
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
                    Domain = h.Domain,
                    Port = h.Port,
                    Note = h.Note,
                    Enabled = h.Enabled,
                    PinnedFingerprint = h.PinnedFingerprint
                })];

            File.WriteAllText(filePath, JsonSerializer.Serialize(records, Options));
        }

        /// <summary>
        /// Reads the list. A missing or damaged file yields an empty list -
        /// without receivers the installation simply connects nowhere, which is
        /// no reason to fail the start.
        /// </summary>
        /// <param name="filePath">The file to read.</param>
        /// <returns>The main scanners; empty if the file is missing or unreadable.</returns>
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
                        Domain = r.Domain ?? string.Empty,
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
