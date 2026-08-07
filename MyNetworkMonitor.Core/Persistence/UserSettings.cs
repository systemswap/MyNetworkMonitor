using System;
using System.Collections.Generic;
using System.IO;

namespace MyNetworkMonitor.Core.Persistence
{
    /// <summary>
    /// Ersatz fuer WPFs Properties.Settings (ApplicationSettingsBase), das an
    /// System.Configuration und damit an Windows haengt. Speichert die wenigen
    /// UI-Schalter als einfache key=value-Datei neben den uebrigen
    /// Einstellungs-XMLs.
    /// </summary>
    public sealed class UserSettings
    {
        private readonly string _filePath;
        private readonly Dictionary<string, string> _values = new(StringComparer.OrdinalIgnoreCase);

        public UserSettings(string settingsFolder)
        {
            _filePath = Path.Combine(settingsFolder, "userSettings.txt");
            Load();
        }

        public bool GetBool(string key, bool fallback)
            => _values.TryGetValue(key, out string? value) && bool.TryParse(value, out bool parsed) ? parsed : fallback;

        public void SetBool(string key, bool value)
        {
            _values[key] = value.ToString();
            Save();
        }

        public int GetInt(string key, int fallback)
            => _values.TryGetValue(key, out string? value) && int.TryParse(value, out int parsed) ? parsed : fallback;

        public void SetInt(string key, int value)
        {
            _values[key] = value.ToString();
            Save();
        }

        /// <summary>
        /// Ein leerer Wert und ein fehlender Schluessel sind dasselbe: nicht
        /// gesetzt. Sonst muesste jeder Aufrufer beides pruefen.
        /// </summary>
        public string GetString(string key, string fallback = "")
            => _values.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value) ? value : fallback;

        public void SetString(string key, string? value)
        {
            _values[key] = value?.Trim() ?? string.Empty;
            Save();
        }

        private void Load()
        {
            if (!File.Exists(_filePath)) return;

            try
            {
                foreach (string line in File.ReadAllLines(_filePath))
                {
                    int separator = line.IndexOf('=');
                    if (separator <= 0) continue;

                    _values[line[..separator].Trim()] = line[(separator + 1)..].Trim();
                }
            }
            catch (Exception)
            {
                // Beschaedigte Datei: Voreinstellungen gelten
            }
        }

        private void Save()
        {
            try
            {
                string? folder = Path.GetDirectoryName(_filePath);
                if (!string.IsNullOrEmpty(folder)) Directory.CreateDirectory(folder);

                var lines = new List<string>();
                foreach (KeyValuePair<string, string> entry in _values)
                {
                    lines.Add($"{entry.Key}={entry.Value}");
                }

                File.WriteAllLines(_filePath, lines);
            }
            catch (Exception)
            {
                // Ein fehlgeschlagenes Speichern darf die Bedienung nicht stoeren
            }
        }
    }
}
