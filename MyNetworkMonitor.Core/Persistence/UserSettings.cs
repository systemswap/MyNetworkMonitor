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

        /// <summary>
        /// Der Schluessel wurde schon einmal geschrieben.
        /// <para>
        /// Noetig, um "noch nie gesetzt" von "bewusst geleert" zu
        /// unterscheiden - <see cref="GetString"/> liefert in beiden Faellen
        /// eine leere Zeichenkette. Wer eine Voreinstellung nur beim ersten
        /// Start setzen will, muss hier fragen.
        /// </para>
        /// </summary>
        public bool Contains(string key) => _values.ContainsKey(key);

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
            // Im Speicher steht der rohe Wert; verpackt wird erst beim
            // Schreiben, ausgepackt beim Lesen.
            _values[key] = value?.Trim() ?? string.Empty;
            Save();
        }

        /// <summary>
        /// Eine Liste von Werten unter einem Schluessel.
        /// <para>
        /// Gibt es, damit niemand mehr selbst zusammenfuegt und zerlegt. Genau
        /// daran ist die Auswahl der gruppierten Dienste gescheitert: als
        /// Trennzeichen war ein Zeilenumbruch gewaehlt, und diese Ablage ist
        /// zeilenweise aufgebaut - jeder Eintrag wurde beim Speichern zu einer
        /// eigenen, unlesbaren Zeile.
        /// </para>
        /// <para>
        /// Wer eine Auswahl speichert, ruft <see cref="SetStrings"/> und
        /// <see cref="GetStrings"/> auf und muss sich um nichts weiter
        /// kuemmern - auch nicht, wenn spaeter Eintraege dazukommen.
        /// </para>
        /// </summary>
        public IReadOnlyList<string> GetStrings(string key)
        {
            string value = GetString(key);

            return value.Length == 0
                ? []
                : value.Split(ListSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        public void SetStrings(string key, IEnumerable<string> values)
        {
            ArgumentNullException.ThrowIfNull(values);

            // Ein Wert, der das Trennzeichen enthaelt, wuerde beim Lesen in
            // zwei zerfallen. Das darf nicht stillschweigend passieren, also
            // wird es entfernt - in einem Dienstnamen hat ein senkrechter
            // Strich ohnehin nichts verloren.
            IEnumerable<string> cleaned = values
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Select(v => v.Replace(ListSeparator, ' ').Trim());

            SetString(key, string.Join(ListSeparator, cleaned));
        }

        private const char ListSeparator = '|';

        // Zeilenumbrueche wuerden die Datei zerreissen, das Gleichheitszeichen
        // nur den ersten Teil eines Wertes durchlassen. Beides kommt in den
        // gespeicherten Werten kaum vor - wenn doch, soll es den naechsten
        // Start nicht kosten.
        private static string Escape(string value) =>
            value.Replace("\\", @"\\").Replace("\r", @"\r").Replace("\n", @"\n");

        private static string Unescape(string value) =>
            value.Replace(@"\n", "\n").Replace(@"\r", "\r").Replace(@"\\", "\\");

        private void Load()
        {
            if (!File.Exists(_filePath)) return;

            try
            {
                foreach (string line in File.ReadAllLines(_filePath))
                {
                    int separator = line.IndexOf('=');
                    if (separator <= 0) continue;

                    _values[line[..separator].Trim()] = Unescape(line[(separator + 1)..].Trim());
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
                    lines.Add($"{entry.Key}={Escape(entry.Value)}");
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
