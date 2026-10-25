// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System;
using System.Collections.Generic;
using System.IO;

namespace MyNetworkMonitor.Core.Persistence
{
    /// <summary>
    /// Stores the user interface options as a plain key=value file next to the
    /// other settings files. Platform-neutral: it does not depend on
    /// System.Configuration (ApplicationSettingsBase), which is tied to
    /// Windows.
    /// </summary>
    public sealed class UserSettings
    {
        private readonly string _filePath;
        private readonly Dictionary<string, string> _values = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Opens the settings file in the given folder and loads it.</summary>
        /// <param name="settingsFolder">The folder containing <c>userSettings.txt</c>.</param>
        public UserSettings(string settingsFolder)
        {
            _filePath = Path.Combine(settingsFolder, "userSettings.txt");
            Load();
        }

        /// <summary>
        /// Whether the key has ever been written.
        /// <para>
        /// Needed to distinguish "never set" from "deliberately cleared" -
        /// <see cref="GetString"/> returns an empty string in both cases. Code
        /// that applies a default only on the first start must check here.
        /// </para>
        /// </summary>
        /// <param name="key">The settings key.</param>
        /// <returns><c>true</c> if the key exists in the file.</returns>
        public bool Contains(string key) => _values.ContainsKey(key);

        /// <summary>Reads a Boolean value.</summary>
        /// <param name="key">The settings key.</param>
        /// <param name="fallback">Returned if the key is missing or not a Boolean.</param>
        /// <returns>The stored value or <paramref name="fallback"/>.</returns>
        public bool GetBool(string key, bool fallback)
            => _values.TryGetValue(key, out string? value) && bool.TryParse(value, out bool parsed) ? parsed : fallback;

        /// <summary>Writes a Boolean value and saves the file.</summary>
        /// <param name="key">The settings key.</param>
        /// <param name="value">The value to store.</param>
        public void SetBool(string key, bool value)
        {
            _values[key] = value.ToString();
            Save();
        }

        /// <summary>Reads an integer value.</summary>
        /// <param name="key">The settings key.</param>
        /// <param name="fallback">Returned if the key is missing or not an integer.</param>
        /// <returns>The stored value or <paramref name="fallback"/>.</returns>
        public int GetInt(string key, int fallback)
            => _values.TryGetValue(key, out string? value) && int.TryParse(value, out int parsed) ? parsed : fallback;

        /// <summary>Writes an integer value and saves the file.</summary>
        /// <param name="key">The settings key.</param>
        /// <param name="value">The value to store.</param>
        public void SetInt(string key, int value)
        {
            _values[key] = value.ToString();
            Save();
        }

        /// <summary>
        /// Reads a string value. An empty value and a missing key are treated
        /// the same: not set. Otherwise every caller would have to check both.
        /// </summary>
        /// <param name="key">The settings key.</param>
        /// <param name="fallback">Returned if the key is missing or empty.</param>
        /// <returns>The stored value or <paramref name="fallback"/>.</returns>
        public string GetString(string key, string fallback = "")
            => _values.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value) ? value : fallback;

        /// <summary>Writes a trimmed string value and saves the file.</summary>
        /// <param name="key">The settings key.</param>
        /// <param name="value">The value to store; <c>null</c> stores an empty string.</param>
        public void SetString(string key, string? value)
        {
            // Memory holds the raw value; escaping happens only when writing
            // and unescaping when reading.
            _values[key] = value?.Trim() ?? string.Empty;
            Save();
        }

        /// <summary>
        /// Reads a list of values stored under one key.
        /// <para>
        /// Exists so that callers never join and split lists themselves. A
        /// hand-picked separator easily breaks the file: this store is
        /// line-based, so a line break as separator turns every list entry into
        /// a separate, unreadable line on save - which is how a stored
        /// selection of grouped services gets lost.
        /// </para>
        /// <para>
        /// Code that stores a selection calls <see cref="SetStrings"/> and
        /// <see cref="GetStrings"/> and needs nothing else, even when entries
        /// are added later.
        /// </para>
        /// </summary>
        /// <param name="key">The settings key.</param>
        /// <returns>The stored values; empty if the key is missing.</returns>
        public IReadOnlyList<string> GetStrings(string key)
        {
            string value = GetString(key);

            return value.Length == 0
                ? []
                : value.Split(ListSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        /// <summary>Writes a list of values under one key and saves the file.</summary>
        /// <param name="key">The settings key.</param>
        /// <param name="values">The values; empty entries are dropped, separator characters replaced by spaces.</param>
        /// <exception cref="ArgumentNullException"><paramref name="values"/> is <c>null</c>.</exception>
        public void SetStrings(string key, IEnumerable<string> values)
        {
            ArgumentNullException.ThrowIfNull(values);

            // A value containing the separator would fall apart into two when
            // read. That must not happen silently, so the separator is removed -
            // a vertical bar has no place in a service name anyway.
            IEnumerable<string> cleaned = values
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Select(v => v.Replace(ListSeparator, ' ').Trim());

            SetString(key, string.Join(ListSeparator, cleaned));
        }

        private const char ListSeparator = '|';

        // Line breaks would tear the line-based file apart. They rarely occur
        // in stored values, but if they do, they must not break the next
        // start. An equals sign needs no escaping: only the first one
        // separates key and value.
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
                // Damaged file: defaults apply.
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
                // A failed save must not interrupt the user interface.
            }
        }
    }
}
