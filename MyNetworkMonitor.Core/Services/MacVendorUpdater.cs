// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Globalization;
using System.Text;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>The outcome of an attempt to update the MAC vendor list.</summary>
    public sealed record MacVendorUpdateResult
    {
        /// <summary>Whether the list was replaced.</summary>
        public required bool Success { get; init; }
        /// <summary>Number of entries written.</summary>
        public int EntryCount { get; init; }
        /// <summary>Why the update failed; null on success.</summary>
        public string? Error { get; init; }
    }

    /// <summary>
    /// Rebuilds <c>mac_vendors.csv</c> from Wireshark's manuf file.
    /// <para>
    /// The bundled list contains only MA-L (the classic 24-bit OUI blocks).
    /// IEEE additionally assigns MA-M (28 bits) and MA-S (36 bits) to vendors
    /// that do not need a whole /24 block - notably many smaller IoT vendors.
    /// Without these two blocks, exactly their equipment stays "Unknown".
    /// Wireshark's manuf file combines all three blocks in one source (rebuilt
    /// daily from the IEEE registry) - one file instead of three separate IEEE
    /// CSV files with their own formats.
    /// </para>
    /// <para>
    /// <b>Why the existing lookup needs no change.</b>
    /// <c>SupportMethods.GetVendorFromMac</c> only checks whether the target MAC
    /// starts with the stored prefix as a string - no knowledge of bit lengths
    /// needed. MA-M and MA-S prefixes in the manuf file are byte-aligned with
    /// trailing zeros and a <c>/28</c> or <c>/36</c> suffix, for example
    /// <c>00:55:DA:00/28</c> for a 28-bit block. Keeping only the significant
    /// nibbles (here: <c>00:55:DA:0</c>, without a trailing colon) turns this
    /// into a plain string prefix on which <c>StartsWith</c> works exactly as on
    /// the 24-bit entries - so no caller needs to know about block sizes; only
    /// the file becomes richer.
    /// </para>
    /// </summary>
    public static class MacVendorUpdater
    {
        private const string ManufUrl = "https://www.wireshark.org/download/automated/data/manuf";

        private static readonly TimeSpan DownloadTimeout = TimeSpan.FromSeconds(90);

        /// <summary>
        /// Downloads the current manuf file and replaces the target CSV. Writes to
        /// a temporary file first and swaps afterwards - an abort in the middle of
        /// writing must never leave a half-written, broken list on which every
        /// subsequent vendor lookup fails.
        /// </summary>
        /// <param name="targetCsvPath">The CSV file to replace.</param>
        /// <param name="cancellationToken">Cancels the download.</param>
        /// <returns>Success and entry count, or the reason for the failure.</returns>
        /// <exception cref="ArgumentException"><paramref name="targetCsvPath"/> is null, empty or whitespace.</exception>
        public static async Task<MacVendorUpdateResult> UpdateAsync(
            string targetCsvPath, CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(targetCsvPath);

            try
            {
                using HttpClient client = new() { Timeout = DownloadTimeout };
                string manuf = await client.GetStringAsync(ManufUrl, cancellationToken);

                List<string> rows = Parse(manuf);

                if (rows.Count == 0)
                {
                    return new MacVendorUpdateResult
                    {
                        Success = false,
                        Error = "Die heruntergeladene Datei enthielt keine auswertbaren Einträge."
                    };
                }

                string? directory = Path.GetDirectoryName(targetCsvPath);
                if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

                string tempPath = targetCsvPath + ".download";

                await using (StreamWriter writer = new(tempPath, append: false, Encoding.UTF8))
                {
                    await writer.WriteLineAsync("Mac Prefix,Vendor Name,Private,Block Type,Last Update");

                    foreach (string row in rows)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        await writer.WriteLineAsync(row);
                    }
                }

                File.Copy(tempPath, targetCsvPath, overwrite: true);
                File.Delete(tempPath);

                return new MacVendorUpdateResult { Success = true, EntryCount = rows.Count };
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return new MacVendorUpdateResult { Success = false, Error = "Zeitlimit beim Herunterladen überschritten." };
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or UnauthorizedAccessException)
            {
                return new MacVendorUpdateResult { Success = false, Error = ex.Message };
            }
        }

        /// <summary>
        /// Converts the manuf lines into CSV lines in the existing schema.
        /// Comments (<c>#</c>) and blank lines are dropped; every remaining line
        /// has tab-separated fields: prefix, short name and optionally long name.
        /// </summary>
        private static List<string> Parse(string manuf)
        {
            List<string> rows = [];

            // Literal "/" instead of the current culture's date separator -
            // otherwise a German system would write dots here.
            string today = DateTime.Now.ToString("yyyy/MM/dd", CultureInfo.InvariantCulture);

            foreach (string rawLine in manuf.Split('\n'))
            {
                string line = rawLine.TrimEnd('\r');
                if (line.Length == 0 || line[0] == '#') continue;

                string[] parts = line.Split('\t', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (parts.Length < 2) continue;

                (string Prefix, int Bits)? parsed = ParsePrefix(parts[0]);
                if (parsed is null) continue;

                string vendorName = parts.Length >= 3 && parts[2].Length > 0 ? parts[2] : parts[1];

                string blockType = parsed.Value.Bits switch
                {
                    24 => "MA-L",
                    28 => "MA-M",
                    36 => "MA-S",
                    _ => "Other"
                };

                rows.Add($"{parsed.Value.Prefix},{CsvField(vendorName)},false,{blockType},{today}");
            }

            return rows;
        }

        /// <summary>
        /// Reads a manuf prefix field such as <c>00:55:DA:00/28</c> or the plain
        /// <c>00:00:0C</c> (no suffix means 24 bits) and truncates it to exactly
        /// the hex digits the given bit length covers - see the class remarks on
        /// why this leaves the string lookup unchanged.
        /// </summary>
        private static (string Prefix, int Bits)? ParsePrefix(string field)
        {
            string hexPart = field;
            int bits = 24;

            int slash = field.IndexOf('/');
            if (slash >= 0)
            {
                hexPart = field[..slash];
                if (!int.TryParse(field[(slash + 1)..], out bits) || bits <= 0) return null;
            }

            string hexDigits = hexPart.Replace(":", "").Replace("-", "");
            if (hexDigits.Length == 0) return null;

            int nibbles = Math.Min((bits + 3) / 4, hexDigits.Length);
            if (nibbles == 0) return null;

            string truncated = hexDigits[..nibbles];

            StringBuilder grouped = new();
            for (int i = 0; i < truncated.Length; i += 2)
            {
                if (i > 0) grouped.Append(':');
                grouped.Append(truncated, i, Math.Min(2, truncated.Length - i));
            }

            return (grouped.ToString(), bits);
        }

        /// <summary>Quotes a field if it contains a comma or a quotation mark.</summary>
        private static string CsvField(string value) =>
            value.Contains(',') || value.Contains('"')
                ? "\"" + value.Replace("\"", "\"\"") + "\""
                : value;
    }
}
