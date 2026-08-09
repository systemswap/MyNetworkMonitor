using System.Globalization;
using System.Text;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>Wie ein Aktualisierungsversuch der MAC-Herstellerliste ausgegangen ist.</summary>
    public sealed record MacVendorUpdateResult
    {
        public required bool Success { get; init; }
        public int EntryCount { get; init; }
        public string? Error { get; init; }
    }

    /// <summary>
    /// Baut <c>mac_vendors.csv</c> aus Wiresharks manuf-Datei neu auf.
    /// <para>
    /// Die mitgelieferte Liste kennt nur MA-L (die klassischen 24-Bit-OUI-Bloecke).
    /// IEEE vergibt seit einigen Jahren zusaetzlich MA-M (28 Bit) und MA-S (36 Bit)
    /// an Hersteller, die keinen ganzen /24-Block brauchen - gerade viele kleinere
    /// IoT-Hersteller. Ohne diese beiden Bloecke bleibt genau deren Ausruestung
    /// "Unknown". Wiresharks manuf-Datei fasst alle drei Bloecke in einer Quelle
    /// zusammen (taeglich aus der IEEE-Registrierung neu gebaut) - eine Datei statt
    /// dreier getrennter IEEE-CSVs mit je eigenem Format.
    /// </para>
    /// <para>
    /// <b>Warum das bestehende Nachschlagen unveraendert bleibt.</b>
    /// <c>SupportMethods.GetVendorFromMac</c> prueft nur, ob die Ziel-MAC mit
    /// dem gespeicherten Praefix als Zeichenkette beginnt - kein Wissen um Bitlaengen
    /// noetig. MA-M- und MA-S-Praefixe aus der manuf-Datei stehen dort byte-aligned
    /// mit nachfolgenden Nullen und einem <c>/28</c> bzw. <c>/36</c>-Zusatz, etwa
    /// <c>00:55:DA:00/28</c> fuer einen 28-Bit-Block. Nur das signifikante Halbbyte
    /// zu behalten (hier: <c>00:55:DA:0</c>, ohne Doppelpunkt danach) macht daraus
    /// wieder einen einfachen String-Praefix, auf den <c>StartsWith</c> exakt so
    /// funktioniert wie bei den bisherigen 24-Bit-Eintraegen - deshalb kein einziger
    /// Aufrufer musste angefasst werden, nur die Datei wird reichhaltiger.
    /// </para>
    /// </summary>
    public static class MacVendorUpdater
    {
        private const string ManufUrl = "https://www.wireshark.org/download/automated/data/manuf";

        private static readonly TimeSpan DownloadTimeout = TimeSpan.FromSeconds(90);

        /// <summary>
        /// Laedt die aktuelle manuf-Datei und ersetzt die Ziel-CSV. Schreibt zuerst
        /// in eine temporaere Datei und tauscht erst danach um - ein Abbruch mitten
        /// im Schreiben darf nie eine halbe, kaputte Liste hinterlassen, an der jede
        /// naechste Herstellersuche scheitert.
        /// </summary>
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
        /// Wandelt die manuf-Zeilen in CSV-Zeilen im bestehenden Schema um.
        /// Kommentare (<c>#</c>) und Leerzeilen fallen heraus; jede uebrige Zeile
        /// hat genau drei Tab-getrennte Felder: Praefix, Kurzname, Langname.
        /// </summary>
        private static List<string> Parse(string manuf)
        {
            List<string> rows = [];

            // Literales "/" statt des Datumstrennzeichens der laufenden Kultur -
            // sonst haette ein deutsches System hier Punkte geschrieben.
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
        /// Liest ein manuf-Praefixfeld wie <c>00:55:DA:00/28</c> oder das schlichte
        /// <c>00:00:0C</c> (kein Zusatz heisst 24 Bit) und kuerzt es auf genau die
        /// Hex-Ziffern, die die angegebene Bitlaenge hergibt - siehe Klassenkommentar
        /// dazu, warum das die Zeichenketten-Suche unveraendert laesst.
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

        /// <summary>Quotet ein Feld, wenn es Komma oder Anführungszeichen enthält.</summary>
        private static string CsvField(string value) =>
            value.Contains(',') || value.Contains('"')
                ? "\"" + value.Replace("\"", "\"\"") + "\""
                : value;
    }
}
