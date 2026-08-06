using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Text;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Aufbereitung der Ergebnistabelle fuer den Export. Bewusst ohne
    /// UI-Bezug: die Views waehlen nur die Zeilen aus und oeffnen den
    /// Speicherdialog, die Tabellen-Umformung und das CSV-Schreiben passieren
    /// hier (im WPF-Original lag beides in MainWindow.xaml.cs).
    /// </summary>
    public static class ScanResultExport
    {
        /// <summary>
        /// Flache Variante: eine Zeile je Geraet. Die Bild-Spalten (ARPStatus,
        /// PingStatus, SSDPStatus, IsIPCam) werden zu "true"/leer und
        /// aussagekraeftig umbenannt, weil ein PNG-Byte-Array im CSV nichts
        /// verloren hat.
        /// </summary>
        public static DataTable BuildFlatTable(IReadOnlyList<DataRow> rows, bool escapeForCsv)
        {
            var table = new DataTable();
            if (rows.Count == 0) return table;

            foreach (DataColumn column in rows[0].Table.Columns)
            {
                table.Columns.Add(column.ColumnName, typeof(string));
            }

            foreach (DataRow source in rows)
            {
                DataRow target = table.NewRow();

                foreach (DataColumn column in source.Table.Columns)
                {
                    string name = column.ColumnName;
                    string value = source[column].ToString() ?? string.Empty;

                    if (IsStatusColumn(name))
                    {
                        target[name] = string.IsNullOrEmpty(value) ? string.Empty : "true";
                    }
                    else
                    {
                        target[name] = Escape(value, escapeForCsv);
                    }
                }

                table.Rows.Add(target);
            }

            RenameIfPresent(table, "SSDPStatus", "supportSSDP");
            RenameIfPresent(table, "ARPStatus", "ARP_Response");
            RenameIfPresent(table, "PingStatus", "PingResponse");

            return table;
        }

        /// <summary>
        /// Aufgeteilte Variante: je erkanntem Dienst eine eigene Zeile mit den
        /// Spalten Services / Ports / Status. Zeilen ohne erkannte Dienste
        /// bleiben als eine Zeile erhalten.
        /// </summary>
        public static DataTable BuildServiceSplitTable(DataTable schemaSource, IReadOnlyList<DataRow> rows)
        {
            DataTable expanded = schemaSource.Clone();

            foreach (DataColumn column in expanded.Columns)
            {
                // Alle Spalten als Text fuehren - sonst scheitert das Setzen von
                // "true" auf den byte[]-Statusspalten.
                if (column.DataType != typeof(string)) column.DataType = typeof(string);
            }

            expanded.Columns.Add("Services", typeof(string));
            expanded.Columns.Add("Ports", typeof(string));
            expanded.Columns.Add("Status", typeof(string));

            foreach (DataRow source in rows)
            {
                string[] serviceLines = (source["detectedServicePorts"] as string)
                    ?.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                    ?? Array.Empty<string>();

                if (serviceLines.Length == 0)
                {
                    expanded.Rows.Add(CopyRow(expanded, source));
                    continue;
                }

                string lastService = string.Empty;

                foreach (string line in serviceLines)
                {
                    string[] parts = line.Split(new[] { '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    string service = parts.Length > 0 ? parts[0].Trim(':').Replace(":", string.Empty) : string.Empty;
                    string port = parts.Length > 1 ? parts[1].Trim() : string.Empty;
                    string status = parts.Length > 2 ? parts[2].Trim('(', ')') : string.Empty;

                    // Folgezeilen eines Dienstes tragen nur den Port
                    if (string.IsNullOrWhiteSpace(service) && !string.IsNullOrWhiteSpace(port)) service = lastService;
                    else lastService = service;

                    DataRow target = CopyRow(expanded, source);
                    target["Services"] = service;
                    target["Ports"] = port;
                    target["Status"] = status;
                    expanded.Rows.Add(target);
                }
            }

            expanded.Columns.Remove("detectedServicePorts");

            RenameIfPresent(expanded, "SSDPStatus", "supportSSDP");
            RenameIfPresent(expanded, "ARPStatus", "ARP_Response");
            RenameIfPresent(expanded, "PingStatus", "PingResponse");

            return expanded;
        }

        /// <summary>Semikolon-getrenntes CSV in UTF-8, wie im WPF-Original.</summary>
        public static void WriteCsv(DataTable table, Stream stream)
        {
            // leaveOpen: der Stream gehoert dem Aufrufer
            using var writer = new StreamWriter(stream, new UTF8Encoding(true), leaveOpen: true);

            writer.WriteLine(string.Join(";", table.Columns.Cast<DataColumn>().Select(c => c.ColumnName)));

            foreach (DataRow row in table.Rows)
            {
                writer.WriteLine(string.Join(";", row.ItemArray.Select(f => f?.ToString()?.Replace(";", ",") ?? string.Empty)));
            }
        }

        private static DataRow CopyRow(DataTable target, DataRow source)
        {
            DataRow row = target.NewRow();

            foreach (DataColumn column in target.Columns)
            {
                string name = column.ColumnName;
                if (!source.Table.Columns.Contains(name)) continue;

                string value = source[name].ToString() ?? string.Empty;

                row[name] = IsStatusColumn(name)
                    ? (string.IsNullOrEmpty(value) ? string.Empty : "true")
                    : value;
            }

            return row;
        }

        /// <summary>Spalten, die im Original PNG-Bytes statt Text enthalten.</summary>
        private static bool IsStatusColumn(string columnName)
            => columnName.Equals("ARPStatus", StringComparison.OrdinalIgnoreCase)
            || columnName.Equals("PingStatus", StringComparison.OrdinalIgnoreCase)
            || columnName.Equals("SSDPStatus", StringComparison.OrdinalIgnoreCase)
            || columnName.Equals("IsIPCam", StringComparison.OrdinalIgnoreCase);

        private static string Escape(string value, bool escapeForCsv)
        {
            if (string.IsNullOrEmpty(value)) return string.Empty;

            if (!escapeForCsv) return value.Replace("\"", "\"\"");

            if (value.Contains('"') || value.Contains('\n') || value.Contains('\r') || value.Contains(';'))
            {
                return $"\"{value.Replace("\"", "\"\"")}\"";
            }

            return value;
        }

        private static void RenameIfPresent(DataTable table, string from, string to)
        {
            if (table.Columns.Contains(from)) table.Columns[from]!.ColumnName = to;
        }
    }
}
