using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Text;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Prepares the result table for export. Deliberately free of UI
    /// dependencies: the views only select the rows and open the save dialog;
    /// reshaping the table and writing the CSV happen here.
    /// </summary>
    public static class ScanResultExport
    {
        /// <summary>
        /// Flat variant: one row per device. The image columns (ARPStatus,
        /// PingStatus, SSDPStatus, IsIPCam) become "true"/empty and are given
        /// meaningful names, because a PNG byte array has no place in a CSV file.
        /// </summary>
        /// <param name="rows">The rows to export; all from the same table.</param>
        /// <param name="escapeForCsv">Quote values that contain quotation marks, line breaks or semicolons.</param>
        /// <returns>A table with string columns only; empty if there are no rows.</returns>
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
        /// Split variant: one row per detected service with the columns
        /// Services / Ports / Status. Rows without detected services remain a
        /// single row.
        /// </summary>
        /// <param name="schemaSource">The table whose columns are taken over.</param>
        /// <param name="rows">The rows to export.</param>
        /// <returns>A table with string columns only, without the detectedServicePorts column.</returns>
        public static DataTable BuildServiceSplitTable(DataTable schemaSource, IReadOnlyList<DataRow> rows)
        {
            DataTable expanded = schemaSource.Clone();

            foreach (DataColumn column in expanded.Columns)
            {
                // Keep all columns as text - otherwise setting "true" on the
                // byte[] status columns fails.
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

                    // Continuation lines of a service carry only the port.
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

        /// <summary>Writes a semicolon-separated CSV file in UTF-8 with BOM.</summary>
        /// <param name="table">The table to write.</param>
        /// <param name="stream">The target stream; it stays open.</param>
        public static void WriteCsv(DataTable table, Stream stream)
        {
            // leaveOpen: the stream belongs to the caller.
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

        /// <summary>Columns that hold PNG bytes instead of text in the result table.</summary>
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
