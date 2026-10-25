// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Data;
using MyNetworkMonitor.Core.Models;

namespace MyNetworkMonitor.Core.Persistence
{
    /// <summary>
    /// Maps between the DataTable/XML format ("IPGroups") and the
    /// platform-neutral <see cref="IpGroup"/> model. System.Data is available
    /// on Windows and Linux, so the stored XML format stays compatible with
    /// existing files.
    /// </summary>
    public static class IpGroupTable
    {
        /// <summary>Name of the table in the stored XML.</summary>
        public const string TableName = "IPGroups";

        // Column names exactly as in the stored schema (IPGroupData / saved XML).
        private const string ColIsActive = "IsActive";
        private const string ColDescription = "IPGroupDescription";
        private const string ColDeviceDescription = "DeviceDescription";
        private const string ColFirstIP = "FirstIP";
        private const string ColLastIP = "LastIP";
        private const string ColDomain = "Domain";
        private const string ColDnsServers = "DNSServers";
        private const string ColGatewayIP = "NMGatewayIP";
        private const string ColAutomaticScan = "AutomaticScan";
        private const string ColScanInterval = "ScanIntervalMinutes";

        // Columns that older files may lack. The obsolete NMGatewayPort column
        // belonged to the remote instance, which is managed separately by the
        // satellite mode (SATELLIT.md); files that still contain it are read
        // without it, and it is not written on the next save. ToStr/ToBool
        // handle missing columns, so files without these two columns still load.
        private const string ColScannedBy = "ScannedBy";
        private const string ColLastScanned = "LastScanned";

        /// <summary>Creates an empty DataTable with the expected schema.</summary>
        /// <returns>The new, empty table.</returns>
        public static DataTable CreateTable()
        {
            var dt = new DataTable(TableName);
            dt.Columns.Add(ColIsActive, typeof(bool));
            dt.Columns.Add(ColDescription, typeof(string));
            dt.Columns.Add(ColDeviceDescription, typeof(string));
            dt.Columns.Add(ColFirstIP, typeof(string));
            dt.Columns.Add(ColLastIP, typeof(string));
            dt.Columns.Add(ColDomain, typeof(string));
            dt.Columns.Add(ColDnsServers, typeof(string));
            dt.Columns.Add(ColGatewayIP, typeof(string));
            dt.Columns.Add(ColScannedBy, typeof(string));
            dt.Columns.Add(ColAutomaticScan, typeof(bool));
            dt.Columns.Add(ColScanInterval, typeof(string));
            dt.Columns.Add(ColLastScanned, typeof(string));
            return dt;
        }

        /// <summary>Reads the rows of a DataTable into models.</summary>
        /// <param name="dt">The table to read; deleted rows are skipped.</param>
        /// <returns>One model per row.</returns>
        public static List<IpGroup> ReadRows(DataTable dt)
        {
            var list = new List<IpGroup>();
            foreach (DataRow row in dt.Rows)
            {
                if (row.RowState == DataRowState.Deleted) continue;
                list.Add(new IpGroup
                {
                    IsActive = ToBool(row, ColIsActive),
                    IpGroupDescription = ToStr(row, ColDescription),
                    DeviceDescription = ToStr(row, ColDeviceDescription),
                    FirstIP = ToStr(row, ColFirstIP),
                    LastIP = ToStr(row, ColLastIP),
                    Domain = ToStr(row, ColDomain),
                    DnsServers = ToStr(row, ColDnsServers),
                    NmGatewayIP = ToStr(row, ColGatewayIP),
                    ScannedBy = ToStr(row, ColScannedBy),
                    AutomaticScan = ToBool(row, ColAutomaticScan),
                    ScanIntervalMinutes = ToStr(row, ColScanInterval),
                    LastScanned = ToStr(row, ColLastScanned),
                });
            }
            return list;
        }

        /// <summary>
        /// Writes the models back into an existing DataTable, replacing its
        /// content. A view bound to the same DataTable therefore stays in sync.
        /// </summary>
        /// <param name="dt">The table to fill.</param>
        /// <param name="groups">The models to write.</param>
        public static void WriteRows(DataTable dt, IEnumerable<IpGroup> groups)
        {
            dt.Rows.Clear();
            foreach (var g in groups)
            {
                DataRow row = dt.NewRow();
                row[ColIsActive] = g.IsActive;
                row[ColDescription] = g.IpGroupDescription ?? string.Empty;
                row[ColDeviceDescription] = g.DeviceDescription ?? string.Empty;
                row[ColFirstIP] = g.FirstIP ?? string.Empty;
                row[ColLastIP] = g.LastIP ?? string.Empty;
                row[ColDomain] = g.Domain ?? string.Empty;
                row[ColDnsServers] = g.DnsServers ?? string.Empty;
                row[ColGatewayIP] = g.NmGatewayIP ?? string.Empty;
                row[ColScannedBy] = g.ScannedBy ?? string.Empty;
                row[ColAutomaticScan] = g.AutomaticScan;
                row[ColScanInterval] = g.ScanIntervalMinutes ?? string.Empty;
                row[ColLastScanned] = g.LastScanned ?? string.Empty;
                dt.Rows.Add(row);
            }
        }

        /// <summary>Saves the models in the XML format, including the schema.</summary>
        /// <param name="groups">The models to save.</param>
        /// <param name="xmlPath">Target file; its directory is created if needed.</param>
        public static void SaveXml(IEnumerable<IpGroup> groups, string xmlPath)
        {
            string? dir = Path.GetDirectoryName(xmlPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            var dt = CreateTable();
            WriteRows(dt, groups);
            dt.WriteXml(xmlPath, XmlWriteMode.WriteSchema);
        }

        private static string ToStr(DataRow row, string col)
            => row.Table.Columns.Contains(col) && row[col] != DBNull.Value ? row[col].ToString() ?? string.Empty : string.Empty;

        private static bool ToBool(DataRow row, string col)
        {
            if (!row.Table.Columns.Contains(col) || row[col] == DBNull.Value) return false;
            return row[col] is bool b ? b : bool.TryParse(row[col].ToString(), out var parsed) && parsed;
        }
    }
}
