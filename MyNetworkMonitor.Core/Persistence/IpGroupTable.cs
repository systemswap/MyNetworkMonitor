using System.Data;
using MyNetworkMonitor.Core.Models;

namespace MyNetworkMonitor.Core.Persistence
{
    /// <summary>
    /// Mappt zwischen dem bestehenden DataTable/XML-Format ("IPGroups") und dem
    /// plattformneutralen <see cref="IpGroup"/>-Model. System.Data ist unter
    /// Windows und Linux verfügbar, dadurch bleibt das gespeicherte XML-Format
    /// unverändert kompatibel zur bisherigen Anwendung.
    /// </summary>
    public static class IpGroupTable
    {
        public const string TableName = "IPGroups";

        // Spaltennamen exakt wie im bisherigen Schema (IPGroupData / gespeichertes XML).
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

        // Neu. NMGatewayPort ist ersatzlos entfallen: der Port gehoerte zur
        // entfernten Instanz, und die zieht mit dem Satellitenbetrieb in eine
        // eigene Verwaltung um (SATELLIT.md). Alte Dateien bringen die Spalte
        // noch mit - sie wird beim Lesen nicht mehr beachtet und beim naechsten
        // Speichern nicht wieder geschrieben. ToStr/ToBool kommen ihrerseits mit
        // fehlenden Spalten zurecht, aeltere Dateien ohne die beiden neuen
        // Spalten gehen also weiter auf.
        private const string ColScannedBy = "ScannedBy";
        private const string ColLastScanned = "LastScanned";

        /// <summary>Erzeugt eine leere DataTable mit dem erwarteten Schema.</summary>
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

        /// <summary>Liest die Zeilen einer DataTable in Models ein.</summary>
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
        /// Schreibt die Models in eine bestehende DataTable zurück (Inhalt wird
        /// ersetzt). So bleibt eine an dieselbe DataTable gebundene Ansicht – etwa
        /// das Grid im MainWindow – synchron.
        /// </summary>
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

        /// <summary>Speichert die Models im bisherigen XML-Format (inkl. Schema).</summary>
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
