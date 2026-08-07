using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>
    /// Ein Diensteintrag: ob nach ihm gesucht wird und auf welchen Ports.
    /// <para>
    /// <see cref="DetectionPacket"/> und die Antwortmuster werden mitgefuehrt,
    /// aber <b>nur angezeigt</b>. Sie sind das Herz der Erkennung - ein Byte
    /// daran geaendert, und ein Dienst wird nicht mehr gefunden, ohne dass die
    /// Ursache erkennbar waere.
    /// </para>
    /// </summary>
    public partial class ServiceEntry : ObservableObject
    {
        [ObservableProperty] private bool _toScan;
        [ObservableProperty] private string _ports = string.Empty;

        public required string Name { get; init; }
        public string Group { get; init; } = string.Empty;

        /// <summary>Nur zur Ansicht - siehe Klassenkommentar.</summary>
        public string DetectionPacket { get; init; } = string.Empty;

        public string ResponseContains { get; init; } = string.Empty;

        public bool HasDetectionPacket => !string.IsNullOrWhiteSpace(DetectionPacket);

        /// <summary>Die Ports als Zahlen - fuer die Anzeige der Anzahl.</summary>
        public int PortCount =>
            Ports.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                 .Count(part => int.TryParse(part, out int port) && port is > 0 and <= 65535);

        partial void OnPortsChanged(string value) => OnPropertyChanged(nameof(PortCount));

        public override string ToString() => $"{Name} [{Ports}]";
    }

    /// <summary>
    /// Welcher Dienst auf welchen Ports gesucht wird.
    /// <para>
    /// Die Liste entsteht wie bisher: <see cref="ScanningMethod_Services"/>
    /// legt jeden Diensttyp mit seinen Standardports an und liest
    /// <c>services.xml</c> nur als Ueberlagerung darueber. Die Datei muss also
    /// nicht vorhanden sein, und ein neu hinzugekommener Diensttyp taucht von
    /// selbst auf, statt zu fehlen.
    /// </para>
    /// </summary>
    public partial class ServiceEditorViewModel : ObservableObject
    {
        private string _xmlPath = string.Empty;
        private bool _loading;

        /// <summary>Alle Dienste, unabhaengig vom Suchfeld.</summary>
        public ObservableCollection<ServiceEntry> All { get; } = [];

        /// <summary>Was das Suchfeld durchlaesst.</summary>
        public ObservableCollection<ServiceEntry> Visible { get; } = [];

        [ObservableProperty] private ServiceEntry? _selected;
        [ObservableProperty] private string _status = string.Empty;
        [ObservableProperty] private string _filter = string.Empty;

        /// <summary>Nur die Dienste zeigen, nach denen tatsaechlich gesucht wird.</summary>
        [ObservableProperty] private bool _onlySelected;

        partial void OnFilterChanged(string value) => ApplyFilter();
        partial void OnOnlySelectedChanged(bool value) => ApplyFilter();

        public int SelectedCount => All.Count(s => s.ToScan);
        public int TotalCount => All.Count;

        /// <summary>
        /// Ist nichts angehakt, sucht der Scan nach allen Diensten - so
        /// verhaelt sich das Modul seit jeher. Das gehoert gesagt, sonst wirkt
        /// eine leere Auswahl wie "nichts wird geprueft".
        /// </summary>
        public bool ScansEverything => SelectedCount == 0;

        // ------------------------------------------------------------- Laden

        public void Load(string xmlPath)
        {
            _xmlPath = xmlPath;
            _loading = true;

            try
            {
                foreach (ServiceEntry entry in All) entry.PropertyChanged -= OnEntryChanged;
                All.Clear();

                // Das Modul baut die Tabelle samt Standardports und legt die
                // XML als Ueberlagerung darueber - genau wie beim Scan.
                ScanningMethod_Services module = new(xmlPath);

                foreach (DataRow row in module.Services.Rows)
                {
                    if (row.RowState == DataRowState.Deleted) continue;

                    ServiceEntry entry = new()
                    {
                        Name = row["Service"]?.ToString() ?? string.Empty,
                        Group = row["ServiceGroup"]?.ToString() ?? string.Empty,
                        ToScan = row["toScan"] is true,
                        Ports = row["Ports"]?.ToString() ?? string.Empty,
                        DetectionPacket = row["HelloBytePackage"]?.ToString() ?? string.Empty,
                        ResponseContains = row["ResponsedContainsString"]?.ToString() ?? string.Empty
                    };

                    entry.PropertyChanged += OnEntryChanged;
                    All.Add(entry);
                }

                Status = $"{All.Count} services loaded.";
            }
            catch (Exception ex)
            {
                Status = $"Services could not be loaded: {ex.Message}";
            }
            finally
            {
                _loading = false;
            }

            ApplyFilter();
            NotifyCounts();
        }

        // --------------------------------------------------------- Speichern

        private static readonly TimeSpan SaveDelay = TimeSpan.FromMilliseconds(600);

        private Timer? _saveTimer;
        private DataTable? _pending;
        private bool _dirty;

        private void OnEntryChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(ServiceEntry.PortCount)) return;

            NotifyCounts();

            // "Nur ausgewaehlte" blendet Zeilen aus, sobald man sie abwaehlt -
            // die Liste muss also mitgehen.
            if (OnlySelected && e.PropertyName == nameof(ServiceEntry.ToScan)) ApplyFilter();

            Save();
        }

        private void NotifyCounts()
        {
            OnPropertyChanged(nameof(SelectedCount));
            OnPropertyChanged(nameof(TotalCount));
            OnPropertyChanged(nameof(ScansEverything));
        }

        public void Save()
        {
            if (_loading || string.IsNullOrEmpty(_xmlPath)) return;

            _dirty = true;
            _pending = BuildTable();

            _saveTimer ??= new Timer(_ => Flush(), null, Timeout.Infinite, Timeout.Infinite);
            _saveTimer.Change(SaveDelay, Timeout.InfiniteTimeSpan);
        }

        public void SaveNow()
        {
            if (_loading || string.IsNullOrEmpty(_xmlPath) || !_dirty) return;

            Save();
            _saveTimer?.Change(Timeout.Infinite, Timeout.Infinite);
            Flush();
        }

        /// <summary>
        /// Baut die Tabelle im bisherigen Format. Erkennungspaket und
        /// Antwortmuster werden unveraendert durchgereicht - sie werden hier
        /// nur mitgeschrieben, nie erzeugt.
        /// </summary>
        private DataTable BuildTable()
        {
            DataTable table = new("ServicesToScan");
            table.Columns.Add("toScan", typeof(bool));
            table.Columns.Add("Service", typeof(string));
            table.Columns.Add("Ports", typeof(string));
            table.Columns.Add("HelloBytePackage", typeof(string));
            table.Columns.Add("ResponsedBytePackagePart", typeof(string));
            table.Columns.Add("ResponsedContainsString", typeof(string));
            table.Columns.Add("ServiceGroup", typeof(string));

            foreach (ServiceEntry entry in All)
            {
                table.Rows.Add(entry.ToScan, entry.Name, entry.Ports ?? string.Empty,
                               entry.DetectionPacket, string.Empty,
                               entry.ResponseContains, entry.Group);
            }

            return table;
        }

        private void Flush()
        {
            try
            {
                if (_pending is null) return;

                string? folder = Path.GetDirectoryName(_xmlPath);
                if (!string.IsNullOrEmpty(folder)) Directory.CreateDirectory(folder);

                _pending.WriteXml(_xmlPath, XmlWriteMode.WriteSchema);
            }
            catch (Exception ex)
            {
                Status = $"Services could not be saved: {ex.Message}";
            }
        }

        // ----------------------------------------------------------- Befehle

        /// <summary>Wirkt auf die sichtbaren Zeilen - wie beim Portfilter.</summary>
        [RelayCommand]
        private void SelectAll() => SetAll(true);

        [RelayCommand]
        private void SelectNone() => SetAll(false);

        private void SetAll(bool value)
        {
            // Ueber eine Kopie laufen: das Abwaehlen kann die sichtbare Liste
            // umbauen, waehrend wir noch darin sind.
            foreach (ServiceEntry entry in Visible.ToList()) entry.ToScan = value;
        }

        // ------------------------------------------------------------ Filter

        private void ApplyFilter()
        {
            Visible.Clear();

            string needle = Filter?.Trim() ?? string.Empty;

            foreach (ServiceEntry entry in All
                         .OrderBy(s => s.Group, StringComparer.CurrentCulture)
                         .ThenBy(s => s.Name, StringComparer.CurrentCulture))
            {
                if (OnlySelected && !entry.ToScan) continue;

                if (needle.Length == 0 ||
                    entry.Name.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
                    entry.Group.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
                    entry.Ports.Contains(needle, StringComparison.OrdinalIgnoreCase))
                {
                    Visible.Add(entry);
                }
            }
        }
    }
}
