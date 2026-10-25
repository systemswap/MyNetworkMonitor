// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>
    /// A service entry: whether it is searched for and on which ports.
    /// <para>
    /// <see cref="DetectionPacket"/> and the response patterns are carried
    /// along but <b>only displayed</b>. They are the core of the detection;
    /// changing a single byte can make a service undetectable without any
    /// visible cause.
    /// </para>
    /// </summary>
    public partial class ServiceEntry : ObservableObject
    {
        /// <summary>The service is searched for.</summary>
        [ObservableProperty] private bool _toScan;

        /// <summary>
        /// Active inquiry; shown only where it has an effect. Its meaning is
        /// described at <c>ProbeContext.ActiveInquiry</c>: the inquiry changes
        /// the state of the remote side, so the operator decides, not the probe.
        /// </summary>
        [ObservableProperty] private bool _activeInquiry;
        /// <summary>The ports to probe, separated by commas.</summary>
        [ObservableProperty] private string _ports = string.Empty;

        /// <summary>The service name (key in <c>services.xml</c>).</summary>
        public required string Name { get; init; }
        /// <summary>The service group the entry belongs to.</summary>
        public string Group { get; init; } = string.Empty;

        /// <summary>Read-only; see the class remarks.</summary>
        public string DetectionPacket { get; init; } = string.Empty;

        /// <summary>Text an answer must contain; read-only, see the class remarks.</summary>
        public string ResponseContains { get; init; } = string.Empty;

        /// <summary>The entry has a detection packet.</summary>
        public bool HasDetectionPacket => !string.IsNullOrWhiteSpace(DetectionPacket);

        /// <summary>
        /// Whether this service supports an active inquiry. Only SECS/GEM does;
        /// for all others the check box would have no effect.
        /// </summary>
        public bool SupportsActiveInquiry => Name == nameof(ServiceType.SecsGem);

        /// <summary>Number of valid ports in <see cref="Ports"/>, for display.</summary>
        public int PortCount =>
            Ports.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                 .Count(part => int.TryParse(part, out int port) && port is > 0 and <= 65535);

        partial void OnPortsChanged(string value) => OnPropertyChanged(nameof(PortCount));

        public override string ToString() => $"{Name} [{Ports}]";
    }

    /// <summary>
    /// Which service is searched for on which ports.
    /// <para>
    /// The list is built by <see cref="ScanningMethod_Services"/>: it creates
    /// every service type with its default ports and reads
    /// <c>services.xml</c> only as an overlay. The file therefore need not
    /// exist, and a service type added to the program appears automatically
    /// instead of missing.
    /// </para>
    /// </summary>
    public partial class ServiceEditorViewModel : ObservableObject
    {
        private string _xmlPath = string.Empty;
        private bool _loading;

        /// <summary>All services, regardless of the search field.</summary>
        public ObservableCollection<ServiceEntry> All { get; } = [];

        /// <summary>The services that pass the search field.</summary>
        public ObservableCollection<ServiceEntry> Visible { get; } = [];

        /// <summary>The selected service.</summary>
        [ObservableProperty] private ServiceEntry? _selected;
        /// <summary>The status line text.</summary>
        [ObservableProperty] private string _status = string.Empty;
        /// <summary>Searches name, group and ports.</summary>
        [ObservableProperty] private string _filter = string.Empty;

        /// <summary>Shows only the services that are actually searched for.</summary>
        [ObservableProperty] private bool _onlySelected;

        partial void OnFilterChanged(string value) => ApplyFilter();
        partial void OnOnlySelectedChanged(bool value) => ApplyFilter();

        /// <summary>Number of services that are searched for.</summary>
        public int SelectedCount => All.Count(s => s.ToScan);
        /// <summary>Number of services in the list.</summary>
        public int TotalCount => All.Count;

        /// <summary>
        /// If nothing is checked, the scan searches for all services. The UI
        /// states this; otherwise an empty selection would read as "nothing is
        /// checked".
        /// </summary>
        public bool ScansEverything => SelectedCount == 0;

        // ------------------------------------------------------------ Loading

        /// <summary>Loads the services: built-in service types overlaid with the file.</summary>
        /// <param name="xmlPath">The <c>services.xml</c> file; also the target for later saves.</param>
        public void Load(string xmlPath)
        {
            _xmlPath = xmlPath;
            _loading = true;

            try
            {
                foreach (ServiceEntry entry in All) entry.PropertyChanged -= OnEntryChanged;
                All.Clear();

                // The module builds the table with default ports and overlays
                // the XML, exactly as during a scan.
                ScanningMethod_Services module = new(xmlPath);

                foreach (DataRow row in module.Services.Rows)
                {
                    if (row.RowState == DataRowState.Deleted) continue;

                    ServiceEntry entry = new()
                    {
                        Name = row["Service"]?.ToString() ?? string.Empty,
                        Group = row["ServiceGroup"]?.ToString() ?? string.Empty,
                        ToScan = row["toScan"] is true,
                        ActiveInquiry = row.Table.Columns.Contains("ActiveInquiry") && row["ActiveInquiry"] is true,
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

        // ------------------------------------------------------------- Saving

        private static readonly TimeSpan SaveDelay = TimeSpan.FromMilliseconds(600);

        private Timer? _saveTimer;
        private DataTable? _pending;
        private bool _dirty;

        private void OnEntryChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(ServiceEntry.PortCount)) return;

            NotifyCounts();

            // "Only selected" hides rows as soon as they are unchecked, so the
            // list has to follow.
            if (OnlySelected && e.PropertyName == nameof(ServiceEntry.ToScan)) ApplyFilter();

            Save();
        }

        private void NotifyCounts()
        {
            OnPropertyChanged(nameof(SelectedCount));
            OnPropertyChanged(nameof(TotalCount));
            OnPropertyChanged(nameof(ScansEverything));
        }

        /// <summary>Captures the current state and writes it after a short delay.</summary>
        public void Save()
        {
            if (_loading || string.IsNullOrEmpty(_xmlPath)) return;

            _dirty = true;
            _pending = BuildTable();

            _saveTimer ??= new Timer(_ => Flush(), null, Timeout.Infinite, Timeout.Infinite);
            _saveTimer.Change(SaveDelay, Timeout.InfiniteTimeSpan);
        }

        /// <summary>Writes pending changes immediately, e.g. before closing.</summary>
        public void SaveNow()
        {
            if (_loading || string.IsNullOrEmpty(_xmlPath) || !_dirty) return;

            Save();
            _saveTimer?.Change(Timeout.Infinite, Timeout.Infinite);
            Flush();
        }

        /// <summary>
        /// Builds the table in the <c>services.xml</c> format. Detection packet
        /// and response pattern are passed through unchanged; they are only
        /// written here, never generated.
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
            table.Columns.Add("ActiveInquiry", typeof(bool));

            foreach (ServiceEntry entry in All)
            {
                table.Rows.Add(entry.ToScan, entry.Name, entry.Ports ?? string.Empty,
                               entry.DetectionPacket, string.Empty,
                               entry.ResponseContains, entry.Group, entry.ActiveInquiry);
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

        // ----------------------------------------------------------- Commands

        /// <summary>Checks all visible rows, as in the port editor.</summary>
        [RelayCommand]
        private void SelectAll() => SetAll(true);

        /// <summary>Unchecks all visible rows.</summary>
        [RelayCommand]
        private void SelectNone() => SetAll(false);

        private void SetAll(bool value)
        {
            // Iterate over a copy: unchecking can rebuild the visible list
            // while it is being iterated.
            foreach (ServiceEntry entry in Visible.ToList()) entry.ToScan = value;
        }

        // ------------------------------------------------------------- Filter

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
