// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MyNetworkMonitor.Core.Scanning.Engine;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>A port in the collection: the number, the protocols it is scanned with, and what it stands for.</summary>
    public partial class PortEntry : ObservableObject
    {
        /// <summary>The port number.</summary>
        [ObservableProperty] private int _port;
        /// <summary>Scanned over TCP.</summary>
        [ObservableProperty] private bool _tcp;
        /// <summary>Scanned over UDP.</summary>
        [ObservableProperty] private bool _udp;
        /// <summary>What the port is used for.</summary>
        [ObservableProperty] private string _description = string.Empty;

        /// <summary>Neither TCP nor UDP; the entry exists but is not scanned.</summary>
        public bool IsIdle => !Tcp && !Udp;

        partial void OnTcpChanged(bool value) => OnPropertyChanged(nameof(IsIdle));
        partial void OnUdpChanged(bool value) => OnPropertyChanged(nameof(IsIdle));

        public override string ToString() => $"{Port} {Description}";
    }

    /// <summary>
    /// The port collection: which ports a scan probes, separately per protocol.
    /// <para>
    /// Reads and writes <c>portsToScan.xml</c>. If the file is missing, the
    /// built-in list from <see cref="PortCollection"/> applies, so there is
    /// always a set of ports.
    /// </para>
    /// </summary>
    public partial class PortEditorViewModel : ObservableObject
    {
        private readonly ScanSettings _settings;
        private string _xmlPath = string.Empty;
        private bool _loading;

        /// <summary>Creates the editor.</summary>
        /// <param name="settings">The scan settings that receive the selected TCP and UDP ports.</param>
        /// <exception cref="ArgumentNullException"><paramref name="settings"/> is <see langword="null"/>.</exception>
        public PortEditorViewModel(ScanSettings settings)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        }

        /// <summary>All ports, regardless of the search field.</summary>
        public ObservableCollection<PortEntry> All { get; } = [];

        /// <summary>The ports that pass the search field; the table binds to this.</summary>
        public ObservableCollection<PortEntry> Visible { get; } = [];

        /// <summary>The selected port.</summary>
        [ObservableProperty] private PortEntry? _selected;
        /// <summary>The status line text.</summary>
        [ObservableProperty] private string _status = string.Empty;

        /// <summary>Searches port number and description at the same time.</summary>
        [ObservableProperty] private string _filter = string.Empty;

        partial void OnFilterChanged(string value) => ApplyFilter();

        /// <summary>Number of ports scanned over TCP.</summary>
        public int TcpCount => All.Count(p => p.Tcp);
        /// <summary>Number of ports scanned over UDP.</summary>
        public int UdpCount => All.Count(p => p.Udp);
        /// <summary>Number of ports in the collection.</summary>
        public int TotalCount => All.Count;

        // ------------------------------------------------------------ Loading

        /// <summary>
        /// Loads the collection and passes the selection to the scan settings.
        /// A missing or unreadable file falls back to the built-in defaults.
        /// </summary>
        /// <param name="xmlPath">The port collection file; also the target for later saves.</param>
        public void Load(string xmlPath)
        {
            _xmlPath = xmlPath;
            _loading = true;

            try
            {
                PortCollection ports = new();

                if (File.Exists(xmlPath))
                {
                    try
                    {
                        ports.TableOfPortsToScan.Rows.Clear();
                        ports.TableOfPortsToScan.ReadXml(xmlPath);
                    }
                    catch (Exception ex)
                    {
                        // Damaged file: continue with the default ports instead
                        // of having none.
                        ports = new PortCollection();
                        Status = $"Port collection could not be read, defaults apply: {ex.Message}";
                    }
                }

                foreach (PortEntry entry in All) entry.PropertyChanged -= OnEntryChanged;
                All.Clear();

                foreach (DataRow row in ports.TableOfPortsToScan.Rows)
                {
                    if (row.RowState == DataRowState.Deleted) continue;

                    PortEntry entry = new()
                    {
                        Port = row["Ports"] is int number ? number : 0,
                        Tcp = row["TCPScan"] is true,
                        Udp = row["UDPScan"] is true,
                        Description = row["Description"]?.ToString() ?? string.Empty
                    };

                    entry.PropertyChanged += OnEntryChanged;
                    All.Add(entry);
                }

                if (Status.Length == 0) Status = $"{All.Count} ports loaded.";
            }
            finally
            {
                _loading = false;
            }

            ApplyFilter();
            PushToSettings();
        }

        // ------------------------------------------------------------- Saving

        private static readonly TimeSpan SaveDelay = TimeSpan.FromMilliseconds(600);

        private Timer? _saveTimer;
        private DataTable? _pending;
        private bool _dirty;

        private void OnEntryChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(PortEntry.IsIdle)) return;

            PushToSettings();
            Save();
        }

        /// <summary>
        /// Writes the selection into the scan settings. Without this step a
        /// check mark would only take effect after a restart; the scan reads
        /// the lists, not the file.
        /// </summary>
        private void PushToSettings()
        {
            _settings.TcpPorts.Clear();
            _settings.TcpPorts.AddRange(All.Where(p => p.Tcp).Select(p => p.Port));

            _settings.UdpPorts.Clear();
            _settings.UdpPorts.AddRange(All.Where(p => p.Udp).Select(p => p.Port));

            OnPropertyChanged(nameof(TcpCount));
            OnPropertyChanged(nameof(UdpCount));
            OnPropertyChanged(nameof(TotalCount));

            // The port methods check whether any ports are selected. Without
            // this notification the verdict from before loading would remain,
            // and since no ports existed then, "TCP ports" could not be
            // checked.
            PortsChanged?.Invoke();
        }

        /// <summary>Raised when the port selection has changed.</summary>
        public event Action? PortsChanged;

        /// <summary>
        /// Captures the current state and writes it shortly afterwards. Check
        /// boxes are often toggled in series; writing the file on every click
        /// would be wasteful.
        /// </summary>
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
        /// Builds the table in the <c>portsToScan.xml</c> format. Runs on the
        /// UI thread because the collection belongs to it.
        /// </summary>
        private DataTable BuildTable()
        {
            PortCollection template = new();
            DataTable table = template.TableOfPortsToScan.Clone();

            foreach (PortEntry entry in All.OrderBy(p => p.Port))
            {
                table.Rows.Add(entry.Port, entry.Tcp, entry.Udp, entry.Description ?? string.Empty);
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
                Status = $"Port collection could not be saved: {ex.Message}";
            }
        }

        // ----------------------------------------------------------- Commands

        [RelayCommand]
        private void Add()
        {
            // Suggest an unused number instead of creating a duplicate.
            int candidate = All.Count == 0 ? 80 : All.Max(p => p.Port) + 1;
            while (All.Any(p => p.Port == candidate) && candidate < 65535) candidate++;

            PortEntry entry = new() { Port = candidate, Tcp = true, Description = string.Empty };
            entry.PropertyChanged += OnEntryChanged;

            All.Add(entry);
            ApplyFilter();

            Selected = entry;
            PushToSettings();
            Save();

            Status = $"Port {candidate} added.";
        }

        [RelayCommand]
        private void Delete()
        {
            if (Selected is null) return;

            int port = Selected.Port;
            Selected.PropertyChanged -= OnEntryChanged;

            All.Remove(Selected);
            Selected = null;

            ApplyFilter();
            PushToSettings();
            Save();

            Status = $"Port {port} deleted.";
        }

        /// <summary>Switches TCP on for all visible entries at once.</summary>
        [RelayCommand]
        private void AllTcp() => SetAll(tcp: true, value: true);

        /// <summary>Switches TCP off for all visible entries.</summary>
        [RelayCommand]
        private void NoTcp() => SetAll(tcp: true, value: false);

        /// <summary>Switches UDP on for all visible entries.</summary>
        [RelayCommand]
        private void AllUdp() => SetAll(tcp: false, value: true);

        /// <summary>Switches UDP off for all visible entries.</summary>
        [RelayCommand]
        private void NoUdp() => SetAll(tcp: false, value: false);

        /// <summary>
        /// Affects only the visible rows. Searching for "SQL" and then pressing
        /// "all TCP" means the SQL ports, not all 300.
        /// </summary>
        private void SetAll(bool tcp, bool value)
        {
            foreach (PortEntry entry in Visible)
            {
                if (tcp) entry.Tcp = value;
                else entry.Udp = value;
            }
        }

        // ------------------------------------------------------------- Filter

        private void ApplyFilter()
        {
            Visible.Clear();

            string needle = Filter?.Trim() ?? string.Empty;

            foreach (PortEntry entry in All.OrderBy(p => p.Port))
            {
                if (needle.Length == 0 ||
                    entry.Port.ToString().Contains(needle, StringComparison.OrdinalIgnoreCase) ||
                    entry.Description.Contains(needle, StringComparison.OrdinalIgnoreCase))
                {
                    Visible.Add(entry);
                }
            }
        }
    }
}
