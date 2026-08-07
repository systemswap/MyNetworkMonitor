using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MyNetworkMonitor.Core.Scanning.Engine;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>Ein Port der Sammlung: die Nummer, wofuer sie gescannt wird, und wofuer sie steht.</summary>
    public partial class PortEntry : ObservableObject
    {
        [ObservableProperty] private int _port;
        [ObservableProperty] private bool _tcp;
        [ObservableProperty] private bool _udp;
        [ObservableProperty] private string _description = string.Empty;

        /// <summary>Weder TCP noch UDP - der Eintrag ist da, wird aber nicht gescannt.</summary>
        public bool IsIdle => !Tcp && !Udp;

        partial void OnTcpChanged(bool value) => OnPropertyChanged(nameof(IsIdle));
        partial void OnUdpChanged(bool value) => OnPropertyChanged(nameof(IsIdle));

        public override string ToString() => $"{Port} {Description}";
    }

    /// <summary>
    /// Die Portsammlung: welche Ports ein Scan anfasst, je Protokoll getrennt.
    /// <para>
    /// Liest und schreibt das bisherige <c>portsToScan.xml</c>, damit beide
    /// Oberflaechen waehrend des Umbaus dieselbe Sammlung sehen. Fehlt die
    /// Datei, gilt die eingebaute Liste aus <see cref="PortCollection"/> - man
    /// steht also nie ohne Ports da.
    /// </para>
    /// </summary>
    public partial class PortEditorViewModel : ObservableObject
    {
        private readonly ScanSettings _settings;
        private string _xmlPath = string.Empty;
        private bool _loading;

        public PortEditorViewModel(ScanSettings settings)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        }

        /// <summary>Alle Ports, unabhaengig vom Suchfeld.</summary>
        public ObservableCollection<PortEntry> All { get; } = [];

        /// <summary>Was das Suchfeld durchlaesst - daran haengt die Tabelle.</summary>
        public ObservableCollection<PortEntry> Visible { get; } = [];

        [ObservableProperty] private PortEntry? _selected;
        [ObservableProperty] private string _status = string.Empty;

        /// <summary>Sucht ueber Portnummer und Beschreibung zugleich.</summary>
        [ObservableProperty] private string _filter = string.Empty;

        partial void OnFilterChanged(string value) => ApplyFilter();

        public int TcpCount => All.Count(p => p.Tcp);
        public int UdpCount => All.Count(p => p.Udp);
        public int TotalCount => All.Count;

        // ------------------------------------------------------------- Laden

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
                        // Beschaedigte Datei: mit den Standardports weiter,
                        // statt ohne Ports dazustehen.
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

        // --------------------------------------------------------- Speichern

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
        /// Traegt die Auswahl in die Scan-Einstellungen. Ohne diesen Schritt
        /// wuerde ein Haken erst nach einem Neustart wirken - der Scan liest
        /// die Listen, nicht die Datei.
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
        }

        /// <summary>
        /// Merkt den Stand vor und schreibt ihn kurz darauf. Die Kaestchen
        /// werden oft in Serie gesetzt; je Klick eine Datei zu schreiben waere
        /// verschwendet.
        /// </summary>
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
        /// Baut die Tabelle im bisherigen Format. Laeuft auf dem
        /// Oberflaechen-Thread, weil die Sammlung ihr gehoert.
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

        // ----------------------------------------------------------- Befehle

        [RelayCommand]
        private void Add()
        {
            // Eine freie Nummer vorschlagen, statt eine doppelte anzulegen.
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

        /// <summary>Alle sichtbaren Eintraege auf einmal umschalten - spart Klickarbeit.</summary>
        [RelayCommand]
        private void AllTcp() => SetAll(tcp: true, value: true);

        [RelayCommand]
        private void NoTcp() => SetAll(tcp: true, value: false);

        [RelayCommand]
        private void AllUdp() => SetAll(tcp: false, value: true);

        [RelayCommand]
        private void NoUdp() => SetAll(tcp: false, value: false);

        /// <summary>
        /// Wirkt nur auf die sichtbaren Zeilen. Wer nach "SQL" sucht und dann
        /// "all TCP" drueckt, meint die SQL-Ports - nicht alle 300.
        /// </summary>
        private void SetAll(bool tcp, bool value)
        {
            foreach (PortEntry entry in Visible)
            {
                if (tcp) entry.Tcp = value;
                else entry.Udp = value;
            }
        }

        // ------------------------------------------------------------ Filter

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
