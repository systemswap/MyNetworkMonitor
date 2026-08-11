using System.Collections.ObjectModel;
using System.Data;
using System.Net;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MyNetworkMonitor.Core.Models;
using MyNetworkMonitor.Core.Persistence;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>
    /// ViewModel für die IP-Gruppen-Verwaltung. Enthält die komplette bisher im
    /// Code-behind liegende Logik (Hinzufügen/Bearbeiten/Löschen/Speichern/Sortieren),
    /// aber ohne jede WPF-Abhängigkeit. Die View bindet nur noch an Properties und
    /// Commands – dadurch ist sie gegen eine Avalonia-View austauschbar.
    /// </summary>
    public partial class ManageIPGroupsViewModel : ObservableObject
    {
        private readonly IDialogService _dialog;
        private readonly DataTable _sharedTable; // dieselbe Instanz wie im MainWindow
        private readonly string _xmlPath;

        /// <summary>Wird ausgelöst, wenn die View geschlossen werden soll.</summary>
        public event Action? CloseRequested;

        public ObservableCollection<IpGroup> Groups { get; } = new();

        // Eingabemaske
        [ObservableProperty] private bool _editIsActive;
        [ObservableProperty] private string _editIpGroupDescription = string.Empty;
        [ObservableProperty] private string _editDeviceDescription = string.Empty;
        [ObservableProperty] private string _editFirstIP = string.Empty;
        [ObservableProperty] private string _editLastIP = string.Empty;
        [ObservableProperty] private string _editDomain = string.Empty;
        [ObservableProperty] private string _editDnsServers = string.Empty;
        [ObservableProperty] private string _editNmGatewayIP = string.Empty;
        /// <summary>
        /// Die Kennung des zustaendigen Satelliten. Wird hier nur
        /// durchgereicht, nicht bearbeitet - zugewiesen wird in der
        /// Bereichsansicht.
        /// </summary>
        [ObservableProperty] private string _editScannedBy = string.Empty;

        /// <summary>
        /// Der Name zur Kennung, fuer die Anzeige. Die Kennung selbst sagt
        /// niemandem etwas.
        /// </summary>
        [ObservableProperty] private string _editScannedByDisplay = string.Empty;

        /// <summary>
        /// Uebersetzt eine Kennung in einen Namen. Setzt das Fenster; ohne
        /// Zuweisung steht die Kennung selbst da, was ehrlicher ist als sie zu
        /// verschweigen.
        /// </summary>
        public Func<string, string>? SatelliteNameOf { get; set; }

        partial void OnEditScannedByChanged(string value) =>
            EditScannedByDisplay = string.IsNullOrWhiteSpace(value)
                ? string.Empty
                : SatelliteNameOf?.Invoke(value) ?? value;
        [ObservableProperty] private bool _editAutomaticScan;
        [ObservableProperty] private string _editScanIntervalMinutes = string.Empty;

        [ObservableProperty] private IpGroup? _selectedGroup;

        // Index der aktuell in der Maske bearbeiteten Zeile (-1 = neuer Eintrag)
        private int _indexOfCurrentRow = -1;

        /// <summary>
        /// Wenn gesetzt, übernimmt die Auswahl in der Liste den Eintrag sofort in
        /// die Maske – der separate Schritt „Edit entry“ entfällt. Die
        /// Avalonia-View schaltet das ein; die ältere WPF-View behält ihren
        /// bisherigen Ablauf (erst auswählen, dann „Edit entry“).
        /// </summary>
        public bool AutoLoadSelectionIntoForm { get; set; }

        /// <summary>Beschriftet die Maske: neuer oder bestehender Eintrag.</summary>
        public string EditorCaption => _indexOfCurrentRow == -1
            ? "New entry"
            : $"Editing entry #{_indexOfCurrentRow + 1}";

        public bool IsEditingExistingEntry => _indexOfCurrentRow != -1;

        /// <summary>Hinweis auf unplausible Eingaben; leer = alles in Ordnung.</summary>
        [ObservableProperty] private string _validationMessage = string.Empty;

        public bool HasValidationMessage => ValidationMessage.Length > 0;

        partial void OnValidationMessageChanged(string value) => OnPropertyChanged(nameof(HasValidationMessage));

        public ManageIPGroupsViewModel(DataTable sharedTable, string xmlPath, IDialogService dialog)
        {
            _sharedTable = sharedTable;
            _xmlPath = xmlPath;
            _dialog = dialog;

            foreach (var g in IpGroupTable.ReadRows(sharedTable))
                Groups.Add(g);

            Renumber();
        }

        partial void OnSelectedGroupChanged(IpGroup? value)
        {
            MoveUpCommand.NotifyCanExecuteChanged();
            MoveDownCommand.NotifyCanExecuteChanged();
            DeleteEntryCommand.NotifyCanExecuteChanged();
            DuplicateEntryCommand.NotifyCanExecuteChanged();

            if (!AutoLoadSelectionIntoForm) return;

            if (value == null) BeginNewEntry();
            else LoadIntoForm(value);
        }

        /// <summary>Vergibt die Anzeige-Indizes nach der aktuellen Reihenfolge neu.</summary>
        private void Renumber()
        {
            for (int i = 0; i < Groups.Count; i++) Groups[i].Index = i + 1;
        }

        private void RaiseEditorState()
        {
            OnPropertyChanged(nameof(EditorCaption));
            OnPropertyChanged(nameof(IsEditingExistingEntry));
        }

        /// <summary>Übernimmt die ausgewählte Zeile in die Eingabemaske.</summary>
        [RelayCommand]
        private void EditRow()
        {
            if (SelectedGroup is null) return;
            LoadIntoForm(SelectedGroup);
        }

        private void LoadIntoForm(IpGroup group)
        {
            EditIsActive = group.IsActive;
            EditIpGroupDescription = group.IpGroupDescription;
            EditDeviceDescription = group.DeviceDescription;
            EditFirstIP = group.FirstIP;
            EditLastIP = group.LastIP;
            EditDomain = group.Domain;
            EditDnsServers = group.DnsServers;
            EditNmGatewayIP = group.NmGatewayIP;
            EditScannedBy = group.ScannedBy;
            EditAutomaticScan = group.AutomaticScan;
            EditScanIntervalMinutes = group.ScanIntervalMinutes;

            _indexOfCurrentRow = Groups.IndexOf(group);
            ValidationMessage = string.Empty;
            RaiseEditorState();
        }

        /// <summary>Leert die Maske für einen neuen Eintrag.</summary>
        [RelayCommand]
        private void BeginNewEntry()
        {
            EditIsActive = true;
            EditIpGroupDescription = string.Empty;
            EditDeviceDescription = string.Empty;
            EditFirstIP = string.Empty;
            EditLastIP = string.Empty;
            EditDomain = string.Empty;
            EditDnsServers = string.Empty;
            EditNmGatewayIP = string.Empty;
            EditScannedBy = string.Empty;
            EditAutomaticScan = false;
            EditScanIntervalMinutes = string.Empty;

            _indexOfCurrentRow = -1;
            ValidationMessage = string.Empty;
            RaiseEditorState();
        }

        /// <summary>
        /// Übernimmt die Maske: legt einen neuen Eintrag an oder aktualisiert den
        /// gerade bearbeiteten. Der neue Eintrag bleibt ausgewählt, damit sich
        /// direkt weiterarbeiten lässt.
        /// </summary>
        [RelayCommand]
        private void ApplyEntry()
        {
            if (!Validate()) return;

            if (_indexOfCurrentRow == -1)
            {
                var group = BuildFromEditFields();
                Groups.Add(group);
                Renumber();
                _indexOfCurrentRow = Groups.Count - 1;
                SelectedGroup = group;
            }
            else
            {
                ApplyEditFieldsTo(Groups[_indexOfCurrentRow]);
            }

            RaiseEditorState();
        }

        /// <summary>
        /// Prüft die Eingaben so weit, dass offensichtliche Fehler auffallen,
        /// ohne die Eingabe zu blockieren (First IP darf auch ein Hostname sein).
        /// </summary>
        private bool Validate()
        {
            if (string.IsNullOrWhiteSpace(EditIpGroupDescription) && string.IsNullOrWhiteSpace(EditDeviceDescription))
            {
                ValidationMessage = "Please enter at least a group or device description.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(EditFirstIP))
            {
                ValidationMessage = "First IP / hostname is required.";
                return false;
            }

            if (!string.IsNullOrWhiteSpace(EditLastIP)
                && IPAddress.TryParse(EditFirstIP.Trim(), out IPAddress? first)
                && IPAddress.TryParse(EditLastIP.Trim(), out IPAddress? last)
                && IpToSortKey(first.ToString()) > IpToSortKey(last.ToString()))
            {
                ValidationMessage = "Last IP is lower than first IP.";
                return false;
            }

            if (!string.IsNullOrWhiteSpace(EditScanIntervalMinutes)
                && !int.TryParse(EditScanIntervalMinutes.Trim(), out _))
            {
                ValidationMessage = "Scan interval must be a number of minutes.";
                return false;
            }

            ValidationMessage = string.Empty;
            return true;
        }

        /// <summary>
        /// Fügt einen neuen Eintrag hinzu oder aktualisiert den bearbeiteten.
        /// Bleibt für die ältere WPF-View erhalten, deren Maske genau diesen
        /// einen Knopf kennt; die Avalonia-View nutzt <see cref="ApplyEntryCommand"/>.
        /// </summary>
        [RelayCommand]
        private void AddEntry()
        {
            ApplyEntry();
            _indexOfCurrentRow = -1;
            RaiseEditorState();
        }

        /// <summary>Legt eine Kopie des ausgewählten Eintrags direkt darunter an.</summary>
        [RelayCommand(CanExecute = nameof(HasSelection))]
        private void DuplicateEntry()
        {
            if (SelectedGroup is null) return;

            var copy = new IpGroup
            {
                IsActive = SelectedGroup.IsActive,
                IpGroupDescription = SelectedGroup.IpGroupDescription,
                DeviceDescription = SelectedGroup.DeviceDescription,
                FirstIP = SelectedGroup.FirstIP,
                LastIP = SelectedGroup.LastIP,
                Domain = SelectedGroup.Domain,
                DnsServers = SelectedGroup.DnsServers,
                NmGatewayIP = SelectedGroup.NmGatewayIP,
                ScannedBy = SelectedGroup.ScannedBy,
                AutomaticScan = SelectedGroup.AutomaticScan,
                ScanIntervalMinutes = SelectedGroup.ScanIntervalMinutes
            };

            Groups.Insert(Groups.IndexOf(SelectedGroup) + 1, copy);
            Renumber();
            SelectedGroup = copy;
        }

        private bool HasSelection() => SelectedGroup is not null;

        /// <summary>Verschiebt den ausgewählten Eintrag eine Position nach oben.</summary>
        [RelayCommand(CanExecute = nameof(CanMoveUp))]
        private void MoveUp() => Move(-1);

        /// <summary>Verschiebt den ausgewählten Eintrag eine Position nach unten.</summary>
        [RelayCommand(CanExecute = nameof(CanMoveDown))]
        private void MoveDown() => Move(1);

        private bool CanMoveUp() => SelectedGroup is not null && Groups.IndexOf(SelectedGroup) > 0;

        private bool CanMoveDown() => SelectedGroup is not null && Groups.IndexOf(SelectedGroup) < Groups.Count - 1;

        private void Move(int offset)
        {
            if (SelectedGroup is null) return;

            int from = Groups.IndexOf(SelectedGroup);
            int to = from + offset;
            if (to < 0 || to >= Groups.Count) return;

            Groups.Move(from, to);
            Renumber();

            // Auswahl folgt dem Eintrag, damit sich mehrfach verschieben lässt
            SelectedGroup = Groups[to];
            _indexOfCurrentRow = to;
            RaiseEditorState();
        }

        /// <summary>Löscht den ausgewählten Eintrag nach Rückfrage.</summary>
        [RelayCommand(CanExecute = nameof(HasSelection))]
        private async Task DeleteEntryAsync()
        {
            if (SelectedGroup is null) return;

            string label = string.IsNullOrWhiteSpace(SelectedGroup.DeviceDescription)
                ? SelectedGroup.IpGroupDescription
                : $"{SelectedGroup.IpGroupDescription} / {SelectedGroup.DeviceDescription}";

            string range = string.IsNullOrWhiteSpace(SelectedGroup.LastIP)
                ? SelectedGroup.FirstIP
                : $"{SelectedGroup.FirstIP} - {SelectedGroup.LastIP}";

            if (!await _dialog.ConfirmAsync($"Delete entry #{SelectedGroup.Index}?\n\n{label}\n{range}", "Delete entry"))
                return;

            Groups.Remove(SelectedGroup);
            Renumber();

            SelectedGroup = null;
            BeginNewEntry();
        }

        /// <summary>Schließt ohne zu speichern.</summary>
        [RelayCommand]
        private void Cancel() => CloseRequested?.Invoke();

        /// <summary>Schreibt die Änderungen in die geteilte DataTable + XML und schließt.</summary>
        [RelayCommand]
        private void SaveChanges()
        {
            // In die vom MainWindow geteilte DataTable zurückschreiben, damit dessen
            // gebundenes Grid aktualisiert wird ...
            IpGroupTable.WriteRows(_sharedTable, Groups);
            // ... und im bisherigen XML-Format persistieren.
            IpGroupTable.SaveXml(Groups, _xmlPath);

            CloseRequested?.Invoke();
        }

        /// <summary>
        /// Numerische Sortierung für die IP-Spalten (FirstIP/LastIP), Richtung
        /// wird pro Spalte umgeschaltet. Gibt true zurück, wenn die Spalte selbst
        /// sortiert wurde (die View unterdrückt dann ihre Standardsortierung).
        /// </summary>
        public bool SortBy(string columnName)
        {
            if (columnName != nameof(IpGroup.FirstIP) && columnName != nameof(IpGroup.LastIP))
                return false;

            bool ascending;
            if (_lastSortedColumn == columnName)
                ascending = !_lastAscending;
            else
                ascending = true;

            var sorted = ascending
                ? Groups.OrderBy(g => IpToSortKey(Select(g, columnName))).ToList()
                : Groups.OrderByDescending(g => IpToSortKey(Select(g, columnName))).ToList();

            Groups.Clear();
            foreach (var g in sorted) Groups.Add(g);
            Renumber();

            _lastSortedColumn = columnName;
            _lastAscending = ascending;
            return true;
        }

        private string? _lastSortedColumn;
        private bool _lastAscending;

        private static string Select(IpGroup g, string columnName)
            => columnName == nameof(IpGroup.FirstIP) ? g.FirstIP : g.LastIP;

        private static long IpToSortKey(string ip)
        {
            // Ungültige/leere IPs ans Ende sortieren, statt zu crashen.
            if (IPAddress.TryParse(ip?.Trim(), out var addr))
                return BitConverter.ToUInt32(addr.GetAddressBytes().Reverse().ToArray(), 0);
            return long.MaxValue;
        }

        private IpGroup BuildFromEditFields()
        {
            var g = new IpGroup();
            ApplyEditFieldsTo(g);
            return g;
        }

        private void ApplyEditFieldsTo(IpGroup g)
        {
            g.IsActive = EditIsActive;
            g.IpGroupDescription = EditIpGroupDescription;
            g.DeviceDescription = EditDeviceDescription;
            g.FirstIP = EditFirstIP;
            g.LastIP = EditLastIP;
            g.Domain = EditDomain;
            g.DnsServers = EditDnsServers;
            g.NmGatewayIP = EditNmGatewayIP;
            g.ScannedBy = EditScannedBy;
            g.AutomaticScan = EditAutomaticScan;
            g.ScanIntervalMinutes = EditScanIntervalMinutes;
        }
    }
}
