// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
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
    /// View model for managing IP groups: add, edit, duplicate, reorder, delete,
    /// save and sort. Independent of any UI framework; a view binds only to
    /// properties and commands.
    /// </summary>
    public partial class ManageIPGroupsViewModel : ObservableObject
    {
        private readonly IDialogService _dialog;
        private readonly DataTable _sharedTable; // shared with the caller, written back on save
        private readonly string _xmlPath;

        /// <summary>Raised when the view should close.</summary>
        public event Action? CloseRequested;

        /// <summary>The IP groups in display order.</summary>
        public ObservableCollection<IpGroup> Groups { get; } = new();

        // Edit form
        [ObservableProperty] private bool _editIsActive;
        [ObservableProperty] private string _editIpGroupDescription = string.Empty;
        [ObservableProperty] private string _editDeviceDescription = string.Empty;
        [ObservableProperty] private string _editFirstIP = string.Empty;
        [ObservableProperty] private string _editLastIP = string.Empty;
        [ObservableProperty] private string _editDomain = string.Empty;
        [ObservableProperty] private string _editDnsServers = string.Empty;
        [ObservableProperty] private string _editNmGatewayIP = string.Empty;
        /// <summary>
        /// The identifier of the responsible satellite. Only passed through
        /// here, not edited; it is assigned in the scope view.
        /// </summary>
        [ObservableProperty] private string _editScannedBy = string.Empty;

        /// <summary>
        /// The display name for the identifier; the identifier itself is not
        /// meaningful to read.
        /// </summary>
        [ObservableProperty] private string _editScannedByDisplay = string.Empty;

        /// <summary>
        /// Translates an identifier into a name. Set by the window; if unset,
        /// the identifier itself is shown rather than hiding it.
        /// </summary>
        public Func<string, string>? SatelliteNameOf { get; set; }

        partial void OnEditScannedByChanged(string value) =>
            EditScannedByDisplay = string.IsNullOrWhiteSpace(value)
                ? string.Empty
                : SatelliteNameOf?.Invoke(value) ?? value;
        [ObservableProperty] private bool _editAutomaticScan;
        [ObservableProperty] private string _editScanIntervalMinutes = string.Empty;

        [ObservableProperty] private IpGroup? _selectedGroup;

        // Index of the row currently being edited in the form (-1 = new entry)
        private int _indexOfCurrentRow = -1;

        /// <summary>
        /// When set, selecting an entry in the list loads it into the form
        /// immediately, so no separate "Edit entry" step is needed. When not
        /// set, an entry is selected first and then loaded with
        /// <see cref="EditRowCommand"/>.
        /// </summary>
        public bool AutoLoadSelectionIntoForm { get; set; }

        /// <summary>Caption of the form: new or existing entry.</summary>
        public string EditorCaption => _indexOfCurrentRow == -1
            ? "New entry"
            : $"Editing entry #{_indexOfCurrentRow + 1}";

        /// <summary>The form holds an existing entry rather than a new one.</summary>
        public bool IsEditingExistingEntry => _indexOfCurrentRow != -1;

        /// <summary>Notice about implausible input; empty means everything is fine.</summary>
        [ObservableProperty] private string _validationMessage = string.Empty;

        /// <summary><see cref="ValidationMessage"/> is not empty.</summary>
        public bool HasValidationMessage => ValidationMessage.Length > 0;

        partial void OnValidationMessageChanged(string value) => OnPropertyChanged(nameof(HasValidationMessage));

        /// <summary>Creates the view model and loads the groups from the shared table.</summary>
        /// <param name="sharedTable">The IP group table shared with the caller; updated on save.</param>
        /// <param name="xmlPath">The XML file the groups are saved to.</param>
        /// <param name="dialog">Service for confirmation dialogs.</param>
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

        /// <summary>Reassigns the display indices according to the current order.</summary>
        private void Renumber()
        {
            for (int i = 0; i < Groups.Count; i++) Groups[i].Index = i + 1;
        }

        private void RaiseEditorState()
        {
            OnPropertyChanged(nameof(EditorCaption));
            OnPropertyChanged(nameof(IsEditingExistingEntry));
        }

        /// <summary>Loads the selected row into the edit form.</summary>
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

        /// <summary>Clears the form for a new entry.</summary>
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
        /// Applies the form: creates a new entry or updates the one being
        /// edited. A new entry stays selected so editing can continue directly.
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
        /// Checks the input far enough to catch obvious mistakes without
        /// blocking valid input (First IP may also be a host name).
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
        /// Adds a new entry or updates the edited one, then switches the form
        /// back to "new entry". For forms with a single add button;
        /// <see cref="ApplyEntryCommand"/> keeps the entry in the form instead.
        /// </summary>
        [RelayCommand]
        private void AddEntry()
        {
            ApplyEntry();
            _indexOfCurrentRow = -1;
            RaiseEditorState();
        }

        /// <summary>Inserts a copy of the selected entry directly below it.</summary>
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

        /// <summary>Moves the selected entry up by one position.</summary>
        [RelayCommand(CanExecute = nameof(CanMoveUp))]
        private void MoveUp() => Move(-1);

        /// <summary>Moves the selected entry down by one position.</summary>
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

            // The selection follows the entry so it can be moved repeatedly
            SelectedGroup = Groups[to];
            _indexOfCurrentRow = to;
            RaiseEditorState();
        }

        /// <summary>Deletes the selected entry after confirmation.</summary>
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

        /// <summary>Closes without saving.</summary>
        [RelayCommand]
        private void Cancel() => CloseRequested?.Invoke();

        /// <summary>Writes the changes to the shared DataTable and the XML file, then closes.</summary>
        [RelayCommand]
        private void SaveChanges()
        {
            // Write back to the shared DataTable so views bound to it update ...
            IpGroupTable.WriteRows(_sharedTable, Groups);
            // ... and persist in the IP group XML format.
            IpGroupTable.SaveXml(Groups, _xmlPath);

            CloseRequested?.Invoke();
        }

        /// <summary>
        /// Numeric sorting for the IP columns (FirstIP/LastIP); the direction
        /// toggles per column.
        /// </summary>
        /// <param name="columnName">The property name of the column to sort by.</param>
        /// <returns>
        /// <see langword="true"/> if the column was sorted here (the view then
        /// suppresses its default sorting); <see langword="false"/> for other columns.
        /// </returns>
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
            // Sort invalid or empty IPs to the end instead of failing.
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
