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
        [ObservableProperty] private string _editNmGatewayPort = string.Empty;
        [ObservableProperty] private bool _editAutomaticScan;
        [ObservableProperty] private string _editScanIntervalMinutes = string.Empty;

        [ObservableProperty] private IpGroup? _selectedGroup;

        // Index der aktuell in der Maske bearbeiteten Zeile (-1 = neuer Eintrag)
        private int _indexOfCurrentRow = -1;

        public ManageIPGroupsViewModel(DataTable sharedTable, string xmlPath, IDialogService dialog)
        {
            _sharedTable = sharedTable;
            _xmlPath = xmlPath;
            _dialog = dialog;

            foreach (var g in IpGroupTable.ReadRows(sharedTable))
                Groups.Add(g);
        }

        /// <summary>Übernimmt die ausgewählte Zeile in die Eingabemaske.</summary>
        [RelayCommand]
        private void EditRow()
        {
            if (SelectedGroup is null) return;

            EditIsActive = SelectedGroup.IsActive;
            EditIpGroupDescription = SelectedGroup.IpGroupDescription;
            EditDeviceDescription = SelectedGroup.DeviceDescription;
            EditFirstIP = SelectedGroup.FirstIP;
            EditLastIP = SelectedGroup.LastIP;
            EditDomain = SelectedGroup.Domain;
            EditDnsServers = SelectedGroup.DnsServers;
            EditNmGatewayIP = SelectedGroup.NmGatewayIP;
            EditNmGatewayPort = SelectedGroup.NmGatewayPort;
            EditAutomaticScan = SelectedGroup.AutomaticScan;
            EditScanIntervalMinutes = SelectedGroup.ScanIntervalMinutes;

            _indexOfCurrentRow = Groups.IndexOf(SelectedGroup);
        }

        /// <summary>Fügt einen neuen Eintrag hinzu oder aktualisiert den bearbeiteten.</summary>
        [RelayCommand]
        private void AddEntry()
        {
            if (_indexOfCurrentRow == -1)
            {
                Groups.Add(BuildFromEditFields());
            }
            else
            {
                ApplyEditFieldsTo(Groups[_indexOfCurrentRow]);
            }
            _indexOfCurrentRow = -1;
        }

        /// <summary>Löscht den ausgewählten Eintrag nach Rückfrage.</summary>
        [RelayCommand]
        private async Task DeleteEntryAsync()
        {
            if (SelectedGroup is null) return;

            string rowContent = string.Join(" // ",
                SelectedGroup.IsActive, SelectedGroup.IpGroupDescription, SelectedGroup.DeviceDescription,
                SelectedGroup.FirstIP, SelectedGroup.LastIP, SelectedGroup.Domain, SelectedGroup.DnsServers,
                SelectedGroup.NmGatewayIP, SelectedGroup.NmGatewayPort, SelectedGroup.AutomaticScan,
                SelectedGroup.ScanIntervalMinutes);

            if (await _dialog.ConfirmAsync($"Delete the entry: {rowContent}", "Delete row"))
            {
                Groups.Remove(SelectedGroup);
            }
        }

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
            g.NmGatewayPort = EditNmGatewayPort;
            g.AutomaticScan = EditAutomaticScan;
            g.ScanIntervalMinutes = EditScanIntervalMinutes;
        }
    }
}
