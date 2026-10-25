// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using CommunityToolkit.Mvvm.ComponentModel;

namespace MyNetworkMonitor.Core.Models
{
    /// <summary>
    /// Platform-neutral model of an IP group. Bindable directly through
    /// INotifyPropertyChanged (via CommunityToolkit.Mvvm). The column names of
    /// the stored XML format are mapped to these properties in
    /// <see cref="Persistence.IpGroupTable"/>.
    /// </summary>
    public partial class IpGroup : ObservableObject
    {
        /// <summary>
        /// Sequence number in the list (1-based). Used for display and ordering
        /// only: it is not stored but reassigned from the position after every
        /// change. It lets the management view address and move a specific entry.
        /// </summary>
        [ObservableProperty] private int _index;

        [ObservableProperty] private bool _isActive;
        [ObservableProperty] private string _ipGroupDescription = string.Empty;
        [ObservableProperty] private string _deviceDescription = string.Empty;
        [ObservableProperty] private string _firstIP = string.Empty;
        [ObservableProperty] private string _lastIP = string.Empty;
        [ObservableProperty] private string _domain = string.Empty;
        [ObservableProperty] private string _dnsServers = string.Empty;
        /// <summary>The router of this network. See <see cref="Model.ScanScope.GatewayIP"/>.</summary>
        [ObservableProperty] private string _nmGatewayIP = string.Empty;

        /// <summary>
        /// Name of the satellite that scans this range; empty means this
        /// machine scans it. See SATELLIT.md.
        /// </summary>
        [ObservableProperty] private string _scannedBy = string.Empty;

        [ObservableProperty] private bool _automaticScan;
        [ObservableProperty] private string _scanIntervalMinutes = string.Empty;

        /// <summary>
        /// Time of the last run as ISO 8601 text; empty if the range has never
        /// been scanned. Stored because the automatic scan catches up on missed
        /// runs.
        /// </summary>
        [ObservableProperty] private string _lastScanned = string.Empty;
    }
}
