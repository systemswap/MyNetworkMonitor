// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>
    /// The network view: the adapters of this computer and their configuration.
    /// <para>
    /// Covers the local side only; prefixes, routers and multicast groups of
    /// the network are not part of this view.
    /// </para>
    /// </summary>
    public sealed partial class NetworkViewModel : ObservableObject
    {
        /// <summary>The adapters shown in the list.</summary>
        public ObservableCollection<AdapterInfo> Adapters { get; } = [];

        /// <summary>The adapter shown in the detail pane.</summary>
        [ObservableProperty] private AdapterInfo? _selected;

        /// <summary>Also shows adapters that are down.</summary>
        [ObservableProperty] private bool _includeDown;

        partial void OnIncludeDownChanged(bool value) => Refresh();

        /// <summary>Number of adapters with an implausibly high number of DNS servers.</summary>
        [ObservableProperty] private int _dnsWarningCount;

        /// <summary>
        /// The notice below the list. Empty unless there is something to
        /// report; a permanent "all good" line quickly stops being read.
        /// </summary>
        public string DnsWarningText
        {
            get
            {
                if (DnsWarningCount == 0) return string.Empty;

                string adapters = DnsWarningCount == 1 ? "adapter has" : "adapters have";

                return $"{DnsWarningCount} {adapters} more than {AdapterInfo.MaxPlausibleDnsServers} DNS servers. " +
                       "Usually a leftover from repeated DHCP leases - every server that does not answer costs " +
                       "waiting time on each lookup.";
            }
        }

        /// <summary>At least one adapter has too many DNS servers.</summary>
        public bool HasDnsWarning => DnsWarningCount > 0;

        /// <summary>Creates the view model and reads the adapters.</summary>
        public NetworkViewModel() => Refresh();

        /// <summary>Re-reads the adapters, keeping the current selection if the adapter still exists.</summary>
        [RelayCommand]
        public void Refresh()
        {
            AdapterInfo? previous = Selected;

            Adapters.Clear();

            foreach (AdapterInfo adapter in NetworkAdapters.Read(IncludeDown)
                         .OrderByDescending(a => a.HasTooManyDnsServers)
                         .ThenByDescending(a => a.IsUp)
                         .ThenBy(a => a.Name, StringComparer.CurrentCulture))
            {
                Adapters.Add(adapter);
            }

            DnsWarningCount = Adapters.Count(a => a.HasTooManyDnsServers);
            OnPropertyChanged(nameof(DnsWarningText));
            OnPropertyChanged(nameof(HasDnsWarning));

            // Keep the selection across reloads as long as the adapter still
            // exists; otherwise the detail pane would blank on every refresh.
            Selected = Adapters.FirstOrDefault(a => a.Name == previous?.Name) ?? Adapters.FirstOrDefault();
        }
    }
}
