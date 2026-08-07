using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>
    /// Die Netzansicht: was dieser Rechner an Adaptern hat und wie sie
    /// eingestellt sind.
    /// <para>
    /// Zunaechst nur die eigene Seite. Praefixe, Router und Multicast-Gruppen
    /// des Netzes kommen dazu, sobald die passiven IPv6-Verfahren stehen -
    /// bis dahin gibt es dafuer schlicht keine Daten.
    /// </para>
    /// </summary>
    public sealed partial class NetworkViewModel : ObservableObject
    {
        public ObservableCollection<AdapterInfo> Adapters { get; } = [];

        [ObservableProperty] private AdapterInfo? _selected;

        /// <summary>Auch abgeschaltete Adapter zeigen.</summary>
        [ObservableProperty] private bool _includeDown;

        partial void OnIncludeDownChanged(bool value) => Refresh();

        /// <summary>Wie viele Adapter auffaellig viele Namensserver tragen.</summary>
        [ObservableProperty] private int _dnsWarningCount;

        /// <summary>
        /// Der Hinweis unter der Liste. Steht dort nur, wenn es etwas zu sagen
        /// gibt - eine Zeile "alles in Ordnung" liest nach dem dritten Mal
        /// niemand mehr.
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

        public bool HasDnsWarning => DnsWarningCount > 0;

        public NetworkViewModel() => Refresh();

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

            // Die Auswahl ueberlebt das Neuladen, solange es den Adapter noch
            // gibt - sonst springt das Detailfeld bei jedem Klick auf leer.
            Selected = Adapters.FirstOrDefault(a => a.Name == previous?.Name) ?? Adapters.FirstOrDefault();
        }
    }
}
