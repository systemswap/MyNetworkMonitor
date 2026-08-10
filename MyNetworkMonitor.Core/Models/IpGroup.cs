using CommunityToolkit.Mvvm.ComponentModel;

namespace MyNetworkMonitor.Core.Models
{
    /// <summary>
    /// Plattformneutrales Model einer IP-Gruppe. Ersetzt in der UI-Schicht die
    /// bisherige DataTable-Zeile und ist über INotifyPropertyChanged (via
    /// CommunityToolkit.Mvvm) direkt datenbindbar – in WPF wie in Avalonia.
    /// Die Spaltennamen des bisherigen XML-Formats werden in
    /// <see cref="Persistence.IpGroupTable"/> auf diese Properties gemappt.
    /// </summary>
    public partial class IpGroup : ObservableObject
    {
        /// <summary>
        /// Laufende Nummer in der Liste (1-basiert). Reine Anzeige- und
        /// Ordnungshilfe: sie wird nicht gespeichert, sondern nach jeder
        /// Aenderung aus der Position neu vergeben. Ueber sie laesst sich ein
        /// Eintrag in der Verwaltung gezielt ansprechen und verschieben.
        /// </summary>
        [ObservableProperty] private int _index;

        [ObservableProperty] private bool _isActive;
        [ObservableProperty] private string _ipGroupDescription = string.Empty;
        [ObservableProperty] private string _deviceDescription = string.Empty;
        [ObservableProperty] private string _firstIP = string.Empty;
        [ObservableProperty] private string _lastIP = string.Empty;
        [ObservableProperty] private string _domain = string.Empty;
        [ObservableProperty] private string _dnsServers = string.Empty;
        /// <summary>Der Router dieses Netzes. Siehe <see cref="Model.ScanScope.GatewayIP"/>.</summary>
        [ObservableProperty] private string _nmGatewayIP = string.Empty;

        /// <summary>
        /// Name des Satelliten, der diesen Bereich scannt - leer heisst: von
        /// diesem Rechner aus. Siehe SATELLIT.md.
        /// </summary>
        [ObservableProperty] private string _scannedBy = string.Empty;

        [ObservableProperty] private bool _automaticScan;
        [ObservableProperty] private string _scanIntervalMinutes = string.Empty;

        /// <summary>
        /// Zeitpunkt des letzten Durchlaufs, als ISO-8601-Text - leer, wenn der
        /// Bereich noch nie gelaufen ist. Gespeichert, weil der automatische
        /// Scan verpasste Termine nachholt.
        /// </summary>
        [ObservableProperty] private string _lastScanned = string.Empty;
    }
}
