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
        [ObservableProperty] private bool _isActive;
        [ObservableProperty] private string _ipGroupDescription = string.Empty;
        [ObservableProperty] private string _deviceDescription = string.Empty;
        [ObservableProperty] private string _firstIP = string.Empty;
        [ObservableProperty] private string _lastIP = string.Empty;
        [ObservableProperty] private string _domain = string.Empty;
        [ObservableProperty] private string _dnsServers = string.Empty;
        [ObservableProperty] private string _nmGatewayIP = string.Empty;
        [ObservableProperty] private string _nmGatewayPort = string.Empty;
        [ObservableProperty] private bool _automaticScan;
        [ObservableProperty] private string _scanIntervalMinutes = string.Empty;
    }
}
