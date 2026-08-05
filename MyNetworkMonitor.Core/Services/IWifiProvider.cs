using MyNetworkMonitor.Core.Models;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Plattformabhängige WLAN-Signalabfrage hinter einer neutralen Schnittstelle.
    /// Die Windows-Implementierung nutzt die native wlanapi.dll; eine spätere
    /// Linux-Implementierung kann z.B. "nmcli"/"iw" verwenden.
    /// </summary>
    public interface IWifiProvider
    {
        bool IsScanning { get; }

        event EventHandler<WiFiSignalResult> WiFiSignalStrengthUpdated;

        Task StartScanningAsync(int intervalMs = 2000);

        void StopScanning();
    }
}
