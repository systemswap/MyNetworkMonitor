using MyNetworkMonitor.Core.Models;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Platform-specific Wi-Fi signal query behind a neutral interface.
    /// The Windows implementation uses the native wlanapi.dll; the Linux
    /// implementation uses "nmcli".
    /// </summary>
    public interface IWifiProvider
    {
        /// <summary>Whether periodic scanning is active.</summary>
        bool IsScanning { get; }

        /// <summary>Raised with every new signal measurement.</summary>
        event EventHandler<WiFiSignalResult> WiFiSignalStrengthUpdated;

        /// <summary>Starts periodic scanning.</summary>
        /// <param name="intervalMs">Interval between two measurements in milliseconds.</param>
        Task StartScanningAsync(int intervalMs = 2000);

        /// <summary>Stops periodic scanning.</summary>
        void StopScanning();
    }
}
