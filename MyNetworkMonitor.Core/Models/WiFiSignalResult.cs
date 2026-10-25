// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.Models
{
    /// <summary>Signal information of a Wi-Fi network (platform-neutral DTO).</summary>
    public sealed class WiFiSignalResult
    {
        /// <summary>The network name.</summary>
        public string SSID { get; set; } = string.Empty;
        /// <summary>Signal quality in percent.</summary>
        public int SignalStrength { get; set; }
        /// <summary>Signal strength in dBm, derived from <see cref="SignalStrength"/> on the scale of the platform
        /// (<see cref="WindowsQualityToDbm"/>, <see cref="NetworkManagerSignalToDbm"/>).</summary>
        public int SignalStrengthDbm { get; set; }
        /// <summary>When the measurement was taken.</summary>
        public DateTime Timestamp { get; set; }

        /// <summary>
        /// Converts a Windows signal quality into dBm: 0 percent is -100 dBm, 100 percent is -50 dBm, linear in between
        /// (WLAN_SIGNAL_QUALITY, wlanapi.h).
        /// </summary>
        /// <param name="quality">Signal quality in percent; values outside 0 to 100 are clamped.</param>
        /// <returns>The signal strength in dBm, from -100 to -50.</returns>
        public static int WindowsQualityToDbm(int quality) => Math.Clamp(quality, 0, 100) / 2 - 100;

        /// <summary>
        /// Converts the signal of NetworkManager (nmcli, field SIGNAL) back into dBm. NetworkManager derives it from the
        /// level in dBm with -100 dBm as 0 and -40 dBm as 100, linear in between (function
        /// nm_wifi_utils_level_to_quality); this is the inverse, rounded to whole dBm.
        /// </summary>
        /// <param name="signal">Signal in percent; values outside 0 to 100 are clamped.</param>
        /// <returns>The signal strength in dBm, from -100 to -40.</returns>
        public static int NetworkManagerSignalToDbm(int signal) => (int)Math.Round(Math.Clamp(signal, 0, 100) * 0.6) - 100;
    }
}
