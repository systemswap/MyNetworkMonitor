namespace MyNetworkMonitor.Core.Models
{
    /// <summary>Signal information of a Wi-Fi network (platform-neutral DTO).</summary>
    public sealed class WiFiSignalResult
    {
        /// <summary>The network name.</summary>
        public string SSID { get; set; } = string.Empty;
        /// <summary>Signal quality in percent.</summary>
        public int SignalStrength { get; set; }
        /// <summary>Signal strength in dBm.</summary>
        public int SignalStrengthDbm { get; set; }
        /// <summary>When the measurement was taken.</summary>
        public DateTime Timestamp { get; set; }
    }
}
