namespace MyNetworkMonitor.Core.Models
{
    /// <summary>Signalinformationen eines WLAN-Netzwerks (plattformneutrales DTO).</summary>
    public sealed class WiFiSignalResult
    {
        public string SSID { get; set; } = string.Empty;
        public int SignalStrength { get; set; }
        public int SignalStrengthDbm { get; set; }
        public DateTime Timestamp { get; set; }
    }
}
