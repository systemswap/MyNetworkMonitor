namespace MyNetworkMonitor.Core.Models
{
    /// <summary>Ein Eintrag der ARP-Tabelle (IP-Adresse ↔ MAC-Adresse).</summary>
    public sealed class ArpEntry
    {
        public string IpAddress { get; init; } = string.Empty;
        public string MacAddress { get; init; } = string.Empty;
    }
}
