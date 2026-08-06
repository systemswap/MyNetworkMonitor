using System.Text.RegularExpressions;
using CommunityToolkit.Mvvm.ComponentModel;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>
    /// Der Filter ueber der Ergebnistabelle. Alle Bedingungen sind
    /// und-verknuepft - was gesetzt ist, muss zutreffen; was leer ist, filtert
    /// nicht.
    /// <para>
    /// Enthaelt jede Bedingung der bisherigen Filterzeile und zusaetzlich
    /// Dienst und Port. Bewusst ohne Bezug zur Oberflaeche, damit sich die
    /// Logik pruefen laesst, ohne ein Fenster zu oeffnen.
    /// </para>
    /// </summary>
    public partial class DeviceFilter : ObservableObject
    {
        // --- Freie Suche (die beiden Felder der bisherigen Zeile) -----------
        [ObservableProperty] private string _text1 = string.Empty;
        [ObservableProperty] private string _text2 = string.Empty;

        // --- Spaltenfilter --------------------------------------------------
        [ObservableProperty] private string _ip = string.Empty;
        [ObservableProperty] private string _hostName = string.Empty;
        [ObservableProperty] private string _internalName = string.Empty;
        [ObservableProperty] private string _mac = string.Empty;
        [ObservableProperty] private string _vendor = string.Empty;

        // --- Dienste und Ports ----------------------------------------------

        /// <summary>
        /// Freie Porteingabe: einzeln, per Komma oder als Bereich.
        /// </summary>
        [ObservableProperty] private string _ports = string.Empty;

        /// <summary>
        /// Ausgewaehlte Dienstnamen. Leer heisst: nicht nach Dienst filtern.
        /// Ein Geraet passt, wenn <b>einer</b> der gewaehlten Dienste zutrifft -
        /// oder-verknuepft, weil man sonst nie etwas faende.
        /// </summary>
        public HashSet<string> Services { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Nur Dienste beruecksichtigen, die tatsaechlich laufen.</summary>
        [ObservableProperty] private bool _onlyRunningServices;

        // --- Adressfamilie ----------------------------------------------------
        [ObservableProperty] private bool _showIPv4 = true;
        [ObservableProperty] private bool _showIPv6 = true;

        /// <summary>
        /// Nur Geraete, die eine globale IPv6-Adresse haben. Zusammen mit dem
        /// Portfilter ergibt das die Frage, die IPv6 erst interessant macht:
        /// was ist ohne NAT von aussen erreichbar?
        /// </summary>
        [ObservableProperty] private bool _onlyGloballyReachable;

        // --- Zustand ----------------------------------------------------------
        [ObservableProperty] private bool _onlyOnline;

        // --- Merkmalsschalter der bisherigen Zeile -----------------------------
        [ObservableProperty] private bool _isCamera;
        [ObservableProperty] private bool _hasSsdp;
        [ObservableProperty] private bool _hasSmb;
        [ObservableProperty] private bool _hasSnmp;
        [ObservableProperty] private bool _hasNetBios;

        /// <summary>Wird ausgeloest, sobald sich irgendeine Bedingung aendert.</summary>
        public event Action? Changed;

        public DeviceFilter()
        {
            PropertyChanged += (_, _) => Changed?.Invoke();
        }

        /// <summary>Nach einer Aenderung an <see cref="Services"/> aufrufen.</summary>
        public void NotifyServicesChanged() => Changed?.Invoke();

        /// <summary>Es ist nichts gesetzt - alle Geraete sind sichtbar.</summary>
        public bool IsEmpty =>
            string.IsNullOrWhiteSpace(Text1) && string.IsNullOrWhiteSpace(Text2) &&
            string.IsNullOrWhiteSpace(Ip) && string.IsNullOrWhiteSpace(HostName) &&
            string.IsNullOrWhiteSpace(InternalName) && string.IsNullOrWhiteSpace(Mac) &&
            string.IsNullOrWhiteSpace(Vendor) && string.IsNullOrWhiteSpace(Ports) &&
            Services.Count == 0 && !OnlyRunningServices && !OnlyOnline &&
            !OnlyGloballyReachable && ShowIPv4 && ShowIPv6 &&
            !IsCamera && !HasSsdp && !HasSmb && !HasSnmp && !HasNetBios;

        public void Reset()
        {
            Text1 = Text2 = Ip = HostName = InternalName = Mac = Vendor = Ports = string.Empty;
            Services.Clear();
            OnlyRunningServices = OnlyOnline = OnlyGloballyReachable = false;
            IsCamera = HasSsdp = HasSmb = HasSnmp = HasNetBios = false;
            ShowIPv4 = ShowIPv6 = true;
            Changed?.Invoke();
        }

        // ------------------------------------------------------------- Pruefung

        public bool Matches(Device device)
        {
            ArgumentNullException.ThrowIfNull(device);

            if (!MatchesFamily(device)) return false;
            if (OnlyOnline && !device.IsOnline) return false;
            if (OnlyGloballyReachable && !device.HasGloballyRoutableAddress) return false;

            if (!MatchesFreeText(device, Text1)) return false;
            if (!MatchesFreeText(device, Text2)) return false;

            if (!MatchesAddress(device, Ip)) return false;
            if (!Contains(device.HostName, HostName)) return false;
            if (!Contains(device.InternalName, InternalName)) return false;
            if (!Contains(MacText(device), Mac)) return false;
            if (!Contains(device.Vendor, Vendor)) return false;

            if (!MatchesPorts(device)) return false;
            if (!MatchesServices(device)) return false;
            if (!MatchesFeatures(device)) return false;

            return true;
        }

        /// <summary>
        /// Ein Geraet faellt nur heraus, wenn <b>keine</b> seiner Adressen zu
        /// einer sichtbaren Familie gehoert. Ein Dual-Stack-Geraet bleibt
        /// darum sichtbar, solange eine der beiden Familien eingeschaltet ist -
        /// alles andere waere ueberraschend.
        /// </summary>
        private bool MatchesFamily(Device device)
        {
            if (ShowIPv4 && ShowIPv6) return true;
            if (!ShowIPv4 && !ShowIPv6) return false;

            return ShowIPv4 ? device.Ipv4Addresses.Any() : device.Ipv6Addresses.Any();
        }

        /// <summary>Sucht ueber alles, was in der Tabelle steht.</summary>
        private static bool MatchesFreeText(Device device, string needle)
        {
            if (string.IsNullOrWhiteSpace(needle)) return true;

            string n = needle.Trim();

            if (Contains(device.DisplayName, n) ||
                Contains(device.HostName, n) ||
                Contains(device.InternalName, n) ||
                Contains(device.NetBiosName, n) ||
                Contains(device.Vendor, n) ||
                Contains(device.Domain, n) ||
                Contains(device.GroupDescription, n) ||
                Contains(MacText(device), n))
            {
                return true;
            }

            if (device.Addresses.Any(a => a.Info.Canonical.Contains(n, StringComparison.OrdinalIgnoreCase)))
                return true;

            if (device.Services.Any(s => s.ServiceName.Contains(n, StringComparison.OrdinalIgnoreCase)))
                return true;

            return device.Details.Values.Any(v => v.Contains(n, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Adressfilter mit Platzhalter. <c>192.168.178.*</c> trifft das ganze
        /// Subnetz, <c>2003:*</c> alles aus diesem Praefix. Ohne Stern wird
        /// als Teilzeichenfolge gesucht - so wie bisher.
        /// </summary>
        private static bool MatchesAddress(Device device, string pattern)
        {
            if (string.IsNullOrWhiteSpace(pattern)) return true;

            string p = pattern.Trim();

            if (!p.Contains('*'))
            {
                return device.Addresses.Any(a =>
                    a.Info.Canonical.Contains(p, StringComparison.OrdinalIgnoreCase));
            }

            string regex = "^" + Regex.Escape(p).Replace("\\*", ".*") + "$";
            Regex compiled = new(regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

            return device.Addresses.Any(a => compiled.IsMatch(a.Info.Canonical));
        }

        private bool MatchesPorts(Device device)
        {
            PortSpec spec = PortSpec.Parse(Ports);
            if (spec.IsEmpty) return true;

            IEnumerable<DeviceServiceResult> services = OnlyRunningServices
                ? device.Services.Where(s => s.IsRunning)
                : device.Services;

            return services.Any(s => spec.ContainsAny(s.Ports));
        }

        private bool MatchesServices(Device device)
        {
            if (Services.Count == 0)
            {
                // Ohne Dienstauswahl wirkt "nur laufende" trotzdem: dann muss
                // wenigstens ein laufender Dienst vorhanden sein.
                return !OnlyRunningServices || device.Services.Any(s => s.IsRunning);
            }

            IEnumerable<DeviceServiceResult> services = OnlyRunningServices
                ? device.Services.Where(s => s.IsRunning)
                : device.Services;

            return services.Any(s => Services.Contains(s.ServiceName));
        }

        private bool MatchesFeatures(Device device)
        {
            if (IsCamera && !HasDetail(device, "Kamera")) return false;
            if (HasSnmp && !HasDetail(device, "SNMP")) return false;
            if (HasSmb && !HasDetail(device, "SMB-Versionen") && !HasService(device, "SMB")) return false;
            if (HasNetBios && string.IsNullOrWhiteSpace(device.NetBiosName)) return false;
            if (HasSsdp && !device.SeenBy.Contains("SSDP / UPnP")) return false;

            return true;
        }

        // -------------------------------------------------------------- Helfer

        private static bool HasDetail(Device device, string key) =>
            device.Details.ContainsKey(key);

        private static bool HasService(Device device, string name) =>
            device.Services.Any(s => s.ServiceName.Contains(name, StringComparison.OrdinalIgnoreCase));

        private static string MacText(Device device) =>
            device.Mac is null
                ? string.Empty
                : string.Join(":", device.Mac.GetAddressBytes().Select(b => b.ToString("x2")));

        private static bool Contains(string? haystack, string? needle) =>
            string.IsNullOrWhiteSpace(needle) ||
            (!string.IsNullOrEmpty(haystack) && haystack.Contains(needle.Trim(), StringComparison.OrdinalIgnoreCase));
    }
}
